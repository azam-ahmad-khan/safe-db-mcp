"""Query guards: decide whether an agent's SQL may run, and mask PII in what comes back.

The checks read the SQL as a syntax tree (via sqlglot), not as text, so tricks like
comments, odd casing or a second statement after a semicolon can't slip past a keyword match.
Anything the parser can't understand is rejected: unknown means no.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

SUPPORTED_DIALECTS = frozenset({"sqlite", "mysql"})

MASKED_VALUE = "[masked]"

# SHOW variants that describe schema only; e.g. SHOW PROCESSLIST would expose other sessions' SQL.
ALLOWED_SHOW_KINDS = frozenset({
    "TABLES",
    "FULL TABLES",
    "COLUMNS",
    "FULL COLUMNS",
    "INDEX",
    "INDEXES",
    "KEYS",
    "CREATE TABLE",
    "CREATE VIEW",
    "TABLE STATUS",
    "DATABASES",
})

# Read-only by syntax, but they stall the server, read server files, or allocate huge blobs.
DENIED_FUNCTION_NAMES = frozenset({
    "sleep",
    "benchmark",
    "pg_sleep",
    "get_lock",
    "release_lock",
    "load_file",
    "load_extension",
    "readfile",
    "writefile",
    "randomblob",
    "zeroblob",
})

READ_QUERY_TYPES = (exp.Select, exp.SetOperation)

# Nodes that write, lock, change session state or touch the file system, wherever they appear.
FORBIDDEN_NODE_TYPES = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Create,
    exp.Drop,
    exp.Alter,
    exp.TruncateTable,
    exp.Command,
    exp.Into,
    exp.Lock,
    exp.Set,
    exp.Attach,
    exp.Detach,
    exp.Pragma,
)

_EXPLAIN_QUERY_PLAN_PREFIX = re.compile(r"^\s*QUERY\s+PLAN\s+", re.IGNORECASE)
_ANALYZE_PREFIX = re.compile(r"^\s*ANALYZE\b", re.IGNORECASE)


class QueryRejected(Exception):
    """Raised when a query fails a guard; `reason` is safe to show to the agent."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def check_query(sql: str, dialect: str, masked_columns: Iterable[str] = ()) -> str:
    """Return the statement kind ("select", "show", "describe" or "explain") or raise QueryRejected."""
    if dialect not in SUPPORTED_DIALECTS:
        raise ValueError(f"unsupported dialect: {dialect}")
    masked_column_names = frozenset(name.lower() for name in masked_columns)

    statement = _parse_single_statement(sql, dialect)

    if isinstance(statement, READ_QUERY_TYPES):
        _check_read_query(statement, masked_column_names)
        return "select"
    if isinstance(statement, exp.Show):
        _check_show(statement)
        return "show"
    if isinstance(statement, exp.Describe):
        return _check_describe_or_explain(statement, masked_column_names)
    if isinstance(statement, exp.Command) and statement.name.upper() == "EXPLAIN":
        _check_explain_command(statement, dialect, masked_column_names)
        return "explain"
    raise QueryRejected(
        f"{_statement_label(statement)} statements are not allowed; only SELECT, SHOW, DESCRIBE and EXPLAIN are"
    )


def apply_row_limit(sql: str, dialect: str, max_rows: int) -> str:
    """Return a SELECT rewritten so the database stops after max_rows + 1 rows; other statements are unchanged.

    The extra row lets the caller tell "exactly max_rows" from "more were cut off". The rewrite
    is generated from the same parsed tree the guards checked, so what runs is what was checked.
    """
    statement = _parse_single_statement(sql, dialect)
    if not isinstance(statement, READ_QUERY_TYPES):
        return sql
    existing_limit = statement.args.get("limit")
    existing_limit_value = existing_limit.expression if existing_limit else None
    if isinstance(existing_limit_value, exp.Literal) and existing_limit_value.is_int:
        if int(existing_limit_value.name) <= max_rows:
            return statement.sql(dialect=dialect)
    return statement.limit(max_rows + 1).sql(dialect=dialect)


def mask_rows(
    column_names: Sequence[str],
    rows: Iterable[Sequence[object]],
    masked_columns: Iterable[str],
) -> list[tuple[object, ...]]:
    """Replace values in masked columns (matched by name, case-insensitive) with MASKED_VALUE; NULLs stay NULL."""
    masked_column_names = frozenset(name.lower() for name in masked_columns)
    masked_positions = {index for index, name in enumerate(column_names) if name.lower() in masked_column_names}
    return [
        tuple(
            MASKED_VALUE if index in masked_positions and value is not None else value
            for index, value in enumerate(row)
        )
        for row in rows
    ]


def _parse_single_statement(sql: str, dialect: str) -> exp.Expression:
    if not sql or not sql.strip():
        raise QueryRejected("query is empty")
    try:
        statements = [statement for statement in sqlglot.parse(sql, read=dialect) if statement is not None]
    except SqlglotError as parse_error:
        raise QueryRejected(f"query could not be parsed, so it is not allowed: {parse_error}") from parse_error
    if len(statements) != 1:
        raise QueryRejected(f"exactly one statement is allowed, got {len(statements)}")
    return statements[0]


def _check_read_query(statement: exp.Expression, masked_column_names: frozenset[str]) -> None:
    for node in statement.walk():
        if isinstance(node, FORBIDDEN_NODE_TYPES):
            raise QueryRejected(f"{_statement_label(node)} is not allowed inside a read query")
        if isinstance(node, exp.Func):
            function_name = (node.name if isinstance(node, exp.Anonymous) else node.sql_name()).lower()
            if function_name in DENIED_FUNCTION_NAMES:
                raise QueryRejected(f"function {function_name}() is not allowed")
    _check_masked_column_usage(statement, masked_column_names)


def _check_masked_column_usage(statement: exp.Expression, masked_column_names: frozenset[str]) -> None:
    """A masked column may only be selected as-is at the top level, where its output name still matches.

    Aliases, functions, filters, joins, ordering, subqueries or UNIONs would let the value
    come back under a different name (unmasked) or be guessed one comparison at a time.
    """
    if not masked_column_names:
        return
    for column in statement.find_all(exp.Column):
        if column.name.lower() not in masked_column_names:
            continue
        is_plain_top_level_projection = (
            isinstance(statement, exp.Select) and column.parent is statement and column.arg_key == "expressions"
        )
        if not is_plain_top_level_projection:
            raise QueryRejected(
                f"masked column '{column.name}' can only be selected directly, "
                "not aliased, transformed, filtered, joined, sorted or used in a subquery"
            )


def _check_show(statement: exp.Show) -> None:
    show_kind = " ".join(statement.name.upper().split())
    if statement.args.get("full") and not show_kind.startswith("FULL"):
        show_kind = f"FULL {show_kind}"
    if show_kind not in ALLOWED_SHOW_KINDS:
        raise QueryRejected(f"SHOW {show_kind} is not allowed; only schema SHOW statements are")


def _check_describe_or_explain(statement: exp.Describe, masked_column_names: frozenset[str]) -> str:
    described = statement.this
    if isinstance(described, exp.Table):
        return "describe"
    # EXPLAIN ANALYZE runs the query for real; the agent only gets plans.
    if statement.args.get("style"):
        raise QueryRejected(f"EXPLAIN {str(statement.args['style']).upper()} is not allowed; use plain EXPLAIN")
    if not isinstance(described, READ_QUERY_TYPES):
        raise QueryRejected(f"EXPLAIN is only allowed for read queries, not {_statement_label(described)}")
    _check_read_query(described, masked_column_names)
    return "explain"


def _check_explain_command(statement: exp.Command, dialect: str, masked_column_names: frozenset[str]) -> None:
    """SQLite's EXPLAIN isn't parsed into a tree, so re-parse the explained query and check it."""
    explained_sql = statement.expression.name if statement.expression else ""
    explained_sql = _EXPLAIN_QUERY_PLAN_PREFIX.sub("", explained_sql)
    if _ANALYZE_PREFIX.match(explained_sql):
        raise QueryRejected("EXPLAIN ANALYZE is not allowed; use plain EXPLAIN")
    explained_statement = _parse_single_statement(explained_sql, dialect)
    if not isinstance(explained_statement, READ_QUERY_TYPES):
        raise QueryRejected(f"EXPLAIN is only allowed for read queries, not {_statement_label(explained_statement)}")
    _check_read_query(explained_statement, masked_column_names)


def _statement_label(node: exp.Expression | None) -> str:
    if node is None:
        return "empty"
    if isinstance(node, exp.Command):
        return node.name.upper()
    return node.key.upper()
