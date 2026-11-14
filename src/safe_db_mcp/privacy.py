"""Local, fail-closed result privacy for explicitly classified reporting sources.

This is redaction, not reversible pseudonymisation or a general PII detector.
Policy files contain classifications, never credentials or original private values.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

import sqlglot
from sqlglot import exp

from safe_db_mcp.database import QueryResult
from safe_db_mcp import diagnostics  # noqa: F401 -- installs safe parser diagnostics

REDACTED = "[REDACTED]"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z", re.ASCII)
_ENUM_VALUE = re.compile(r"[A-Za-z0-9 _./-]{1,64}\Z", re.ASCII)
_MONTH = re.compile(r"[0-9]{4}-(0[1-9]|1[0-2])\Z", re.ASCII)
# Fixed bounded patterns are defense in depth. Negative detection never approves free text.
_CREDENTIAL = re.compile(r"(?:AKIA[0-9A-Z]{16}|(?:gh[pousr]_|github_pat_|sk-)[A-Za-z0-9_-]{16,})", re.ASCII)


class Reason(str, Enum):
    ALLOW = "ALLOW_CLASSIFIED_FIELDS"
    SCHEMA = "ALLOW_APPROVED_SCHEMA"
    REDACT = "REDACT_POLICY_CELL"
    CREDENTIAL = "REDACT_CREDENTIAL"
    QUERY = "BLOCK_QUERY_SHAPE"
    GUARD = "BLOCK_QUERY_REJECTED"
    OUTPUT = "BLOCK_UNCLASSIFIED_OUTPUT"
    VALUE = "BLOCK_UNSUPPORTED_VALUE"
    BUDGET = "BLOCK_SCAN_BUDGET"
    DATABASE = "BLOCK_DATABASE_ERROR"
    TIMEOUT = "BLOCK_TIMEOUT"
    AUDIT = "BLOCK_AUDIT_UNAVAILABLE"
    INTERNAL = "BLOCK_INTERNAL_ERROR"


class PrivacyBlocked(Exception):
    def __init__(self, reason: Reason):
        self.reason = reason
        super().__init__(reason.value)


class PolicyInvalid(ValueError):
    def __init__(self):
        super().__init__("BLOCK_POLICY_INVALID: check the local privacy policy schema")


@dataclass(frozen=True)
class FieldPolicy:
    kind: str
    nullable: bool
    minimum: Decimal | None = None
    maximum: Decimal | None = None
    values: frozenset[str] = frozenset()


@dataclass(frozen=True)
class QueryPlan:
    sql: str
    fields: tuple[tuple[str, FieldPolicy], ...]


@dataclass(frozen=True)
class PrivacyPolicy:
    sources: Mapping[str, Mapping[str, FieldPolicy]]
    max_cell_bytes: int = 16384
    max_result_bytes: int = 262144
    max_cells: int = 10000

    @classmethod
    def load(cls, path: str | Path) -> PrivacyPolicy:
        try:
            with open(path, "rb") as stream:
                data = stream.read(262145)
            if len(data) > 262144:
                raise PolicyInvalid()
            return cls.from_dict(json.loads(data, object_pairs_hook=_unique_keys))
        except Exception:
            # Parser errors, filesystem paths and policy fragments never cross this boundary.
            raise PolicyInvalid() from None

    @classmethod
    def from_dict(cls, data: dict) -> PrivacyPolicy:
        try:
            _keys(data, {"schema_version", "sources"}, {"limits"})
            if type(data["schema_version"]) is not int or data["schema_version"] != 1:
                raise PolicyInvalid()
            sources = data["sources"]
            if type(sources) is not dict or not 1 <= len(sources) <= 64:
                raise PolicyInvalid()
            parsed = {}
            for source, fields in sources.items():
                if not _identifier(source) or type(fields) is not dict or not 1 <= len(fields) <= 64:
                    raise PolicyInvalid()
                if len({name.lower() for name in fields}) != len(fields):
                    raise PolicyInvalid()
                parsed[source] = MappingProxyType({name: _field(name, rule) for name, rule in fields.items()})
            if len({name.lower() for name in sources}) != len(sources):
                raise PolicyInvalid()
            limits = data.get("limits", {})
            _keys(limits, set(), {"max_cell_bytes", "max_result_bytes", "max_cells"})
            bounds = {"max_cell_bytes": 16384, "max_result_bytes": 262144, "max_cells": 10000}
            for name, ceiling in bounds.items():
                value = limits.get(name, ceiling)
                if type(value) is not int or not 1 <= value <= ceiling:
                    raise PolicyInvalid()
                bounds[name] = value
            return cls(MappingProxyType(parsed), **bounds)
        except Exception:
            raise PolicyInvalid() from None

    def authorize(self, sql: str, dialect: str) -> QueryPlan:
        """Only explicit columns from one source; private fields cannot affect predicates/order."""
        try:
            if not isinstance(sql, str) or len(sql) > 16384 or len(sql.encode("utf-8")) > 16384:
                raise PrivacyBlocked(Reason.BUDGET)
            statements = sqlglot.parse(sql, read=dialect, max_nodes=2048)
            if len(statements) != 1 or type(statements[0]) is not exp.Select:
                raise PrivacyBlocked(Reason.QUERY)
            tree = statements[0]
            _args(tree, {"expressions", "from_", "where", "order", "limit", "offset"})
            source_from = tree.args.get("from_")
            if type(source_from) is not exp.From:
                raise PrivacyBlocked(Reason.QUERY)
            _args(source_from, {"this"})
            source = source_from.this
            if type(source) is not exp.Table or type(source.this) is not exp.Identifier:
                raise PrivacyBlocked(Reason.QUERY)
            _args(source, {"this"})
            fields = self.sources.get(source.name)
            if fields is None:
                raise PrivacyBlocked(Reason.QUERY)
            names = [_column(item, fields) for item in tree.expressions]
            if not names or len(set(names)) != len(names):
                raise PrivacyBlocked(Reason.QUERY)
            where = tree.args.get("where")
            if where is not None:
                if type(where) is not exp.Where:
                    raise PrivacyBlocked(Reason.QUERY)
                _args(where, {"this"})
                _predicate(where.this, fields)
            order = tree.args.get("order")
            if order is not None:
                _args(order, {"expressions"})
                for item in order.expressions:
                    if type(item) is not exp.Ordered:
                        raise PrivacyBlocked(Reason.QUERY)
                    _args(item, {"this", "desc", "nulls_first"})
                    _public_column(item.this, fields)
            for name, node_type in (("limit", exp.Limit), ("offset", exp.Offset)):
                node = tree.args.get(name)
                if node is not None:
                    if type(node) is not node_type:
                        raise PrivacyBlocked(Reason.QUERY)
                    _args(node, {"expression"})
                    literal = node.expression
                    if type(literal) is not exp.Literal or not literal.is_int or not 0 <= int(literal.this) <= 2147483647:
                        raise PrivacyBlocked(Reason.QUERY)
            for node in tree.walk():
                node.comments = None
            return QueryPlan(tree.sql(dialect=dialect), tuple((name, fields[name]) for name in names))
        except PrivacyBlocked:
            raise
        except Exception:
            raise PrivacyBlocked(Reason.QUERY) from None

    def sanitize(self, result: QueryResult, plan: QueryPlan, masked_columns=frozenset()) -> dict:
        names = [name for name, _ in plan.fields]
        if list(result.column_names) != names or type(result.truncated) is not bool:
            raise PrivacyBlocked(Reason.OUTPUT)
        if len(result.rows) * len(names) > self.max_cells:
            raise PrivacyBlocked(Reason.BUDGET)
        rows, redacted, policy_redacted, credential, candidate_bytes = [], 0, 0, False, 0
        for row in result.rows:
            if len(row) != len(names):
                raise PrivacyBlocked(Reason.OUTPUT)
            safe_row = []
            for (_, field), value, name in zip(plan.fields, row, names):
                if value is not None and type(value) not in (str, int, float, bool, Decimal):
                    raise PrivacyBlocked(Reason.VALUE)
                if type(value) is str:
                    if len(value) > self.max_cell_bytes:
                        raise PrivacyBlocked(Reason.BUDGET)
                    size = len(value.encode("utf-8"))
                    if size > self.max_cell_bytes:
                        raise PrivacyBlocked(Reason.BUDGET)
                    candidate_bytes += size
                elif type(value) is Decimal:
                    # Reject enormous coefficients before converting a public Decimal into JSON text.
                    if len(value.as_tuple().digits) > self.max_cell_bytes:
                        raise PrivacyBlocked(Reason.BUDGET)
                    size = len(str(value))
                    if size > self.max_cell_bytes:
                        raise PrivacyBlocked(Reason.BUDGET)
                    candidate_bytes += size
                else:
                    candidate_bytes += 32
                if candidate_bytes > self.max_result_bytes:
                    raise PrivacyBlocked(Reason.BUDGET)
                if value is None:
                    if not field.nullable:
                        raise PrivacyBlocked(Reason.VALUE)
                    safe_row.append(None)
                elif field.kind == "redact_cell" or name.lower() in masked_columns:
                    redacted += 1
                    policy_redacted += 1
                    safe_row.append(REDACTED)
                elif type(value) is str and _CREDENTIAL.search(value):
                    # Never restore credentials, including mistakenly classified enum values.
                    credential = True
                    redacted += 1
                    safe_row.append(REDACTED)
                else:
                    safe_row.append(_public_value(value, field))
            rows.append(safe_row)
        reasons = [Reason.REDACT.value] if policy_redacted else []
        if credential:
            reasons.append(Reason.CREDENTIAL.value)
        if not reasons:
            reasons.append(Reason.ALLOW.value)
        response = {"columns": names, "rows": rows, "row_count": len(rows), "truncated": result.truncated,
                    "privacy": {"mode": "strict", "schema_version": 1, "decision": "redact" if redacted else "allow",
                                "reasons": reasons, "redacted_cells": redacted}}
        if len(json.dumps(response, allow_nan=False).encode("utf-8")) > self.max_result_bytes:
            raise PrivacyBlocked(Reason.BUDGET)
        return response

    def schema(self, table: str | None = None) -> dict:
        if table is None:
            response = {"columns": ["name", "type"], "rows": [[name, "approved_source"] for name in self.sources]}
        else:
            fields = self.sources.get(table)
            if fields is None:
                raise PrivacyBlocked(Reason.QUERY)
            response = {"columns": ["name", "classification", "nullable"],
                        "rows": [[name, rule.kind, rule.nullable] for name, rule in fields.items()]}
        response.update(row_count=len(response["rows"]), truncated=False,
                        privacy={"mode": "strict", "schema_version": 1, "decision": "allow",
                                 "reasons": [Reason.SCHEMA.value], "redacted_cells": 0})
        if len(json.dumps(response).encode("utf-8")) > self.max_result_bytes:
            raise PrivacyBlocked(Reason.BUDGET)
        return response


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyInvalid()
        result[key] = value
    return result


def _keys(data, required, optional):
    if type(data) is not dict or not required <= data.keys() or data.keys() - required - optional:
        raise PolicyInvalid()


def _identifier(name):
    return type(name) is str and _IDENTIFIER.fullmatch(name) is not None


def _field(name, rule):
    if not _identifier(name):
        raise PolicyInvalid()
    _keys(rule, {"kind", "nullable"}, {"min", "max", "values"})
    kind = rule["kind"]
    if type(rule["nullable"]) is not bool:
        raise PolicyInvalid()
    if kind == "public_number":
        if set(rule) != {"kind", "nullable", "min", "max"}:
            raise PolicyInvalid()
        for key in ("min", "max"):
            if type(rule[key]) not in (int, float) or not math.isfinite(rule[key]) or abs(rule[key]) > 10**15:
                raise PolicyInvalid()
        if rule["min"] > rule["max"]:
            raise PolicyInvalid()
        return FieldPolicy(kind, rule["nullable"], Decimal(str(rule["min"])), Decimal(str(rule["max"])))
    if kind == "public_enum":
        values = rule.get("values")
        if set(rule) != {"kind", "nullable", "values"} or type(values) is not list or not 1 <= len(values) <= 100:
            raise PolicyInvalid()
        if any(type(v) is not str or not _ENUM_VALUE.fullmatch(v) for v in values) or len(set(values)) != len(values):
            raise PolicyInvalid()
        return FieldPolicy(kind, rule["nullable"], values=frozenset(values))
    if kind not in ("redact_cell", "public_month") or set(rule) != {"kind", "nullable"}:
        raise PolicyInvalid()
    return FieldPolicy(kind, rule["nullable"])


def _public_value(value, rule):
    if rule.kind == "public_number" and type(value) in (int, float, Decimal):
        try:
            number = Decimal(str(value))
            if number.is_finite() and rule.minimum <= number <= rule.maximum:
                # Preserve exact MySQL Decimal values; never call str() on unknown objects.
                return str(value) if type(value) is Decimal else value
        except Exception:
            pass
    elif rule.kind == "public_enum" and type(value) is str and value in rule.values:
        return value
    elif rule.kind == "public_month" and type(value) is str and _MONTH.fullmatch(value) and value[:4] != "0000":
        return value
    raise PrivacyBlocked(Reason.VALUE)


def _args(node, allowed):
    if any(value is not None and value is not False and value != [] for key, value in node.args.items() if key not in allowed):
        raise PrivacyBlocked(Reason.QUERY)


def _column(node, fields):
    if type(node) is not exp.Column or type(node.this) is not exp.Identifier:
        raise PrivacyBlocked(Reason.QUERY)
    _args(node, {"this"})
    if node.name not in fields:
        raise PrivacyBlocked(Reason.QUERY)
    return node.name


def _public_column(node, fields):
    name = _column(node, fields)
    if fields[name].kind == "redact_cell":
        raise PrivacyBlocked(Reason.QUERY)
    return name


def _literal(node, rule):
    if type(node) is exp.Null:
        return
    if type(node) is exp.Neg:
        _args(node, {"this"})
        if type(node.this) is not exp.Literal or node.this.is_string:
            raise PrivacyBlocked(Reason.QUERY)
        _public_value(Decimal("-" + node.this.this), rule)
    elif type(node) is exp.Literal:
        _public_value(node.this if node.is_string else Decimal(node.this), rule)
    else:
        raise PrivacyBlocked(Reason.QUERY)


def _predicate(node, fields, depth=0):
    if depth > 32:
        raise PrivacyBlocked(Reason.BUDGET)
    if type(node) in (exp.And, exp.Or):
        _args(node, {"this", "expression"})
        _predicate(node.this, fields, depth + 1)
        _predicate(node.expression, fields, depth + 1)
    elif type(node) in (exp.Paren, exp.Not):
        _args(node, {"this"})
        _predicate(node.this, fields, depth + 1)
    elif type(node) in (exp.EQ, exp.NEQ, exp.GT, exp.GTE, exp.LT, exp.LTE, exp.Is):
        _args(node, {"this", "expression"})
        rule = fields[_public_column(node.this, fields)]
        _literal(node.expression, rule)
    elif type(node) is exp.In:
        _args(node, {"this", "expressions"})
        rule = fields[_public_column(node.this, fields)]
        if not node.expressions or len(node.expressions) > 100:
            raise PrivacyBlocked(Reason.QUERY)
        for item in node.expressions:
            _literal(item, rule)
    elif type(node) is exp.Between:
        _args(node, {"this", "low", "high"})
        rule = fields[_public_column(node.this, fields)]
        _literal(node.args["low"], rule)
        _literal(node.args["high"], rule)
    else:
        raise PrivacyBlocked(Reason.QUERY)
