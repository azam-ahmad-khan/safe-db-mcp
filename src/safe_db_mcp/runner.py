"""Runs an agent's request through every guard in order: check, cap, execute, mask, audit."""

from __future__ import annotations

import base64
import time
from collections.abc import Iterable
from datetime import date, datetime, time as time_of_day, timedelta
from decimal import Decimal
from typing import Any

from safe_db_mcp.audit import AuditLog
from safe_db_mcp.database import Database, DatabaseQueryError, QueryResult, QueryTimeout
from safe_db_mcp.guards import QueryRejected, apply_row_limit, check_query, mask_rows
from safe_db_mcp.relationships import RelationshipGraph


class SafeQueryRunner:
    def __init__(
        self,
        database: Database,
        audit_log: AuditLog,
        max_rows: int,
        masked_columns: Iterable[str] = (),
        relationships: RelationshipGraph | None = None,
    ):
        self._database = database
        self._audit_log = audit_log
        self._max_rows = max_rows
        self._masked_columns = frozenset(name.lower() for name in masked_columns)
        self.relationships = relationships

    def run_query(self, sql: str) -> dict[str, Any]:
        started = time.monotonic()
        try:
            statement_kind = check_query(sql, self._database.dialect, self._masked_columns)
        except QueryRejected as rejection:
            self._audit_log.record(tool="run_query", outcome="rejected", sql=sql, reason=rejection.reason)
            raise

        capped_sql = apply_row_limit(sql, self._database.dialect, self._max_rows)
        query_result = self._execute(
            "run_query",
            lambda: self._database.run_query(capped_sql),
            started,
            sql=sql,
            executed_sql=capped_sql if capped_sql != sql else None,
            statement_kind=statement_kind,
        )
        return self._to_response(query_result, mask_values=True)

    def list_tables(self) -> dict[str, Any]:
        query_result = self._execute("list_tables", self._database.list_tables, time.monotonic())
        return self._to_response(query_result)

    def describe_table(self, table_name: str) -> dict[str, Any]:
        query_result = self._execute(
            "describe_table", lambda: self._database.describe_table(table_name), time.monotonic(), table=table_name
        )
        if not query_result.rows:
            raise DatabaseQueryError(f"no table or view named {table_name!r}")
        return self._to_response(query_result)

    def describe_relationships(self, table_name: str) -> dict[str, Any]:
        response = self.relationships.describe(table_name)
        self._audit_log.record(
            tool="describe_relationships",
            outcome="allowed",
            table=table_name,
            row_count=len(response["references"]) + len(response["referenced_by"]),
        )
        return response

    def join_path(self, table_a: str, table_b: str) -> dict[str, Any]:
        response = self.relationships.join_path(table_a, table_b)
        self._audit_log.record(
            tool="join_path", outcome="allowed", table=table_a, other_table=table_b, found=response["found"]
        )
        return response

    def _execute(self, tool: str, run, started: float, **audit_details: Any) -> QueryResult:
        try:
            query_result = run()
        except QueryTimeout as timeout:
            self._audit_log.record(tool=tool, outcome="timeout", reason=str(timeout), **audit_details)
            raise
        except DatabaseQueryError as error:
            self._audit_log.record(tool=tool, outcome="error", reason=str(error), **audit_details)
            raise
        self._audit_log.record(
            tool=tool,
            outcome="allowed",
            row_count=len(query_result.rows),
            truncated=query_result.truncated,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
            **audit_details,
        )
        return query_result

    def _to_response(self, query_result: QueryResult, mask_values: bool = False) -> dict[str, Any]:
        # Schema tools return column *names* under headers like "name"; only data rows are masked.
        masked_columns = self._masked_columns if mask_values else frozenset()
        masked_rows = mask_rows(query_result.column_names, query_result.rows, masked_columns)
        response: dict[str, Any] = {
            "columns": query_result.column_names,
            "rows": [[_to_json_value(value) for value in row] for row in masked_rows],
            "row_count": len(masked_rows),
            "truncated": query_result.truncated,
        }
        masked_columns_in_result = [name for name in query_result.column_names if name.lower() in masked_columns]
        if masked_columns_in_result:
            response["masked_columns"] = masked_columns_in_result
        if query_result.truncated:
            response["note"] = (
                f"Only the first {len(masked_rows)} rows are shown. "
                "Add filters, aggregate, or page with LIMIT/OFFSET to see the rest."
            )
        return response


def _to_json_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Decimal):
        # As a string so money values keep their exact digits.
        return str(value)
    if isinstance(value, (datetime, date, time_of_day)):
        return value.isoformat()
    if isinstance(value, timedelta):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"base64": base64.b64encode(bytes(value)).decode("ascii")}
    return str(value)
