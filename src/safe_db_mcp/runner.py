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
from safe_db_mcp.privacy import PrivacyBlocked, PrivacyPolicy, Reason


class SafeQueryRunner:
    def __init__(
        self,
        database: Database,
        audit_log: AuditLog,
        max_rows: int,
        masked_columns: Iterable[str] = (),
        relationships: RelationshipGraph | None = None,
        privacy_policy: PrivacyPolicy | None = None,
        timeout_seconds: float = 10.0,
    ):
        self._database = database
        self._audit_log = audit_log
        self._max_rows = max_rows
        self._masked_columns = frozenset(name.lower() for name in masked_columns)
        self.privacy_policy = privacy_policy
        # Relationship metadata includes arbitrary notes/SQL; never expose it through strict tools.
        self.relationships = relationships if privacy_policy is None else None
        self._timeout_seconds = timeout_seconds

    def run_query(self, sql: str) -> dict[str, Any]:
        if self.privacy_policy is not None:
            return self._protected("run_query", lambda: self._private_query(sql))
        started = time.monotonic()
        try:
            check_query(sql, self._database.dialect, self._masked_columns)
        except QueryRejected:
            self._audit_log.record(tool="run_query", outcome="rejected", reason=Reason.GUARD)
            raise

        capped_sql = apply_row_limit(sql, self._database.dialect, self._max_rows)
        query_result = self._execute(
            "run_query",
            lambda: self._database.run_query(capped_sql),
            started,
        )
        return self._to_response(query_result, mask_values=True)

    def list_tables(self) -> dict[str, Any]:
        if self.privacy_policy is not None:
            return self._protected("list_tables", self.privacy_policy.schema)
        query_result = self._execute("list_tables", self._database.list_tables, time.monotonic())
        return self._to_response(query_result)

    def describe_table(self, table_name: str) -> dict[str, Any]:
        if self.privacy_policy is not None:
            return self._protected("describe_table", lambda: self.privacy_policy.schema(table_name))
        query_result = self._execute(
            "describe_table", lambda: self._database.describe_table(table_name), time.monotonic()
        )
        if not query_result.rows:
            raise DatabaseQueryError(f"no table or view named {table_name!r}")
        return self._to_response(query_result)

    def describe_relationships(self, table_name: str) -> dict[str, Any]:
        if self.privacy_policy is not None:
            return self._protected("describe_relationships", self._deny_relationships)
        response = self.relationships.describe(table_name)
        self._audit_log.record(
            tool="describe_relationships",
            outcome="allowed",
            row_count=len(response["references"]) + len(response["referenced_by"]),
        )
        return response

    def join_path(self, table_a: str, table_b: str) -> dict[str, Any]:
        if self.privacy_policy is not None:
            return self._protected("join_path", self._deny_relationships)
        response = self.relationships.join_path(table_a, table_b)
        self._audit_log.record(
            tool="join_path", outcome="allowed"
        )
        return response

    @staticmethod
    def _deny_relationships():
        raise PrivacyBlocked(Reason.QUERY)

    def _private_query(self, sql: str) -> dict[str, Any]:
        plan = self.privacy_policy.authorize(sql, self._database.dialect)
        check_query(plan.sql, self._database.dialect, self._masked_columns)
        result = self._database.run_query(apply_row_limit(plan.sql, self._database.dialect, self._max_rows))
        if len(result.rows) > self._max_rows:
            raise PrivacyBlocked(Reason.BUDGET)
        return self.privacy_policy.sanitize(result, plan, self._masked_columns)

    def _protected(self, tool: str, operation) -> dict[str, Any]:
        started = time.monotonic()
        try:
            response = operation()
            if time.monotonic() - started > self._timeout_seconds:
                raise PrivacyBlocked(Reason.TIMEOUT)
        except Exception as error:
            if isinstance(error, PrivacyBlocked):
                reason = error.reason
            elif isinstance(error, QueryRejected):
                reason = Reason.GUARD
            elif isinstance(error, QueryTimeout):
                reason = Reason.TIMEOUT
            elif isinstance(error, DatabaseQueryError):
                reason = Reason.DATABASE
            else:
                reason = Reason.INTERNAL
            self._private_audit(tool, "blocked", started, reason=reason)
            raise PrivacyBlocked(reason) from None
        privacy = response["privacy"]
        self._private_audit(tool, "redacted" if privacy["decision"] == "redact" else "allowed", started,
                            reason=Reason(privacy["reasons"][0]), row_count=response["row_count"],
                            truncated=response["truncated"], redacted_cells=privacy["redacted_cells"])
        return response

    def _private_audit(self, tool, outcome, started, **metadata):
        try:
            self._audit_log.record(tool=tool, outcome=outcome, privacy_mode="strict",
                                   duration_ms=round((time.monotonic() - started) * 1000, 1), **metadata)
        except Exception:
            raise PrivacyBlocked(Reason.AUDIT) from None

    def _execute(self, tool: str, run, started: float) -> QueryResult:
        try:
            query_result = run()
        except QueryTimeout:
            self._audit_log.record(tool=tool, outcome="timeout", reason=Reason.TIMEOUT)
            raise
        except DatabaseQueryError:
            self._audit_log.record(tool=tool, outcome="error", reason=Reason.DATABASE)
            raise
        self._audit_log.record(
            tool=tool,
            outcome="allowed",
            row_count=len(query_result.rows),
            truncated=query_result.truncated,
            duration_ms=round((time.monotonic() - started) * 1000, 1),
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
        response["privacy"] = {"mode": "legacy", "strict_protection": False}
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
