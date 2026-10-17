import json
import stat

import pytest

from safe_db_mcp.database import DatabaseQueryError, QueryTimeout
from safe_db_mcp.guards import MASKED_VALUE, QueryRejected

from conftest import TEST_MAX_ROWS


def read_audit_entries(audit_log):
    return [json.loads(line) for line in audit_log.path.read_text().splitlines()]


def test_select_returns_rows_with_pii_masked(runner):
    response = runner.run_query("SELECT id, name, email, phone FROM customers WHERE id IN (1, 5) ORDER BY id")
    assert response["columns"] == ["id", "name", "email", "phone"]
    assert response["rows"] == [[1, "Customer 1", MASKED_VALUE, MASKED_VALUE], [5, "Customer 5", MASKED_VALUE, None]]
    assert response["masked_columns"] == ["email", "phone"]
    assert response["truncated"] is False


def test_select_star_masks_pii_too(runner):
    response = runner.run_query("SELECT * FROM customers WHERE id = 2")
    assert response["rows"] == [[2, "Customer 2", MASKED_VALUE, MASKED_VALUE]]


def test_large_result_is_capped_with_a_note_for_the_agent(runner):
    response = runner.run_query("SELECT id FROM orders")
    assert response["row_count"] == TEST_MAX_ROWS
    assert response["truncated"] is True
    assert "first 10 rows" in response["note"]


def test_rejected_query_is_audited_and_never_reaches_the_database(runner, audit_log):
    with pytest.raises(QueryRejected):
        runner.run_query("DELETE FROM customers")
    assert runner.run_query("SELECT COUNT(*) AS n FROM customers")["rows"] == [[25]]

    rejected_entry = read_audit_entries(audit_log)[0]
    assert rejected_entry["tool"] == "run_query"
    assert rejected_entry["outcome"] == "rejected"
    assert rejected_entry["sql"] == "DELETE FROM customers"
    assert "DELETE" in rejected_entry["reason"]


def test_allowed_query_audit_entry_records_what_actually_ran(runner, audit_log):
    runner.run_query("SELECT id FROM orders")
    allowed_entry = read_audit_entries(audit_log)[0]
    assert allowed_entry["outcome"] == "allowed"
    assert allowed_entry["sql"] == "SELECT id FROM orders"
    assert allowed_entry["executed_sql"] == "SELECT id FROM orders LIMIT 11"
    assert allowed_entry["row_count"] == TEST_MAX_ROWS
    assert allowed_entry["truncated"] is True
    assert "duration_ms" in allowed_entry
    assert "timestamp" in allowed_entry


def test_database_errors_are_audited(runner, audit_log):
    with pytest.raises(DatabaseQueryError):
        runner.run_query("SELECT * FROM no_such_table")
    assert read_audit_entries(audit_log)[0]["outcome"] == "error"


def test_timeouts_are_audited(runner, audit_log, monkeypatch):
    def run_forever(_sql):
        raise QueryTimeout("query exceeded 2s and was stopped")

    monkeypatch.setattr(runner._database, "run_query", run_forever)
    with pytest.raises(QueryTimeout):
        runner.run_query("SELECT 1")
    assert read_audit_entries(audit_log)[0]["outcome"] == "timeout"


def test_audit_log_is_readable_only_by_its_owner(audit_log):
    assert stat.S_IMODE(audit_log.path.stat().st_mode) == 0o600


def test_schema_tools_do_not_mask_column_names(runner):
    described = runner.describe_table("customers")
    assert [row[0] for row in described["rows"]] == ["id", "name", "email", "phone"]
    assert "masked_columns" not in described


def test_describe_unknown_table_is_an_error(runner):
    with pytest.raises(DatabaseQueryError):
        runner.describe_table("no_such_table")


def test_list_tables(runner, audit_log):
    assert [row[0] for row in runner.list_tables()["rows"]] == ["big_orders", "customers", "orders"]
    assert read_audit_entries(audit_log)[0]["tool"] == "list_tables"
