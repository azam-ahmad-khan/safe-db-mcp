import pytest

from safe_db_mcp.database import DatabaseQueryError, QueryTimeout, SqliteDatabase
from safe_db_mcp.guards import apply_row_limit

from conftest import TEST_MAX_ROWS


@pytest.mark.parametrize(
    "write_sql",
    [
        "DELETE FROM customers",
        "UPDATE customers SET name = 'x'",
        "INSERT INTO customers (name) VALUES ('x')",
        "DROP TABLE orders",
        "CREATE TABLE sneaky (id INT)",
    ],
)
def test_connection_refuses_writes_even_without_the_guards(sqlite_database, write_sql):
    with pytest.raises(DatabaseQueryError):
        sqlite_database.run_query(write_sql)
    assert sqlite_database.run_query("SELECT COUNT(*) FROM customers").rows == [(25,)]


def test_row_cap_truncates_and_says_so(sqlite_database):
    capped = sqlite_database.run_query("SELECT id FROM orders ORDER BY id")
    assert len(capped.rows) == TEST_MAX_ROWS
    assert capped.truncated is True


def test_result_exactly_at_the_cap_is_not_marked_truncated(sqlite_database):
    exact = sqlite_database.run_query(f"SELECT id FROM orders LIMIT {TEST_MAX_ROWS}")
    assert len(exact.rows) == TEST_MAX_ROWS
    assert exact.truncated is False


def test_long_running_query_is_stopped(sqlite_path):
    impatient_database = SqliteDatabase(sqlite_path, timeout_seconds=0.2, max_rows=TEST_MAX_ROWS)
    endless_count = (
        "WITH RECURSIVE counter(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM counter) "
        "SELECT COUNT(*) FROM counter"
    )
    with pytest.raises(QueryTimeout):
        impatient_database.run_query(endless_count)


def test_list_tables_includes_views(sqlite_database):
    assert sqlite_database.list_tables().rows == [("big_orders", "view"), ("customers", "table"), ("orders", "table")]


def test_describe_table_lists_columns(sqlite_database):
    described = sqlite_database.describe_table("customers")
    assert [row[0] for row in described.rows] == ["id", "name", "email", "phone"]


def test_schema_tools_are_not_cut_off_by_the_data_row_cap(sqlite_path):
    tiny_cap_database = SqliteDatabase(sqlite_path, timeout_seconds=2, max_rows=2)
    assert len(tiny_cap_database.describe_table("customers").rows) == 4
    assert len(tiny_cap_database.list_tables().rows) == 3


def test_missing_database_file_fails_fast(tmp_path):
    with pytest.raises(FileNotFoundError):
        SqliteDatabase(tmp_path / "missing.db", timeout_seconds=1, max_rows=1)


@pytest.mark.parametrize(
    ("sql", "expected_sql"),
    [
        ("SELECT id FROM orders", "SELECT id FROM orders LIMIT 11"),
        ("SELECT id FROM orders LIMIT 5", "SELECT id FROM orders LIMIT 5"),
        ("SELECT id FROM orders LIMIT 500", "SELECT id FROM orders LIMIT 11"),
        ("SELECT id FROM orders LIMIT 500 OFFSET 20", "SELECT id FROM orders LIMIT 11 OFFSET 20"),
        ("SELECT 1 UNION SELECT 2", "SELECT 1 UNION SELECT 2 LIMIT 11"),
        ("EXPLAIN QUERY PLAN SELECT id FROM orders", "EXPLAIN QUERY PLAN SELECT id FROM orders"),
    ],
)
def test_row_limit_is_pushed_into_select_queries(sql, expected_sql):
    assert apply_row_limit(sql, "sqlite", TEST_MAX_ROWS) == expected_sql
