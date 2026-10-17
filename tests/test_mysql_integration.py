"""Runs only when a disposable MySQL is configured, e.g.

    docker run -d --name safe-db-mcp-test-mysql -e MYSQL_ROOT_PASSWORD=test-only-root-pw \
        -e MYSQL_DATABASE=shop -p 127.0.0.1:33061:3306 mysql:8.4
    SAFE_DB_TEST_MYSQL_PORT=33061 SAFE_DB_TEST_MYSQL_PASSWORD=test-only-root-pw uv run pytest tests/test_mysql_integration.py

It connects as root on purpose: the read-only session must hold even for a user that is allowed to write.
"""

import os

import pytest

pymysql = pytest.importorskip("pymysql")

from safe_db_mcp.database import DatabaseQueryError, MysqlDatabase, QueryTimeout  # noqa: E402
from safe_db_mcp.guards import apply_row_limit  # noqa: E402

MYSQL_PORT = os.environ.get("SAFE_DB_TEST_MYSQL_PORT")
pytestmark = pytest.mark.skipif(not MYSQL_PORT, reason="set SAFE_DB_TEST_MYSQL_PORT to run MySQL integration tests")

TEST_MAX_ROWS = 10


def mysql_connection_settings():
    return {
        "host": os.environ.get("SAFE_DB_TEST_MYSQL_HOST", "127.0.0.1"),
        "port": int(MYSQL_PORT),
        "user": os.environ.get("SAFE_DB_TEST_MYSQL_USER", "root"),
        "password": os.environ.get("SAFE_DB_TEST_MYSQL_PASSWORD", ""),
        "database": os.environ.get("SAFE_DB_TEST_MYSQL_DATABASE", "shop"),
    }


@pytest.fixture(scope="module")
def mysql_database():
    settings = mysql_connection_settings()
    setup_connection = pymysql.connect(**settings, autocommit=True)
    with setup_connection.cursor() as cursor:
        cursor.execute("DROP TABLE IF EXISTS orders")
        cursor.execute("CREATE TABLE orders (id INT PRIMARY KEY, total DECIMAL(10, 2), note VARCHAR(50))")
        cursor.executemany("INSERT INTO orders VALUES (%s, %s, %s)", [(i, i * 1.25, f"order {i}") for i in range(1, 31)])
    setup_connection.close()
    return MysqlDatabase(**settings, timeout_seconds=1, max_rows=TEST_MAX_ROWS)


@pytest.mark.parametrize(
    "write_sql",
    [
        "DELETE FROM orders",
        "UPDATE orders SET note = 'x'",
        "INSERT INTO orders VALUES (999, 1, 'x')",
    ],
)
def test_read_only_session_refuses_writes_even_as_root(mysql_database, write_sql):
    with pytest.raises(DatabaseQueryError, match="READ ONLY"):
        mysql_database.run_query(write_sql)
    assert mysql_database.run_query("SELECT COUNT(*) FROM orders").rows == [(30,)]


def test_row_cap(mysql_database):
    capped = mysql_database.run_query(apply_row_limit("SELECT id FROM orders ORDER BY id", "mysql", TEST_MAX_ROWS))
    assert len(capped.rows) == TEST_MAX_ROWS
    assert capped.truncated is True


def test_percent_signs_in_agent_sql_are_not_treated_as_parameters(mysql_database):
    assert mysql_database.run_query("SELECT COUNT(*) FROM orders WHERE note LIKE 'order 1%'").rows == [(11,)]


def test_long_running_select_is_stopped_by_max_execution_time(mysql_database):
    huge_cross_join = (
        "SELECT COUNT(*) FROM information_schema.columns a, information_schema.columns b, information_schema.columns c"
    )
    with pytest.raises(QueryTimeout):
        mysql_database.run_query(huge_cross_join)


def test_schema_tools(mysql_database):
    assert ("orders", "BASE TABLE") in mysql_database.list_tables().rows
    assert [row[0] for row in mysql_database.describe_table("orders").rows] == ["id", "total", "note"]
