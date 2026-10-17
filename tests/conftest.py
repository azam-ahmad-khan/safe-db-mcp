import sqlite3

import pytest

from safe_db_mcp.audit import AuditLog
from safe_db_mcp.database import SqliteDatabase
from safe_db_mcp.runner import SafeQueryRunner

TEST_MAX_ROWS = 10
TEST_MASKED_COLUMNS = ["email", "phone"]


@pytest.fixture
def sqlite_path(tmp_path):
    path = tmp_path / "shop.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT, phone TEXT);
        CREATE TABLE orders (id INTEGER PRIMARY KEY, customer_id INTEGER, total NUMERIC, created_at TEXT);
        CREATE VIEW big_orders AS SELECT * FROM orders WHERE total > 100;
        """
    )
    connection.executemany(
        "INSERT INTO customers VALUES (?, ?, ?, ?)",
        [(i, f"Customer {i}", f"customer{i}@example.test", None if i % 5 == 0 else f"+1-555-{i:04d}") for i in range(1, 26)],
    )
    connection.executemany(
        "INSERT INTO orders VALUES (?, ?, ?, ?)",
        [(i, (i % 25) + 1, i * 7.5, f"2026-01-{(i % 28) + 1:02d}") for i in range(1, 51)],
    )
    connection.commit()
    connection.close()
    return path


@pytest.fixture
def sqlite_database(sqlite_path):
    return SqliteDatabase(sqlite_path, timeout_seconds=2, max_rows=TEST_MAX_ROWS)


@pytest.fixture
def audit_log(tmp_path):
    return AuditLog(tmp_path / "audit" / "audit.jsonl")


@pytest.fixture
def runner(sqlite_database, audit_log):
    return SafeQueryRunner(sqlite_database, audit_log, max_rows=TEST_MAX_ROWS, masked_columns=TEST_MASKED_COLUMNS)
