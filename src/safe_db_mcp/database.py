"""Database backends that open read-only connections and enforce a row cap and a time limit.

These are the second line of defence: even if a write slipped past the guards,
the connection itself refuses it.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, Sequence
from urllib.parse import quote

# MySQL error codes: 3024 = MAX_EXECUTION_TIME exceeded, 2013 = connection lost (socket read timeout).
_MYSQL_TIMEOUT_ERROR_CODES = frozenset({3024, 2013})

# Schema listings are small and the agent needs them whole, so they get their own, higher cap.
SCHEMA_MAX_ROWS = 2_000


@dataclass(frozen=True)
class QueryResult:
    column_names: list[str]
    rows: list[tuple[Any, ...]]
    truncated: bool


class QueryTimeout(Exception):
    """The query ran longer than the configured time limit and was stopped."""


class DatabaseQueryError(Exception):
    """The database refused or failed the query (syntax error, missing table, read-only violation...)."""


class Database(Protocol):
    dialect: str

    def run_query(self, sql: str, parameters: Sequence[Any] = (), max_rows: int | None = None) -> QueryResult: ...

    def list_tables(self) -> QueryResult: ...

    def describe_table(self, table_name: str) -> QueryResult: ...


class SqliteDatabase:
    dialect = "sqlite"

    def __init__(self, path: str | Path, timeout_seconds: float, max_rows: int):
        self._path = Path(path)
        if not self._path.is_file():
            raise FileNotFoundError(f"SQLite database not found: {self._path}")
        self._timeout_seconds = timeout_seconds
        self._max_rows = max_rows

    def run_query(self, sql: str, parameters: Sequence[Any] = (), max_rows: int | None = None) -> QueryResult:
        deadline = time.monotonic() + self._timeout_seconds
        connection = self._connect_read_only()
        # SQLite has no statement timeout; this callback runs every N VM steps and aborts past the deadline.
        connection.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 1_000)
        try:
            cursor = connection.execute(sql, parameters)
            return _fetch_capped(cursor, max_rows or self._max_rows)
        except sqlite3.OperationalError as error:
            if time.monotonic() > deadline:
                raise QueryTimeout(f"query exceeded {self._timeout_seconds:g}s and was stopped") from error
            raise DatabaseQueryError(str(error)) from error
        except sqlite3.Error as error:
            raise DatabaseQueryError(str(error)) from error
        finally:
            connection.close()

    def list_tables(self) -> QueryResult:
        return self.run_query(
            "SELECT name, type FROM sqlite_master "
            "WHERE type IN ('table', 'view') AND name NOT LIKE 'sqlite_%' ORDER BY name",
            max_rows=SCHEMA_MAX_ROWS,
        )

    def describe_table(self, table_name: str) -> QueryResult:
        return self.run_query(
            'SELECT name, type, "notnull" AS not_null, pk AS primary_key FROM pragma_table_info(?)',
            (table_name,),
            max_rows=SCHEMA_MAX_ROWS,
        )

    def _connect_read_only(self) -> sqlite3.Connection:
        connection = sqlite3.connect(f"file:{quote(str(self._path.resolve()))}?mode=ro", uri=True)
        connection.execute("PRAGMA query_only = ON")
        return connection


class MysqlDatabase:
    dialect = "mysql"

    def __init__(
        self,
        host: str,
        port: int,
        user: str,
        password: str | None,
        database: str,
        timeout_seconds: float,
        max_rows: int,
    ):
        try:
            import pymysql
        except ImportError as error:
            raise RuntimeError("MySQL support needs the 'mysql' extra: pip install 'safe-db-mcp[mysql]'") from error
        self._pymysql = pymysql
        self._connection_arguments = {
            "host": host,
            "port": port,
            "user": user,
            "password": password or "",
            "database": database,
            "connect_timeout": 10,
            # Socket backstop in case the server-side limit doesn't apply (it only covers SELECT).
            "read_timeout": int(timeout_seconds) + 5,
            "autocommit": True,
            "charset": "utf8mb4",
        }
        self._timeout_seconds = timeout_seconds
        self._max_rows = max_rows

    def run_query(self, sql: str, parameters: Sequence[Any] = (), max_rows: int | None = None) -> QueryResult:
        try:
            connection = self._connect_read_only()
        except self._pymysql.Error as error:
            raise DatabaseQueryError(f"could not connect: {error}") from error
        try:
            with connection.cursor() as cursor:
                cursor.execute(sql, tuple(parameters) or None)
                return _fetch_capped(cursor, max_rows or self._max_rows)
        except self._pymysql.Error as error:
            error_code = error.args[0] if error.args else None
            if error_code in _MYSQL_TIMEOUT_ERROR_CODES:
                raise QueryTimeout(f"query exceeded {self._timeout_seconds:g}s and was stopped") from error
            raise DatabaseQueryError(str(error)) from error
        finally:
            connection.close()

    def list_tables(self) -> QueryResult:
        return self.run_query(
            "SELECT table_name AS name, table_type AS type FROM information_schema.tables "
            "WHERE table_schema = DATABASE() ORDER BY table_name",
            max_rows=SCHEMA_MAX_ROWS,
        )

    def describe_table(self, table_name: str) -> QueryResult:
        return self.run_query(
            "SELECT column_name AS name, column_type AS type, is_nullable, column_key "
            "FROM information_schema.columns "
            "WHERE table_schema = DATABASE() AND table_name = %s ORDER BY ordinal_position",
            (table_name,),
            max_rows=SCHEMA_MAX_ROWS,
        )

    def _connect_read_only(self):
        connection = self._pymysql.connect(**self._connection_arguments)
        with connection.cursor() as cursor:
            # With autocommit on, every statement is its own transaction, so the whole session is read-only.
            cursor.execute("SET SESSION TRANSACTION READ ONLY")
            cursor.execute("SET SESSION MAX_EXECUTION_TIME = %s", (int(self._timeout_seconds * 1000),))
        return connection


def _fetch_capped(cursor: Any, max_rows: int) -> QueryResult:
    column_names = [column[0] for column in cursor.description or []]
    rows = [tuple(row) for row in cursor.fetchmany(max_rows + 1)]
    return QueryResult(column_names=column_names, rows=rows[:max_rows], truncated=len(rows) > max_rows)
