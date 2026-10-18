"""Server settings, read once at start-up from environment variables.

Connection details and the password come from the environment or the OS keychain,
never from the agent: no tool takes a host, user or password argument.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from safe_db_mcp.database import Database, MysqlDatabase, SqliteDatabase
from safe_db_mcp.guards import SUPPORTED_DIALECTS

KEYCHAIN_SERVICE_NAME = "safe-db-mcp"

DEFAULT_MAX_ROWS = 200
DEFAULT_TIMEOUT_SECONDS = 10.0
DEFAULT_AUDIT_LOG_PATH = Path.home() / ".safe-db-mcp" / "audit.jsonl"


class ConfigError(Exception):
    """A required setting is missing or invalid; the server refuses to start."""


@dataclass(frozen=True)
class Settings:
    dialect: str
    max_rows: int
    timeout_seconds: float
    masked_columns: frozenset[str]
    audit_log_path: Path
    relationships_path: Path | None = None
    sqlite_path: Path | None = None
    mysql_host: str | None = None
    mysql_port: int = 3306
    mysql_user: str | None = None
    mysql_database: str | None = None
    mysql_password: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        environ = os.environ if environ is None else environ
        dialect = environ.get("SAFE_DB_DIALECT", "").strip().lower()
        if dialect not in SUPPORTED_DIALECTS:
            raise ConfigError(f"SAFE_DB_DIALECT must be one of {sorted(SUPPORTED_DIALECTS)}, got {dialect!r}")

        common_settings = {
            "dialect": dialect,
            "max_rows": _positive_number(environ, "SAFE_DB_MAX_ROWS", DEFAULT_MAX_ROWS, int),
            "timeout_seconds": _positive_number(environ, "SAFE_DB_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS, float),
            "masked_columns": frozenset(
                name.strip().lower() for name in environ.get("SAFE_DB_MASKED_COLUMNS", "").split(",") if name.strip()
            ),
            "audit_log_path": Path(environ.get("SAFE_DB_AUDIT_LOG") or DEFAULT_AUDIT_LOG_PATH).expanduser(),
            "relationships_path": _optional_path(environ, "SAFE_DB_RELATIONSHIPS_FILE"),
        }

        if dialect == "sqlite":
            return cls(**common_settings, sqlite_path=Path(_required(environ, "SAFE_DB_SQLITE_PATH")).expanduser())

        mysql_user = _required(environ, "SAFE_DB_USER")
        return cls(
            **common_settings,
            mysql_host=_required(environ, "SAFE_DB_HOST"),
            mysql_port=_positive_number(environ, "SAFE_DB_PORT", 3306, int),
            mysql_user=mysql_user,
            mysql_database=_required(environ, "SAFE_DB_NAME"),
            mysql_password=_load_mysql_password(environ, mysql_user),
        )


def create_database(settings: Settings) -> Database:
    if settings.dialect == "sqlite":
        return SqliteDatabase(settings.sqlite_path, settings.timeout_seconds, settings.max_rows)
    return MysqlDatabase(
        host=settings.mysql_host,
        port=settings.mysql_port,
        user=settings.mysql_user,
        password=settings.mysql_password,
        database=settings.mysql_database,
        timeout_seconds=settings.timeout_seconds,
        max_rows=settings.max_rows,
    )


def _load_mysql_password(environ: Mapping[str, str], mysql_user: str) -> str | None:
    """SAFE_DB_PASSWORD if set, otherwise the OS keychain entry for (KEYCHAIN_SERVICE_NAME, user)."""
    password_from_env = environ.get("SAFE_DB_PASSWORD")
    if password_from_env:
        return password_from_env
    try:
        import keyring
    except ImportError:
        return None
    return keyring.get_password(KEYCHAIN_SERVICE_NAME, mysql_user)


def _optional_path(environ: Mapping[str, str], name: str) -> Path | None:
    value = environ.get(name, "").strip()
    return Path(value).expanduser() if value else None


def _required(environ: Mapping[str, str], name: str) -> str:
    value = environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"{name} is required")
    return value


def _positive_number(environ: Mapping[str, str], name: str, default, number_type):
    raw_value = environ.get(name, "").strip()
    if not raw_value:
        return default
    try:
        value = number_type(raw_value)
    except ValueError as error:
        raise ConfigError(f"{name} must be a number, got {raw_value!r}") from error
    if value <= 0:
        raise ConfigError(f"{name} must be greater than zero, got {raw_value!r}")
    return value
