import sys
import types

import pytest

from safe_db_mcp.config import KEYCHAIN_SERVICE_NAME, ConfigError, Settings

MYSQL_ENV = {
    "SAFE_DB_DIALECT": "mysql",
    "SAFE_DB_HOST": "db.internal.test",
    "SAFE_DB_USER": "agent_reader",
    "SAFE_DB_NAME": "shop",
}


def test_sqlite_settings_with_defaults(tmp_path):
    settings = Settings.from_env({"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": str(tmp_path / "shop.db")})
    assert settings.dialect == "sqlite"
    assert settings.max_rows == 200
    assert settings.timeout_seconds == 10.0
    assert settings.masked_columns == frozenset()


def test_masked_columns_are_trimmed_and_lowercased(tmp_path):
    settings = Settings.from_env(
        {"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": "x.db", "SAFE_DB_MASKED_COLUMNS": " Email, phone ,,"}
    )
    assert settings.masked_columns == frozenset({"email", "phone"})


def test_password_comes_from_env_and_never_appears_in_repr():
    settings = Settings.from_env({**MYSQL_ENV, "SAFE_DB_PASSWORD": "s3cret-value"})
    assert settings.mysql_password == "s3cret-value"
    assert "s3cret-value" not in repr(settings)


def test_password_falls_back_to_the_os_keychain(monkeypatch):
    keychain_lookups = []

    def fake_get_password(service_name, user):
        keychain_lookups.append((service_name, user))
        return "from-keychain"

    monkeypatch.setitem(sys.modules, "keyring", types.SimpleNamespace(get_password=fake_get_password))
    settings = Settings.from_env(MYSQL_ENV)
    assert settings.mysql_password == "from-keychain"
    assert keychain_lookups == [(KEYCHAIN_SERVICE_NAME, "agent_reader")]


@pytest.mark.parametrize(
    ("environ", "expected_message"),
    [
        ({}, "SAFE_DB_DIALECT"),
        ({"SAFE_DB_DIALECT": "postgres"}, "SAFE_DB_DIALECT"),
        ({"SAFE_DB_DIALECT": "sqlite"}, "SAFE_DB_SQLITE_PATH"),
        ({**MYSQL_ENV, "SAFE_DB_HOST": ""}, "SAFE_DB_HOST"),
        ({"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": "x.db", "SAFE_DB_MAX_ROWS": "0"}, "SAFE_DB_MAX_ROWS"),
        ({"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": "x.db", "SAFE_DB_TIMEOUT_SECONDS": "soon"}, "SAFE_DB_TIMEOUT_SECONDS"),
    ],
)
def test_invalid_settings_stop_the_server_from_starting(environ, expected_message):
    with pytest.raises(ConfigError, match=expected_message):
        Settings.from_env(environ)
