import sqlite3

import pytest
from mcp.client import Client

from safe_db_mcp.server import build_server
from safe_db_mcp.audit import AuditLog
from safe_db_mcp.database import SqliteDatabase
from safe_db_mcp.runner import SafeQueryRunner

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_tools_are_read_only_and_take_no_connection_details(runner):
    async with Client(build_server(runner)) as client:
        tools = (await client.list_tools()).tools

    assert sorted(tool.name for tool in tools) == ["describe_table", "list_tables", "run_query"]
    for tool in tools:
        assert tool.annotations.read_only_hint is True
        parameter_names = set(tool.input_schema.get("properties", {}))
        assert parameter_names <= {"sql", "table_name"}


async def test_run_query_returns_structured_rows(runner):
    async with Client(build_server(runner)) as client:
        result = await client.call_tool("run_query", {"sql": "SELECT id, email FROM customers WHERE id = 3"})

    assert result.is_error is False
    assert result.structured_content["rows"] == [[3, "[masked]"]]


async def test_unsafe_query_comes_back_as_a_readable_tool_error(runner):
    async with Client(build_server(runner)) as client:
        result = await client.call_tool("run_query", {"sql": "DROP TABLE customers"})

    assert result.is_error is True
    assert "Query rejected: BLOCK_QUERY_REJECTED" in result.content[0].text


async def test_masked_column_list_bypass_is_a_tool_error_without_customer_values(runner):
    sql = (
        "WITH c(id, full_name, contact, telephone) AS (SELECT * FROM customers) "
        "SELECT contact, telephone FROM c"
    )
    async with Client(build_server(runner)) as client:
        result = await client.call_tool("run_query", {"sql": sql})

    assert result.is_error is True
    assert "Query rejected: BLOCK_QUERY_REJECTED" in result.content[0].text
    assert "customer1@example.test" not in result.content[0].text


async def test_explicit_unmasked_cte_alias_still_returns_structured_rows(runner):
    sql = "WITH c(customer_id, display_name) AS (SELECT id, name FROM customers WHERE id = 1) SELECT * FROM c"
    async with Client(build_server(runner)) as client:
        result = await client.call_tool("run_query", {"sql": sql})

    assert result.is_error is False
    assert result.structured_content["columns"] == ["customer_id", "display_name"]
    assert result.structured_content["rows"] == [[1, "Customer 1"]]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT (SELECT * FROM contacts LIMIT 1) AS contact",
        "WITH c(contact) AS (SELECT (SELECT * FROM contacts LIMIT 1)) SELECT contact FROM c",
        "SELECT COALESCE((SELECT * FROM contacts LIMIT 1), 'none') AS contact",
        "SELECT (SELECT c.* FROM contacts c LIMIT 1) AS contact",
        "SELECT * FROM labels UNION ALL SELECT * FROM contacts",
        "SELECT * FROM (SELECT a.*, b.* FROM contacts a CROSS JOIN contacts b) AS c",
    ],
)
async def test_single_column_protected_values_cannot_escape_through_stars(tmp_path, sql):
    path = tmp_path / "fictional.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        "CREATE TABLE contacts(email TEXT);"
        "INSERT INTO contacts VALUES('person@example.invalid');"
        "CREATE TABLE labels(contact TEXT);"
        "INSERT INTO labels VALUES('fictional label');"
    )
    connection.commit()
    connection.close()
    runner = SafeQueryRunner(SqliteDatabase(path, 1, 10), AuditLog(tmp_path / "audit.jsonl"), 10, ["email"])
    async with Client(build_server(runner)) as client:
        result = await client.call_tool("run_query", {"sql": sql})

    assert result.is_error is True
    assert "Query rejected: BLOCK_QUERY_REJECTED" in result.content[0].text
    assert "person@example.invalid" not in result.content[0].text
