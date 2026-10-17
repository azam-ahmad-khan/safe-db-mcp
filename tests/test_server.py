import pytest
from mcp.client import Client

from safe_db_mcp.server import build_server

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
    assert "Query rejected: DROP" in result.content[0].text
