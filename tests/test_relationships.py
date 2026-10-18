import json
from pathlib import Path

import pytest
from mcp.client import Client

from safe_db_mcp.config import Settings
from safe_db_mcp.relationships import RelationshipFileError, RelationshipGraph, load_relationships
from safe_db_mcp.runner import SafeQueryRunner
from safe_db_mcp.server import build_server

DEMO_FILE = Path(__file__).parent.parent / "demo" / "relationships.yml"

FILE_TEXT = """\
version: 1
dialect: sqlite
relationships:
- from: {table: orders, columns: [customer_id]}
  to: {table: customers, columns: [id]}
  cardinality: many_to_one
  status: approved
  confidence: 0.9
  evidence: [{kind: name, detail: customer_id = <customers singular>_id}]
- from: {table: order_items, columns: [order_id]}
  to: {table: orders, columns: [id]}
  status: approved
- from: {table: order_items, columns: [product_id]}
  to: {table: products, columns: [id]}
  status: approved
- from: {table: orders, columns: [quantity]}
  to: {table: customers, columns: [id]}
  status: rejected
- from: {table: reviews, columns: [product_id]}
  to: {table: products, columns: [id]}
  status: proposed
- from: {table: newsletter, columns: [email]}
  to: {table: customers, columns: [email]}
  status: approved
"""


@pytest.fixture
def relationships_file(tmp_path):
    path = tmp_path / "relationships.yml"
    path.write_text(FILE_TEXT)
    return path


@pytest.fixture
def graph(relationships_file):
    return RelationshipGraph(load_relationships(relationships_file, frozenset({"email", "phone"})))


def test_only_approved_entries_are_loaded_and_masked_joins_are_dropped(graph):
    conditions = {r["join_condition"] for t in ("orders", "order_items") for r in graph.describe(t)["references"]}
    assert conditions == {
        "orders.customer_id = customers.id",
        "order_items.order_id = orders.id",
        "order_items.product_id = products.id",
    }
    assert len(graph) == 3  # rejected, proposed and the join on the masked email column are gone


def test_describe_relationships_lists_both_directions(graph):
    orders = graph.describe("ORDERS")
    assert orders["table"] == "orders"
    assert [r["to_table"] for r in orders["references"]] == ["customers"]
    assert [r["from_table"] for r in orders["referenced_by"]] == ["order_items"]
    assert "note" in graph.describe("audit")


def test_join_path_across_several_hops(graph):
    path = graph.join_path("customers", "products")
    assert path["found"] is True
    assert path["sql"] == (
        "FROM customers\n"
        "JOIN orders ON orders.customer_id = customers.id\n"
        "JOIN order_items ON order_items.order_id = orders.id\n"
        "JOIN products ON order_items.product_id = products.id"
    )
    assert [hop["from_table"] for hop in path["hops"]] == ["orders", "order_items", "order_items"]


def test_join_path_edge_cases(graph):
    assert graph.join_path("orders", "orders") == {"found": True, "hops": [], "sql": "FROM orders"}
    assert graph.join_path("orders", "reviews")["found"] is False  # reviews only had a proposed link


def test_join_path_respects_the_hop_limit():
    chain = [load_entry(f"t{i}", f"t{i + 1}") for i in range(6)]
    graph = RelationshipGraph(chain)
    assert graph.join_path("t0", "t4")["found"] is True
    assert graph.join_path("t0", "t6")["found"] is False


def load_entry(child, parent):
    from safe_db_mcp.relationships import Relationship

    return Relationship(child, (f"{parent}_id",), parent, ("id",), "many_to_one")


@pytest.mark.parametrize("text, message", [
    ("version: 2\nrelationships: []\n", "version: 1"),
    ("version: 1\nrelationships: {}\n", "must be a list"),
    ("version: 1\nrelationships:\n- {from: {table: a, columns: [x]}, to: {table: b}}\n", "columns must be"),
    ("version: 1\nrelationships:\n- {from: {table: a, columns: [x, y]}, to: {table: b, columns: [id]}}\n",
     "same number of columns"),
    ("version: 1\nrelationships:\n- {from: {table: a, columns: [x]}, to: {table: b, columns: [id]}, status: yes}\n",
     "unknown status"),
    ("version: 1\nrelationships: [\n", "not valid YAML"),
])
def test_malformed_files_stop_the_server(tmp_path, text, message):
    path = tmp_path / "relationships.yml"
    path.write_text(text)
    with pytest.raises(RelationshipFileError, match=message):
        load_relationships(path)


def test_missing_file_stops_the_server(tmp_path):
    with pytest.raises(RelationshipFileError, match="cannot read"):
        load_relationships(tmp_path / "nope.yml")


def test_demo_file_written_by_joinscout_loads():
    graph = RelationshipGraph(load_relationships(DEMO_FILE))
    assert graph.join_path("customers", "products")["found"] is True


def test_settings_read_the_relationships_path(tmp_path):
    settings = Settings.from_env({"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": str(tmp_path / "db"),
                                  "SAFE_DB_RELATIONSHIPS_FILE": "~/rels.yml"})
    assert settings.relationships_path == Path.home() / "rels.yml"
    assert Settings.from_env({"SAFE_DB_DIALECT": "sqlite", "SAFE_DB_SQLITE_PATH": "x"}).relationships_path is None


class UntouchableDatabase:
    """Fails the test if a relationship tool reaches the database."""

    dialect = "sqlite"

    def __getattr__(self, name):
        raise AssertionError(f"relationship tools must not touch the database (called {name})")



@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def relationship_runner(graph, audit_log):
    return SafeQueryRunner(UntouchableDatabase(), audit_log, max_rows=10, relationships=graph)


@pytest.mark.anyio
async def test_relationship_tools_are_read_only_and_never_touch_the_database(relationship_runner, audit_log):
    async with Client(build_server(relationship_runner)) as client:
        tools = {tool.name: tool for tool in (await client.list_tools()).tools}
        path = await client.call_tool("join_path", {"table_a": "customers", "table_b": "order_items"})
        described = await client.call_tool("describe_relationships", {"table_name": "products"})

    assert set(tools) == {"describe_table", "list_tables", "run_query", "describe_relationships", "join_path"}
    for name in ("describe_relationships", "join_path"):
        assert tools[name].annotations.read_only_hint is True
        assert set(tools[name].input_schema["properties"]) <= {"table_name", "table_a", "table_b"}
    assert path.is_error is False
    assert path.structured_content["sql"].endswith("JOIN order_items ON order_items.order_id = orders.id")
    assert described.structured_content["referenced_by"][0]["from_table"] == "order_items"

    entries = [json.loads(line) for line in audit_log.path.read_text().splitlines()]
    assert [(e["tool"], e["outcome"]) for e in entries] == [("join_path", "allowed"), ("describe_relationships", "allowed")]


@pytest.mark.anyio
async def test_without_a_file_the_tools_do_not_exist(runner):
    async with Client(build_server(runner)) as client:
        names = {tool.name for tool in (await client.list_tools()).tools}
    assert "join_path" not in names and "describe_relationships" not in names
