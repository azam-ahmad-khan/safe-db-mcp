"""MCP server exposing read-only database tools to an AI agent over stdio."""

from __future__ import annotations

import logging
import sys
from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from safe_db_mcp.audit import AuditLog
from safe_db_mcp.config import ConfigError, Settings, create_database
from safe_db_mcp.database import DatabaseQueryError, QueryTimeout
from safe_db_mcp.guards import QueryRejected
from safe_db_mcp.relationships import RelationshipFileError, RelationshipGraph, load_relationships
from safe_db_mcp.runner import SafeQueryRunner

log = logging.getLogger("safe_db_mcp")

SERVER_INSTRUCTIONS = """\
Read-only access to a SQL database. Start with list_tables and describe_table, then run_query.
Only single SELECT, SHOW, DESCRIBE and EXPLAIN statements are accepted; anything else is rejected.
Results are capped, so filter and aggregate in SQL instead of fetching whole tables.
Some columns hold personal data: they come back masked and cannot be filtered, sorted or transformed."""

RELATIONSHIP_INSTRUCTIONS = """
This database declares few or no foreign keys. Before writing a join, call join_path or describe_relationships:
they list joins a person has reviewed and approved. Prefer those over guessing from column names."""

READ_ONLY_TOOL = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)


def build_server(runner: SafeQueryRunner) -> MCPServer:
    instructions = SERVER_INSTRUCTIONS + (RELATIONSHIP_INSTRUCTIONS if runner.relationships is not None else "")
    server = MCPServer(name="safe-db", instructions=instructions)

    @server.tool(annotations=READ_ONLY_TOOL)
    def run_query(sql: str) -> dict[str, Any]:
        """Run one read-only SQL statement (SELECT, SHOW, DESCRIBE or EXPLAIN) and return its rows."""
        return _call_guarded(lambda: runner.run_query(sql))

    @server.tool(annotations=READ_ONLY_TOOL)
    def list_tables() -> dict[str, Any]:
        """List the tables and views in the database."""
        return _call_guarded(runner.list_tables)

    @server.tool(annotations=READ_ONLY_TOOL)
    def describe_table(table_name: str) -> dict[str, Any]:
        """List a table's columns with their types."""
        return _call_guarded(lambda: runner.describe_table(table_name))

    if runner.relationships is not None:

        @server.tool(annotations=READ_ONLY_TOOL)
        def describe_relationships(table_name: str) -> dict[str, Any]:
            """List the approved joins into and out of a table, with ready-to-use join conditions."""
            return runner.describe_relationships(table_name)

        @server.tool(annotations=READ_ONLY_TOOL)
        def join_path(table_a: str, table_b: str) -> dict[str, Any]:
            """Find the shortest chain of approved joins between two tables, as a FROM ... JOIN ... clause."""
            return runner.join_path(table_a, table_b)

    return server


def _call_guarded(call) -> dict[str, Any]:
    """Turn guard and database failures into tool errors the agent can read and act on."""
    try:
        return call()
    except QueryRejected as rejection:
        raise ToolError(f"Query rejected: {rejection.reason}") from rejection
    except QueryTimeout as timeout:
        raise ToolError(f"Query timed out: {timeout}. Narrow it with filters or LIMIT.") from timeout
    except DatabaseQueryError as error:
        raise ToolError(f"Database error: {error}") from error


def main() -> None:
    # stdout carries the MCP protocol, so logs must go to stderr.
    logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        settings = Settings.from_env()
        relationships = None
        if settings.relationships_path is not None:
            relationships = RelationshipGraph(load_relationships(settings.relationships_path, settings.masked_columns))
        runner = SafeQueryRunner(
            database=create_database(settings),
            audit_log=AuditLog(settings.audit_log_path),
            max_rows=settings.max_rows,
            masked_columns=settings.masked_columns,
            relationships=relationships,
        )
    except (ConfigError, RelationshipFileError, FileNotFoundError, RuntimeError, OSError) as start_up_error:
        log.error("safe_db_mcp main start-up failed reason->%s", start_up_error)
        sys.exit(1)
    log.info(
        "safe_db_mcp main started dialect->%s maxRows->%s timeoutSeconds->%s maskedColumns->%s auditLog->%s "
        "approvedRelationships->%s",
        settings.dialect,
        settings.max_rows,
        settings.timeout_seconds,
        len(settings.masked_columns),
        settings.audit_log_path,
        len(relationships) if relationships is not None else "off",
    )
    build_server(runner).run("stdio")


if __name__ == "__main__":
    main()
