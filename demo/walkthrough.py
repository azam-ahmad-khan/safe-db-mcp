"""A scripted agent session against demo/shop.db, run through the real MCP server over stdio.

    uv run python demo/build_sample_db.py
    uv run python demo/walkthrough.py
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

DEMO_DIRECTORY = Path(__file__).parent
SAMPLE_DATABASE_PATH = DEMO_DIRECTORY / "shop.db"

SCRIPTED_STEPS = [
    ("What tables are there?", "list_tables", {}),
    ("What does a customer look like?", "describe_table", {"table_name": "customers"}),
    (
        "Top 3 products by revenue",
        "run_query",
        {
            "sql": "SELECT p.name, ROUND(SUM(i.quantity * i.unit_price), 2) AS revenue "
            "FROM order_items i JOIN products p ON p.id = i.product_id "
            "GROUP BY p.name ORDER BY revenue DESC LIMIT 3"
        },
    ),
    ("Show me a few customers", "run_query", {"sql": "SELECT id, full_name, email, phone, city FROM customers LIMIT 3"}),
    ("Give me every order", "run_query", {"sql": "SELECT * FROM orders"}),
    ("Clean up cancelled orders", "run_query", {"sql": "DELETE FROM orders WHERE status = 'cancelled'"}),
    ("Sneak the emails out under another name", "run_query", {"sql": "SELECT email AS contact FROM customers"}),
    ("Stack a second statement", "run_query", {"sql": "SELECT 1; DROP TABLE customers"}),
]


def server_parameters(audit_log_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "safe_db_mcp.server"],
        env={
            **os.environ,
            "SAFE_DB_DIALECT": "sqlite",
            "SAFE_DB_SQLITE_PATH": str(SAMPLE_DATABASE_PATH),
            "SAFE_DB_MAX_ROWS": "5",
            "SAFE_DB_MASKED_COLUMNS": "email,phone",
            "SAFE_DB_AUDIT_LOG": str(audit_log_path),
        },
    )


async def run_walkthrough() -> None:
    audit_log_path = Path(tempfile.mkdtemp()) / "audit.jsonl"
    async with Client(server_parameters(audit_log_path)) as client:
        for request, tool_name, arguments in SCRIPTED_STEPS:
            print(f"\n\033[1m> {request}\033[0m")
            print(f"  {tool_name}({json.dumps(arguments)})")
            result = await client.call_tool(tool_name, arguments)
            if result.is_error:
                print(f"  \033[31m✗ {result.content[0].text}\033[0m")
                continue
            response = result.structured_content
            print(f"  \033[32m✓\033[0m columns: {response['columns']}")
            for row in response["rows"]:
                print(f"    {row}")
            if response.get("note"):
                print(f"  note: {response['note']}")

    print(f"\n\033[1mAudit log\033[0m ({audit_log_path}):")
    for line in audit_log_path.read_text().splitlines():
        entry = json.loads(line)
        print(f"  {entry['outcome']:<8} {entry['tool']:<15} {entry.get('sql') or entry.get('table') or ''}")


if __name__ == "__main__":
    if not SAMPLE_DATABASE_PATH.exists():
        sys.exit("demo/shop.db not found; run: uv run python demo/build_sample_db.py")
    anyio.run(run_walkthrough)
