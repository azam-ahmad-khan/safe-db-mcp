"""Fire a suite of legitimate and hostile queries at the real MCP server and score the outcome.

Each case passes only if the server does what the case expects (allow / reject / timeout).
On top of that the whole run fails if:
  - any response contains a real email or phone number from the sample data, or
  - the database file changed in any way.

    uv run python evals/run_evals.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

import anyio
from mcp.client import Client
from mcp.client.stdio import StdioServerParameters

EVALS_DIRECTORY = Path(__file__).parent
sys.path.insert(0, str(EVALS_DIRECTORY.parent / "demo"))
from build_sample_db import build  # noqa: E402

CASES_PATH = EVALS_DIRECTORY / "cases.json"
PII_PATTERN = re.compile(r"[\w.+-]+@example\.com|\+1-202-555-\d{4}")


def file_fingerprint(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def server_parameters(database_path: Path, audit_log_path: Path) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "safe_db_mcp.server"],
        env={
            **os.environ,
            "SAFE_DB_DIALECT": "sqlite",
            "SAFE_DB_SQLITE_PATH": str(database_path),
            "SAFE_DB_MAX_ROWS": "50",
            "SAFE_DB_TIMEOUT_SECONDS": "2",
            "SAFE_DB_MASKED_COLUMNS": "email,phone",
            "SAFE_DB_AUDIT_LOG": str(audit_log_path),
        },
    )


def classify(result) -> str:
    if not result.is_error:
        return "allow"
    error_text = result.content[0].text if result.content else ""
    if "Query rejected" in error_text:
        return "reject"
    if "Query timed out" in error_text:
        return "timeout"
    return "error"


async def run_cases(cases: list[dict], database_path: Path, audit_log_path: Path) -> list[dict]:
    outcomes = []
    async with Client(server_parameters(database_path, audit_log_path)) as client:
        for case in cases:
            result = await client.call_tool("run_query", {"sql": case["sql"]})
            actual = classify(result)
            response_text = json.dumps(result.structured_content) + " ".join(
                getattr(block, "text", "") for block in result.content
            )
            failures = []
            if actual != case["expect"]:
                failures.append(f"expected {case['expect']}, got {actual}: {response_text[:160]}")
            if PII_PATTERN.search(response_text):
                failures.append("response leaked an email or phone number")
            if case.get("expect_truncated") and not (result.structured_content or {}).get("truncated"):
                failures.append("expected the result to be truncated")
            outcomes.append({**case, "actual": actual, "failures": failures})
    return outcomes


def main() -> int:
    cases = json.loads(CASES_PATH.read_text())
    work_directory = Path(tempfile.mkdtemp(prefix="safe-db-evals-"))
    database_path = build(work_directory / "shop.db")
    audit_log_path = work_directory / "audit.jsonl"
    fingerprint_before = file_fingerprint(database_path)

    outcomes = anyio.run(run_cases, cases, database_path, audit_log_path)
    database_unchanged = file_fingerprint(database_path) == fingerprint_before
    audit_entry_count = len(audit_log_path.read_text().splitlines())

    passed_by_category: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for outcome in outcomes:
        passed_by_category[outcome["category"]][1] += 1
        if not outcome["failures"]:
            passed_by_category[outcome["category"]][0] += 1

    print(f"{'category':<28} {'passed':>8}")
    print("-" * 37)
    for category, (passed, total) in passed_by_category.items():
        print(f"{category:<28} {passed:>4}/{total:<3}")
    total_passed = sum(passed for passed, _ in passed_by_category.values())
    print("-" * 37)
    print(f"{'total':<28} {total_passed:>4}/{len(outcomes):<3}")
    print(f"\ndatabase file unchanged: {'yes' if database_unchanged else 'NO'}")
    print(f"audit log entries:       {audit_entry_count} for {len(outcomes)} calls")

    failed_outcomes = [outcome for outcome in outcomes if outcome["failures"]]
    for outcome in failed_outcomes:
        print(f"\nFAIL [{outcome['category']}] {outcome['sql']!r}")
        for failure in outcome["failures"]:
            print(f"  - {failure}")

    all_good = not failed_outcomes and database_unchanged and audit_entry_count == len(outcomes)
    return 0 if all_good else 1


if __name__ == "__main__":
    sys.exit(main())
