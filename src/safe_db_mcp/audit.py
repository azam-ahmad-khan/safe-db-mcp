"""Append-only audit log: one JSON line per tool call, allowed or not."""

from __future__ import annotations

import json
import os
import threading
import math
import uuid
from datetime import datetime, timezone
from pathlib import Path

from safe_db_mcp.privacy import Reason


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Metadata only, and owner-only even though SQL and cells are never written.
        os.close(os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))
        self._write_lock = threading.Lock()

    def record(self, *, tool: str, outcome: str, reason: Reason | None = None,
               row_count: int | None = None, truncated: bool | None = None,
               duration_ms: float | None = None, privacy_mode: str = "legacy",
               redacted_cells: int = 0) -> None:
        """Typed metadata only. There is deliberately no SQL, path, error-text or arbitrary-details argument."""
        if tool not in {"run_query", "list_tables", "describe_table", "describe_relationships", "join_path"}:
            raise ValueError("invalid audit tool")
        if outcome not in {"allowed", "redacted", "blocked", "rejected", "timeout", "error"}:
            raise ValueError("invalid audit outcome")
        if privacy_mode not in {"legacy", "strict"} or (reason is not None and not isinstance(reason, Reason)):
            raise ValueError("invalid audit classification")
        if row_count is not None and (type(row_count) is not int or row_count < 0):
            raise ValueError("invalid audit row count")
        if type(redacted_cells) is not int or redacted_cells < 0 or (truncated is not None and type(truncated) is not bool):
            raise ValueError("invalid audit counters")
        if duration_ms is not None and (type(duration_ms) not in (int, float) or not math.isfinite(duration_ms) or duration_ms < 0):
            raise ValueError("invalid audit duration")
        details = {"reason": reason.value if reason else None, "row_count": row_count, "truncated": truncated,
                   "duration_ms": duration_ms, "privacy_mode": privacy_mode, "redacted_cells": redacted_cells}
        entry = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": tool,
            "outcome": outcome,
            **{key: value for key, value in details.items() if value is not None},
        }
        line = json.dumps(entry, ensure_ascii=False, allow_nan=False) + "\n"
        with self._write_lock, open(self.path, "a", encoding="utf-8") as audit_file:
            audit_file.write(line)
