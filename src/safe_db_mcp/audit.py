"""Append-only audit log: one JSON line per tool call, allowed or not."""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Owner-only: queries can contain customer identifiers in their WHERE clauses.
        os.close(os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600))
        self._write_lock = threading.Lock()

    def record(self, *, tool: str, outcome: str, **details: Any) -> None:
        """Write one entry; `outcome` is one of allowed, rejected, timeout or error. None-valued details are dropped."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "tool": tool,
            "outcome": outcome,
            **{key: value for key, value in details.items() if value is not None},
        }
        line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
        with self._write_lock, open(self.path, "a", encoding="utf-8") as audit_file:
            audit_file.write(line)
