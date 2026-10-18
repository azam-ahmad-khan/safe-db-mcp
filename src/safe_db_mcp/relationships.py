"""Human-approved join relationships, loaded from a relationships.yml file, so agents can write correct joins.

The file comes from an inference tool such as joinscout and is reviewed by a person. This server never infers
anything: it loads the file once at start-up, keeps only entries marked `approved`, and answers from memory.
No tool here touches the database.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger("safe_db_mcp")

SUPPORTED_FORMAT_VERSION = 1
MAX_JOIN_HOPS = 4


class RelationshipFileError(Exception):
    """The relationships file is missing or malformed; the server refuses to start rather than guess."""


@dataclass(frozen=True)
class Relationship:
    from_table: str
    from_columns: tuple[str, ...]
    to_table: str
    to_columns: tuple[str, ...]
    cardinality: str

    @property
    def join_condition(self) -> str:
        return " AND ".join(
            f"{self.from_table}.{child} = {self.to_table}.{parent}"
            for child, parent in zip(self.from_columns, self.to_columns)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "from_table": self.from_table,
            "from_columns": list(self.from_columns),
            "to_table": self.to_table,
            "to_columns": list(self.to_columns),
            "cardinality": self.cardinality,
            "join_condition": self.join_condition,
        }


def load_relationships(path: Path, masked_columns: frozenset[str] = frozenset()) -> list[Relationship]:
    """Read the file and return its approved relationships. Proposed and rejected entries are skipped.

    Relationships that join on a masked column are dropped too: run_query refuses predicates on those columns,
    so advertising them would only lead the agent into a rejected query.
    """
    try:
        import yaml
    except ImportError as error:
        raise RelationshipFileError(
            "SAFE_DB_RELATIONSHIPS_FILE needs PyYAML: uv sync --extra relationships"
        ) from error
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise RelationshipFileError(f"cannot read {path}: {error}") from error
    except yaml.YAMLError as error:
        raise RelationshipFileError(f"{path} is not valid YAML: {error}") from error

    if not isinstance(data, dict) or data.get("version") != SUPPORTED_FORMAT_VERSION:
        raise RelationshipFileError(f"{path}: expected a mapping with version: {SUPPORTED_FORMAT_VERSION}")
    entries = data.get("relationships")
    entries = [] if entries is None else entries
    if not isinstance(entries, list):
        raise RelationshipFileError(f"{path}: relationships must be a list")

    approved = []
    for index, entry in enumerate(entries):
        relationship, status = _parse_entry(entry, f"{path}: relationships[{index}]")
        if status != "approved":
            continue
        if masked_columns & {c.lower() for c in relationship.from_columns + relationship.to_columns}:
            log.warning("relationships load_relationships skipped maskedJoin->%s", relationship.join_condition)
            continue
        approved.append(relationship)
    log.info("relationships load_relationships path->%s entries->%s approved->%s", path, len(entries), len(approved))
    return approved


def _parse_entry(entry: Any, where: str) -> tuple[Relationship, str]:
    if not isinstance(entry, dict):
        raise RelationshipFileError(f"{where}: must be a mapping")
    endpoints = []
    for side in ("from", "to"):
        endpoint = entry.get(side)
        if not isinstance(endpoint, dict) or not isinstance(endpoint.get("table"), str) or not endpoint["table"]:
            raise RelationshipFileError(f"{where}.{side}: needs a table name")
        columns = endpoint.get("columns")
        if not isinstance(columns, list) or not columns or not all(isinstance(c, str) and c for c in columns):
            raise RelationshipFileError(f"{where}.{side}: columns must be a non-empty list of names")
        endpoints.append((endpoint["table"], tuple(columns)))
    (from_table, from_columns), (to_table, to_columns) = endpoints
    if len(from_columns) != len(to_columns):
        raise RelationshipFileError(f"{where}: from and to need the same number of columns")
    status = entry.get("status", "proposed")
    if status not in ("proposed", "approved", "rejected"):
        raise RelationshipFileError(f"{where}: unknown status {status!r}")
    cardinality = entry.get("cardinality", "many_to_one")
    return Relationship(from_table, from_columns, to_table, to_columns, cardinality), status


class RelationshipGraph:
    """Approved relationships as an undirected graph of tables, for lookups and shortest join paths."""

    def __init__(self, relationships: list[Relationship]):
        self._relationships = relationships
        self._names = {}
        self._edges: dict[str, list[tuple[str, Relationship]]] = {}
        for r in relationships:
            for table in (r.from_table, r.to_table):
                self._names.setdefault(table.lower(), table)
            self._edges.setdefault(r.from_table.lower(), []).append((r.to_table.lower(), r))
            self._edges.setdefault(r.to_table.lower(), []).append((r.from_table.lower(), r))
        for neighbours in self._edges.values():
            neighbours.sort(key=lambda edge: (edge[0], edge[1].join_condition))

    def __len__(self) -> int:
        return len(self._relationships)

    def describe(self, table: str) -> dict[str, Any]:
        key = table.lower()
        references = [r.to_dict() for r in self._relationships if r.from_table.lower() == key]
        referenced_by = [r.to_dict() for r in self._relationships if r.to_table.lower() == key]
        response: dict[str, Any] = {"table": self._names.get(key, table), "references": references,
                                    "referenced_by": referenced_by}
        if not references and not referenced_by:
            response["note"] = f"No approved relationships involve {table!r}."
        return response

    def join_path(self, table_a: str, table_b: str) -> dict[str, Any]:
        start, goal = table_a.lower(), table_b.lower()
        for table in (table_a, table_b):
            if table.lower() not in self._edges:
                return {"found": False, "note": f"No approved relationships involve {table!r}."}
        if start == goal:
            return {"found": True, "hops": [], "sql": f"FROM {self._names[start]}"}

        previous: dict[str, tuple[str, Relationship]] = {}
        frontier, seen = deque([(start, 0)]), {start}
        while frontier:
            table, depth = frontier.popleft()
            if table == goal or depth == MAX_JOIN_HOPS:
                continue
            for neighbour, relationship in self._edges[table]:
                if neighbour not in seen:
                    seen.add(neighbour)
                    previous[neighbour] = (table, relationship)
                    frontier.append((neighbour, depth + 1))
        if goal not in previous:
            return {"found": False,
                    "note": f"No path of up to {MAX_JOIN_HOPS} approved joins between {table_a!r} and {table_b!r}."}

        hops, table = [], goal
        while table != start:
            parent, relationship = previous[table]
            hops.append((parent, table, relationship))
            table = parent
        hops.reverse()
        sql = [f"FROM {self._names[start]}"]
        for _, joined, relationship in hops:
            sql.append(f"JOIN {self._names[joined]} ON {relationship.join_condition}")
        return {"found": True, "hops": [r.to_dict() for _, _, r in hops], "sql": "\n".join(sql)}
