"""Typed, persisted mission correlation for the first native Orchestrator handoff.

This module does not grant dispatch authority. A MissionBinding is copied only from a
persisted, already-spent owner approval; the root observer carries that value alongside
its independently observed turn, and the Resources consumer joins it back to this ledger
immediately before its one native delegation.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import quote


_ID_RE = re.compile(r"[A-Za-z0-9_-]{24,64}\Z", re.ASCII)
_SHA256_RE = re.compile(r"[a-f0-9]{64}\Z", re.ASCII)
_MISSION_BINDING_FIELDS = frozenset({
    "schema", "mission_id", "revision", "plan_sha256", "task_sha256", "source_profile_id",
})


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class MissionBinding:
    """Closed correlation from a spent mission approval to one observed turn."""

    schema: int
    mission_id: str
    revision: int
    plan_sha256: str
    task_sha256: str
    source_profile_id: str

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not isinstance(self.mission_id, str) or _ID_RE.fullmatch(self.mission_id) is None
                or type(self.revision) is not int or self.revision < 1
                or not isinstance(self.plan_sha256, str) or _SHA256_RE.fullmatch(self.plan_sha256) is None
                or not isinstance(self.task_sha256, str) or _SHA256_RE.fullmatch(self.task_sha256) is None
                or self.source_profile_id != "orchestrator"):
            raise ValueError("mission binding is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "mission_id": self.mission_id,
            "revision": self.revision,
            "plan_sha256": self.plan_sha256,
            "task_sha256": self.task_sha256,
            "source_profile_id": self.source_profile_id,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "MissionBinding":
        if not isinstance(value, Mapping) or set(value) != _MISSION_BINDING_FIELDS:
            raise ValueError("mission binding fields differ")
        return cls(
            schema=value["schema"], mission_id=value["mission_id"],
            revision=value["revision"], plan_sha256=value["plan_sha256"],
            task_sha256=value["task_sha256"], source_profile_id=value["source_profile_id"],
        )


class MissionLedgerReader:
    """Read the fixed mission ledger without initializing or mutating chat storage."""

    def __init__(self, path: Path):
        if not isinstance(path, Path) or not path.is_absolute():
            raise ValueError("absolute mission ledger path required")
        self.path = path

    def _connect(self) -> sqlite3.Connection:
        uri = "file:" + quote(self.path.as_posix(), safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=2, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA busy_timeout=2000")
        return connection


def _spent_row(store: Any, binding: MissionBinding, *, gateway_turn_id: str,
               owner_subject_sha256: str, core_generation: str,
               core_source_generation: str) -> sqlite3.Row | None:
    if (type(binding) is not MissionBinding
            or not isinstance(gateway_turn_id, str) or _ID_RE.fullmatch(gateway_turn_id) is None
            or not isinstance(owner_subject_sha256, str)
            or _SHA256_RE.fullmatch(owner_subject_sha256) is None
            or not isinstance(core_generation, str) or _SHA256_RE.fullmatch(core_generation) is None
            or not isinstance(core_source_generation, str)
            or _SHA256_RE.fullmatch(core_source_generation) is None):
        return None
    try:
        with store._connect() as db:
            db.execute("BEGIN")
            rows = db.execute(
                "SELECT m.id AS mission_id,m.owner,m.revision,m.brief,m.team_ids,"
                "m.status AS mission_status,m.plan_sha256,m.source_binding,"
                "a.status AS approval_status,a.gateway_turn_id,a.launch_request_hash,"
                "a.launch_idempotency_hash,a.plan_sha256 AS approval_plan_sha256,"
                "a.source_binding AS approval_source_binding "
                "FROM jarvis_mission_approvals a JOIN jarvis_missions m "
                "ON m.id=a.mission_id AND m.owner=a.owner "
                "WHERE a.mission_id=? AND a.owner=? AND a.revision=? AND a.gateway_turn_id=?",
                (binding.mission_id, owner_subject_sha256, binding.revision, gateway_turn_id),
            ).fetchall()
            db.execute("COMMIT")
        if len(rows) != 1:
            return None
        row = rows[0]
        source = json.loads(row["source_binding"])
        approval_source = json.loads(row["approval_source_binding"])
        team = json.loads(row["team_ids"])
        expected_request = _digest({
            "mission_id": binding.mission_id,
            "revision": binding.revision,
            "plan_sha256": binding.plan_sha256,
        })
        expected_task = _digest({"goal": row["brief"]})
        if (row["approval_status"] != "spent" or row["mission_status"] != "preview_pending"
                or row["launch_idempotency_hash"] is None
                or row["mission_id"] != binding.mission_id
                or int(row["revision"]) != binding.revision
                or row["plan_sha256"] != binding.plan_sha256
                or row["approval_plan_sha256"] != binding.plan_sha256
                or row["launch_request_hash"] != expected_request
                or type(team) is not list or team != ["orchestrator"]
                or not isinstance(row["brief"], str) or not row["brief"]
                or expected_task != binding.task_sha256
                or type(source) is not dict or set(source) != {"core_source_generation", "core_generation"}
                or source != approval_source
                or source.get("core_generation") != core_generation
                or source.get("core_source_generation") != core_source_generation):
            return None
        return row
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        return None


def resolve_spent_mission_binding(store: Any, binding: MissionBinding, *,
                                  gateway_turn_id: str, owner_subject_sha256: str,
                                  core_generation: str, core_source_generation: str) -> bool:
    """Check that the sealed turn binding is backed by exactly one persisted spent approval."""
    return _spent_row(
        store, binding, gateway_turn_id=gateway_turn_id,
        owner_subject_sha256=owner_subject_sha256, core_generation=core_generation,
        core_source_generation=core_source_generation,
    ) is not None


def resolve_spent_mission_claim(store: Any, binding: MissionBinding, gateway_turn_id: str,
                                owner_subject_sha256: str, core_generation: str,
                                core_source_generation: str, source_profile_id: str,
                                canonical_arguments_sha256: str) -> bool:
    """Join one consumed native claim to the exact approved Orchestrator goal bytes."""
    if (type(binding) is not MissionBinding or source_profile_id != "orchestrator"
            or binding.source_profile_id != source_profile_id
            or not isinstance(canonical_arguments_sha256, str)
            or _SHA256_RE.fullmatch(canonical_arguments_sha256) is None
            or canonical_arguments_sha256 != binding.task_sha256):
        return False
    return _spent_row(
        store, binding, gateway_turn_id=gateway_turn_id,
        owner_subject_sha256=owner_subject_sha256, core_generation=core_generation,
        core_source_generation=core_source_generation,
    ) is not None


__all__ = [
    "MissionBinding", "MissionLedgerReader", "resolve_spent_mission_binding",
    "resolve_spent_mission_claim",
]
