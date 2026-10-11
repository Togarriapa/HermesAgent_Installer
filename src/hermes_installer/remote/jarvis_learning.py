"""Read-only projection of Hermes' native skill-learning review queue.

This module never creates, approves, rejects, applies, or rolls back a skill
change.  A root-owned adapter supplies current pending records and the official
``write_approval.skill_pending_diff`` result from the active Hermes session.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections.abc import Mapping, Sequence
from typing import Any, Protocol


_PENDING_ID = re.compile(r"[0-9a-f]{8}\Z")
_READ_ACTIONS = frozenset({"create", "edit", "patch", "write_file"})
_MAX_ROWS = 100
_MAX_DIFF_CHARS = 16_000


class JarvisLearningUnavailable(RuntimeError):
    """The owner review queue or its native diff source is unavailable."""


class NativeSkillReviewReader(Protocol):
    """Read-only adapter over native write_approval APIs, bound to one owner HOME."""

    def list_pending_skills(self) -> Sequence[Mapping[str, Any]]: ...

    def skill_pending_diff(self, record: Mapping[str, Any]) -> str: ...


def _plain_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(ch for ch in value if ch >= " " and ch != "\x7f").split())[:limit]


def build_learning_projection(reader: NativeSkillReviewReader, *,
                              owner_principal_verified: bool) -> dict[str, Any]:
    """Return bounded review metadata/diffs for the authenticated owner only.

    ``owner_principal_verified`` must come from the protected Jarvis ingress
    principal, never a request field. The projection exposes no native pending
    payload, path, account, prompt, or credential and has no mutation surface.
    """
    if owner_principal_verified is not True:
        raise JarvisLearningUnavailable("skill learning review is owner-only")
    if reader is None or not callable(getattr(reader, "list_pending_skills", None)):
        raise JarvisLearningUnavailable("native skill review source is unavailable")
    try:
        records = reader.list_pending_skills()
    except Exception:
        raise JarvisLearningUnavailable("native skill review source is unavailable") from None
    if not isinstance(records, Sequence) or isinstance(records, (str, bytes)) or len(records) > _MAX_ROWS:
        raise JarvisLearningUnavailable("native skill review source returned an invalid record set")

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        if not isinstance(record, Mapping):
            raise JarvisLearningUnavailable("native skill review record is malformed")
        pending_id = record.get("id")
        action = record.get("action")
        if (not isinstance(pending_id, str) or not _PENDING_ID.fullmatch(pending_id)
                or pending_id in seen or not isinstance(action, str) or action not in _READ_ACTIONS):
            raise JarvisLearningUnavailable("native skill review record is malformed")
        seen.add(pending_id)
        created = record.get("created_at")
        try:
            created_value = float(created)
        except (TypeError, ValueError, OverflowError):
            created_value = float("nan")
        if (isinstance(created, bool) or not isinstance(created, (int, float))
                or not math.isfinite(created_value) or created_value < 0):
            raise JarvisLearningUnavailable("native skill review record is malformed")
        try:
            diff = reader.skill_pending_diff(record)
        except Exception:
            raise JarvisLearningUnavailable("native skill review diff is unavailable") from None
        if not isinstance(diff, str) or len(diff) > _MAX_DIFF_CHARS:
            raise JarvisLearningUnavailable("native skill review diff exceeds its bound")
        try:
            diff_bytes = diff.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise JarvisLearningUnavailable("native skill review diff is malformed") from None
        if len(diff_bytes) > _MAX_DIFF_CHARS * 4:
            raise JarvisLearningUnavailable("native skill review diff exceeds its bound")
        rows.append({
            "id": pending_id,
            "action": action,
            "summary": _plain_text(record.get("summary"), 240),
            "origin": (record.get("origin") if isinstance(record.get("origin"), str)
                       and record.get("origin") in {"foreground", "background_review"} else "unknown"),
            "createdAt": created_value,
            "diff": diff,
            "diffSha256": hashlib.sha256(diff_bytes).hexdigest(),
            "reviewState": "awaiting-native-approval",
            "approvalRoute": "Hermes /skills pending and /skills approve <id>",
        })
    rows.sort(key=lambda item: (item["createdAt"], item["id"]))
    return {
        "schema": 1,
        "state": "read-only-native-review",
        "canApply": False,
        "canRollback": False,
        "candidates": rows,
        "nextStep": "Use Hermes /refine on the intended owner conversation to propose changes; review and approve them in Hermes /skills.",
    }
