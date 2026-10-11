"""Sanitized read-only view over the sealed root native skill-learning observation."""
from __future__ import annotations

import hashlib
import math
import re
import time
from collections.abc import Mapping, Sequence
from typing import Any


_OPAQUE_ID = re.compile(r"[0-9a-f]{24}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ACTIONS = frozenset({"create", "edit", "patch", "write_file", "remove_file", "delete", "batch"})
_READINESS = frozenset({"read-only-native-review", "partial", "unavailable"})
_PENDING_REASONS = frozenset({
    "pending_directory_unavailable", "pending_member_invalid", "pending_limit_exceeded",
    "pending_record_skipped", "pending_record_invalid", "native_diff_unavailable",
    "diff_limit_reached", "pending_custody_changed",
})
_MAX_ROWS = 64
_MAX_DIFF_BYTES = 256 * 1024


class JarvisLearningUnavailable(RuntimeError):
    """The sealed owner review observation is unavailable or no longer current."""


def _plain_text(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(ch for ch in value if ch >= " " and ch != "\x7f").split())[:limit]


def _verify_current(observation: object, *, config: object, peer_pid: int,
                    peer_uid: int, peer_gid: int, accepted_ingress: object,
                    now: float) -> bool:
    from .core_gateway_inspector import CoreVerifiedSkillLearningObservation

    if type(observation) is not CoreVerifiedSkillLearningObservation:
        return False
    try:
        return observation.verify_current(
            config, peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
            accepted_ingress=accepted_ingress, now=now,
        ) is True
    except Exception:
        return False


def build_learning_projection(observation: object, *, config: object,
                              peer_pid: int, peer_uid: int, peer_gid: int,
                              accepted_ingress: object) -> dict[str, Any]:
    """Project one sealed, current root observation; this module reads no files.

    Owner identity, forwarded JWT, ingress proof, fixed native HOME/source and
    before/after custody are attested by CoreVerifiedSkillLearningObservation.
    Browser input never supplies these bindings. The projection is read-only.
    """
    now = time.monotonic()
    if not _verify_current(observation, config=config, peer_pid=peer_pid, peer_uid=peer_uid,
                           peer_gid=peer_gid, accepted_ingress=accepted_ingress, now=now):
        raise JarvisLearningUnavailable("current root skill-learning observation is unavailable")
    readiness = getattr(observation, "readiness", None)
    reasons = getattr(observation, "pending_reasons", None)
    candidates = getattr(observation, "candidates", None)
    expires = getattr(observation, "expires_monotonic", None)
    try:
        expires_value = float(expires)
    except (TypeError, ValueError, OverflowError):
        expires_value = float("nan")
    if (not isinstance(readiness, str) or readiness not in _READINESS
            or not isinstance(reasons, Sequence)
            or isinstance(reasons, (str, bytes)) or len(reasons) > 16
            or not isinstance(candidates, Sequence) or isinstance(candidates, (str, bytes))
            or len(candidates) > _MAX_ROWS or isinstance(expires, bool)
            or not isinstance(expires, (int, float)) or not math.isfinite(expires_value)
            or now >= expires or (readiness == "unavailable" and candidates)):
        raise JarvisLearningUnavailable("root skill-learning observation schema is invalid")

    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_bytes = 0
    for candidate in candidates:
        if not isinstance(candidate, Mapping):
            raise JarvisLearningUnavailable("root candidate record is malformed")
        expected = {
            "opaque_id", "revision_sha256", "action", "created_at", "skill_label", "summary",
            "diff_text", "diff_sha256", "truncated", "state",
        }
        if set(candidate) != expected:
            raise JarvisLearningUnavailable("root candidate record has an unexpected schema")
        opaque_id = candidate["opaque_id"]
        revision = candidate["revision_sha256"]
        diff_hash = candidate["diff_sha256"]
        action = candidate["action"]
        diff = candidate["diff_text"]
        created = candidate["created_at"]
        truncated = candidate["truncated"]
        try:
            created_value = float(created) if created is not None else None
        except (TypeError, ValueError, OverflowError):
            created_value = float("nan")
        if (not isinstance(opaque_id, str) or not _OPAQUE_ID.fullmatch(opaque_id)
                or opaque_id in seen or not isinstance(revision, str) or not _SHA256.fullmatch(revision)
                or not isinstance(diff_hash, str) or not _SHA256.fullmatch(diff_hash)
                or not isinstance(action, str) or action not in _ACTIONS
                or not isinstance(diff, str) or type(truncated) is not bool
                or not isinstance(candidate["skill_label"], str)
                or not isinstance(candidate["summary"], str)
                or candidate["state"] != "pending-review"
                or (created is not None and (isinstance(created, bool)
                    or not isinstance(created, (int, float)) or not math.isfinite(created_value)))):
            raise JarvisLearningUnavailable("root candidate record is malformed")
        try:
            diff_bytes = diff.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            raise JarvisLearningUnavailable("root candidate diff is malformed") from None
        if any(ord(char) < 0x20 and char not in "\n\r\t" or ord(char) == 0x7f for char in diff):
            raise JarvisLearningUnavailable("root candidate diff contains control characters")
        total_bytes += len(diff_bytes)
        if total_bytes > _MAX_DIFF_BYTES:
            raise JarvisLearningUnavailable("root candidate diff exceeds the projection bound")
        if not truncated and hashlib.sha256(diff_bytes).hexdigest() != diff_hash:
            raise JarvisLearningUnavailable("root candidate diff digest does not match")
        seen.add(opaque_id)
        rows.append({
            "id": opaque_id,
            "revisionSha256": revision,
            "action": action,
            "skillLabel": _plain_text(candidate["skill_label"], 120),
            "summary": _plain_text(candidate["summary"], 240),
            "createdAt": created_value,
            "diff": diff,
            "diffSha256": diff_hash,
            "truncated": truncated,
            "reviewState": "awaiting-native-approval",
            "approvalRoute": "Review in the owner Hermes conversation with /skills pending.",
        })
    if not _verify_current(observation, config=config, peer_pid=peer_pid, peer_uid=peer_uid,
                           peer_gid=peer_gid, accepted_ingress=accepted_ingress,
                           now=time.monotonic()):
        raise JarvisLearningUnavailable("root skill-learning observation changed during projection")
    safe_reasons = [reason for reason in reasons
                    if isinstance(reason, str) and reason in _PENDING_REASONS]
    if len(safe_reasons) != len(reasons):
        raise JarvisLearningUnavailable("root skill-learning pending reasons are malformed")
    return {
        "schema": 1,
        "state": readiness,
        "canApply": False,
        "canRollback": False,
        "pendingReasons": safe_reasons,
        "candidates": rows,
        "nextStep": "Use /skills pending in the owner Hermes conversation for the full native review. This view cannot approve or apply changes.",
    }
