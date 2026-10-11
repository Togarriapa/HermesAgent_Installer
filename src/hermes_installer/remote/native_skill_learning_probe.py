"""Fixed, read-only bridge to Hermes' native skill proposal review APIs.

This helper accepts no caller-selected path, identity, or request data. It runs
inside the fixed owner PM interpreter, derives the canonical Hermes HOME from
the pinned Hermes constants, and emits a closed bounded observation. Approval,
discard, apply, and filesystem-write APIs are never imported or called.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


_CANONICAL_HOME = Path("/home/admin/.hermes")
_PENDING_COMPONENTS = ("home", "admin", ".hermes", "pending", "skills")
_UID = 1000
_MAX_RECORDS = 64
_MAX_RECORD_BYTES = 256 * 1024
_MAX_INPUT_BYTES = 8 * 1024 * 1024
_MAX_DIFF_BYTES = 256 * 1024
_MAX_SUMMARY_CHARS = 240
_MAX_SKILL_LABEL_CHARS = 120
_ID = re.compile(r"[0-9a-f]{8}\Z")
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9 _.-]{0,119}\Z")
_ACTIONS = frozenset({"create", "edit", "patch", "write_file", "remove_file", "delete", "batch"})
_REASONS = frozenset({
    "pending_directory_unavailable", "pending_member_invalid", "pending_limit_exceeded",
    "pending_record_skipped", "pending_record_invalid", "native_diff_unavailable",
    "diff_limit_reached", "pending_custody_changed",
})


class NativeSkillLearningProbeUnavailable(RuntimeError):
    """The fixed native review source could not be read safely."""


def _clean(value: Any, limit: int) -> str:
    if not isinstance(value, str):
        return ""
    return " ".join("".join(char for char in value if char >= " " and char != "\x7f").split())[:limit]


def _safe_directory_identity(path: Path, *, home: Path,
                             components: tuple[str, ...]) -> tuple[int, int, int, int, int, int, int]:
    """Verify a fixed path chain without following symlinks and return stat custody."""
    if (home != _CANONICAL_HOME or path != Path("/").joinpath(*components)
            or not path.is_relative_to(home)):
        raise NativeSkillLearningProbeUnavailable("fixed pending path mismatch")
    current = Path("/")
    chain = [current]
    for component in components:
        current = current / component
        chain.append(current)
    for index, item in enumerate(chain):
        info = os.lstat(item)
        if not stat.S_ISDIR(info.st_mode):
            raise NativeSkillLearningProbeUnavailable("pending directory chain is not real directories")
        if index >= 1 and info.st_uid not in {0, _UID}:
            raise NativeSkillLearningProbeUnavailable("pending directory chain is not owner-controlled")
        if item == home and info.st_uid != _UID:
            raise NativeSkillLearningProbeUnavailable("canonical Hermes HOME is not owner-controlled")
        if item.is_relative_to(home) and item != home and info.st_uid != _UID:
            raise NativeSkillLearningProbeUnavailable("pending descendants are not owner-controlled")
        writable_by_others = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        if writable_by_others and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX):
            raise NativeSkillLearningProbeUnavailable("pending directory chain is writable by other principals")
    info = os.lstat(path)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
            stat.S_IMODE(info.st_mode), info.st_mtime_ns, info.st_ctime_ns)


def _read_member(directory: Path, name: str) -> tuple[tuple[int, ...], bytes]:
    if not _ID.fullmatch(name[:-5]) or not name.endswith(".json"):
        raise NativeSkillLearningProbeUnavailable("pending member name is invalid")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(directory / name, flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _UID or info.st_nlink != 1
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or info.st_size < 1 or info.st_size > _MAX_RECORD_BYTES):
            raise NativeSkillLearningProbeUnavailable("pending member ownership, type, or size is invalid")
        parts: list[bytes] = []
        remaining = _MAX_RECORD_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            parts.append(chunk)
            remaining -= len(chunk)
        content = b"".join(parts)
        if len(content) != info.st_size:
            raise NativeSkillLearningProbeUnavailable("pending member changed while it was read")
        signature = (info.st_dev, info.st_ino, info.st_uid, info.st_gid,
                     stat.S_IMODE(info.st_mode), info.st_nlink, info.st_size,
                     info.st_mtime_ns, info.st_ctime_ns, hashlib.sha256(content).digest())
        return signature, content
    finally:
        os.close(fd)


def _scan(directory: Path) -> tuple[tuple[int, ...], dict[str, tuple[tuple[int, ...], bytes]]]:
    home = _CANONICAL_HOME
    directory_signature = _safe_directory_identity(directory, home=home,
                                                   components=_PENDING_COMPONENTS)
    names = sorted(name for name in os.listdir(directory) if name.endswith(".json"))
    if len(names) > _MAX_RECORDS:
        raise NativeSkillLearningProbeUnavailable("pending record count exceeds the fixed bound")
    members: dict[str, tuple[tuple[int, ...], bytes]] = {}
    total = 0
    for name in names:
        member = _read_member(directory, name)
        total += len(member[1])
        if total > _MAX_INPUT_BYTES:
            raise NativeSkillLearningProbeUnavailable("pending source bytes exceed the fixed bound")
        members[name] = member
    return directory_signature, members


def _validate_payload(action: str, payload: Any) -> bool:
    if not isinstance(payload, dict) or action not in _ACTIONS:
        return False
    if action == "batch":
        operations = payload.get("operations")
        return (isinstance(operations, list) and 0 < len(operations) <= _MAX_RECORDS
                and all(_valid_operation(item) for item in operations))
    return _valid_operation({**payload, "action": action})


def _valid_operation(operation: Any) -> bool:
    if not isinstance(operation, dict):
        return False
    action = operation.get("action")
    if not isinstance(action, str) or action not in _ACTIONS - {"batch"}:
        return False
    name = operation.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return False
    if action in {"patch", "write_file", "remove_file"}:
        raw = operation.get("file_path") or ("SKILL.md" if action == "patch" else None)
        if raw is None:
            return False
        if (not isinstance(raw, str) or not raw or len(raw) > 240 or raw.startswith("/")
                or "\\" in raw or any(part in {"", ".", ".."} for part in raw.split("/"))):
            return False
        parts = raw.split("/")
        if parts[-1] == "SKILL.md":
            return len(parts) in {1, 2}
        return len(parts) >= 2 and parts[0] in {"references", "templates", "scripts", "assets"}
    return True


def _native_diff_reads_stay_in_owned_skills(home: Path, action: str, payload: dict[str, Any]) -> bool:
    """Guard the native diff helper's existing-skill reads to this owner's HOME."""
    operations = payload.get("operations", []) if action == "batch" else [payload]
    for operation in operations:
        op_action = operation.get("action")
        if op_action not in {"edit", "patch", "write_file"}:
            continue
        name = operation.get("name")
        label = "SKILL.md" if op_action == "edit" else (operation.get("file_path") or "SKILL.md")
        target = home / "skills" / name
        root = home / "skills"
        try:
            root_info = os.lstat(root)
        except OSError:
            return False
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != _UID
                or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return False
        # Hermes searches the active HOME skills root before configured external
        # roots. Require exactly one matching owner-local skill directory so the
        # official diff implementation cannot fall through to an external path.
        matches: list[Path] = []
        for current, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [entry for entry in dirs if not (Path(current) / entry).is_symlink()]
            current_path = Path(current)
            if current_path.name == name and "SKILL.md" in files:
                matches.append(current_path)
        if len(matches) != 1 or matches[0] != target:
            return False
        target_info = os.lstat(target)
        if (not stat.S_ISDIR(target_info.st_mode) or target_info.st_uid != _UID
                or target_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return False
        parts = label.split("/")
        cursor = target
        for part in parts[:-1]:
            cursor = cursor / part
            try:
                info = os.lstat(cursor)
            except OSError:
                return False
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != _UID
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                return False
        cursor = cursor / parts[-1]
        try:
            info = os.lstat(cursor)
        except OSError:
            return False
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != _UID or info.st_nlink != 1
                or info.st_size > _MAX_RECORD_BYTES
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            return False
    return True


def _partial(reasons: set[str], candidates: list[dict[str, Any]] | None = None,
             diff_bytes: int = 0) -> dict[str, Any]:
    bounded = sorted(reason for reason in reasons if reason in _REASONS)
    return {
        "schema": 1,
        "state": "partial" if bounded else "read-only-native-review",
        "candidates": candidates or [],
        "pending_reasons": bounded,
        "candidate_count": len(candidates or []),
        "diff_bytes": diff_bytes,
    }


def _collect(home: Path, approval: Any) -> dict[str, Any]:
    if home != _CANONICAL_HOME:
        return _partial({"pending_directory_unavailable"})
    directory = home / "pending" / "skills"
    try:
        before_directory, before_members = _scan(directory)
    except FileNotFoundError:
        # The native empty-queue case may have no pending/skills directory.
        # Observe existing parents on both sides of the official empty read.
        try:
            home_signature = _safe_directory_identity(home, home=home,
                                                      components=("home", "admin", ".hermes"))
            pending = home / "pending"
            try:
                pending_signature = _safe_directory_identity(
                    pending, home=home, components=("home", "admin", ".hermes", "pending"))
            except FileNotFoundError:
                pending_signature = None
            records = approval.list_pending("skills")
            if records != []:
                return _partial({"pending_record_invalid"})
            home_after = _safe_directory_identity(home, home=home,
                                                  components=("home", "admin", ".hermes"))
            try:
                pending_after = _safe_directory_identity(
                    pending, home=home, components=("home", "admin", ".hermes", "pending"))
            except FileNotFoundError:
                pending_after = None
            if home_signature != home_after or pending_signature != pending_after:
                return _partial({"pending_custody_changed"})
        except Exception:
            return _partial({"pending_directory_unavailable"})
        return _partial(set())
    except NativeSkillLearningProbeUnavailable as exc:
        reason = "pending_limit_exceeded" if "bound" in str(exc) else "pending_member_invalid"
        return _partial({reason})
    except OSError:
        return _partial({"pending_directory_unavailable"})

    reasons: set[str] = set()
    expected_ids: set[str] = set()
    matching_file_ids: set[str] = set()
    for filename, (_, raw) in before_members.items():
        file_id = filename[:-5]
        expected_ids.add(file_id)
        try:
            record = json.loads(raw.decode("utf-8-sig"))
        except (UnicodeError, ValueError):
            reasons.add("pending_record_skipped")
            continue
        if not isinstance(record, dict) or record.get("id") != file_id or record.get("subsystem") != "skills":
            reasons.add("pending_record_invalid")
        else:
            matching_file_ids.add(file_id)

    try:
        records = approval.list_pending("skills")
    except Exception:
        return _partial(reasons | {"pending_directory_unavailable"})
    if not isinstance(records, list):
        return _partial(reasons | {"pending_record_invalid"})

    returned_ids: set[str] = set()
    valid_records: list[tuple[dict[str, Any], bytes]] = []
    for record in records:
        if not isinstance(record, dict):
            reasons.add("pending_record_invalid")
            continue
        pending_id = record.get("id")
        if (not isinstance(pending_id, str) or not _ID.fullmatch(pending_id)
                or pending_id in returned_ids or pending_id + ".json" not in before_members):
            reasons.add("pending_record_invalid")
            continue
        returned_ids.add(pending_id)
        if pending_id not in matching_file_ids:
            reasons.add("pending_record_invalid")
            continue
        raw = before_members[pending_id + ".json"][1]
        payload = record.get("payload")
        action = record.get("action")
        if not isinstance(action, str) or not _validate_payload(action, payload):
            reasons.add("pending_record_invalid")
            continue
        if not _native_diff_reads_stay_in_owned_skills(home, action, payload):
            reasons.add("pending_record_invalid")
            continue
        valid_records.append((record, raw))
    if returned_ids != expected_ids:
        reasons.add("pending_record_skipped")

    candidates: list[dict[str, Any]] = []
    remaining = _MAX_DIFF_BYTES
    for record, raw in valid_records:
        try:
            diff = approval.skill_pending_diff(record)
        except Exception:
            reasons.add("native_diff_unavailable")
            continue
        if not isinstance(diff, str):
            reasons.add("native_diff_unavailable")
            continue
        try:
            encoded = diff.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            reasons.add("native_diff_unavailable")
            continue
        if any(ord(char) < 0x20 and char not in "\n\r\t" or ord(char) == 0x7f for char in diff):
            reasons.add("native_diff_unavailable")
            continue
        full_digest = hashlib.sha256(encoded).hexdigest()
        truncated = len(encoded) > remaining
        if truncated:
            shown = encoded[:remaining].decode("utf-8", errors="ignore")
            shown_bytes = len(shown.encode("utf-8"))
            reasons.add("diff_limit_reached")
        else:
            shown = diff
            shown_bytes = len(encoded)
        remaining -= shown_bytes
        payload = record["payload"]
        name = _clean(payload.get("name"), _MAX_SKILL_LABEL_CHARS)
        created = record.get("created_at")
        try:
            created_value = float(created)
        except (TypeError, ValueError, OverflowError):
            created_value = float("nan")
        if (isinstance(created, bool) or not isinstance(created, (int, float))
                or not math.isfinite(created_value)):
            created = None
        revision = hashlib.sha256(raw).hexdigest()
        opaque_id = hashlib.sha256(
            b"hermes-native-skill-learning-v1\0" + record["id"].encode() + b"\0" + revision.encode()
        ).hexdigest()[:24]
        candidates.append({
            "opaque_id": opaque_id,
            "revision_sha256": revision,
            "action": record["action"],
            "created_at": created_value if created is not None else None,
            "skill_label": name or ("Multiple skill changes" if record["action"] == "batch" else "Skill proposal"),
            "summary": _clean(record.get("summary"), _MAX_SUMMARY_CHARS),
            "diff_text": shown,
            "diff_sha256": full_digest,
            "truncated": truncated,
            "state": "pending-review",
        })

    try:
        after_directory, after_members = _scan(directory)
    except Exception:
        return _partial(reasons | {"pending_custody_changed"})
    if before_directory != after_directory or before_members.keys() != after_members.keys() or any(
        before_members[name][0] != after_members[name][0] for name in before_members
    ):
        return _partial(reasons | {"pending_custody_changed"})
    used = _MAX_DIFF_BYTES - remaining
    return _partial(reasons, candidates, used)


def read_native_skill_learning_candidates() -> dict[str, Any]:
    """Read the fixed canonical owner's native skill review queue, fail-closed."""
    try:
        from hermes_constants import get_hermes_home
        import tools.write_approval as approval

        home = Path(get_hermes_home())
        if home != _CANONICAL_HOME:
            return _partial({"pending_directory_unavailable"})
        return _collect(home, approval)
    except Exception:
        return _partial({"pending_directory_unavailable"})


def main() -> int:
    """Fixed no-argument CLI for the root's PM-Python launcher."""
    if len(sys.argv) != 1:
        print(json.dumps(_partial({"pending_directory_unavailable"}), separators=(",", ":")))
        return 2
    result = read_native_skill_learning_candidates()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
