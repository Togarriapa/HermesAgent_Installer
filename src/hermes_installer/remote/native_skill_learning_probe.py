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
    "missing_store", "unsafe_store", "corrupt_record", "record_limit",
    "diff_limit", "native_read_failed", "source_unavailable", "snapshot_changed",
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


def _strict_json(raw: bytes) -> dict[str, Any]:
    def reject_constant(_value: str) -> None:
        raise ValueError("non-standard JSON constant")

    def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result

    value = json.loads(raw.decode("utf-8-sig"), object_pairs_hook=reject_duplicate_pairs,
                       parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("record is not an object")
    return value


def _canonical_record(value: Any) -> bytes | None:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8", errors="strict")
    except (TypeError, ValueError, UnicodeError):
        return None


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


def _hash_owned_file(path: Path) -> tuple[Any, ...]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != _UID or before.st_nlink != 1
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or before.st_size < 0 or before.st_size > _MAX_INPUT_BYTES):
            raise NativeSkillLearningProbeUnavailable("skill base file is not a bounded owner file")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > _MAX_INPUT_BYTES:
                raise NativeSkillLearningProbeUnavailable("skill base bytes exceed fixed bound")
            digest.update(chunk)
        after = os.fstat(fd)
        if (total != before.st_size or _stat_signature(before) != _stat_signature(after)):
            raise NativeSkillLearningProbeUnavailable("skill base file changed while read")
        return (*_stat_signature(after), digest.hexdigest())
    finally:
        os.close(fd)


def _stat_signature(info: os.stat_result) -> tuple[int, ...]:
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _native_diff_reads_stay_in_owned_skills(home: Path, action: str,
                                            payload: dict[str, Any]) -> tuple[tuple[str, tuple[Any, ...]], ...] | None:
    """Return custody for the skill tree whose bytes the native diff may read."""
    operations = payload.get("operations", []) if action == "batch" else [payload]
    names: set[str] = set()
    files_to_hash: set[Path] = set()
    for operation in operations:
        op_action = operation.get("action")
        if op_action not in {"edit", "patch", "write_file"}:
            continue
        name = operation.get("name")
        names.add(name)
        label = "SKILL.md" if op_action == "edit" else (operation.get("file_path") or "SKILL.md")
        files_to_hash.add(home / "skills" / name / label)
    if not names:
        return ()
    root = home / "skills"
    try:
        root_info = os.lstat(root)
    except OSError:
        return None
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != _UID
            or root_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        return None
    # Capture every directory entry for deterministic name selection, plus the
    # complete selected skill trees because the official diff can read support
    # files while constructing a proposal diff. Symlinks in selected trees fail.
    directories: list[Path] = [root]
    matches: dict[str, list[Path]] = {name: [] for name in names}
    for current, dirs, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept: list[str] = []
        for entry in sorted(dirs):
            child = current_path / entry
            info = os.lstat(child)
            if stat.S_ISLNK(info.st_mode):
                if entry in names or current_path.name in names:
                    return None
                continue
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != _UID or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                return None
            directories.append(child)
            kept.append(entry)
            if entry in names:
                matches[entry].append(child)
        dirs[:] = kept
        if len(directories) > 8192:
            return None
    if any(len(matches[name]) != 1 or matches[name][0] != root / name for name in names):
        return None
    selected = {root / name for name in names}
    selected_directories: list[Path] = []
    for base in selected:
        info = os.lstat(base)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != _UID:
            return None
        for current, dirs, files in os.walk(base, followlinks=False):
            current_path = Path(current)
            selected_directories.append(current_path)
            if len(selected_directories) > 8192:
                return None
            for entry in dirs:
                child = current_path / entry
                info = os.lstat(child)
                if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                        or info.st_uid != _UID or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    return None
            for entry in files:
                file_path = current_path / entry
                info = os.lstat(file_path)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != _UID or info.st_nlink != 1
                        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
                    return None
                files_to_hash.add(file_path)
                if len(files_to_hash) > 8192:
                    return None
    try:
        entries: list[tuple[str, tuple[int, ...]]] = []
        for directory in directories:
            info = os.lstat(directory)
            entries.append((directory.relative_to(root).as_posix() or ".", _stat_signature(info)))
        for directory in selected_directories:
            info = os.lstat(directory)
            entries.append((directory.relative_to(root).as_posix(), _stat_signature(info)))
        total_file_bytes = 0
        for path in sorted(files_to_hash):
            file_signature = _hash_owned_file(path)
            total_file_bytes += file_signature[6]
            if total_file_bytes > _MAX_INPUT_BYTES:
                return None
            entries.append((path.relative_to(root).as_posix(), file_signature))
        encoded_size = sum(len(name.encode()) + 128 for name, _ in entries)
        if encoded_size > _MAX_INPUT_BYTES:
            return None
        return tuple(sorted(entries))
    except (OSError, ValueError, NativeSkillLearningProbeUnavailable):
        return None


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
        return _partial({"source_unavailable"})
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
                return _partial({"corrupt_record"})
            home_after = _safe_directory_identity(home, home=home,
                                                  components=("home", "admin", ".hermes"))
            try:
                pending_after = _safe_directory_identity(
                    pending, home=home, components=("home", "admin", ".hermes", "pending"))
            except FileNotFoundError:
                pending_after = None
            if home_signature != home_after or pending_signature != pending_after:
                return _partial({"snapshot_changed"})
        except Exception:
            return _partial({"source_unavailable"})
        return _partial(set())
    except NativeSkillLearningProbeUnavailable as exc:
        reason = "record_limit" if "bound" in str(exc) else "unsafe_store"
        return _partial({reason})
    except OSError:
        return _partial({"source_unavailable"})

    reasons: set[str] = set()
    expected_ids: set[str] = set()
    expected_records: dict[str, dict[str, Any]] = {}
    for filename, (_, raw) in before_members.items():
        file_id = filename[:-5]
        expected_ids.add(file_id)
        try:
            record = _strict_json(raw)
        except (UnicodeError, ValueError):
            reasons.add("corrupt_record")
            continue
        if not isinstance(record, dict) or record.get("id") != file_id or record.get("subsystem") != "skills":
            reasons.add("corrupt_record")
        else:
            expected_records[file_id] = record

    try:
        records = approval.list_pending("skills")
    except Exception:
        return _partial(reasons | {"source_unavailable"})
    if not isinstance(records, list):
        return _partial(reasons | {"corrupt_record"})

    returned_ids: set[str] = set()
    valid_records: list[tuple[dict[str, Any], bytes]] = []
    for record in records:
        if not isinstance(record, dict):
            reasons.add("corrupt_record")
            continue
        pending_id = record.get("id")
        if (not isinstance(pending_id, str) or not _ID.fullmatch(pending_id)
                or pending_id in returned_ids or pending_id + ".json" not in before_members):
            reasons.add("corrupt_record")
            continue
        returned_ids.add(pending_id)
        preread = expected_records.get(pending_id)
        native_bytes = _canonical_record(record)
        preread_bytes = _canonical_record(preread)
        if preread is None or native_bytes is None or native_bytes != preread_bytes:
            reasons.add("snapshot_changed")
            continue
        raw = before_members[pending_id + ".json"][1]
        payload = record.get("payload")
        action = record.get("action")
        if not isinstance(action, str) or not _validate_payload(action, payload):
            reasons.add("corrupt_record")
            continue
        if action in {"edit", "patch", "write_file"} and _native_diff_reads_stay_in_owned_skills(home, action, payload) is None:
            reasons.add("unsafe_store")
            continue
        valid_records.append((record, raw))
    if returned_ids != expected_ids:
        reasons.add("corrupt_record")

    candidates: list[dict[str, Any]] = []
    remaining = _MAX_DIFF_BYTES
    base_snapshots: dict[str, tuple[tuple[str, tuple[Any, ...]], ...]] = {}
    for record, raw in valid_records:
        if record["action"] in {"edit", "patch", "write_file"}:
            before_base = _native_diff_reads_stay_in_owned_skills(home, record["action"], record["payload"])
            if before_base is None:
                reasons.add("unsafe_store")
                continue
            base_snapshots[record["id"]] = before_base
        try:
            diff = approval.skill_pending_diff(record)
        except Exception:
            reasons.add("native_read_failed")
            continue
        if not isinstance(diff, str):
            reasons.add("native_read_failed")
            continue
        try:
            encoded = diff.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            reasons.add("native_read_failed")
            continue
        if any(ord(char) < 0x20 and char not in "\n\r\t" or ord(char) == 0x7f for char in diff):
            reasons.add("native_read_failed")
            continue
        full_digest = hashlib.sha256(encoded).hexdigest()
        truncated = len(encoded) > remaining
        if truncated:
            shown = encoded[:remaining].decode("utf-8", errors="ignore")
            shown_bytes = len(shown.encode("utf-8"))
            reasons.add("diff_limit")
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
        if record["id"] in base_snapshots:
            after_base = _native_diff_reads_stay_in_owned_skills(home, record["action"], record["payload"])
            if after_base is None or after_base != base_snapshots[record["id"]]:
                reasons.add("snapshot_changed")
                return _partial(reasons)

    try:
        after_directory, after_members = _scan(directory)
    except Exception:
        return _partial(reasons | {"snapshot_changed"})
    if before_directory != after_directory or before_members.keys() != after_members.keys() or any(
        before_members[name][0] != after_members[name][0] for name in before_members
    ):
        return _partial(reasons | {"snapshot_changed"})
    used = _MAX_DIFF_BYTES - remaining
    return _partial(reasons, candidates, used)


def read_native_skill_learning_candidates() -> dict[str, Any]:
    """Read the fixed canonical owner's native skill review queue, fail-closed."""
    try:
        if (os.getuid() != _UID or os.geteuid() != _UID
                or os.getgid() != _UID or os.getegid() != _UID):
            return _partial({"source_unavailable"})
        from hermes_constants import get_hermes_home
        import tools.write_approval as approval

        home = Path(get_hermes_home())
        if home != _CANONICAL_HOME:
            return _partial({"source_unavailable"})
        return _collect(home, approval)
    except Exception:
        return _partial({"source_unavailable"})


def main() -> int:
    """Fixed no-argument CLI for the root's PM-Python launcher."""
    if len(sys.argv) != 1:
        print(json.dumps(_partial({"source_unavailable"}), separators=(",", ":")))
        return 2
    result = read_native_skill_learning_candidates()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
