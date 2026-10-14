"""Protected current-core native Codex process observations.

This adapter reports observations made by the root-enrolled, source-pinned Hermes
process.  It is explicitly *not* an independent TLS observer.  The root service
must authenticate the peer against the active core custody before accepting any
record and must join records to a registered owner turn and selected subscription.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import select
import secrets
import socket
import stat
import struct
import threading
import weakref
import base64
import time
import os
import sqlite3
import contextvars
import fcntl
from types import SimpleNamespace
from contextlib import contextmanager
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from hermes_installer.remote.jarvis_mission_executor import MissionBinding


CORE_NATIVE_OBSERVER_SOCKET = Path("/run/hermes-jarvis-native-observer/native-observer.sock")
LIFECYCLE_NATIVE_OBSERVER_SOCKET = Path(
    "/run/hermes-jarvis-lifecycle-observer/lifecycle-observer.sock")
_LIFECYCLE_NATIVE_OBSERVER_OWNER = Path(
    "/run/hermes-jarvis-lifecycle-observer/lifecycle-observer.owner.json")
_LIFECYCLE_NATIVE_OBSERVER_LOCK = Path(
    "/run/hermes-jarvis-lifecycle-observer/lifecycle-observer.lock")
_CORE_NATIVE_OBSERVER_GROUP = 1000
MAX_FRAME = 256 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z", re.ASCII)
_CODEX_ENDPOINT = "https://chatgpt.com/backend-api/codex"
_CODEX_PROVIDER = "openai-codex"
_CODEX_MODE = "codex_responses"
_OBSERVER_RUNTIME_DIR = Path("/run/hermes-jarvis-native-observer")
_MASTER_PLAN_STORE_MAX_BYTES = 48 * 1024
_MASTER_PLAN_STORE_MAX_RECORDS = 4096
_NATIVE_ACTIVITY_STORE_NAME = "native-child-activity.json"
_NATIVE_ACTIVITY_MAX_BYTES = 512 * 1024
_NATIVE_ACTIVITY_MAX_INSTANCES = 100
_NATIVE_ACTIVITY_MAX_EVENTS_PER_INSTANCE = 8
_NATIVE_ACTIVITY_MAX_DEDUP_IDS_PER_INSTANCE = 32
_NATIVE_ACTIVITY_MAX_EVENTS_PER_READ = 200
_NATIVE_ACTIVITY_MAX_RELATIONS_PER_READ = 200
_NATIVE_ACTIVITY_WINDOW_SECONDS = 7 * 24 * 60 * 60
_OBSIDIAN_ORIGIN_STORE_NAME = "obsidian-draft-origins.json"
_OBSIDIAN_ORIGIN_MAX_RECORDS = 4096
_OBSIDIAN_ORIGIN_MAX_BYTES = 512 * 1024
_OBSIDIAN_ORIGIN_HISTORY_NAME = "obsidian-draft-origin-history.json"
_OBSIDIAN_ORIGIN_HISTORY_MAX_RECORDS = 4096
_OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES = 4 * 1024 * 1024
_OBSIDIAN_DELIVERY_MAX_RECORDS = 4096
_OBSIDIAN_PROPOSAL_MAX_RECORDS = 4096
_NATIVE_INHERITANCE_POLICY_SEAL = object()
_MASTER_PLAN_RECORD_SEAL = object()


@dataclass(frozen=True, slots=True)
class RootObservedMasterPlanRecord:
    """Root-memory evidence of a provider-completed, zero-tool planning result."""

    owner_subject_sha256: str
    mission_id: str
    revision: int
    gateway_turn_id: str
    conversation_id: str
    session_id: str
    native_turn_id: str
    owner_turn_handle: str
    core_generation: str
    core_source_generation: str
    goal_sha256: str
    catalog_sha256: str
    planner_prompt_sha256: str
    master_source_generation_sha256: str
    master_source_manifest_sha256: str
    master_prompt_sha256: str
    attempt_handle: str
    api_request_id: str
    provider: str
    api_mode: str
    base_url: str
    model: str
    account_fingerprint: str
    request_sha256: str
    retry_count: int
    completed: bool
    request_tool_count: int
    tool_call_count: int
    plan_json: str
    plan_sha256: str
    response_sha256: str
    selected_source_ids: tuple[str, ...]
    execution_mode: str
    _seal: object = field(repr=False, compare=False)

    def is_root_observed(self) -> bool:
        try:
            return bool(type(self) is RootObservedMasterPlanRecord
                and self._seal is _MASTER_PLAN_RECORD_SEAL
                and all(_HASH.fullmatch(getattr(self, name) or "") for name in (
                    "owner_subject_sha256", "core_generation", "core_source_generation",
                    "goal_sha256", "catalog_sha256", "planner_prompt_sha256",
                    "master_source_generation_sha256", "master_source_manifest_sha256",
                    "master_prompt_sha256", "account_fingerprint", "request_sha256",
                    "plan_sha256", "response_sha256"))
                and isinstance(self.mission_id, str) and _ID.fullmatch(self.mission_id)
                and type(self.revision) is int and self.revision >= 1
                and isinstance(self.gateway_turn_id, str) and _ID.fullmatch(self.gateway_turn_id)
                and isinstance(self.conversation_id, str) and _ID.fullmatch(self.conversation_id)
                and isinstance(self.session_id, str) and _ID.fullmatch(self.session_id)
                and isinstance(self.native_turn_id, str) and _ID.fullmatch(self.native_turn_id)
                and isinstance(self.owner_turn_handle, str) and _OPAQUE.fullmatch(self.owner_turn_handle)
                and isinstance(self.attempt_handle, str) and _OPAQUE.fullmatch(self.attempt_handle)
                and isinstance(self.api_request_id, str) and _ID.fullmatch(self.api_request_id)
                and self.provider == _CODEX_PROVIDER and self.api_mode == _CODEX_MODE
                and self.base_url == _CODEX_ENDPOINT
                and isinstance(self.model, str) and _ID.fullmatch(self.model)
                and type(self.retry_count) is int and self.retry_count == 0
                and self.completed is True
                and type(self.request_tool_count) is int and self.request_tool_count == 0
                and type(self.tool_call_count) is int and self.tool_call_count == 0
                and isinstance(self.plan_json, str) and 1 <= len(self.plan_json.encode("utf-8")) <= 16_384
                and type(self.selected_source_ids) is tuple
                and len(self.selected_source_ids) <= 12
                and len(set(self.selected_source_ids)) == len(self.selected_source_ids)
                and all(isinstance(item, str) and _ID.fullmatch(item) for item in self.selected_source_ids)
                and self.execution_mode in {"oneshot", "kanban"}
                and (bool(self.selected_source_ids) or self.execution_mode == "oneshot")
                and _master_plan_content_matches(self))
        except Exception:
            return False


def _master_plan_content_matches(record: RootObservedMasterPlanRecord) -> bool:
    try:
        plan = json.loads(record.plan_json, object_pairs_hook=_unique_json_pairs)
        if not isinstance(plan, dict):
            return False
        canonical_plan = json.dumps(plan, ensure_ascii=False, sort_keys=True,
                                    separators=(",", ":"), allow_nan=False)
        if canonical_plan != record.plan_json:
            return False
        full = {"execution_mode": record.execution_mode,
                "selected_source_ids": list(record.selected_source_ids), "plan": plan}
        digest = hashlib.sha256(json.dumps(full, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"), allow_nan=False).encode("utf-8", errors="strict")).hexdigest()
        return digest == record.plan_sha256
    except Exception:
        return False


def _unique_json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


_MASTER_PLAN_RECORD_FIELDS = frozenset({
    "schema", "owner_subject_sha256", "mission_id", "revision", "gateway_turn_id",
    "conversation_id", "session_id", "native_turn_id", "owner_turn_handle",
    "core_generation", "core_source_generation", "goal_sha256", "catalog_sha256",
    "planner_prompt_sha256", "master_source_generation_sha256",
    "master_source_manifest_sha256", "master_prompt_sha256", "attempt_handle",
    "api_request_id", "provider", "api_mode", "base_url", "model",
    "account_fingerprint", "request_sha256", "retry_count", "completed",
    "request_tool_count", "tool_call_count",
    "plan_json", "plan_sha256", "response_sha256", "selected_source_ids",
    "execution_mode",
})


def _master_plan_record_identity(owner_subject_sha256: str, mission_id: str,
                                 revision: int) -> tuple[str, str]:
    identity = json.dumps([owner_subject_sha256, mission_id, revision],
                          ensure_ascii=True, separators=(",", ":"))
    basename = "master-plan-" + hashlib.sha256(identity.encode("ascii")).hexdigest() + ".json"
    return basename, identity


def _open_root_master_plan_store() -> int:
    """Open the existing root-private core runtime journal directory safely."""
    if os.geteuid() != 0:
        raise PermissionError("root is required for durable master-plan custody")
    from hermes_installer.core_runtime import JOURNAL

    expected = Path("/var/lib/hermes-installer/core-runtime")
    if JOURNAL != expected / "ownership.json":
        raise PermissionError("core runtime journal path is not fixed")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        for component in ("var", "lib", "hermes-installer", "core-runtime"):
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or info.st_mode & 0o022):
                raise PermissionError("core runtime path custody changed")
        if stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            raise PermissionError("core runtime journal directory mode changed")
        journal_fd = os.open("ownership.json", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
        try:
            journal = os.fstat(journal_fd)
            if (not stat.S_ISREG(journal.st_mode) or journal.st_uid != 0 or journal.st_gid != 0
                    or stat.S_IMODE(journal.st_mode) != 0o600 or journal.st_nlink != 1
                    or journal.st_size > 64 * 1024):
                raise PermissionError("core runtime ownership journal custody changed")
        finally:
            os.close(journal_fd)
        result, fd = fd, -1
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def _read_root_master_plan_bytes(owner_subject_sha256: str, mission_id: str,
                                 revision: int) -> bytes | None:
    basename, _identity = _master_plan_record_identity(owner_subject_sha256, mission_id, revision)
    directory_fd = _open_root_master_plan_store()
    try:
        try:
            fd = os.open(basename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= _MASTER_PLAN_STORE_MAX_BYTES):
                raise PermissionError("master-plan journal record custody changed")
            chunks: list[bytes] = []
            remaining = _MASTER_PLAN_STORE_MAX_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(basename, dir_fd=directory_fd, follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > _MASTER_PLAN_STORE_MAX_BYTES
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise PermissionError("master-plan journal record changed during read")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _master_plan_record_bytes(record: RootObservedMasterPlanRecord) -> bytes:
    if type(record) is not RootObservedMasterPlanRecord or record.is_root_observed() is not True:
        raise ValueError("unverified master-plan record")
    payload = {
        "schema": 1, "owner_subject_sha256": record.owner_subject_sha256,
        "mission_id": record.mission_id, "revision": record.revision,
        "gateway_turn_id": record.gateway_turn_id, "conversation_id": record.conversation_id,
        "session_id": record.session_id, "native_turn_id": record.native_turn_id,
        "owner_turn_handle": record.owner_turn_handle,
        "core_generation": record.core_generation,
        "core_source_generation": record.core_source_generation,
        "goal_sha256": record.goal_sha256, "catalog_sha256": record.catalog_sha256,
        "planner_prompt_sha256": record.planner_prompt_sha256,
        "master_source_generation_sha256": record.master_source_generation_sha256,
        "master_source_manifest_sha256": record.master_source_manifest_sha256,
        "master_prompt_sha256": record.master_prompt_sha256,
        "attempt_handle": record.attempt_handle, "api_request_id": record.api_request_id,
        "provider": record.provider, "api_mode": record.api_mode, "base_url": record.base_url,
        "model": record.model, "account_fingerprint": record.account_fingerprint,
        "request_sha256": record.request_sha256, "retry_count": record.retry_count,
        "completed": record.completed, "request_tool_count": record.request_tool_count,
        "tool_call_count": record.tool_call_count,
        "plan_json": record.plan_json,
        "plan_sha256": record.plan_sha256, "response_sha256": record.response_sha256,
        "selected_source_ids": list(record.selected_source_ids),
        "execution_mode": record.execution_mode,
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True,
                       separators=(",", ":"), allow_nan=False).encode("utf-8", errors="strict")


def _publish_root_master_plan_record(record: RootObservedMasterPlanRecord) -> None:
    raw = _master_plan_record_bytes(record)
    if len(raw) > _MASTER_PLAN_STORE_MAX_BYTES:
        raise ValueError("master-plan record exceeds its fixed bound")
    basename, _identity = _master_plan_record_identity(
        record.owner_subject_sha256, record.mission_id, record.revision)
    directory_fd = _open_root_master_plan_store()
    temp = ".master-plan-" + secrets.token_hex(16) + ".tmp"
    temp_created = False
    try:
        try:
            existing = _read_root_master_plan_bytes(record.owner_subject_sha256,
                record.mission_id, record.revision)
            if existing is not None:
                if existing != raw:
                    raise FileExistsError("a different plan record already exists")
                return
            names = os.listdir(directory_fd)
            if sum(1 for name in names
                   if re.fullmatch(r"master-plan-[0-9a-f]{64}\.json", name)) >= _MASTER_PLAN_STORE_MAX_RECORDS:
                raise OSError("root master-plan journal is full")
            fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
            temp_created = True
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o600)
                offset = 0
                while offset < len(raw):
                    offset += os.write(fd, raw[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                os.link(temp, basename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd,
                        follow_symlinks=False)
            except FileExistsError:
                existing = _read_root_master_plan_bytes(record.owner_subject_sha256,
                    record.mission_id, record.revision)
                if existing != raw:
                    raise
            os.unlink(temp, dir_fd=directory_fd)
            os.fsync(directory_fd)
            if _read_root_master_plan_bytes(record.owner_subject_sha256,
                    record.mission_id, record.revision) != raw:
                raise OSError("published master-plan record failed readback")
        finally:
            if temp_created:
                try:
                    os.unlink(temp, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_fd)


def _root_master_plan_record_from_bytes(raw: bytes, *, owner_subject_sha256: str,
                                        mission_id: str, revision: int
                                        ) -> RootObservedMasterPlanRecord | None:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _MASTER_PLAN_STORE_MAX_BYTES:
        return None
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_pairs)
        if (type(payload) is not dict or set(payload) != _MASTER_PLAN_RECORD_FIELDS
                or type(payload.get("schema")) is not int or payload.get("schema") != 1
                or payload.get("owner_subject_sha256") != owner_subject_sha256
                or payload.get("mission_id") != mission_id or payload.get("revision") != revision
                or type(payload.get("selected_source_ids")) is not list
                or not isinstance(payload.get("plan_json"), str)):
            return None
        if json.dumps(payload, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8") != raw:
            return None
        values = dict(payload)
        values.pop("schema")
        values["selected_source_ids"] = tuple(values["selected_source_ids"])
        values["_seal"] = _MASTER_PLAN_RECORD_SEAL
        record = RootObservedMasterPlanRecord(**values)
        return record if record.is_root_observed() is True else None
    except Exception:
        return None


def _read_root_native_activity_bytes() -> bytes | None:
    """Read the bounded activity snapshot from the existing protected core journal."""
    directory_fd = _open_root_master_plan_store()
    try:
        try:
            fd = os.open(_NATIVE_ACTIVITY_STORE_NAME,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= _NATIVE_ACTIVITY_MAX_BYTES):
                raise PermissionError("native activity journal custody changed")
            chunks: list[bytes] = []
            remaining = _NATIVE_ACTIVITY_MAX_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(_NATIVE_ACTIVITY_STORE_NAME, dir_fd=directory_fd,
                            follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > _NATIVE_ACTIVITY_MAX_BYTES
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise PermissionError("native activity journal changed during read")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _publish_root_native_activity_bytes(raw: bytes) -> None:
    """Atomically replace the bounded event snapshot under existing journal custody."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _NATIVE_ACTIVITY_MAX_BYTES:
        raise ValueError("native activity snapshot exceeds its fixed bound")
    directory_fd = _open_root_master_plan_store()
    temp = ".native-activity-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        try:
            existing = os.stat(_NATIVE_ACTIVITY_STORE_NAME, dir_fd=directory_fd,
                               follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_uid != 0
                or existing.st_gid != 0 or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_nlink != 1):
            raise PermissionError("native activity snapshot custody changed")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        created = True
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short native activity journal write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, _NATIVE_ACTIVITY_STORE_NAME,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        created = False
        os.fsync(directory_fd)
        if _read_root_native_activity_bytes() != raw:
            raise OSError("published native activity snapshot failed readback")
    finally:
        if created:
            try:
                os.unlink(temp, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _read_root_obsidian_origin_bytes() -> bytes | None:
    """Read the bounded Obsidian provenance journal under existing root custody."""
    directory_fd = _open_root_master_plan_store()
    try:
        try:
            fd = os.open(_OBSIDIAN_ORIGIN_STORE_NAME,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= _OBSIDIAN_ORIGIN_MAX_BYTES):
                raise PermissionError("Obsidian origin journal custody changed")
            chunks: list[bytes] = []
            remaining = _OBSIDIAN_ORIGIN_MAX_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(_OBSIDIAN_ORIGIN_STORE_NAME, dir_fd=directory_fd,
                            follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > _OBSIDIAN_ORIGIN_MAX_BYTES
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise PermissionError("Obsidian origin journal changed during read")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _publish_root_obsidian_origin_bytes(raw: bytes) -> None:
    """Atomically publish a bounded root-only Obsidian origin snapshot."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _OBSIDIAN_ORIGIN_MAX_BYTES:
        raise ValueError("Obsidian origin snapshot exceeds its fixed bound")
    directory_fd = _open_root_master_plan_store()
    temp = ".obsidian-origin-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        try:
            existing = os.stat(_OBSIDIAN_ORIGIN_STORE_NAME, dir_fd=directory_fd,
                               follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_uid != 0
                or existing.st_gid != 0 or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_nlink != 1):
            raise PermissionError("Obsidian origin journal custody changed")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        created = True
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short Obsidian origin journal write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, _OBSIDIAN_ORIGIN_STORE_NAME,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        created = False
        os.fsync(directory_fd)
        if _read_root_obsidian_origin_bytes() != raw:
            raise OSError("published Obsidian origin journal failed readback")
    finally:
        if created:
            try:
                os.unlink(temp, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _read_root_obsidian_history_bytes() -> bytes | None:
    directory_fd = _open_root_master_plan_store()
    try:
        try:
            fd = os.open(_OBSIDIAN_ORIGIN_HISTORY_NAME,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
        except FileNotFoundError:
            return None
        try:
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                    or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                    or not 1 <= before.st_size <= _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES):
                raise PermissionError("Obsidian origin history custody changed")
            chunks: list[bytes] = []
            remaining = _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES + 1
            while remaining:
                chunk = os.read(fd, min(8192, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(_OBSIDIAN_ORIGIN_HISTORY_NAME, dir_fd=directory_fd,
                            follow_symlinks=False)
            if (len(raw) != before.st_size or len(raw) > _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES
                    or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                raise PermissionError("Obsidian origin history changed during read")
            return raw
        finally:
            os.close(fd)
    finally:
        os.close(directory_fd)


def _publish_root_obsidian_history_bytes(raw: bytes) -> None:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES:
        raise ValueError("Obsidian origin history exceeds its fixed bound")
    directory_fd = _open_root_master_plan_store()
    temp = ".obsidian-origin-history-" + secrets.token_hex(16) + ".tmp"
    created = False
    try:
        try:
            existing = os.stat(_OBSIDIAN_ORIGIN_HISTORY_NAME, dir_fd=directory_fd,
                               follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and (not stat.S_ISREG(existing.st_mode) or existing.st_uid != 0
                or existing.st_gid != 0 or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_nlink != 1):
            raise PermissionError("Obsidian origin history custody changed")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                     | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=directory_fd)
        created = True
        try:
            os.fchown(fd, 0, 0)
            os.fchmod(fd, 0o600)
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("short Obsidian origin history write")
                offset += written
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temp, _OBSIDIAN_ORIGIN_HISTORY_NAME,
                   src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        created = False
        os.fsync(directory_fd)
        if _read_root_obsidian_history_bytes() != raw:
            raise OSError("published Obsidian origin history failed readback")
    finally:
        if created:
            try:
                os.unlink(temp, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
        os.close(directory_fd)


def _obsidian_origin_record_digest(row: Mapping[str, Any]) -> str:
    fields = {key: row[key] for key in (
        "draft_id", "owner_subject_sha256", "registration_sha256", "origin_execution_id",
        "origin_source_id", "origin_source_revision", "source_generation_sha256",
        "mission_sha256", "content_sha256", "base_sha256", "state")}
    return hashlib.sha256(_canonical(fields)).hexdigest()


def _obsidian_origin_state_from_bytes(raw: bytes) -> tuple[
        dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]]] | None:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _OBSIDIAN_ORIGIN_MAX_BYTES:
        return None
    fields = {"draft_id", "owner_subject_sha256", "registration_sha256", "origin_execution_id",
        "origin_source_id", "origin_source_revision", "source_generation_sha256",
        "mission_sha256", "content_sha256", "base_sha256", "origin_record_sha256", "state"}
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_pairs)
        if (type(value) is not dict or value.get("schema") not in (1, 2)
                or type(value.get("schema")) is not int
                or set(value) != ({"schema", "records"} if value["schema"] == 1
                                  else {"schema", "records", "completed"})
                or type(value["records"]) is not list
                or len(value["records"]) > _OBSIDIAN_ORIGIN_MAX_RECORDS
                or (value["schema"] == 2 and (type(value["completed"]) is not list
                    or len(value["completed"]) > _OBSIDIAN_ORIGIN_MAX_RECORDS))
                or _canonical(value) != raw):
            return None
        result: dict[tuple[str, str], dict[str, Any]] = {}
        for row in value["records"]:
            if (type(row) is not dict or set(row) != fields
                    or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", row.get("draft_id", ""))
                    or not all(_HASH.fullmatch(row.get(key, "") or "") for key in (
                        "owner_subject_sha256", "registration_sha256", "source_generation_sha256",
                        "content_sha256", "origin_record_sha256"))
                    or not _ID.fullmatch(row.get("origin_execution_id", ""))
                    or not _ID.fullmatch(row.get("origin_source_id", ""))
                    or not isinstance(row.get("origin_source_revision"), str)
                    or not 1 <= len(row["origin_source_revision"]) <= 128
                    or any(ord(char) < 0x20 for char in row["origin_source_revision"])
                    or (row["mission_sha256"] is not None
                        and not _HASH.fullmatch(row["mission_sha256"] or ""))
                    or (row["base_sha256"] is not None
                        and not _HASH.fullmatch(row["base_sha256"] or ""))
                    or row.get("state") != "private-draft"
                    or row["origin_record_sha256"] != _obsidian_origin_record_digest(row)):
                return None
            key = (row["owner_subject_sha256"], row["draft_id"])
            if key in result:
                return None
            result[key] = dict(row)
        completed: dict[tuple[str, str], dict[str, Any]] = {}
        for row in value.get("completed", ()):
            fields_completed = {"owner_subject_sha256", "draft_id", "origin_record_sha256",
                "history_record_id", "history_record_sha256", "destination", "note_id",
                "content_sha256", "completed_at", "completed_record_sha256"}
            if (type(row) is not dict or set(row) != fields_completed
                    or not all(_HASH.fullmatch(row.get(key, "") or "") for key in (
                        "owner_subject_sha256", "origin_record_sha256",
                        "history_record_sha256", "content_sha256", "completed_record_sha256"))
                    or not _ID.fullmatch(row.get("draft_id", ""))
                    or not _OPAQUE.fullmatch(row.get("history_record_id", ""))
                    or not isinstance(row.get("destination"), str)
                    or not 1 <= len(row["destination"]) <= 240
                    or not _ID.fullmatch(row.get("note_id", ""))
                    or type(row.get("completed_at")) not in (int, float)
                    or not math.isfinite(row["completed_at"])):
                return None
            tombstone_body = {key: item for key, item in row.items()
                              if key != "completed_record_sha256"}
            if hashlib.sha256(_canonical(tombstone_body)).hexdigest() != row["completed_record_sha256"]:
                return None
            key = (row["owner_subject_sha256"], row["draft_id"])
            if key in completed or key in result:
                return None
            completed[key] = dict(row)
        return result, completed
    except Exception:
        return None


def _obsidian_origin_snapshot_from_bytes(raw: bytes) -> dict[tuple[str, str], dict[str, Any]] | None:
    state = _obsidian_origin_state_from_bytes(raw)
    return None if state is None else state[0]


def _obsidian_history_from_bytes(raw: bytes) -> list[dict[str, Any]] | None:
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES:
        return None
    expected_origin = {"draft_id", "owner_subject_sha256", "registration_sha256",
        "origin_execution_id", "origin_source_id", "origin_source_revision",
        "source_generation_sha256", "mission_sha256", "content_sha256", "base_sha256",
        "origin_record_sha256", "state"}
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_pairs)
        if (type(value) is not dict or set(value) != {"schema", "records"}
                or type(value["schema"]) is not int or value["schema"] != 1
                or type(value["records"]) is not list
                or len(value["records"]) > _OBSIDIAN_ORIGIN_HISTORY_MAX_RECORDS
                or _canonical(value) != raw):
            return None
        seen: set[str] = set()
        for row in value["records"]:
            row_fields = {"record_id", "origin", "proposal", "approval", "result",
                          "completed_at", "record_sha256"}
            if (type(row) is not dict or set(row) not in (
                    row_fields, row_fields | {"phase"}, row_fields | {"phase", "attempts"})
                    or not _OPAQUE.fullmatch(row.get("record_id", ""))
                    or row["record_id"] in seen or type(row["origin"]) is not dict
                    or ("phase" in row and row["phase"] not in {"reserved", "completed"})
                    or set(row["origin"]) != expected_origin
                    or type(row["proposal"]) is not dict or type(row["approval"]) is not dict
                    or type(row["result"]) is not dict
                    or ("attempts" in row and (type(row["attempts"]) is not list
                        or not 1 <= len(row["attempts"]) <= 8
                        or any(type(attempt) is not dict
                               or set(attempt) != {"proposal", "approval"}
                               or type(attempt["proposal"]) is not dict
                               or type(attempt["approval"]) is not dict
                               for attempt in row["attempts"])))
                    or type(row["completed_at"]) not in (int, float)
                    or not math.isfinite(row["completed_at"])):
                return None
            seen.add(row["record_id"])
            if any(key.casefold() in {"markdown", "private_text", "body"}
                   for section in (row["origin"], row["proposal"], row["approval"], row["result"])
                   for key in section):
                return None
            body = {key: item for key, item in row.items() if key != "record_sha256"}
            if hashlib.sha256(_canonical(body)).hexdigest() != row["record_sha256"]:
                return None
            origin = row["origin"]
            if (origin["state"] != "private-draft"
                    or origin["origin_record_sha256"] != _obsidian_origin_record_digest(origin)
                    or not all(_HASH.fullmatch(origin.get(key, "") or "") for key in (
                        "owner_subject_sha256", "registration_sha256", "source_generation_sha256",
                        "content_sha256", "origin_record_sha256"))):
                return None
        return [dict(row) for row in value["records"]]
    except Exception:
        return None


def _reserved_origin_tombstone(row: Mapping[str, Any]) -> dict[str, Any] | None:
    """Project the exact future tombstone reserved by an Obsidian history row."""
    # Before phase-tagged reservations existed, every root-history row was
    # written only after a completed promotion. Preserve that exact legacy
    # record hash while treating it as completed retained data.
    phase = row.get("phase") if isinstance(row, Mapping) else None
    if (not isinstance(row, Mapping) or phase not in {None, "reserved", "completed"}
            or type(row.get("origin")) is not dict or type(row.get("result")) is not dict
            or not _OPAQUE.fullmatch(row.get("record_id", ""))):
        return None
    origin, result = row["origin"], row["result"]
    if (not all(isinstance(result.get(name), str) for name in (
            "destination", "note_id", "title", "content_sha256"))
            or not _HASH.fullmatch(result.get("content_sha256", "") or "")
            or type(row.get("completed_at")) not in (int, float)
            or not math.isfinite(row["completed_at"])):
        return None
    completed_body = {key: value for key, value in row.items()
                      if key != "record_sha256"}
    if phase is not None:
        completed_body["phase"] = "completed"
    completed_sha = hashlib.sha256(_canonical(completed_body)).hexdigest()
    tombstone_body = {
        "owner_subject_sha256": origin["owner_subject_sha256"],
        "draft_id": origin["draft_id"],
        "origin_record_sha256": origin["origin_record_sha256"],
        "history_record_id": row["record_id"],
        "history_record_sha256": completed_sha,
        "destination": result["destination"], "note_id": result["note_id"],
        "content_sha256": result["content_sha256"], "completed_at": row["completed_at"],
    }
    return {**tombstone_body,
            "completed_record_sha256": hashlib.sha256(_canonical(tombstone_body)).hexdigest()}


def _obsidian_archive_proposal(proposal: Mapping[str, Any]) -> dict[str, Any]:
    return {key: proposal[key] for key in (
        "proposal_id", "proposal_sha256", "owner_subject_sha256", "owner_turn_handle",
        "draft_id", "content_sha256", "destination", "expected_base_sha256",
        "disposition", "observed_call_handle", "tool_call_id", "arguments_sha256",
        "source_generation_sha256", "read_delivery_receipt_id",
        "read_delivery_sha256", "read_delivery_output_sha256", "origin_record_sha256")}


def _obsidian_archive_approval(*, pending_id: str, review_sha256: str,
                               owner: Any, source_generation_sha256: str,
                               call: Mapping[str, Any]) -> dict[str, Any]:
    return {"pending_id": pending_id, "review_sha256": review_sha256,
        "owner_subject_sha256": owner.owner_subject_sha256,
        "owner_turn_handle": owner.owner_turn_handle,
        "source_generation_sha256": source_generation_sha256,
        "observed_call_handle": call["handle"],
        "tool_call_id": call["tool_call_id"],
        "arguments_sha256": call["arguments_sha256"]}


def _obsidian_archive_row(*, record_id: str, phase: str, origin: Mapping[str, Any],
                          proposal: Mapping[str, Any], approval: Mapping[str, Any],
                          result: Mapping[str, Any], completed_at: float,
                          attempts: list[dict[str, Any]]) -> dict[str, Any]:
    body = {"record_id": record_id, "phase": phase, "origin": dict(origin),
        "proposal": dict(proposal), "approval": dict(approval), "result": dict(result),
        "completed_at": completed_at, "attempts": [dict(item) for item in attempts]}
    return {**body, "record_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


def _load_root_obsidian_history() -> list[dict[str, Any]]:
    raw = _read_root_obsidian_history_bytes()
    if raw is None:
        return []
    records = _obsidian_history_from_bytes(raw)
    if records is None:
        raise ValueError("root Obsidian origin history is malformed")
    return records


def _load_root_obsidian_origin_snapshot() -> dict[tuple[str, str], dict[str, Any]]:
    """Load retained provenance as data; this never restores a live call grant."""
    raw = _read_root_obsidian_origin_bytes()
    if raw is None:
        return {}
    origins = _obsidian_origin_snapshot_from_bytes(raw)
    if origins is None:
        raise ValueError("root Obsidian origin journal is malformed")
    return origins


def _load_root_obsidian_origin_state() -> tuple[
        dict[tuple[str, str], dict[str, Any]], dict[tuple[str, str], dict[str, Any]]]:
    raw = _read_root_obsidian_origin_bytes()
    if raw is None:
        return {}, {}
    state = _obsidian_origin_state_from_bytes(raw)
    if state is None:
        raise ValueError("root Obsidian origin journal is malformed")
    return state


def _native_activity_snapshot_from_bytes(raw: bytes) -> list[dict[str, Any]] | None:
    """Validate the exact small root-owned child activity snapshot."""
    if not isinstance(raw, bytes) or not 1 <= len(raw) <= _NATIVE_ACTIVITY_MAX_BYTES:
        return None
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_json_pairs)
        if (type(value) is not dict or set(value) != {"schema", "instances"}
                or type(value["schema"]) is not int or value["schema"] not in {1, 2}
                or type(value["instances"]) is not list
                or len(value["instances"]) > _NATIVE_ACTIVITY_MAX_INSTANCES
                or json.dumps(value, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False).encode("utf-8") != raw):
            return None
        seen: set[str] = set()
        team_keys: dict[str, tuple[Any, ...]] = {}
        binding_keys: dict[tuple[str, str], str] = {}
        relation_dedupes: set[str] = set()
        relation_bindings: set[str] = set()
        fields = {"execution_key", "display_alias", "owner_subject_sha256", "mission_id",
            "mission_revision", "gateway_turn_id", "profile_id", "source_revision",
            "source_generation_sha256", "source_manifest_sha256", "core_generation",
            "core_source_generation", "child_lineage_sha256", "parent_lineage_sha256",
            "created_at", "updated_at", "tool_count_total", "seen_event_ids", "status", "events"}
        team_lineage_fields = {"team_execution_key", "binding_id_sha256", "team_id",
            "team_source_revision", "catalog_sha256", "bundle_generation_sha256",
            "bundle_member_sha256", "selected_expert_ids", "binding_deadline_at",
            "admission_deadline_at"}
        team_relation_fields = {"relation_key", "dedupe_sha256", "binding_id_sha256",
            "team_execution_key", "sender_execution_key", "recipient_execution_key",
            "sender_profile_id", "recipient_profile_id", "sender_completion_sha256",
            "recipient_completion_sha256", "team_message_sha256", "excerpt_sha256",
            "recipient_request_sha256", "sender_response_sha256", "recipient_response_sha256",
            "sender_text_sha256", "recipient_text_sha256", "sender_source_generation_sha256",
            "recipient_source_generation_sha256", "event_at"}
        if value["schema"] == 2:
            fields = fields | {"team_lineage", "team_relation", "history_partial"}
        event_fields = {"event_id", "kind", "status", "at", "duration_ms", "tool_count"}
        for row in value["instances"]:
            if (type(row) is not dict or set(row) != fields
                    or not _OPAQUE.fullmatch(row.get("execution_key", ""))
                    or row["execution_key"] in seen
                    or not isinstance(row["display_alias"], str)
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9 .·_-]{1,48}", row["display_alias"]) is None
                    or not all(_HASH.fullmatch(row.get(name, "")) for name in (
                        "owner_subject_sha256", "source_generation_sha256", "source_manifest_sha256",
                        "core_generation", "core_source_generation", "child_lineage_sha256",
                        "parent_lineage_sha256"))
                    or not isinstance(row["profile_id"], str) or not _ID.fullmatch(row["profile_id"])
                    or not isinstance(row["source_revision"], str)
                    or not 1 <= len(row["source_revision"]) <= 128
                    or not isinstance(row["gateway_turn_id"], str)
                    or not _ID.fullmatch(row["gateway_turn_id"])
                    or (row["mission_id"] is not None
                        and (not isinstance(row["mission_id"], str) or not _ID.fullmatch(row["mission_id"])))
                    or (row["mission_revision"] is not None
                        and (type(row["mission_revision"]) is not int or row["mission_revision"] < 1))
                    or ((row["mission_id"] is None) != (row["mission_revision"] is None))
                    or any(type(row[name]) not in (int, float) or not math.isfinite(row[name])
                           for name in ("created_at", "updated_at"))
                    or type(row["tool_count_total"]) is not int
                    or not 0 <= row["tool_count_total"] <= 1_000_000
                    or type(row["seen_event_ids"]) is not list
                    or len(row["seen_event_ids"]) > _NATIVE_ACTIVITY_MAX_DEDUP_IDS_PER_INSTANCE
                    or len(set(row["seen_event_ids"])) != len(row["seen_event_ids"])
                    or any(not isinstance(item, str) or not _HASH.fullmatch(item)
                           for item in row["seen_event_ids"])
                    or row["status"] not in {"admitted", "running", "responded", "completed", "unknown"}
                    or type(row["events"]) is not list
                    or len(row["events"]) > _NATIVE_ACTIVITY_MAX_EVENTS_PER_INSTANCE):
                return None
            seen.add(row["execution_key"])
            event_ids: set[str] = set()
            for event in row["events"]:
                if (type(event) is not dict or set(event) != event_fields
                        or not _HASH.fullmatch(event.get("event_id", ""))
                        or event["event_id"] in event_ids
                        or event["kind"] not in {"admitted", "attempt", "response", "tool_call", "completed"}
                        or event["status"] not in {"accepted", "started", "completed", "incomplete", "observed"}
                        or type(event["at"]) not in (int, float) or not math.isfinite(event["at"])
                        or (event["duration_ms"] is not None
                            and (type(event["duration_ms"]) is not int or event["duration_ms"] < 0))
                        or type(event["tool_count"]) is not int or not 0 <= event["tool_count"] <= 128):
                    return None
                event_ids.add(event["event_id"])
            if not event_ids.issubset(set(row["seen_event_ids"])):
                return None
            if value["schema"] == 2:
                lineage = row["team_lineage"]
                if lineage is not None and (
                        type(lineage) is not dict or set(lineage) != team_lineage_fields
                        or not _OPAQUE.fullmatch(lineage.get("team_execution_key", ""))
                        or not _HASH.fullmatch(lineage.get("binding_id_sha256", ""))
                        or not isinstance(lineage.get("team_id"), str)
                        or not _ID.fullmatch(lineage["team_id"])
                        or not isinstance(lineage.get("team_source_revision"), str)
                        or not 1 <= len(lineage["team_source_revision"]) <= 128
                        or not all(_HASH.fullmatch(lineage.get(name, "")) for name in (
                            "catalog_sha256", "bundle_generation_sha256", "bundle_member_sha256"))
                        or type(lineage.get("selected_expert_ids")) is not list
                        or len(lineage["selected_expert_ids"]) != 2
                        or len(set(lineage["selected_expert_ids"])) != 2
                        or any(not isinstance(item, str) or not _ID.fullmatch(item)
                               for item in lineage["selected_expert_ids"])
                        or row["profile_id"] not in lineage["selected_expert_ids"]
                        or row["mission_id"] is None or row["mission_revision"] is None
                        or any(type(lineage.get(name)) not in (int, float)
                               or not math.isfinite(lineage[name])
                               or not row["created_at"] <= lineage[name] <= row["created_at"] + 600.0
                               for name in ("binding_deadline_at", "admission_deadline_at"))):
                    return None
                relation = row["team_relation"]
                if relation is not None and (
                        type(relation) is not dict or set(relation) != team_relation_fields
                        or not _OPAQUE.fullmatch(relation.get("relation_key", ""))
                        or not all(_HASH.fullmatch(relation.get(name, "")) for name in (
                            "dedupe_sha256", "binding_id_sha256", "sender_completion_sha256",
                            "recipient_completion_sha256", "team_message_sha256", "excerpt_sha256",
                            "recipient_request_sha256", "sender_response_sha256",
                            "recipient_response_sha256", "sender_text_sha256", "recipient_text_sha256",
                            "sender_source_generation_sha256", "recipient_source_generation_sha256"))
                        or not _OPAQUE.fullmatch(relation.get("team_execution_key", ""))
                        or not all(_OPAQUE.fullmatch(relation.get(name, "")) for name in (
                            "sender_execution_key", "recipient_execution_key"))
                        or relation["sender_execution_key"] == relation["recipient_execution_key"]
                        or not all(isinstance(relation.get(name), str) and _ID.fullmatch(relation[name])
                                   for name in ("sender_profile_id", "recipient_profile_id"))
                        or relation["sender_profile_id"] == relation["recipient_profile_id"]
                        or type(relation.get("event_at")) not in (int, float)
                        or not math.isfinite(relation["event_at"])
                        or lineage is None
                        or relation["binding_id_sha256"] != lineage["binding_id_sha256"]
                        or relation["team_execution_key"] != lineage["team_execution_key"]
                        or not row["created_at"] <= relation["event_at"] <= row["updated_at"]):
                    return None
                if relation is not None and (row["execution_key"] != relation["recipient_execution_key"]
                        or row["profile_id"] != relation["recipient_profile_id"]):
                    return None
                if type(row["history_partial"]) is not bool:
                    return None
                if lineage is not None:
                    owner_binding = (row["owner_subject_sha256"], lineage["binding_id_sha256"])
                    fingerprint = (row["owner_subject_sha256"], lineage["team_id"],
                        lineage["team_source_revision"],
                        lineage["catalog_sha256"], lineage["bundle_generation_sha256"],
                        lineage["bundle_member_sha256"], tuple(lineage["selected_expert_ids"]),
                        row["mission_id"], row["mission_revision"], row["gateway_turn_id"])
                    old = team_keys.setdefault(lineage["team_execution_key"], fingerprint)
                    if old != fingerprint or binding_keys.setdefault(
                            owner_binding, lineage["team_execution_key"]) != lineage["team_execution_key"]:
                        return None
                if relation is not None:
                    if (relation["dedupe_sha256"] in relation_dedupes
                            or relation["binding_id_sha256"] in relation_bindings):
                        return None
                    relation_dedupes.add(relation["dedupe_sha256"])
                    relation_bindings.add(relation["binding_id_sha256"])
        rows_by_execution = {row["execution_key"]: row for row in value["instances"]}
        for recipient in value["instances"]:
            relation = recipient.get("team_relation")
            if relation is None:
                continue
            sender = rows_by_execution.get(relation["sender_execution_key"])
            if sender is None:
                continue  # bounded eviction may omit an endpoint; read marks coverage partial.
            sender_team = sender.get("team_lineage")
            recipient_team = recipient.get("team_lineage")
            if (sender.get("status") != "completed"
                    or sender.get("owner_subject_sha256") != recipient.get("owner_subject_sha256")
                    or sender.get("gateway_turn_id") != recipient.get("gateway_turn_id")
                    or sender.get("mission_id") != recipient.get("mission_id")
                    or sender.get("mission_revision") != recipient.get("mission_revision")
                    or sender.get("profile_id") != relation["sender_profile_id"]
                    or sender.get("source_generation_sha256")
                        != relation["sender_source_generation_sha256"]
                    or recipient.get("source_generation_sha256")
                        != relation["recipient_source_generation_sha256"]
                    or not isinstance(sender_team, dict) or not isinstance(recipient_team, dict)
                    or sender_team.get("team_execution_key") != relation["team_execution_key"]
                    or recipient_team.get("team_execution_key") != relation["team_execution_key"]
                    or sender_team.get("binding_id_sha256") != relation["binding_id_sha256"]
                    or recipient_team.get("binding_id_sha256") != relation["binding_id_sha256"]):
                return None
        return value["instances"]
    except Exception:
        return None
_RESOURCES_DELEGATE_REGISTRATION_SEAL = object()
_RESOURCES_DELEGATE_SOURCE_SHA256 = "47c3eb1ec9e21d15d9f86f184dad3e2020878e6d8b3de2edf4a63568f141aecd"
_RESOURCES_DELEGATE_SCHEMA_SHA256 = "9325cea421e122395475b0ba0d0517cb4aa4c16c3d4a14c5145f9fcc3f957f33"
_MISSION_AUTHORIZATION_SEAL = object()
_NATIVE_CHILD_AUTHORIZATION_SEAL = object()
_MASTER_PLANNING_COMPLETION_SEAL = object()
_MASTER_REVIEW_COMPLETION_SEAL = object()
_LIFECYCLE_STARTUP_COHORT_SEAL = object()
_LIFECYCLE_STARTUP_CONTEXT_SEAL = object()
_LIFECYCLE_STARTUP_COMPLETION_SEAL = object()
_ROOT_LIFECYCLE_REGISTRY_SEAL = object()
_LIFECYCLE_STARTUP_PROMPT_PREFIX = "Reply with exactly JARVIS-STARTUP-"
_LIFECYCLE_STARTUP_PROMPT_SUFFIX = ". Do not use tools."
_LIFECYCLE_STARTUP_RESPONSE_PREFIX = "JARVIS-STARTUP-"


@dataclass(frozen=True, slots=True)
class RootLifecycleStartupCohort:
    """Root-process cohort identity used only to enroll one private startup probe."""

    transaction_id: str
    starting_journal_sha256: str
    cohort_sha256: str
    core_generation: str
    old_adapter_generation: str
    new_adapter_generation: str
    core_source_generation: str
    generation_a1_sha256: str
    js_sha256: str
    rs_sha256: str
    u1_sha256: str
    l1_sha256: str
    primary_source_sha256: str
    active_soul_sha256: str
    native_inventory_sha256: str
    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_ticks: str
    boot_id: str
    invocation_id: str
    provider: str
    api_mode: str
    base_url: str
    model: str
    account_fingerprint: str
    issued_monotonic: float
    deadline_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def is_root_selected(self) -> bool:
        try:
            return bool(
                type(self) is RootLifecycleStartupCohort
                and self._seal is _LIFECYCLE_STARTUP_COHORT_SEAL
                and isinstance(self.transaction_id, str) and _ID.fullmatch(self.transaction_id)
                and all(_HASH.fullmatch(getattr(self, name) or "") for name in (
                    "starting_journal_sha256", "cohort_sha256", "core_generation", "old_adapter_generation",
                    "new_adapter_generation", "core_source_generation", "generation_a1_sha256",
                    "js_sha256", "rs_sha256", "u1_sha256", "l1_sha256",
                    "primary_source_sha256", "active_soul_sha256",
                    "native_inventory_sha256", "account_fingerprint"))
                and (type(self.peer_pid) is int and self.peer_pid > 1
                     and type(self.peer_uid) is int and self.peer_uid > 0
                     and type(self.peer_gid) is int and self.peer_gid >= 0
                     and isinstance(self.peer_start_ticks, str) and self.peer_start_ticks.isdecimal()
                     and isinstance(self.boot_id, str) and re.fullmatch(r"[0-9a-fA-F-]{32,36}", self.boot_id)
                     and isinstance(self.invocation_id, str) and re.fullmatch(r"[0-9a-fA-F-]{32,36}", self.invocation_id))
                and self.provider == _CODEX_PROVIDER and self.api_mode == _CODEX_MODE
                and self.base_url == _CODEX_ENDPOINT
                and isinstance(self.model, str) and _ID.fullmatch(self.model)
                and type(self.issued_monotonic) in {int, float}
                and type(self.deadline_monotonic) in {int, float}
                and self.issued_monotonic <= time.monotonic() < self.deadline_monotonic
                and self.deadline_monotonic - self.issued_monotonic <= 120.0)
        except Exception:
            return False


def make_root_lifecycle_startup_cohort(**values: Any) -> RootLifecycleStartupCohort:
    """Construct the private enrollment input from CoreRuntime's guarded cohort."""
    required = {
        "transaction_id", "starting_journal_sha256", "cohort_sha256", "core_generation",
        "old_adapter_generation", "new_adapter_generation", "core_source_generation",
        "generation_a1_sha256", "js_sha256", "rs_sha256", "u1_sha256", "l1_sha256", "primary_source_sha256",
        "active_soul_sha256", "native_inventory_sha256", "peer_pid", "peer_uid", "peer_gid",
        "peer_start_ticks", "boot_id", "invocation_id", "provider", "api_mode", "base_url",
        "model", "account_fingerprint", "issued_monotonic", "deadline_monotonic",
    }
    if set(values) != required:
        raise CoreNativeObservationUnavailable("startup cohort has an unknown schema")
    cohort = RootLifecycleStartupCohort(**values, _seal=_LIFECYCLE_STARTUP_COHORT_SEAL)
    if not cohort.is_root_selected():
        raise CoreNativeObservationUnavailable("guarded starting cohort is stale or malformed")
    return cohort


@dataclass(frozen=True, slots=True)
class LifecycleStartupProbeContext:
    probe_handle: str
    probe_id: str
    session_id: str
    nonce: str
    deadline_monotonic: float
    cohort_sha256: str
    core_generation: str
    core_source_generation: str
    generation_a1_sha256: str
    js_sha256: str
    rs_sha256: str
    u1_sha256: str
    l1_sha256: str
    primary_source_sha256: str
    active_soul_sha256: str
    native_inventory_sha256: str
    provider: str
    api_mode: str
    base_url: str
    model: str
    account_fingerprint: str
    _seal: object = field(repr=False, compare=False)
    _terminal: list[dict[str, str]] = field(default_factory=list, repr=False, compare=False)

    def is_root_issued(self) -> bool:
        return bool(type(self) is LifecycleStartupProbeContext
            and self._seal is _LIFECYCLE_STARTUP_CONTEXT_SEAL
            and _OPAQUE.fullmatch(self.probe_handle or "")
            and _ID.fullmatch(self.probe_id or "") and _ID.fullmatch(self.session_id or "")
            and re.fullmatch(r"[0-9a-f]{32}", self.nonce or "")
            and _HASH.fullmatch(self.cohort_sha256 or "")
            and _HASH.fullmatch(self.core_generation or "")
            and _HASH.fullmatch(self.core_source_generation or "")
            and _HASH.fullmatch(self.generation_a1_sha256 or "")
            and _HASH.fullmatch(self.js_sha256 or "")
            and _HASH.fullmatch(self.rs_sha256 or "")
            and _HASH.fullmatch(self.u1_sha256 or "")
            and _HASH.fullmatch(self.l1_sha256 or "")
            and _HASH.fullmatch(self.primary_source_sha256 or "")
            and _HASH.fullmatch(self.active_soul_sha256 or "")
            and _HASH.fullmatch(self.native_inventory_sha256 or "")
            and self.provider == _CODEX_PROVIDER and self.api_mode == _CODEX_MODE
            and self.base_url == _CODEX_ENDPOINT and _ID.fullmatch(self.model or "")
            and _HASH.fullmatch(self.account_fingerprint or "")
            and type(self.deadline_monotonic) in {int, float}
            and time.monotonic() < self.deadline_monotonic)


@dataclass(frozen=True, slots=True)
class CoreVerifiedLifecycleStartupCompletion:
    """Single-use Root seal for one actual native/provider startup completion."""

    schema: int
    purpose: str
    probe_handle: str
    completion_handle: str
    transaction_id: str
    starting_journal_sha256: str
    cohort_sha256: str
    core_generation: str
    old_adapter_generation: str
    new_adapter_generation: str
    core_source_generation: str
    generation_a1_sha256: str
    js_sha256: str
    rs_sha256: str
    u1_sha256: str
    l1_sha256: str
    primary_source_sha256: str
    active_soul_sha256: str
    native_inventory_sha256: str
    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_ticks: str
    boot_id: str
    invocation_id: str
    probe_id: str
    session_id: str
    turn_id: str
    api_request_id: str
    provider_request_sha256: str
    provider_response_sha256: str
    provider_response_text_sha256: str
    native_response_sha256: str
    prompt_sha256: str
    provider: str
    api_mode: str
    base_url: str
    model: str
    account_fingerprint: str
    tools_sha256: str
    deadline_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def is_root_verified(self) -> bool:
        return bool(type(self) is CoreVerifiedLifecycleStartupCompletion
                and self._seal is _LIFECYCLE_STARTUP_COMPLETION_SEAL
            and type(self.schema) is int and self.schema == 1
            and self.purpose == "lifecycle-startup"
            and _OPAQUE.fullmatch(self.probe_handle or "")
            and _OPAQUE.fullmatch(self.completion_handle or "")
            and _ID.fullmatch(self.transaction_id or "")
            and all(_HASH.fullmatch(getattr(self, name) or "") for name in (
                "starting_journal_sha256", "cohort_sha256", "core_generation", "old_adapter_generation",
                "new_adapter_generation", "core_source_generation", "generation_a1_sha256",
                "js_sha256", "rs_sha256", "u1_sha256", "l1_sha256",
                "primary_source_sha256", "active_soul_sha256",
                "native_inventory_sha256", "provider_request_sha256", "provider_response_sha256",
                "provider_response_text_sha256", "native_response_sha256", "prompt_sha256",
                "account_fingerprint", "tools_sha256"))
            and type(self.peer_pid) is int and self.peer_pid > 1
            and type(self.peer_uid) is int and self.peer_uid > 0
            and type(self.peer_gid) is int and self.peer_gid >= 0
            and isinstance(self.peer_start_ticks, str) and self.peer_start_ticks.isdecimal()
            and isinstance(self.boot_id, str) and re.fullmatch(r"[0-9a-fA-F-]{32,36}", self.boot_id)
            and isinstance(self.invocation_id, str) and re.fullmatch(r"[0-9a-fA-F-]{32,36}", self.invocation_id)
            and self.provider == _CODEX_PROVIDER and self.api_mode == _CODEX_MODE
            and self.base_url == _CODEX_ENDPOINT
            and all(_ID.fullmatch(getattr(self, name) or "") for name in (
                "probe_id", "session_id", "turn_id", "api_request_id", "model"))
            and type(self.deadline_monotonic) in {int, float}
            and time.monotonic() < self.deadline_monotonic)
_SELECTED_SOURCE_DELIVERY_SEAL = object()


@dataclass(frozen=True, slots=True)
class CoreNativeResourcesDelegateRegistration:
    """Fixed registration descriptor consumed by the inspector's source verifier.

    This is an expected-value descriptor, not runtime evidence by itself. The
    inspector must independently verify the package-relative bytes and the
    Hermes process must expose the tool in the observed provider request.
    """

    schema: int
    name: str
    toolset: str
    package_relative_path: str
    schema_sha256: str
    source_sha256: str
    _seal: object


def current_resources_delegate_registration() -> CoreNativeResourcesDelegateRegistration:
    """Return the fixed Resources tool identity and expected source digests."""
    return CoreNativeResourcesDelegateRegistration(
        schema=1,
        name="resources_delegate",
        toolset="resources_internal",
        package_relative_path="components/resources_internal_dispatch.py",
        schema_sha256=_RESOURCES_DELEGATE_SCHEMA_SHA256,
        source_sha256=_RESOURCES_DELEGATE_SOURCE_SHA256,
        _seal=_RESOURCES_DELEGATE_REGISTRATION_SEAL,
    )


class CoreNativeObservationUnavailable(PermissionError):
    """Current protected core observation could not be registered or consumed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mission_binding_from_wire(value: Any) -> MissionBinding | None:
    if value is None:
        return None
    try:
        binding = MissionBinding.from_wire(value)
        if type(binding) is not MissionBinding or binding.to_wire() != value:
            raise ValueError
        return binding
    except Exception:
        raise CoreNativeObservationUnavailable("mission binding payload is malformed") from None


def _require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise CoreNativeObservationUnavailable(f"{label} is malformed")
    return value


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CoreNativeObservationUnavailable(f"{label} is malformed")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("invalid JSON number")


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        block = conn.recv(size - len(chunks))
        if not block:
            raise OSError("observer socket closed during a frame")
        chunks.extend(block)
    return bytes(chunks)


def _read_frame(conn: socket.socket) -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(conn, 4))[0]
    if not 2 <= size <= MAX_FRAME:
        raise ValueError("observer frame exceeded its bound")
    value = json.loads(_read_exact(conn, size).decode("utf-8", errors="strict"),
                       object_pairs_hook=_unique_pairs,
                       parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("observer frame must be an object")
    return value


def _obsidian_startup_facts_sha256(binding: dict[str, Any]) -> str:
    """Digest stable startup custody facts; binding leases themselves are not durable authority."""
    facts = {
        "peer": list(binding["peer"]),
        "owner_subject_sha256": binding["owner_subject_sha256"],
        "registration_sha256": binding["registration_sha256"],
        "core_generation": binding["core_generation"],
        "core_source_generation": binding["core_source_generation"],
        "core_pid": binding["core_pid"],
        "core_start_ticks": binding["core_start_ticks"],
    }
    return hashlib.sha256(_canonical(facts)).hexdigest()


@dataclass(frozen=True, slots=True)
class OwnerTurnHandle:
    """Opaque root handle for an accepted owner turn; contains no JWT or prompt."""

    handle: str
    core_generation: str
    session_id: str
    conversation_id: str
    gateway_turn_id: str
    prompt_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _ID.fullmatch(self.session_id or "")
                or not _ID.fullmatch(self.conversation_id or "")
                or not _ID.fullmatch(self.gateway_turn_id or "")
                or not _HASH.fullmatch(self.prompt_sha256 or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 600.0):
            raise CoreNativeObservationUnavailable("root owner-turn handle is malformed")


@dataclass(frozen=True, slots=True)
class ObservedProviderAttempt:
    """A short-lived attempt handle returned by the protected root registry."""

    handle: str
    owner_turn_handle: str
    expires_monotonic: float
    capture_child_output: bool = False

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 600.0
                or type(self.capture_child_output) is not bool):
            raise CoreNativeObservationUnavailable("root provider-attempt handle is malformed")


@dataclass(frozen=True, slots=True)
class RootObservedExpertCompletion:
    """Exact provider text and source identity retained after a real Expert completion."""

    completion_handle: str
    owner_turn_handle: str
    child_session_id: str
    profile_id: str
    source_revision: str
    source_generation_sha256: str
    source_manifest_sha256: str
    goal_sha256: str
    provider_attempt_handle: str
    request_sha256: str
    response_sha256: str
    response_text_sha256: str
    response_text: str
    expires_monotonic: float
    _seal: object
    team_message_handle: str | None = None
    team_lineage: dict[str, str] | None = None

    def __post_init__(self) -> None:
        if (self._seal is not _EXPERT_COMPLETION_SEAL
                or not _OPAQUE.fullmatch(self.completion_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.child_session_id or "")
                or not _ID.fullmatch(self.profile_id or "")
                or not _OPAQUE.fullmatch(self.provider_attempt_handle or "")
                or not all(_HASH.fullmatch(value or "") for value in (
                    self.source_generation_sha256, self.source_manifest_sha256,
                    self.goal_sha256, self.request_sha256, self.response_sha256,
                    self.response_text_sha256))
                or not isinstance(self.source_revision, str) or not 1 <= len(self.source_revision) <= 128
                or not isinstance(self.response_text, str)
                or not 1 <= len(self.response_text.encode("utf-8", errors="strict")) <= 32 * 1024
                or hashlib.sha256(self.response_text.encode("utf-8", errors="strict")).hexdigest()
                    != self.response_text_sha256
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root Expert completion is malformed")
        if self.team_message_handle is not None and not _OPAQUE.fullmatch(self.team_message_handle):
            raise CoreNativeObservationUnavailable("root Team response lineage is malformed")
        if (self.team_message_handle is None) != (self.team_lineage is None):
            raise CoreNativeObservationUnavailable("root Team message and completion must arrive together")
        if self.team_lineage is not None:
            fields = {"sender_completion_handle", "sender_profile_id", "recipient_profile_id",
                "excerpt_sha256", "recipient_request_sha256", "recipient_response_sha256",
                "recipient_text_sha256", "recipient_completion_handle"}
            if (type(self.team_lineage) is not dict or set(self.team_lineage) != fields
                    or not all(_OPAQUE.fullmatch(self.team_lineage[key] or "") for key in (
                        "sender_completion_handle", "recipient_completion_handle"))
                    or not all(_ID.fullmatch(self.team_lineage[key] or "") for key in (
                        "sender_profile_id", "recipient_profile_id"))
                    or self.team_lineage["sender_profile_id"] == self.team_lineage["recipient_profile_id"]
                    or not all(_HASH.fullmatch(self.team_lineage[key] or "") for key in (
                        "excerpt_sha256", "recipient_request_sha256", "recipient_response_sha256",
                        "recipient_text_sha256"))
                    or self.team_message_handle is None):
                raise CoreNativeObservationUnavailable("root Team discussion edge is malformed")


_EXPERT_COMPLETION_SEAL = object()


@dataclass(frozen=True, slots=True)
class RootSelectedTeamBinding:
    """Short root-retained Team selection joined to one sealed mission decision."""

    schema: int
    binding_id: str
    owner_subject_sha256: str
    mission_id: str
    revision: int
    goal_sha256: str
    plan_sha256: str
    catalog_sha256: str
    team_id: str
    source_revision: str
    bundle_generation_sha256: str
    bundle_member_sha256: str
    ordered_member_ids: tuple[str, ...]
    selected_expert_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not _OPAQUE.fullmatch(self.binding_id or "")
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or not _ID.fullmatch(self.mission_id or "")
                or type(self.revision) is not int or self.revision < 1
                or not all(_HASH.fullmatch(item or "") for item in (
                    self.goal_sha256, self.plan_sha256, self.catalog_sha256,
                    self.bundle_generation_sha256, self.bundle_member_sha256))
                or not _ID.fullmatch(self.team_id or "")
                or not isinstance(self.source_revision, str) or not 1 <= len(self.source_revision) <= 128
                or not isinstance(self.ordered_member_ids, tuple) or not 1 <= len(self.ordered_member_ids) <= 32
                or any(not _ID.fullmatch(item or "") for item in self.ordered_member_ids)
                or len(set(self.ordered_member_ids)) != len(self.ordered_member_ids)
                or not isinstance(self.selected_expert_ids, tuple) or len(self.selected_expert_ids) != 2
                or len(set(self.selected_expert_ids)) != 2
                or any(item not in self.ordered_member_ids for item in self.selected_expert_ids)
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic) or not math.isfinite(self.expires_monotonic)
                or not self.issued_monotonic < self.expires_monotonic <= self.issued_monotonic + 600.0
                or self._seal is not _TEAM_BINDING_SEAL):
            raise CoreNativeObservationUnavailable("root Team selection binding is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": self.schema, "binding_id": self.binding_id,
            "owner_subject_sha256": self.owner_subject_sha256, "mission_id": self.mission_id,
            "revision": self.revision, "goal_sha256": self.goal_sha256,
            "plan_sha256": self.plan_sha256, "catalog_sha256": self.catalog_sha256,
            "team_id": self.team_id, "source_revision": self.source_revision,
            "bundle_generation_sha256": self.bundle_generation_sha256,
            "bundle_member_sha256": self.bundle_member_sha256,
            "ordered_member_ids": list(self.ordered_member_ids),
            "selected_expert_ids": list(self.selected_expert_ids),
            "issued_monotonic": self.issued_monotonic, "expires_monotonic": self.expires_monotonic}

    @classmethod
    def from_wire(cls, value: Any) -> "RootSelectedTeamBinding":
        fields = {"schema", "binding_id", "owner_subject_sha256", "mission_id", "revision",
            "goal_sha256", "plan_sha256", "catalog_sha256", "team_id", "source_revision",
            "bundle_generation_sha256", "bundle_member_sha256", "ordered_member_ids",
            "selected_expert_ids", "issued_monotonic", "expires_monotonic"}
        if type(value) is not dict or set(value) != fields:
            raise CoreNativeObservationUnavailable("root Team binding fields differ")
        try:
            binding = cls(**{**value, "ordered_member_ids": tuple(value["ordered_member_ids"]),
                "selected_expert_ids": tuple(value["selected_expert_ids"]),
                "_seal": _TEAM_BINDING_SEAL})
            if binding.expires_monotonic > time.monotonic() + 600.0:
                raise ValueError
            return binding
        except Exception:
            raise CoreNativeObservationUnavailable("root Team binding is malformed or stale") from None


@dataclass(frozen=True, slots=True)
class RootTeamMessageDelivery:
    """One-use exact sender excerpt admitted to a distinct recipient child."""

    message_handle: str
    binding_id: str
    sender_completion_handle: str
    sender_profile_id: str
    recipient_profile_id: str
    excerpt_sha256: str
    excerpt: str
    recipient_goal_sha256: str
    recipient_goal: str
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (self._seal is not _TEAM_MESSAGE_SEAL
                or not all(_OPAQUE.fullmatch(item or "") for item in (
                    self.message_handle, self.binding_id, self.sender_completion_handle))
                or not _ID.fullmatch(self.sender_profile_id or "")
                or not _ID.fullmatch(self.recipient_profile_id or "")
                or self.sender_profile_id == self.recipient_profile_id
                or not all(_HASH.fullmatch(item or "") for item in (
                    self.excerpt_sha256, self.recipient_goal_sha256))
                or not isinstance(self.excerpt, str) or not 1 <= len(self.excerpt.encode("utf-8")) <= 8192
                or hashlib.sha256(self.excerpt.encode("utf-8")).hexdigest() != self.excerpt_sha256
                or not isinstance(self.recipient_goal, str)
                or hashlib.sha256(self.recipient_goal.encode("utf-8")).hexdigest() != self.recipient_goal_sha256
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root Team message delivery is malformed")


_TEAM_BINDING_SEAL = object()
_TEAM_MESSAGE_SEAL = object()


@dataclass(frozen=True, slots=True)
class ObservedNativeToolCall:
    """Root-retained provider tool call, correlated with its live native attempt."""

    handle: str
    attempt_handle: str
    owner_turn_handle: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _OPAQUE.fullmatch(self.attempt_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.tool_call_id or "")
                or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root observed-tool handle is malformed")


_MASTER_READ_CALL_SEAL = object()
_OBSIDIAN_READ_TOOL_NAMES = frozenset({
    "obsidian_list_notes", "obsidian_search_notes", "obsidian_read_note",
    "obsidian_note_links", "obsidian_graph_snapshot", "obsidian_create_private_draft",
})
_OBSIDIAN_MASTER_READ_TOOL_NAMES = _OBSIDIAN_READ_TOOL_NAMES | {"obsidian_read_private_draft"}
_OBSIDIAN_TOOL_NAMES = _OBSIDIAN_MASTER_READ_TOOL_NAMES | {"obsidian_promote_reviewed_draft"}
_MASTER_READ_TOOL_NAMES = frozenset({
    "web_search", "web_extract", "skills_list", "skill_view",
}) | _OBSIDIAN_MASTER_READ_TOOL_NAMES


@dataclass(frozen=True, slots=True)
class RootVerifiedMasterReadCall:
    """Root classification of one exact current master/selected-child call."""

    observed_call_handle: str
    owner_turn_handle: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    source_generation_sha256: str
    mode: str
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.observed_call_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.tool_call_id or "")
                or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or not _HASH.fullmatch(self.source_generation_sha256 or "")
                or self.mode not in {"master_read", "master_effect", "expert_read"}
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + 30.0
                or self._seal is not _MASTER_READ_CALL_SEAL):
            raise CoreNativeObservationUnavailable("root native caller classification is malformed")

    def matches_call(self, observed_call: Any, *, tool_name: str,
                     arguments_sha256: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return (type(observed_call) is ObservedNativeToolCall
                and self._seal is _MASTER_READ_CALL_SEAL
                and now < self.expires_monotonic
                and self.observed_call_handle == observed_call.handle
                and self.owner_turn_handle == observed_call.owner_turn_handle
                and self.tool_call_id == observed_call.tool_call_id
                and self.tool_name == tool_name == observed_call.tool_name
                and self.arguments_sha256 == arguments_sha256 == observed_call.arguments_sha256)


@dataclass(frozen=True, slots=True)
class NativeSourceMember:
    """One exact source member in a root-selected Resources profile."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise CoreNativeObservationUnavailable("root source-member manifest is malformed")
        parts = PurePosixPath(self.path)
        if (not self.path or len(self.path) > 512
                or parts.is_absolute() or any(part in {"", ".", ".."} for part in parts.parts)
                or str(parts) != self.path or not _HASH.fullmatch(self.sha256 or "")
                or type(self.size) is not int or not 0 <= self.size <= 4 * 1024 * 1024):
            raise CoreNativeObservationUnavailable("root source-member manifest is malformed")


@dataclass(frozen=True, slots=True)
class RootSelectedOrchestratorDelegationPolicy:
    """Root-enrolled owner policy for Hermes' native inherited-tool delegation.

    This policy is distinct from the Resources profile manifest: the profile has
    no tool grants, and its empty ``profile_tool_names`` remains empty.  The
    policy caps tools at the configured native parent maximum. The observed
    provider request carries the effective current subset. Hermes still applies its own blocked,
    disabled, pause, depth, and lifecycle rules when it builds the child.
    """

    schema: int
    policy_handle: str
    policy_sha256: str
    core_generation: str
    core_source_generation: str
    owner_subject_sha256: str
    profile_id: str
    mode: str
    parent_tool_configuration_sha256: str
    configured_parent_tool_names: tuple[str, ...]
    resources_delegate_schema_sha256: str
    resources_delegate_source_sha256: str
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    additional_metered_budget: int
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not _OPAQUE.fullmatch(self.policy_handle or "")
                or not _HASH.fullmatch(self.policy_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.core_source_generation or "")
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or self.profile_id != "hermes"
                or self.mode != "native-parent-inheritance"
                or not _HASH.fullmatch(self.parent_tool_configuration_sha256 or "")
                or self.resources_delegate_schema_sha256 != _RESOURCES_DELEGATE_SCHEMA_SHA256
                or self.resources_delegate_source_sha256 != _RESOURCES_DELEGATE_SOURCE_SHA256
                or not isinstance(self.configured_parent_tool_names, tuple)
                or not self.configured_parent_tool_names or len(self.configured_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.configured_parent_tool_names)
                or len(set(self.configured_parent_tool_names)) != len(self.configured_parent_tool_names)
                or tuple(sorted(self.configured_parent_tool_names)) != self.configured_parent_tool_names
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or "delegate_task" not in self.configured_parent_tool_names
                or "resources_delegate" not in self.configured_parent_tool_names
                or type(self.additional_metered_budget) is not int
                or self.additional_metered_budget != 0
                or type(self.issued_monotonic) not in (float, int)
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.issued_monotonic > time.monotonic()
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic > self.issued_monotonic + 600.0
                or self._seal is not _NATIVE_INHERITANCE_POLICY_SEAL):
            raise CoreNativeObservationUnavailable("root native inheritance policy is malformed")


def _native_policy_digest_fields(policy: RootSelectedOrchestratorDelegationPolicy) -> dict[str, Any]:
    return {
        "schema": policy.schema,
        "policy_handle": policy.policy_handle,
        "core_generation": policy.core_generation,
        "core_source_generation": policy.core_source_generation,
        "owner_subject_sha256": policy.owner_subject_sha256,
        "profile_id": policy.profile_id,
        "mode": policy.mode,
        "parent_tool_configuration_sha256": policy.parent_tool_configuration_sha256,
        "configured_parent_tool_names": list(policy.configured_parent_tool_names),
        "resources_delegate_schema_sha256": policy.resources_delegate_schema_sha256,
        "resources_delegate_source_sha256": policy.resources_delegate_source_sha256,
        "allow_inherited_mcp": policy.allow_inherited_mcp,
        "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
        "additional_metered_budget": policy.additional_metered_budget,
        "issued_monotonic": policy.issued_monotonic,
        "expires_monotonic": policy.expires_monotonic,
    }


def _configuration_has_fixed_resources_delegate(configuration: Any) -> bool:
    registration = current_resources_delegate_registration()
    return (
        type(registration) is CoreNativeResourcesDelegateRegistration
        and registration._seal is _RESOURCES_DELEGATE_REGISTRATION_SEAL
        and getattr(configuration, "resources_delegate_name", None) == registration.name
        and getattr(configuration, "resources_delegate_toolset", None) == registration.toolset
        and getattr(configuration, "resources_delegate_schema_sha256", None) == registration.schema_sha256
        and getattr(configuration, "resources_delegate_source_sha256", None) == registration.source_sha256
    )


@dataclass(frozen=True, slots=True)
class RootSelectedInternalProfileDispatchClaim:
    """Closed, short-lived dispatch claim returned only over authenticated root IPC.

    Prompt bytes and member identities are revealed only after one-use consume to
    the same protected core process. This DTO is still not a serialized Hermes
    Agent or authority to widen its tool/privacy closure.
    """

    claim_handle: str
    owner_turn_handle: str
    gateway_turn_id: str
    owner_subject_sha256: str
    observed_call_handle: str
    core_generation: str
    core_source_generation: str
    generation_sha256: str
    session_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    account_fingerprint: str
    profile_id: str
    source_revision: str
    profile_manifest_sha256: str
    source_manifest: tuple[NativeSourceMember, ...]
    source_manifest_sha256: str
    prompt_bytes: bytes
    prompt_sha256: str
    prompt_revision: str
    evidence_class: str
    provider: str
    api_mode: str
    base_url: str
    additional_metered_budget: int
    parent_tool_names: tuple[str, ...]
    delegation_policy_handle: str
    delegation_policy_sha256: str
    parent_tool_configuration_sha256: str
    configured_parent_tool_names: tuple[str, ...]
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    mission_binding: MissionBinding | None
    profile_tool_names: tuple[str, ...]
    parent_privacy_grants: tuple[str, ...]
    profile_privacy_requirements: tuple[str, ...]
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (any(not _OPAQUE.fullmatch(value or "") for value in (
                    self.claim_handle, self.owner_turn_handle, self.observed_call_handle))
                or not _ID.fullmatch(self.gateway_turn_id or "")
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.core_source_generation or "")
                or not _HASH.fullmatch(self.generation_sha256 or "")
                or not _ID.fullmatch(self.session_id or "") or not _ID.fullmatch(self.turn_id or "")
                or not _ID.fullmatch(self.tool_call_id or "") or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or not _HASH.fullmatch(self.account_fingerprint or "")
                or not _ID.fullmatch(self.profile_id or "")
                or not _HASH.fullmatch(self.profile_manifest_sha256 or "")
                or not isinstance(self.source_revision, str) or not 1 <= len(self.source_revision) <= 128
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in self.source_revision)
                or not isinstance(self.source_manifest, tuple) or not self.source_manifest
                or len(self.source_manifest) > 512
                or any(type(row) is not NativeSourceMember for row in self.source_manifest)
                or len({row.path for row in self.source_manifest}) != len(self.source_manifest)
                or _hash([{"path": row.path, "sha256": row.sha256, "size": row.size}
                          for row in self.source_manifest]) != self.source_manifest_sha256
                or not isinstance(self.prompt_bytes, bytes) or not self.prompt_bytes
                or len(self.prompt_bytes) > 128 * 1024
                or hashlib.sha256(self.prompt_bytes).hexdigest() != self.prompt_sha256
                or not _ID.fullmatch(self.prompt_revision or "")
                or self.evidence_class != "protected-core-process-observation"
                or self.provider != _CODEX_PROVIDER or self.api_mode != _CODEX_MODE
                or self.base_url != _CODEX_ENDPOINT
                or type(self.additional_metered_budget) is not int
                or self.additional_metered_budget != 0
                or not isinstance(self.parent_tool_names, tuple)
                or not self.parent_tool_names or len(self.parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.parent_tool_names)
                or not _OPAQUE.fullmatch(self.delegation_policy_handle or "")
                or not _HASH.fullmatch(self.delegation_policy_sha256 or "")
                or not _HASH.fullmatch(self.parent_tool_configuration_sha256 or "")
                or not isinstance(self.configured_parent_tool_names, tuple)
                or not self.configured_parent_tool_names or len(self.configured_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.configured_parent_tool_names)
                or tuple(sorted(set(self.parent_tool_names))) != self.parent_tool_names
                or tuple(sorted(set(self.configured_parent_tool_names))) != self.configured_parent_tool_names
                or not set(self.parent_tool_names).issubset(self.configured_parent_tool_names)
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or (self.mission_binding is not None
                    and type(self.mission_binding) is not MissionBinding)
                or not isinstance(self.profile_tool_names, tuple)
                or len(self.profile_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.profile_tool_names)
                or not isinstance(self.parent_privacy_grants, tuple)
                or len(self.parent_privacy_grants) > 128
                or any(not _ID.fullmatch(item or "") for item in self.parent_privacy_grants)
                or not isinstance(self.profile_privacy_requirements, tuple)
                or self.profile_privacy_requirements
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")


@dataclass(frozen=True, slots=True)
class RootVerifiedMissionDispatchAuthorization:
    """Typed one-use result of the root's immediate persisted-approval recheck."""

    claim_handle: str
    mission_binding_sha256: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    source_profile_id: str
    canonical_arguments_sha256: str
    expires_monotonic: float
    _seal: object

    def matches_claim(self, claim: RootSelectedInternalProfileDispatchClaim,
                      canonical_arguments_sha256: str, *, now: float) -> bool:
        return bool(
            type(self) is RootVerifiedMissionDispatchAuthorization
            and self._seal is _MISSION_AUTHORIZATION_SEAL
            and type(claim) is RootSelectedInternalProfileDispatchClaim
            and claim.mission_binding is not None
            and self.claim_handle == claim.claim_handle
            and self.mission_binding_sha256 == _hash(claim.mission_binding.to_wire())
            and self.gateway_turn_id == claim.gateway_turn_id
            and self.owner_subject_sha256 == claim.owner_subject_sha256
            and self.core_generation == claim.core_generation
            and self.core_source_generation == claim.core_source_generation
            and self.source_profile_id == claim.mission_binding.source_profile_id == "hermes"
            and self.canonical_arguments_sha256 == canonical_arguments_sha256
            and self.canonical_arguments_sha256 == claim.arguments_sha256
            and _HASH.fullmatch(self.mission_binding_sha256 or "") is not None
            and type(self.expires_monotonic) in (int, float)
            and math.isfinite(float(self.expires_monotonic))
            and now < self.expires_monotonic <= min(claim.expires_monotonic, now + 30.0)
        )


@dataclass(frozen=True, slots=True)
class RootNativeSelectedSourceDelivery:
    """Exact selected source bytes delivered from root for a single child build."""

    source_handle: str
    profile_id: str
    source_revision: str
    generation_sha256: str
    source_manifest_sha256: str
    profile_manifest_sha256: str
    effective_prompt: bytes
    effective_prompt_sha256: str
    expires_monotonic: float
    _seal: object
    team_binding: RootSelectedTeamBinding | None = None

    @property
    def source_member_manifest_sha256(self) -> str:
        """Compatibility name used by native child authorization matching."""
        return self.source_manifest_sha256

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.source_handle or "")
                or not _ID.fullmatch(self.profile_id or "")
                or not isinstance(self.source_revision, str) or not self.source_revision
                or not all(_HASH.fullmatch(item or "") for item in (
                    self.generation_sha256, self.source_manifest_sha256,
                    self.profile_manifest_sha256, self.effective_prompt_sha256))
                or not isinstance(self.effective_prompt, bytes) or not self.effective_prompt
                or len(self.effective_prompt) > 128 * 1024
                or hashlib.sha256(self.effective_prompt).hexdigest() != self.effective_prompt_sha256
                or (self.team_binding is not None and (
                    type(self.team_binding) is not RootSelectedTeamBinding
                    or self._seal is not _SELECTED_SOURCE_DELIVERY_SEAL
                    or self.profile_id not in self.team_binding.selected_expert_ids
                    or self.generation_sha256 != self.team_binding.bundle_generation_sha256))
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + 30.0
                or self._seal is not _SELECTED_SOURCE_DELIVERY_SEAL):
            raise CoreNativeObservationUnavailable("root selected source delivery is malformed")


@dataclass(frozen=True, slots=True)
class RootVerifiedNativeChildAuthorization:
    """Short-lived root admission for one exact native child session."""

    owner_turn_handle: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    parent_session_id: str
    parent_turn_id: str
    child_session_id: str
    profile_id: str
    source_generation_sha256: str
    source_manifest_sha256: str
    prompt_sha256: str
    goal_sha256: str
    account_fingerprint: str
    mode: str
    allowed_tool_names: tuple[str, ...]
    tool_closure_sha256: str
    additional_metered_budget: int
    admission_handle: str
    expires_monotonic: float
    initial_owner_turn: bool
    _parent_agent: Any
    _child_agent: Any
    _source: Any
    _seal: object

    def matches_child(self, *, parent_agent: Any, child: Any, source: Any,
                      mode: Any, goal: str, now: float) -> bool:
        try:
            actual_names = tuple(sorted(getattr(child, "valid_tool_names")))
            actual_source = (
                getattr(source, "profile_id", getattr(source, "source_id", None)),
                getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None)),
                getattr(source, "source_member_manifest_sha256",
                        getattr(source, "profile_member_manifest_sha256", None)),
                getattr(source, "effective_prompt_sha256",
                        getattr(source, "profile_prompt_sha256", None)),
            )
            parent_route = tuple(getattr(parent_agent, key, None)
                                 for key in ("provider", "api_mode", "base_url", "model"))
            child_route = tuple(getattr(child, key, None)
                                for key in ("provider", "api_mode", "base_url", "model"))
        except (TypeError, AttributeError):
            return False
        fixed_names = frozenset(
            {"web_search", "web_extract", "skills_list", "skill_view"} | _OBSIDIAN_READ_TOOL_NAMES
            if getattr(mode, "value", None) == "expert-read-research" else set()
        )
        expected_names = tuple(self.allowed_tool_names)
        return bool(
            type(self) is RootVerifiedNativeChildAuthorization
            and self._seal is _NATIVE_CHILD_AUTHORIZATION_SEAL
            and self._parent_agent is parent_agent and self._child_agent is child
            and self._source is source
            and self.owner_turn_handle and self.gateway_turn_id
            and _HASH.fullmatch(self.owner_subject_sha256 or "")
            and _HASH.fullmatch(self.core_generation or "")
            and _HASH.fullmatch(self.core_source_generation or "")
            and self.parent_session_id == getattr(parent_agent, "session_id", None)
            and ((self.initial_owner_turn and self.parent_turn_id == "")
                 or (not self.initial_owner_turn
                     and self.parent_turn_id == getattr(parent_agent, "_current_turn_id", None)))
            and self.child_session_id == getattr(child, "session_id", None)
            and hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest() == self.goal_sha256
            and actual_source == (self.profile_id, self.source_generation_sha256,
                                  self.source_manifest_sha256, self.prompt_sha256)
            and tuple(sorted(expected_names)) == expected_names
            and set(expected_names).issubset(fixed_names)
            and actual_names == expected_names
            and type(self.initial_owner_turn) is bool
            and (not self.initial_owner_turn or (self.mode == "planner" and self.parent_turn_id == ""))
            and type(self.additional_metered_budget) is int
            and self.additional_metered_budget == 0
            and _hash(list(actual_names)) == self.tool_closure_sha256
            and parent_route == child_route
            and parent_route == (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT,
                                 getattr(parent_agent, "model", None))
            and _HASH.fullmatch(self.account_fingerprint or "")
            and _HASH.fullmatch(self.goal_sha256 or "")
            and type(self.expires_monotonic) in (int, float)
            and math.isfinite(float(self.expires_monotonic))
            and now < self.expires_monotonic <= now + 30.0
        )


_CURRENT_LIFECYCLE_STARTUP_PROBE: contextvars.ContextVar[LifecycleStartupProbeContext | None] = \
    contextvars.ContextVar("hermes_lifecycle_startup_probe", default=None)
_CURRENT_LIFECYCLE_STARTUP_IDENTITY: contextvars.ContextVar[str | None] = \
    contextvars.ContextVar("hermes_lifecycle_startup_identity", default=None)
_CURRENT_LIFECYCLE_STARTUP_INSTRUCTIONS_SHA256: contextvars.ContextVar[str | None] = \
    contextvars.ContextVar("hermes_lifecycle_startup_instructions_sha256", default=None)


@contextmanager
def lifecycle_startup_probe_scope(context: LifecycleStartupProbeContext, *, identity: str,
                                  expected_instructions: str):
    if type(context) is not LifecycleStartupProbeContext or not context.is_root_issued():
        raise CoreNativeObservationUnavailable("Root lifecycle probe context is required")
    if (not isinstance(identity, str) or not identity
            or not isinstance(expected_instructions, str) or not expected_instructions
            or identity not in expected_instructions):
        raise CoreNativeObservationUnavailable("loaded Jarvis primary identity is required")
    expected_sha256 = hashlib.sha256(expected_instructions.encode("utf-8", "strict")).hexdigest()
    token = _CURRENT_LIFECYCLE_STARTUP_PROBE.set(context)
    identity_token = _CURRENT_LIFECYCLE_STARTUP_IDENTITY.set(identity)
    instructions_token = _CURRENT_LIFECYCLE_STARTUP_INSTRUCTIONS_SHA256.set(expected_sha256)
    try:
        yield context
    finally:
        _CURRENT_LIFECYCLE_STARTUP_INSTRUCTIONS_SHA256.reset(instructions_token)
        _CURRENT_LIFECYCLE_STARTUP_IDENTITY.reset(identity_token)
        _CURRENT_LIFECYCLE_STARTUP_PROBE.reset(token)


def take_lifecycle_startup_terminal(context: LifecycleStartupProbeContext) -> dict[str, str]:
    if type(context) is not LifecycleStartupProbeContext or not context.is_root_issued():
        raise CoreNativeObservationUnavailable("Root lifecycle probe context is required")
    if len(context._terminal) != 1:
        raise CoreNativeObservationUnavailable("actual lifecycle provider terminal is missing or ambiguous")
    return context._terminal.pop()


@dataclass(frozen=True, slots=True)
class CoreVerifiedJarvisMasterPlanningCompletion:
    """Root-confirmed completion receipt for a no-tools Jarvis planner child."""

    owner_subject_sha256: str
    owner_turn_handle: str
    gateway_turn_id: str
    core_generation: str
    core_source_generation: str
    prompt_sha256: str
    response_sha256: str
    completion_handle: str
    expires_monotonic: float
    owner_turn_expires_monotonic: float
    _client: Any
    _seal: object

    def is_current_sealed(self, config: Any = None, custody: Any = None,
                          now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        if (type(self) is not CoreVerifiedJarvisMasterPlanningCompletion
                or self._seal is not _MASTER_PLANNING_COMPLETION_SEAL
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.core_source_generation or "")
                or not _HASH.fullmatch(self.prompt_sha256 or "")
                or not _HASH.fullmatch(self.response_sha256 or "")
                or not isinstance(self.owner_turn_handle, str)
                or not isinstance(self.gateway_turn_id, str)
                or not _OPAQUE.fullmatch(self.completion_handle or "")
                or not current < self.expires_monotonic <= current + 30.0
                or type(self.owner_turn_expires_monotonic) not in (int, float)
                or not current < self.owner_turn_expires_monotonic <= current + 600.0
                or self.expires_monotonic > self.owner_turn_expires_monotonic):
            return False
        verifier = getattr(self._client, "verify_planning_completion", None)
        return bool(callable(verifier) and verifier(self, config=config, custody=custody) is True)


@dataclass(frozen=True, slots=True)
class CoreVerifiedJarvisMasterReviewCompletion:
    """Root-captured actual zero-tool Jarvis review response over one retained Mission result."""

    owner_subject_sha256: str
    owner_turn_handle: str
    gateway_turn_id: str
    core_generation: str
    core_source_generation: str
    prompt_sha256: str
    response_sha256: str
    mission_id: str
    revision: int
    run_id: str
    result_sha256: str
    execution_core_generation: str
    execution_core_source_generation: str
    response_text: str = field(repr=False, compare=False)
    completion_handle: str
    expires_monotonic: float
    owner_turn_expires_monotonic: float
    _client: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def is_current_sealed(self, config: Any = None, custody: Any = None,
                          now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            return bool(type(self) is CoreVerifiedJarvisMasterReviewCompletion
                and self._seal is _MASTER_REVIEW_COMPLETION_SEAL
                and all(_HASH.fullmatch(getattr(self, name) or "") for name in (
                    "owner_subject_sha256", "core_generation", "core_source_generation",
                    "prompt_sha256", "response_sha256", "result_sha256",
                    "execution_core_generation", "execution_core_source_generation"))
                and isinstance(self.mission_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.mission_id)
                and type(self.revision) is int and self.revision >= 1
                and isinstance(self.run_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,64}", self.run_id)
                and isinstance(self.owner_turn_handle, str) and re.fullmatch(r"[0-9a-f]{32}", self.owner_turn_handle)
                and isinstance(self.gateway_turn_id, str) and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.gateway_turn_id)
                and isinstance(self.response_text, str) and 1 <= len(self.response_text.encode("utf-8", "strict")) <= 32 * 1024
                and hashlib.sha256(self.response_text.encode("utf-8", "strict")).hexdigest() == self.response_sha256
                and _OPAQUE.fullmatch(self.completion_handle or "")
                and current < self.expires_monotonic <= current + 30.0
                and current < self.owner_turn_expires_monotonic <= current + 600.0
                and self.expires_monotonic <= self.owner_turn_expires_monotonic
                and self._client.verify_master_review_completion(
                    self, config=config, custody=custody) is True)
        except Exception:
            return False


class CoreNativeObservationClient:
    """Fixed bounded client for the root-owned current-core observation socket."""

    def __init__(self, *, socket_path: Path = CORE_NATIVE_OBSERVER_SOCKET,
                 timeout: float = 2.0):
        if (not isinstance(socket_path, Path) or not socket_path.is_absolute()
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= 5.0):
            raise ValueError("fixed absolute observer socket and bounded timeout are required")
        self._socket_path = socket_path
        self._timeout = float(timeout)

    def _socket_for_operation(self, operation: str) -> Path:
        if operation in {
            "claim-lifecycle-startup-probe",
            "register-lifecycle-startup-attempt",
            "register-lifecycle-startup-response",
        }:
            return LIFECYCLE_NATIVE_OBSERVER_SOCKET
        return self._socket_path

    def _rpc(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if operation not in {
            "claim-lifecycle-startup-probe", "register-lifecycle-startup-attempt",
            "register-lifecycle-startup-response",
            "register-attempt", "register-response",
            "register-tool-call", "prepare-dispatch", "consume-dispatch",
            "authorize-mission-dispatch", "admit-native-child",
            "admit-master-planner-child",
            "read-current-master-source", "admit-initial-master-plan",
            "verify-master-review-completion",
            "complete-native-child", "verify-planning-completion",
            "request-final-effect", "poll-final-effect", "authorize-master-read-call",
            "read-selected-expert-source", "admit-selected-expert-child",
            "complete-selected-expert-child", "prepare-team-message",
            "planning-turn-context", "bind-obsidian-native-vault",
            "master-review-turn-context",
            "authorize-obsidian-call-scope", "record-obsidian-draft-origin",
            "resolve-obsidian-draft-origin", "read-obsidian-private-draft",
            "confirm-obsidian-draft-read-delivery", "reserve-obsidian-draft-completion",
            "resolve-obsidian-review-proposal",
            "complete-obsidian-draft-origin",
            "current-project-context",
        }:
            raise CoreNativeObservationUnavailable("observer operation is not supported")
        nonce = secrets.token_urlsafe(32)
        request = {"schema": 1, "op": operation, "nonce": nonce, **dict(payload)}
        if "nonce" in payload or "op" in payload or "schema" in payload:
            raise CoreNativeObservationUnavailable("observer payload contains reserved fields")
        raw = _canonical(request)
        if len(raw) > MAX_FRAME:
            raise CoreNativeObservationUnavailable("observer request exceeded its bound")
        try:
            socket_path = self._socket_for_operation(operation)
            parent_info = socket_path.parent.lstat()
            info = socket_path.lstat()
            if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
                    or parent_info.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(parent_info.st_mode) != 0o750
                    or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                    or info.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(info.st_mode) != 0o660
                    or info.st_gid not in {*os.getgroups(), os.getegid()}):
                raise ValueError("root observer socket custody differs")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self._timeout)
                conn.connect(str(socket_path))
                if not hasattr(socket, "SO_PEERCRED"):
                    raise ValueError("observer peer credentials are unavailable")
                peer_pid, peer_uid, _peer_gid = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_pid <= 1 or peer_uid != 0:
                    raise ValueError("observer peer is not root")
                conn.sendall(struct.pack("!I", len(raw)) + raw)
                response = _read_frame(conn)
            if (not {"schema", "nonce", "ok"} <= set(response)
                    or type(response.get("schema")) is not int or response["schema"] != 1
                    or response.get("nonce") != nonce or type(response.get("ok")) is not bool):
                raise ValueError("observer response does not match request")
            if response["ok"] is not True:
                raise CoreNativeObservationUnavailable("root rejected current-core observation")
            return response
        except CoreNativeObservationUnavailable:
            raise
        except Exception:
            raise CoreNativeObservationUnavailable("protected core observer is unavailable") from None

    def claim_lifecycle_startup_probe(self, probe_handle: str) -> LifecycleStartupProbeContext:
        """Claim one Root-enrolled probe from this process over the protected socket."""
        if not isinstance(probe_handle, str) or not _OPAQUE.fullmatch(probe_handle):
            raise CoreNativeObservationUnavailable("startup probe handle is malformed")
        row = self._rpc("claim-lifecycle-startup-probe", {"probe_handle": probe_handle})
        fields = {
            "schema", "nonce", "ok", "probe_handle", "probe_id", "session_id", "startup_nonce",
            "deadline_monotonic", "cohort_sha256", "core_source_generation",
            "core_generation", "generation_a1_sha256", "js_sha256", "rs_sha256",
            "u1_sha256", "l1_sha256", "primary_source_sha256", "active_soul_sha256",
            "native_inventory_sha256", "provider", "api_mode", "base_url", "model",
            "account_fingerprint",
        }
        if set(row) != fields or row.get("probe_handle") != probe_handle:
            raise CoreNativeObservationUnavailable("Root startup probe context has an unknown schema")
        try:
            context = LifecycleStartupProbeContext(
                probe_handle=probe_handle, probe_id=row["probe_id"], session_id=row["session_id"],
                nonce=row["startup_nonce"], deadline_monotonic=row["deadline_monotonic"],
                cohort_sha256=row["cohort_sha256"],
                core_generation=row["core_generation"],
                core_source_generation=row["core_source_generation"],
                generation_a1_sha256=row["generation_a1_sha256"],
                js_sha256=row["js_sha256"], rs_sha256=row["rs_sha256"],
                u1_sha256=row["u1_sha256"], l1_sha256=row["l1_sha256"],
                primary_source_sha256=row["primary_source_sha256"],
                active_soul_sha256=row["active_soul_sha256"],
                native_inventory_sha256=row["native_inventory_sha256"],
                provider=row["provider"], api_mode=row["api_mode"], base_url=row["base_url"],
                model=row["model"], account_fingerprint=row["account_fingerprint"],
                _seal=_LIFECYCLE_STARTUP_CONTEXT_SEAL,
            )
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("Root startup probe context is malformed") from None
        if (row.get("ok") is not True or type(row.get("schema")) is not int
                or row.get("schema") != 1 or not context.is_root_issued()):
            raise CoreNativeObservationUnavailable("Root startup probe is stale or malformed")
        return context

    def register_lifecycle_startup_attempt(
        self, context: LifecycleStartupProbeContext, *, turn_id: str, api_request_id: str,
        provider: str, api_mode: str, base_url: str, model: str, account_fingerprint: str,
        request_sha256: str, prompt_sha256: str, tool_names: tuple[str, ...], retry_count: int,
    ) -> str:
        if (type(context) is not LifecycleStartupProbeContext or not context.is_root_issued()
                or provider != context.provider or api_mode != context.api_mode
                or base_url.rstrip("/") != context.base_url or model != context.model
                or account_fingerprint != context.account_fingerprint
                or type(retry_count) is not int or retry_count != 0
                or type(tool_names) is not tuple or tool_names
                or prompt_sha256 != hashlib.sha256(
                    (_LIFECYCLE_STARTUP_PROMPT_PREFIX + context.nonce
                     + _LIFECYCLE_STARTUP_PROMPT_SUFFIX).encode("ascii")).hexdigest()):
            raise CoreNativeObservationUnavailable("Codex attempt is outside the fixed lifecycle probe")
        row = self._rpc("register-lifecycle-startup-attempt", {
            "probe_handle": context.probe_handle, "probe_id": context.probe_id,
            "session_id": context.session_id, "turn_id": _require_id(turn_id, "turn ID"),
            "api_request_id": _require_id(api_request_id, "API request ID"),
            "provider": provider, "api_mode": api_mode, "base_url": context.base_url,
            "model": model, "account_fingerprint": account_fingerprint,
            "request_sha256": _require_hash(request_sha256, "request digest"),
            "prompt_sha256": prompt_sha256, "tool_names": [], "retry_count": 0,
        })
        attempt_handle = row.get("attempt_handle")
        if (set(row) != {"schema", "nonce", "ok", "attempt_handle"}
                or type(row.get("schema")) is not int or row.get("schema") != 1
                or row.get("ok") is not True
                or not isinstance(attempt_handle, str) or not _OPAQUE.fullmatch(attempt_handle)):
            raise CoreNativeObservationUnavailable("Root lifecycle attempt receipt is malformed")
        return attempt_handle

    def register_lifecycle_startup_response(
        self, context: LifecycleStartupProbeContext, *, attempt_handle: str,
        turn_id: str, api_request_id: str, request_sha256: str,
        response_sha256: str, response_text: str | None,
        completed: bool, tool_call_count: int,
    ) -> str:
        if (type(context) is not LifecycleStartupProbeContext or not context.is_root_issued()
                or not _OPAQUE.fullmatch(attempt_handle or "") or type(completed) is not bool
                or completed is not True or type(tool_call_count) is not int or tool_call_count != 0
                or not isinstance(response_text, str) or not 1 <= len(response_text) <= 1024
                or any(ord(char) < 0x20 and char not in "\n\t" for char in response_text)):
            raise CoreNativeObservationUnavailable("lifecycle provider terminal is incomplete")
        response_text_sha256 = hashlib.sha256(response_text.encode("utf-8", "strict")).hexdigest()
        row = self._rpc("register-lifecycle-startup-response", {
            "probe_handle": context.probe_handle, "attempt_handle": attempt_handle,
            "turn_id": _require_id(turn_id, "turn ID"),
            "api_request_id": _require_id(api_request_id, "API request ID"),
            "request_sha256": _require_hash(request_sha256, "request digest"),
            "response_sha256": _require_hash(response_sha256, "response digest"),
            "response_text": response_text,
            "response_text_sha256": _require_hash(response_text_sha256, "response text digest"),
            "completed": True, "tool_call_count": 0,
        })
        handle = row.get("completion_handle")
        if (set(row) != {"schema", "nonce", "ok", "completion_handle"}
                or type(row.get("schema")) is not int or row.get("schema") != 1
                or row.get("ok") is not True
                or not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)):
            raise CoreNativeObservationUnavailable("Root lifecycle completion handle is malformed")
        return handle

    def register_attempt(self, *, session_id: str, turn_id: str, api_request_id: str,
                         provider: str, model: str, base_url: str, api_mode: str,
                         account_fingerprint: str, request_sha256: str,
                         parent_tool_names: tuple[str, ...],
                         prompt_sha256: str,
                         retry_count: int) -> ObservedProviderAttempt:
        """Register one exact native logical attempt; route uncertainty is denied."""
        if (provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url.rstrip("/") != _CODEX_ENDPOINT or type(retry_count) is not int
                or retry_count != 0 or not isinstance(parent_tool_names, tuple)
                or len(parent_tool_names) > 512
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in parent_tool_names)
                or len(set(parent_tool_names)) != len(parent_tool_names)):
            raise CoreNativeObservationUnavailable("attempt is outside the selected Codex subscription route")
        payload = {
            "session_id": _require_id(session_id, "session ID"),
            "turn_id": _require_id(turn_id, "turn ID"),
            "api_request_id": _require_id(api_request_id, "API request ID"),
            "provider": provider, "model": _require_id(model, "model"),
            "base_url": _CODEX_ENDPOINT, "api_mode": _CODEX_MODE,
            "account_fingerprint": _require_hash(account_fingerprint, "account fingerprint"),
            "request_sha256": _require_hash(request_sha256, "request digest"),
            "prompt_sha256": _require_hash(prompt_sha256, "prompt digest"),
            "parent_tool_names": list(parent_tool_names),
            "retry_count": retry_count,
        }
        row = self._rpc("register-attempt", payload)
        try:
            if type(row.get("capture_child_output", False)) is not bool:
                raise ValueError
            return ObservedProviderAttempt(row["attempt_handle"], row["owner_turn_handle"],
                                          row["expires_monotonic"], row.get("capture_child_output", False))
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root provider-attempt receipt is malformed") from None

    def planning_context_for_attempt(self, *, session_id: str, turn_id: str,
                                    prompt_sha256: str) -> Any | None:
        """Resolve whether this exact native turn is a root-enrolled planning turn."""
        from .core_gateway_inspector import PlanningContext
        row = self._rpc("planning-turn-context", {
            "session_id": _require_id(session_id, "session ID"),
            "turn_id": _require_id(turn_id, "turn ID"),
            "prompt_sha256": _require_hash(prompt_sha256, "prompt digest"),
        })
        if set(row) != {"schema", "nonce", "ok", "planning", "planning_context"}:
            raise CoreNativeObservationUnavailable("planning-turn response has an unknown schema")
        if type(row["planning"]) is not bool:
            raise CoreNativeObservationUnavailable("planning-turn response is malformed")
        if not row["planning"]:
            if row["planning_context"] is not None:
                raise CoreNativeObservationUnavailable("ordinary turn carried planning authority")
            return None
        try:
            context = PlanningContext.from_wire(row["planning_context"])
        except Exception:
            raise CoreNativeObservationUnavailable("root planning context is malformed") from None
        if context.planner_prompt_sha256 != prompt_sha256:
            raise CoreNativeObservationUnavailable("planning prompt changed before provider dispatch")
        return context

    def master_review_context_for_attempt(self, *, session_id: str, turn_id: str,
                                          prompt_sha256: str) -> Any | None:
        """Resolve only the exact root-enrolled Mission-review prompt for this turn."""
        from .core_gateway_inspector import MasterReviewContext
        row = self._rpc("master-review-turn-context", {
            "session_id": _require_id(session_id, "session ID"),
            "turn_id": _require_id(turn_id, "turn ID"),
            "prompt_sha256": _require_hash(prompt_sha256, "prompt digest"),
        })
        if set(row) != {"schema", "nonce", "ok", "reviewing", "review_context"}:
            raise CoreNativeObservationUnavailable("master-review response has an unknown schema")
        if type(row["reviewing"]) is not bool:
            raise CoreNativeObservationUnavailable("master-review response is malformed")
        if not row["reviewing"]:
            if row["review_context"] is not None:
                raise CoreNativeObservationUnavailable("ordinary turn carried review purpose")
            return None
        try:
            context = MasterReviewContext.from_wire(row["review_context"])
        except Exception:
            raise CoreNativeObservationUnavailable("root master-review context is malformed") from None
        if context.review_prompt_sha256 != prompt_sha256:
            raise CoreNativeObservationUnavailable("master-review prompt changed before provider dispatch")
        return context

    def verify_master_review_completion(self, receipt: Any, *, config: Any = None,
                                        custody: Any = None) -> bool:
        """Revalidate a short-lived review receipt against the issuing root registry.

        ``config`` and ``custody`` satisfy the common sealed-receipt interface;
        the client never serializes caller-provided objects as authority. The
        issuing root registry resolves and checks its own current custody.
        """
        if (type(receipt) is not CoreVerifiedJarvisMasterReviewCompletion
                or receipt._seal is not _MASTER_REVIEW_COMPLETION_SEAL):
            return False
        try:
            row = self._rpc("verify-master-review-completion", {
                "completion_handle": receipt.completion_handle,
                "owner_turn_handle": receipt.owner_turn_handle,
                "gateway_turn_id": receipt.gateway_turn_id,
                "owner_subject_sha256": receipt.owner_subject_sha256,
                "core_generation": receipt.core_generation,
                "core_source_generation": receipt.core_source_generation,
                "prompt_sha256": receipt.prompt_sha256,
                "response_sha256": receipt.response_sha256,
                "mission_id": receipt.mission_id,
                "revision": receipt.revision,
                "run_id": receipt.run_id,
                "result_sha256": receipt.result_sha256,
                "execution_core_generation": receipt.execution_core_generation,
                "execution_core_source_generation": receipt.execution_core_source_generation,
                "owner_turn_expires_monotonic": receipt.owner_turn_expires_monotonic,
            })
            return (set(row) == {"schema", "nonce", "ok"}
                    and row.get("schema") == 1 and row.get("ok") is True)
        except Exception:
            return False

    def current_project_context(self, *, session_id: str,
                                prompt_sha256: str) -> dict[str, Any] | None:
        """Read root-joined Projects context for the exact active owner submission."""
        if (not isinstance(session_id, str) or not 1 <= len(session_id) <= 512
                or not session_id.isascii() or any(ord(char) < 0x20 for char in session_id)
                or not _HASH.fullmatch(prompt_sha256 or "")):
            raise CoreNativeObservationUnavailable("native project-context request is malformed")
        row = self._rpc("current-project-context", {
            "session_id": session_id, "prompt_sha256": prompt_sha256,
        })
        if set(row) != {"schema", "nonce", "ok", "available", "session_id",
                        "prompt_sha256", "owner_turn_handle", "conversation_id", "gateway_turn_id",
                        "owner_subject_sha256", "core_generation", "context_sha256", "text",
                        "project_source_refs"}:
            raise CoreNativeObservationUnavailable("root project-context response has an unknown schema")
        if type(row["available"]) is not bool:
            raise CoreNativeObservationUnavailable("root project-context availability is malformed")
        if not row["available"]:
            if any(row[name] is not None for name in (
                    "conversation_id", "gateway_turn_id", "owner_subject_sha256",
                    "core_generation", "context_sha256", "text", "owner_turn_handle",
                    "project_source_refs")):
                raise CoreNativeObservationUnavailable("unavailable project context carried data")
            return None
        if (row["session_id"] != session_id or row["prompt_sha256"] != prompt_sha256
                or any(not isinstance(row[name], str) for name in (
                    "conversation_id", "gateway_turn_id", "owner_subject_sha256",
                    "core_generation", "context_sha256", "text"))
                or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", row["conversation_id"])
                or not re.fullmatch(r"[A-Za-z0-9_-]{24,64}", row["gateway_turn_id"])
                or not re.fullmatch(r"[0-9a-f]{32}", row["owner_turn_handle"])
                or not _HASH.fullmatch(row["owner_subject_sha256"])
                or not _HASH.fullmatch(row["core_generation"])
                or not _HASH.fullmatch(row["context_sha256"])
                or type(row["project_source_refs"]) is not list
                or len(row["project_source_refs"]) > 51
                or any(not isinstance(item, str) or not 1 <= len(item) <= 192
                       or not item.isascii() for item in row["project_source_refs"])
                or len(row["text"]) > 24_000
                or hashlib.sha256(row["text"].encode("utf-8", "strict")).hexdigest()
                    != row["context_sha256"]):
            raise CoreNativeObservationUnavailable("root project context is malformed or stale")
        return row

    def register_response(self, *, attempt: ObservedProviderAttempt,
                          response_sha256: str, response_text_sha256: str | None,
                          tool_calls: list[dict[str, str]],
                          completed: bool, response_text: str | None = None) -> None:
        if type(attempt) is not ObservedProviderAttempt or type(completed) is not bool:
            raise CoreNativeObservationUnavailable("provider response is not correlated")
        calls = []
        text_digest = (_require_hash(response_text_sha256, "response text digest")
                       if response_text_sha256 is not None else None)
        if not isinstance(tool_calls, list) or len(tool_calls) > 128:
            raise CoreNativeObservationUnavailable("provider tool-call inventory is malformed")
        for call in tool_calls:
            if not isinstance(call, dict) or set(call) != {"id", "name", "arguments_sha256"}:
                raise CoreNativeObservationUnavailable("provider tool-call row is malformed")
            calls.append({"id": _require_id(call["id"], "provider tool-call ID"),
                          "name": _require_id(call["name"], "provider tool name"),
                          "arguments_sha256": _require_hash(call["arguments_sha256"], "tool arguments digest")})
        payload = {
            "attempt_handle": attempt.handle,
            "response_sha256": _require_hash(response_sha256, "response digest"),
            "response_text_sha256": text_digest,
            "tool_calls": calls, "completed": completed,
        }
        if response_text is not None:
            if (not isinstance(response_text, str)
                    or not 1 <= len(response_text.encode("utf-8", errors="strict")) <= 32 * 1024
                    or hashlib.sha256(response_text.encode("utf-8", errors="strict")).hexdigest()
                        != text_digest):
                raise CoreNativeObservationUnavailable("provider result text is not digest-bound")
            payload["response_text"] = response_text
        self._rpc("register-response", payload)

    def complete_selected_expert_child(self, *, authorization: RootVerifiedNativeChildAuthorization
                                       ) -> RootObservedExpertCompletion:
        """Return only the exact final provider text captured for this admitted child."""
        if (type(authorization) is not RootVerifiedNativeChildAuthorization
                or authorization._seal is not _NATIVE_CHILD_AUTHORIZATION_SEAL
                or authorization.mode != "expert-read-research"):
            raise CoreNativeObservationUnavailable("root-admitted Expert child is required")
        row = self._rpc("complete-selected-expert-child", {
            "admission_handle": authorization.admission_handle,
            "owner_turn_handle": authorization.owner_turn_handle,
            "child_session_id": authorization.child_session_id,
        })
        required = {"schema", "nonce", "ok", "completion_handle", "owner_turn_handle",
                    "child_session_id", "profile_id", "source_revision",
                    "source_generation_sha256", "source_manifest_sha256", "goal_sha256",
                    "provider_attempt_handle", "request_sha256", "response_sha256",
                    "response_text_sha256", "response_text", "team_message_handle",
                    "team_lineage", "expires_monotonic"}
        if (set(row) != required or row.get("schema") != 1 or row.get("ok") is not True
                or row["owner_turn_handle"] != authorization.owner_turn_handle
                or row["child_session_id"] != authorization.child_session_id
                or row["profile_id"] != authorization.profile_id
                or row["source_generation_sha256"] != authorization.source_generation_sha256
                or row["source_manifest_sha256"] != authorization.source_manifest_sha256
                or row["goal_sha256"] != authorization.goal_sha256):
            raise CoreNativeObservationUnavailable("root Expert completion does not match its admission")
        try:
            return RootObservedExpertCompletion(
                completion_handle=row["completion_handle"],
                owner_turn_handle=row["owner_turn_handle"],
                child_session_id=row["child_session_id"], profile_id=row["profile_id"],
                source_revision=row["source_revision"],
                source_generation_sha256=row["source_generation_sha256"],
                source_manifest_sha256=row["source_manifest_sha256"], goal_sha256=row["goal_sha256"],
                provider_attempt_handle=row["provider_attempt_handle"], request_sha256=row["request_sha256"],
                response_sha256=row["response_sha256"],
                response_text_sha256=row["response_text_sha256"], response_text=row["response_text"],
                expires_monotonic=float(row["expires_monotonic"]), _seal=_EXPERT_COMPLETION_SEAL,
                team_message_handle=row["team_message_handle"],
                team_lineage=row["team_lineage"],
            )
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root Expert completion is malformed") from None

    def prepare_team_message(self, *, native_claim: RootSelectedInternalProfileDispatchClaim,
                             binding: RootSelectedTeamBinding,
                             sender: RootObservedExpertCompletion,
                             recipient: RootNativeSelectedSourceDelivery,
                             original_goal: str, excerpt: str) -> RootTeamMessageDelivery:
        if (type(native_claim) is not RootSelectedInternalProfileDispatchClaim
                or type(binding) is not RootSelectedTeamBinding
                or type(sender) is not RootObservedExpertCompletion
                or type(recipient) is not RootNativeSelectedSourceDelivery
                or recipient.team_binding is None
                or recipient.team_binding.binding_id != binding.binding_id
                or sender.profile_id not in binding.selected_expert_ids
                or recipient.profile_id not in binding.selected_expert_ids
                or sender.profile_id == recipient.profile_id
                or hashlib.sha256(original_goal.encode("utf-8", "strict")).hexdigest() != binding.goal_sha256
                or not isinstance(excerpt, str) or not excerpt
                or not sender.response_text.startswith(excerpt)
                or len(excerpt.encode("utf-8", "strict")) > 8192):
            raise CoreNativeObservationUnavailable("root Team sender, recipient and exact excerpt are required")
        row = self._rpc("prepare-team-message", {
            "claim_handle": native_claim.claim_handle,
            "owner_turn_handle": native_claim.owner_turn_handle,
            "team_binding_id": binding.binding_id,
            "sender_completion_handle": sender.completion_handle,
            "recipient_source_handle": recipient.source_handle,
            "original_goal_sha256": binding.goal_sha256,
            "original_goal": original_goal,
            "excerpt": excerpt,
        })
        required = {"schema", "nonce", "ok", "message_handle", "binding_id",
            "sender_completion_handle", "sender_profile_id", "recipient_profile_id",
            "excerpt_sha256", "excerpt", "recipient_goal_sha256", "recipient_goal",
            "expires_monotonic"}
        if (set(row) != required or row.get("schema") != 1 or row.get("ok") is not True
                or row["binding_id"] != binding.binding_id
                or row["sender_completion_handle"] != sender.completion_handle
                or row["sender_profile_id"] != sender.profile_id
                or row["recipient_profile_id"] != recipient.profile_id
                or row["excerpt"] != excerpt):
            raise CoreNativeObservationUnavailable("root Team message does not match the actual completion")
        try:
            delivery = RootTeamMessageDelivery(
                message_handle=row["message_handle"], binding_id=row["binding_id"],
                sender_completion_handle=row["sender_completion_handle"],
                sender_profile_id=row["sender_profile_id"], recipient_profile_id=row["recipient_profile_id"],
                excerpt_sha256=row["excerpt_sha256"], excerpt=row["excerpt"],
                recipient_goal_sha256=row["recipient_goal_sha256"], recipient_goal=row["recipient_goal"],
                expires_monotonic=float(row["expires_monotonic"]), _seal=_TEAM_MESSAGE_SEAL)
            if not time.monotonic() < delivery.expires_monotonic <= min(
                    binding.expires_monotonic, native_claim.expires_monotonic):
                raise ValueError
            return delivery
        except Exception:
            raise CoreNativeObservationUnavailable("root Team message delivery is stale or malformed") from None

    def register_tool_call(self, *, attempt: ObservedProviderAttempt,
                           tool_call_id: str, canonical_arguments: bytes) -> ObservedNativeToolCall:
        if (type(attempt) is not ObservedProviderAttempt or not isinstance(canonical_arguments, bytes)
                or not 2 <= len(canonical_arguments) <= 64 * 1024):
            raise CoreNativeObservationUnavailable("native tool-call arguments are invalid")
        try:
            parsed = json.loads(canonical_arguments.decode("utf-8", errors="strict"),
                                object_pairs_hook=_unique_pairs)
            if not isinstance(parsed, dict) or _canonical(parsed) != canonical_arguments:
                raise ValueError
        except Exception:
            raise CoreNativeObservationUnavailable("native tool-call arguments are not canonical") from None
        row = self._rpc("register-tool-call", {
            "attempt_handle": attempt.handle,
            "tool_call_id": _require_id(tool_call_id, "tool-call ID"),
            "canonical_arguments_b64": __import__("base64").b64encode(canonical_arguments).decode("ascii"),
        })
        try:
            return ObservedNativeToolCall(row["observed_call_handle"], row["attempt_handle"],
                                          row["owner_turn_handle"], row["tool_call_id"],
                                          row["tool_name"], row["arguments_sha256"],
                                          row["expires_monotonic"])
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root native tool-call receipt is malformed") from None

    def prepare_dispatch(self, *, observed_call: ObservedNativeToolCall) -> str:
        if type(observed_call) is not ObservedNativeToolCall:
            raise CoreNativeObservationUnavailable("root observed call is required")
        row = self._rpc("prepare-dispatch", {"observed_call_handle": observed_call.handle})
        claim = row.get("claim_handle")
        if not isinstance(claim, str) or not _OPAQUE.fullmatch(claim):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")
        return claim

    def consume_dispatch(self, *, claim_handle: str) -> RootSelectedInternalProfileDispatchClaim:
        if not isinstance(claim_handle, str) or not _OPAQUE.fullmatch(claim_handle):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")
        row = self._rpc("consume-dispatch", {"claim_handle": claim_handle})
        claim = row.get("dispatch_claim")
        required = {
            "schema", "claim_handle", "owner_turn_handle", "gateway_turn_id",
            "owner_subject_sha256", "observed_call_handle",
            "core_generation", "core_source_generation", "session_id", "turn_id", "tool_call_id", "tool_name",
            "generation_sha256",
            "arguments_sha256", "account_fingerprint", "profile_id", "source_revision",
            "profile_manifest_sha256", "profile_tool_names", "profile_privacy_requirements",
            "source_manifest", "source_manifest_sha256", "prompt_b64", "prompt_sha256",
            "prompt_revision", "parent_tool_names", "parent_privacy_grants", "expires_monotonic",
            "evidence_class", "provider", "api_mode", "base_url", "additional_metered_budget",
            "delegation_policy_handle", "delegation_policy_sha256",
            "parent_tool_configuration_sha256", "configured_parent_tool_names",
            "allow_inherited_mcp", "allow_native_orchestrator_delegation",
            "mission_binding",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed")
        try:
            if type(claim["schema"]) is not int or claim["schema"] != 1:
                raise ValueError
            mission_binding = _mission_binding_from_wire(claim["mission_binding"])
            encoded_prompt = claim["prompt_b64"]
            if not isinstance(encoded_prompt, str) or len(encoded_prompt) > 4 * 128 * 1024:
                raise ValueError
            prompt_bytes = base64.b64decode(encoded_prompt, validate=True)
            prompt_bytes.decode("utf-8", errors="strict")
            raw_manifest = claim["source_manifest"]
            if not isinstance(raw_manifest, list) or not 1 <= len(raw_manifest) <= 512:
                raise ValueError
            manifest = []
            for item in raw_manifest:
                if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
                    raise ValueError
                manifest.append(NativeSourceMember(item["path"], item["sha256"], item["size"]))
            names, grants = claim["parent_tool_names"], claim["parent_privacy_grants"]
            profile_tools, privacy_requirements = claim["profile_tool_names"], claim["profile_privacy_requirements"]
            configured_names = claim["configured_parent_tool_names"]
            if (not isinstance(names, list) or not isinstance(grants, list)
                    or not isinstance(configured_names, list)
                    or not isinstance(profile_tools, list) or not isinstance(privacy_requirements, list)
                    or any(not isinstance(value, str) for value in (*names, *grants, *configured_names, *profile_tools, *privacy_requirements))
                    or type(claim["allow_inherited_mcp"]) is not bool
                    or type(claim["allow_native_orchestrator_delegation"]) is not bool):
                raise ValueError
            if claim["claim_handle"] != claim_handle:
                raise ValueError
            return RootSelectedInternalProfileDispatchClaim(
                claim_handle=claim["claim_handle"], owner_turn_handle=claim["owner_turn_handle"],
                gateway_turn_id=claim["gateway_turn_id"],
                owner_subject_sha256=claim["owner_subject_sha256"],
                observed_call_handle=claim["observed_call_handle"],
                core_generation=claim["core_generation"], session_id=claim["session_id"],
                core_source_generation=claim["core_source_generation"],
                generation_sha256=claim["generation_sha256"],
                turn_id=claim["turn_id"], tool_call_id=claim["tool_call_id"],
                tool_name=claim["tool_name"], arguments_sha256=claim["arguments_sha256"],
                account_fingerprint=claim["account_fingerprint"], profile_id=claim["profile_id"],
                source_revision=claim["source_revision"],
                profile_manifest_sha256=claim["profile_manifest_sha256"],
                source_manifest=tuple(manifest),
                source_manifest_sha256=claim["source_manifest_sha256"],
                prompt_bytes=prompt_bytes, prompt_sha256=claim["prompt_sha256"],
                prompt_revision=claim["prompt_revision"], parent_tool_names=tuple(names),
                delegation_policy_handle=claim["delegation_policy_handle"],
                delegation_policy_sha256=claim["delegation_policy_sha256"],
                parent_tool_configuration_sha256=claim["parent_tool_configuration_sha256"],
                configured_parent_tool_names=tuple(configured_names),
                allow_inherited_mcp=claim["allow_inherited_mcp"],
                allow_native_orchestrator_delegation=claim["allow_native_orchestrator_delegation"],
                mission_binding=mission_binding,
                profile_tool_names=tuple(profile_tools), parent_privacy_grants=tuple(grants),
                profile_privacy_requirements=tuple(privacy_requirements),
                expires_monotonic=claim["expires_monotonic"],
                evidence_class=claim["evidence_class"], provider=claim["provider"],
                api_mode=claim["api_mode"], base_url=claim["base_url"],
                additional_metered_budget=claim["additional_metered_budget"],
            )
        except Exception:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed") from None

    def authorize_mission_dispatch(self, *, claim: RootSelectedInternalProfileDispatchClaim):
        if type(claim) is not RootSelectedInternalProfileDispatchClaim or claim.mission_binding is None:
            raise CoreNativeObservationUnavailable("a root-sealed mission claim is required")
        row = self._rpc("authorize-mission-dispatch", {"claim_handle": claim.claim_handle})
        required = {"schema", "nonce", "ok", "claim_handle", "mission_binding_sha256", "gateway_turn_id",
                    "owner_subject_sha256", "core_generation", "core_source_generation",
                    "source_profile_id", "canonical_arguments_sha256", "expires_monotonic"}
        if (not isinstance(row, dict) or set(row) != required
                or type(row.get("ok")) is not bool or row["ok"] is not True):
            raise CoreNativeObservationUnavailable("mission authorization response is malformed")
        binding = claim.mission_binding
        if (type(row["schema"]) is not int or row["schema"] != 1
                or row["claim_handle"] != claim.claim_handle
                or row["mission_binding_sha256"] != _hash(binding.to_wire())
                or row["gateway_turn_id"] != claim.gateway_turn_id
                or row["owner_subject_sha256"] != claim.owner_subject_sha256
                or row["core_generation"] != claim.core_generation
                or row["core_source_generation"] != claim.core_source_generation
                or row["source_profile_id"] != binding.source_profile_id
                or row["canonical_arguments_sha256"] != claim.arguments_sha256):
            raise CoreNativeObservationUnavailable("mission authorization does not match the claim")
        return RootVerifiedMissionDispatchAuthorization(
            claim_handle=claim.claim_handle,
            mission_binding_sha256=row["mission_binding_sha256"],
            gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"],
            core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"],
            source_profile_id=row["source_profile_id"],
            canonical_arguments_sha256=row["canonical_arguments_sha256"],
            expires_monotonic=row["expires_monotonic"],
            _seal=_MISSION_AUTHORIZATION_SEAL,
        )

    def admit_native_child(self, *, parent_claim: RootSelectedInternalProfileDispatchClaim,
                           child: Any, source: Any, mode: Any, goal: str
                           ) -> RootVerifiedNativeChildAuthorization:
        """Root-admit one constructed child before any child provider request."""
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (type(parent_claim) is not RootSelectedInternalProfileDispatchClaim
                or type(mode) is not NativeChildMode or not isinstance(goal, str)
                or not goal or len(goal.encode("utf-8", errors="strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("typed parent claim, child mode, and bounded goal are required")
        parent = parent_claim.parent_agent
        try:
            profile_id = getattr(source, "profile_id", getattr(source, "source_id", None))
            generation = getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None))
            manifest = getattr(source, "source_member_manifest_sha256",
                               getattr(source, "profile_member_manifest_sha256", None))
            prompt = getattr(source, "effective_prompt_sha256", getattr(source, "profile_prompt_sha256", None))
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            current_child_turn = getattr(child, "_current_turn_id", None)
            child_turn = (_require_id(current_child_turn, "child turn ID")
                          if current_child_turn else "")
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("constructed child lineage is incomplete") from None
        if (not isinstance(profile_id, str) or not isinstance(generation, str)
                or not isinstance(manifest, str) or not isinstance(prompt, str)
                or provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url != _CODEX_ENDPOINT or model != getattr(parent, "model", None)
                or tuple(sorted(set(tool_names))) != tool_names):
            raise CoreNativeObservationUnavailable("child differs from the selected source or Codex route")
        row = self._rpc("admit-native-child", {
            "parent_claim_handle": parent_claim.claim_handle,
            "owner_turn_handle": parent_claim.owner_turn_handle,
            "parent_session_id": parent_claim.session_id,
            "parent_turn_id": parent_claim.turn_id,
            "child_session_id": child_session,
            "child_turn_id": child_turn,
            "profile_id": _require_id(profile_id, "selected profile ID"),
            "source_generation_sha256": _require_hash(generation, "selected source generation"),
            "source_manifest_sha256": _require_hash(manifest, "selected source manifest"),
            "prompt_sha256": _require_hash(prompt, "selected source prompt"),
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest(),
            "mode": mode.value,
            "tool_names": list(tool_names), "tool_closure_sha256": _hash(list(tool_names)),
            "account_fingerprint": parent_claim.account_fingerprint,
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "parent_session_id", "parent_turn_id",
                    "child_session_id", "profile_id", "source_generation_sha256",
                    "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["owner_turn_handle"] != parent_claim.owner_turn_handle
                or row["gateway_turn_id"] != parent_claim.gateway_turn_id
                or row["owner_subject_sha256"] != parent_claim.owner_subject_sha256
                or row["core_generation"] != parent_claim.core_generation
                or row["core_source_generation"] != parent_claim.core_source_generation
                or row["parent_session_id"] != parent_claim.session_id
                or row["parent_turn_id"] != parent_claim.turn_id
                or row["child_session_id"] != child_session
                or row["profile_id"] != profile_id
                or row["source_generation_sha256"] != generation
                or row["source_manifest_sha256"] != manifest
                or row["prompt_sha256"] != prompt
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8")).hexdigest()
                or row["account_fingerprint"] != parent_claim.account_fingerprint
                or row["mode"] != mode.value
                or row["tool_names"] != list(tool_names)
                or row["tool_closure_sha256"] != _hash(list(tool_names))
                or type(row["additional_metered_budget"]) is not int
                or row["additional_metered_budget"] != 0
                or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root child admission does not match its request")
        try:
            expiry = float(row["expires_monotonic"])
        except (TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root child admission expiry is malformed") from None
        if not time.monotonic() < expiry <= min(parent_claim.expires_monotonic, time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root child admission is stale")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"],
            parent_session_id=row["parent_session_id"], parent_turn_id=row["parent_turn_id"],
            child_session_id=row["child_session_id"], profile_id=row["profile_id"],
            source_generation_sha256=row["source_generation_sha256"],
            source_manifest_sha256=row["source_manifest_sha256"], prompt_sha256=row["prompt_sha256"],
            goal_sha256=row["goal_sha256"], account_fingerprint=row["account_fingerprint"],
            mode=row["mode"], allowed_tool_names=tool_names,
            tool_closure_sha256=row["tool_closure_sha256"],
            additional_metered_budget=row["additional_metered_budget"],
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            initial_owner_turn=False,
            _parent_agent=parent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def read_current_master_source(self, *, owner_turn_handle: str
                                   ) -> RootNativeSelectedSourceDelivery:
        """Fetch exact current Jarvis prompt bytes from the root-retained source."""
        if not isinstance(owner_turn_handle, str) or not _OPAQUE.fullmatch(owner_turn_handle):
            raise CoreNativeObservationUnavailable("current owner turn is required")
        row = self._rpc("read-current-master-source", {"owner_turn_handle": owner_turn_handle})
        required = {"schema", "nonce", "ok", "source_handle", "profile_id", "source_revision",
                    "generation_sha256", "source_manifest_sha256", "profile_manifest_sha256",
                    "prompt_b64", "prompt_sha256", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["profile_id"] != "hermes" or not _OPAQUE.fullmatch(row["source_handle"] or "")):
            raise CoreNativeObservationUnavailable("root master source response is malformed")
        try:
            prompt = base64.b64decode(row["prompt_b64"], validate=True)
            source = RootNativeSelectedSourceDelivery(
                source_handle=row["source_handle"], profile_id=row["profile_id"],
                source_revision=row["source_revision"], generation_sha256=row["generation_sha256"],
                source_manifest_sha256=row["source_manifest_sha256"],
                profile_manifest_sha256=row["profile_manifest_sha256"],
                effective_prompt=prompt, effective_prompt_sha256=row["prompt_sha256"],
                expires_monotonic=float(row["expires_monotonic"]),
                _seal=_SELECTED_SOURCE_DELIVERY_SEAL,
            )
            if source.expires_monotonic > time.monotonic() + 5.1:
                raise ValueError
            return source
        except Exception:
            raise CoreNativeObservationUnavailable("root master source is stale or malformed") from None

    def admit_initial_master_plan_child(
            self, *, owner_turn_handle: str, parent_agent: Any, child: Any,
            source: RootNativeSelectedSourceDelivery, goal: str
    ) -> RootVerifiedNativeChildAuthorization:
        """Admit the first no-tools planning child from a registered owner turn.

        Unlike the follow-on planner operation, this root op requires no prior
        completed parent provider response or predicted native turn ID. The first
        actual child attempt binds its emitted turn ID in the root observer.
        """
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (not isinstance(owner_turn_handle, str) or not _OPAQUE.fullmatch(owner_turn_handle)
                or type(source) is not RootNativeSelectedSourceDelivery
                or source.profile_id != "hermes"
                or not time.monotonic() < source.expires_monotonic
                or not isinstance(goal, str) or not goal
                or len(goal.encode("utf-8", errors="strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("current owner, master source, and bounded plan prompt are required")
        try:
            parent_session = _require_id(getattr(parent_agent, "session_id"), "owner session ID")
            child_session = _require_id(getattr(child, "session_id"), "planner child session ID")
            child_turn_value = getattr(child, "_current_turn_id", None)
            if child_turn_value not in (None, ""):
                raise ValueError
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            parent_route = tuple(getattr(parent_agent, key, None)
                                 for key in ("provider", "api_mode", "base_url", "model"))
            child_route = tuple(getattr(child, key, None)
                                for key in ("provider", "api_mode", "base_url", "model"))
            account = _codex_account_fingerprint(
                lambda: __import__("hermes_cli.auth_codex", fromlist=[
                    "resolve_codex_runtime_credentials"]).resolve_codex_runtime_credentials(read_only=True))
        except Exception:
            raise CoreNativeObservationUnavailable("initial planner child lineage is incomplete") from None
        if (parent_route != child_route
                or parent_route[:3] != (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT)
                or not isinstance(parent_route[3], str) or not parent_route[3]
                or tool_names):
            raise CoreNativeObservationUnavailable("initial planner must be no-tools on the current Codex route")
        goal_sha256 = hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest()
        row = self._rpc("admit-initial-master-plan", {
            "owner_turn_handle": owner_turn_handle,
            "parent_session_id": parent_session,
            "child_session_id": child_session,
            "child_turn_id": "",
            "source_handle": source.source_handle,
            "source_generation_sha256": source.generation_sha256,
            "source_manifest_sha256": source.source_manifest_sha256,
            "profile_manifest_sha256": source.profile_manifest_sha256,
            "prompt_sha256": source.effective_prompt_sha256,
            "goal_sha256": goal_sha256,
            "provider": parent_route[0], "api_mode": parent_route[1],
            "base_url": parent_route[2], "model": parent_route[3],
            "account_fingerprint": account,
            "tool_names": [], "tool_closure_sha256": _hash([]),
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "parent_session_id", "parent_turn_id",
                    "child_session_id", "profile_id", "source_generation_sha256",
                    "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic", "owner_turn_expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["owner_turn_handle"] != owner_turn_handle
                or row["parent_session_id"] != parent_session or row["parent_turn_id"] != ""
                or row["child_session_id"] != child_session or row["profile_id"] != "hermes"
                or row["source_generation_sha256"] != source.generation_sha256
                or row["source_manifest_sha256"] != source.source_manifest_sha256
                or row["prompt_sha256"] != source.effective_prompt_sha256
                or row["goal_sha256"] != goal_sha256
                or row["account_fingerprint"] != account
                or row["mode"] != NativeChildMode.PLANNER.value or row["tool_names"] != []
                or row["tool_closure_sha256"] != _hash([])
                or row["additional_metered_budget"] != 0
                or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root initial plan admission does not match its request")
        expiry = float(row["expires_monotonic"])
        owner_expiry = float(row["owner_turn_expires_monotonic"])
        now = time.monotonic()
        if (not now < expiry <= min(owner_expiry, now + 30.0)
                or not now < owner_expiry <= now + 600.0):
            raise CoreNativeObservationUnavailable("root initial plan admission has an invalid lease")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=owner_turn_handle, gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], parent_session_id=parent_session,
            parent_turn_id="", child_session_id=child_session, profile_id="hermes",
            source_generation_sha256=source.generation_sha256,
            source_manifest_sha256=source.source_manifest_sha256,
            prompt_sha256=source.effective_prompt_sha256, goal_sha256=goal_sha256,
            account_fingerprint=account, mode=NativeChildMode.PLANNER.value,
            allowed_tool_names=(), tool_closure_sha256=_hash([]), additional_metered_budget=0,
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            initial_owner_turn=True, _parent_agent=parent_agent, _child_agent=child,
            _source=source, _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def admit_master_planner_child(self, *, owner_turn_handle: str, parent_agent: Any,
                                   child: Any, goal: str) -> RootVerifiedNativeChildAuthorization:
        """Admit a no-tools Jarvis planner child from a registered live owner turn.

        This bootstrap path intentionally does not consume a Resources delegation
        claim: planning must be based on the root-verified active master source,
        before any expert selection exists. The owner handle, session/turn and
        Codex account are all rejoined by the root registry.
        """
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (not isinstance(owner_turn_handle, str) or not _OPAQUE.fullmatch(owner_turn_handle)
                or type(child) is type(None) or not isinstance(goal, str) or not goal
                or len(goal.encode("utf-8", errors="strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("registered owner turn and bounded planner request are required")
        try:
            parent_session = _require_id(getattr(parent_agent, "session_id"), "parent session ID")
            parent_turn = _require_id(getattr(parent_agent, "_current_turn_id"), "parent turn ID")
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            child_turn = getattr(child, "_current_turn_id", None)
            child_turn = _require_id(child_turn, "child turn ID") if child_turn else ""
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
            source = self.read_current_master_source(owner_turn_handle=owner_turn_handle)
            source_generation = getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None))
            source_manifest = getattr(source, "source_member_manifest_sha256",
                                      getattr(source, "profile_member_manifest_sha256", None))
            prompt_sha256 = getattr(source, "effective_prompt_sha256", getattr(source, "profile_prompt_sha256", None))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("planner child lineage is incomplete") from None
        if (type(source) is not RootNativeSelectedSourceDelivery
                or getattr(source, "profile_id", None) != "hermes"
                or not time.monotonic() < source.expires_monotonic
                or provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url != _CODEX_ENDPOINT or not isinstance(model, str)
                or tuple(sorted(set(tool_names))) != tool_names or tool_names):
            raise CoreNativeObservationUnavailable("current no-tools Jarvis planner source/route is unavailable")
        parent_route = tuple(getattr(parent_agent, key, None)
                             for key in ("provider", "api_mode", "base_url", "model"))
        if parent_route != (provider, api_mode, base_url, model):
            raise CoreNativeObservationUnavailable("planner child route differs from its live parent")
        row = self._rpc("admit-master-planner-child", {
            "owner_turn_handle": owner_turn_handle, "parent_session_id": parent_session,
            "parent_turn_id": parent_turn, "child_session_id": child_session,
            "child_turn_id": child_turn, "source_generation_sha256": _require_hash(source_generation, "master source generation"),
            "source_manifest_sha256": _require_hash(source_manifest, "master source manifest"),
            "prompt_sha256": _require_hash(prompt_sha256, "master prompt"),
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest(),
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
            "tool_names": [], "tool_closure_sha256": _hash([]),
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "parent_session_id", "parent_turn_id",
                    "child_session_id", "profile_id", "source_generation_sha256",
                    "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or row.get("schema") != 1
                or row["owner_turn_handle"] != owner_turn_handle
                or row["parent_session_id"] != parent_session or row["parent_turn_id"] != parent_turn
                or row["child_session_id"] != child_session or row["profile_id"] != "hermes"
                or row["source_generation_sha256"] != source_generation
                or row["source_manifest_sha256"] != source_manifest or row["prompt_sha256"] != prompt_sha256
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest()
                or row["mode"] != NativeChildMode.PLANNER.value or row["tool_names"] != []
                or row["tool_closure_sha256"] != _hash([]) or row["additional_metered_budget"] != 0
                or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root planner admission does not match this request")
        expiry = float(row["expires_monotonic"])
        now = time.monotonic()
        owner = self._owners.get(owner_turn_handle)
        if owner is None or not now < expiry <= min(owner.expires_monotonic, now + 30.0):
            raise CoreNativeObservationUnavailable("root planner admission is stale")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=owner_turn_handle, gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], parent_session_id=parent_session,
            parent_turn_id=parent_turn, child_session_id=child_session, profile_id="hermes",
            source_generation_sha256=source_generation, source_manifest_sha256=source_manifest,
            prompt_sha256=prompt_sha256, goal_sha256=row["goal_sha256"],
            account_fingerprint=row["account_fingerprint"], mode=NativeChildMode.PLANNER.value,
            allowed_tool_names=(), tool_closure_sha256=_hash([]), additional_metered_budget=0,
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            initial_owner_turn=False,
            _parent_agent=parent_agent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def read_selected_expert_source(self, *, native_claim: RootSelectedInternalProfileDispatchClaim,
                                    source_id: str) -> RootNativeSelectedSourceDelivery:
        if (type(native_claim) is not RootSelectedInternalProfileDispatchClaim
                or native_claim.profile_id != "hermes"
                or not _ID.fullmatch(source_id or "")):
            raise CoreNativeObservationUnavailable("root Resources claim and selected source ID are required")
        row = self._rpc("read-selected-expert-source", {
            "claim_handle": native_claim.claim_handle,
            "owner_turn_handle": native_claim.owner_turn_handle,
            "source_id": source_id,
        })
        required = {"schema", "nonce", "ok", "source_handle", "profile_id", "source_revision",
                    "generation_sha256", "source_manifest_sha256", "profile_manifest_sha256",
                    "prompt_b64", "prompt_sha256", "team_binding", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["profile_id"] != source_id or not _OPAQUE.fullmatch(row["source_handle"] or "")):
            raise CoreNativeObservationUnavailable("root selected source response is malformed")
        try:
            prompt = base64.b64decode(row["prompt_b64"], validate=True)
            team_binding = (RootSelectedTeamBinding.from_wire(row["team_binding"])
                            if row["team_binding"] is not None else None)
            delivery = RootNativeSelectedSourceDelivery(
                source_handle=row["source_handle"], profile_id=row["profile_id"],
                source_revision=row["source_revision"], generation_sha256=row["generation_sha256"],
                source_manifest_sha256=row["source_manifest_sha256"],
                profile_manifest_sha256=row["profile_manifest_sha256"],
                effective_prompt=prompt, effective_prompt_sha256=row["prompt_sha256"],
                expires_monotonic=float(row["expires_monotonic"]),
                _seal=_SELECTED_SOURCE_DELIVERY_SEAL,
                team_binding=team_binding,
            )
            if not time.monotonic() < float(row["expires_monotonic"]) <= min(
                    native_claim.expires_monotonic, time.monotonic() + 30.0):
                raise ValueError
            return delivery
        except Exception:
            raise CoreNativeObservationUnavailable("root selected source is stale or malformed") from None

    def admit_selected_expert_child(self, *, native_claim: RootSelectedInternalProfileDispatchClaim,
                                    child: Any, source: RootNativeSelectedSourceDelivery,
                                    goal: str,
                                    team_message: RootTeamMessageDelivery | None = None
                                    ) -> RootVerifiedNativeChildAuthorization:
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (type(native_claim) is not RootSelectedInternalProfileDispatchClaim
                or type(source) is not RootNativeSelectedSourceDelivery
                or source._seal is not _SELECTED_SOURCE_DELIVERY_SEAL
                or (team_message is not None and type(team_message) is not RootTeamMessageDelivery)
                or (team_message is not None and (
                    source.team_binding is None
                    or team_message.binding_id != source.team_binding.binding_id
                    or team_message.recipient_profile_id != source.profile_id
                    or team_message.recipient_goal != goal))
                or not isinstance(goal, str) or not goal or len(goal.encode("utf-8", "strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("typed Resources claim/source and bounded goal are required")
        try:
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            child_turn = getattr(child, "_current_turn_id", None)
            child_turn = _require_id(child_turn, "child turn ID") if child_turn else ""
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("constructed expert child lineage is incomplete") from None
        if (provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE or base_url != _CODEX_ENDPOINT
                or not isinstance(model, str) or not model
                or tuple(sorted(set(tool_names))) != tool_names
                or not set(tool_names).issubset(
                    {"web_search", "web_extract", "skills_list", "skill_view"} | _OBSIDIAN_READ_TOOL_NAMES)):
            raise CoreNativeObservationUnavailable("expert child route or finite tool closure differs")
        row = self._rpc("admit-selected-expert-child", {
            "claim_handle": native_claim.claim_handle,
            "owner_turn_handle": native_claim.owner_turn_handle,
            "source_handle": source.source_handle, "source_id": source.profile_id,
            "child_session_id": child_session, "child_turn_id": child_turn,
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", "strict")).hexdigest(),
            "team_message_handle": (team_message.message_handle
                                    if type(team_message) is RootTeamMessageDelivery else None),
            "tool_names": list(tool_names), "tool_closure_sha256": _hash(list(tool_names)),
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation", "core_source_generation",
                    "parent_session_id", "parent_turn_id", "child_session_id", "profile_id",
                    "source_generation_sha256", "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["owner_turn_handle"] != native_claim.owner_turn_handle
                or row["gateway_turn_id"] != native_claim.gateway_turn_id
                or row["owner_subject_sha256"] != native_claim.owner_subject_sha256
                or row["core_generation"] != native_claim.core_generation
                or row["core_source_generation"] != native_claim.core_source_generation
                or row["parent_session_id"] != native_claim.session_id
                or row["child_session_id"] != child_session or row["profile_id"] != source.profile_id
                or row["source_generation_sha256"] != source.generation_sha256
                or row["source_manifest_sha256"] != source.source_manifest_sha256
                or row["prompt_sha256"] != source.effective_prompt_sha256
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8", "strict")).hexdigest()
                or row["mode"] != NativeChildMode.EXPERT_READ_RESEARCH.value
                or row["tool_names"] != list(tool_names) or row["tool_closure_sha256"] != _hash(list(tool_names))
                or row["additional_metered_budget"] != 0 or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root expert admission does not match this child")
        expiry = float(row["expires_monotonic"])
        if not time.monotonic() < expiry <= min(native_claim.expires_monotonic, time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root expert admission expired")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], parent_session_id=row["parent_session_id"],
            parent_turn_id=row["parent_turn_id"], child_session_id=row["child_session_id"],
            profile_id=row["profile_id"], source_generation_sha256=row["source_generation_sha256"],
            source_manifest_sha256=row["source_manifest_sha256"], prompt_sha256=row["prompt_sha256"],
            goal_sha256=row["goal_sha256"], account_fingerprint=row["account_fingerprint"],
            mode=row["mode"], allowed_tool_names=tuple(row["tool_names"]),
            tool_closure_sha256=row["tool_closure_sha256"],
            additional_metered_budget=row["additional_metered_budget"],
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            initial_owner_turn=False,
            _parent_agent=native_claim.parent_agent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def complete_native_child(self, *, authorization: RootVerifiedNativeChildAuthorization,
                              result: Mapping[str, Any]) -> CoreVerifiedJarvisMasterPlanningCompletion | None:
        if (type(authorization) is not RootVerifiedNativeChildAuthorization
                or authorization._seal is not _NATIVE_CHILD_AUTHORIZATION_SEAL
                or not isinstance(result, Mapping)):
            raise CoreNativeObservationUnavailable("root-admitted child result is required")
        if authorization.mode != "planner":
            return None
        if result.get("status") != "completed" or result.get("failed") is True:
            raise CoreNativeObservationUnavailable("planner child did not complete successfully")
        summary = result.get("summary")
        if not isinstance(summary, str) or not summary:
            raise CoreNativeObservationUnavailable("planner child completion text is unavailable")
        response_sha256 = hashlib.sha256(summary.encode("utf-8", errors="strict")).hexdigest()
        row = self._rpc("complete-native-child", {
            "admission_handle": authorization.admission_handle,
            "status": "completed", "response_sha256": response_sha256,
        })
        required = {"schema", "nonce", "ok", "completion_handle", "owner_subject_sha256",
                    "owner_turn_handle", "gateway_turn_id", "core_generation",
                    "core_source_generation", "prompt_sha256", "response_sha256",
                    "expires_monotonic", "owner_turn_expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["completion_handle"] == ""
                or row["owner_subject_sha256"] != authorization.owner_subject_sha256
                or row["owner_turn_handle"] != authorization.owner_turn_handle
                or row["gateway_turn_id"] != authorization.gateway_turn_id
                or row["core_generation"] != authorization.core_generation
                or row["core_source_generation"] != authorization.core_source_generation
                or row["prompt_sha256"] != authorization.goal_sha256
                or row["response_sha256"] != response_sha256
                or not _OPAQUE.fullmatch(row["completion_handle"] or "")):
            raise CoreNativeObservationUnavailable("root planning completion receipt is malformed")
        expiry = float(row["expires_monotonic"])
        owner_expiry = float(row["owner_turn_expires_monotonic"])
        if (not time.monotonic() < expiry <= time.monotonic() + 30.0
                or not expiry <= owner_expiry <= time.monotonic() + 600.0):
            raise CoreNativeObservationUnavailable("root planning completion expired")
        return CoreVerifiedJarvisMasterPlanningCompletion(
            owner_subject_sha256=row["owner_subject_sha256"],
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            core_generation=row["core_generation"], core_source_generation=row["core_source_generation"],
            prompt_sha256=row["prompt_sha256"], response_sha256=row["response_sha256"],
            completion_handle=row["completion_handle"], expires_monotonic=expiry,
            owner_turn_expires_monotonic=owner_expiry,
            _client=self, _seal=_MASTER_PLANNING_COMPLETION_SEAL,
        )

    def verify_planning_completion(self, completion: CoreVerifiedJarvisMasterPlanningCompletion,
                                   *, config: Any = None, custody: Any = None) -> bool:
        if (type(completion) is not CoreVerifiedJarvisMasterPlanningCompletion
                or completion._seal is not _MASTER_PLANNING_COMPLETION_SEAL):
            return False
        try:
            row = self._rpc("verify-planning-completion", {
                "completion_handle": completion.completion_handle,
                "owner_turn_handle": completion.owner_turn_handle,
                "gateway_turn_id": completion.gateway_turn_id,
                "owner_subject_sha256": completion.owner_subject_sha256,
                "core_generation": completion.core_generation,
                "core_source_generation": completion.core_source_generation,
                "prompt_sha256": completion.prompt_sha256,
                "response_sha256": completion.response_sha256,
                "owner_turn_expires_monotonic": completion.owner_turn_expires_monotonic,
            })
            return (set(row) == {"schema", "nonce", "ok"}
                    and type(row["schema"]) is int and row["schema"] == 1
                    and row["ok"] is True)
        except Exception:
            return False

    def request_final_effect(self, *, observed_call_handle: str, review_sha256: str,
                             startup_binding_id: str | None = None):
        """Request owner approval for one exact observed normal-master tool call."""
        from hermes_installer.remote.jarvis_final_effects import FinalEffectPending, review_digest
        if (not isinstance(observed_call_handle, str) or not _OPAQUE.fullmatch(observed_call_handle)
                or not isinstance(review_sha256, str) or not _HASH.fullmatch(review_sha256)
                or (startup_binding_id is not None
                    and (not isinstance(startup_binding_id, str)
                         or not _OPAQUE.fullmatch(startup_binding_id)))):
            raise CoreNativeObservationUnavailable("observed effect identity is malformed")
        payload = {
            "observed_call_handle": observed_call_handle, "review_sha256": review_sha256,
        }
        if startup_binding_id is not None:
            payload["startup_binding_id"] = startup_binding_id
        row = self._rpc("request-final-effect", payload)
        required = {"schema", "nonce", "ok", "pending_id", "review_sha256", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["review_sha256"] != review_sha256
                or not _OPAQUE.fullmatch(row["pending_id"] or "")):
            raise CoreNativeObservationUnavailable("root final-effect pending receipt is malformed")
        try:
            return FinalEffectPending(row["pending_id"], row["review_sha256"], row["expires_monotonic"])
        except Exception:
            raise CoreNativeObservationUnavailable("root final-effect pending receipt is stale") from None

    def poll_final_effect(self, *, pending: Any, observed_call: ObservedNativeToolCall):
        """Return one exact root-consumed approval; None means still pending only."""
        from hermes_installer.remote.jarvis_final_effects import FinalEffectPending, FinalEffectPermit
        if (type(pending) is not FinalEffectPending or type(observed_call) is not ObservedNativeToolCall
                or pending.expires_monotonic > observed_call.expires_monotonic):
            raise CoreNativeObservationUnavailable("typed live final-effect request is required")
        row = self._rpc("poll-final-effect", {
            "observed_call_handle": observed_call.handle,
            "pending_id": pending.pending_id, "review_sha256": pending.review_sha256,
        })
        if set(row) == {"schema", "nonce", "ok", "state"}:
            if type(row.get("schema")) is int and row["schema"] == 1 and row["state"] == "pending":
                return None
            raise CoreNativeObservationUnavailable("owner did not approve this final effect")
        fields = {"schema", "nonce", "ok", "state", "permit"}
        permit_fields = {"pending_id", "owner_turn_handle", "gateway_turn_id", "owner_subject_sha256",
                         "core_generation", "core_source_generation", "source_generation_sha256",
                         "source_profile_id", "tool_call_id", "tool_name", "arguments_sha256",
                         "review_sha256", "expires_monotonic"}
        payload = row.get("permit") if isinstance(row, dict) else None
        if (set(row) != fields or type(row.get("schema")) is not int or row["schema"] != 1
                or row.get("state") != "permit" or not isinstance(payload, dict)
                or set(payload) != permit_fields):
            raise CoreNativeObservationUnavailable("root final-effect permit is malformed")
        try:
            permit = FinalEffectPermit(**payload)
        except Exception:
            raise CoreNativeObservationUnavailable("root final-effect permit is stale") from None
        if not permit.matches_call(observed_call, tool_name=observed_call.tool_name,
                                  arguments_sha256=observed_call.arguments_sha256,
                                  review_sha256=pending.review_sha256):
            raise CoreNativeObservationUnavailable("root final-effect permit does not match this call")
        return permit

    def authorize_current_tool_call(self, *, observed_call: ObservedNativeToolCall
                                    ) -> RootVerifiedMasterReadCall:
        """Classify this exact call as master read/effect or admitted expert read.

        A name alone never grants the bypass: the root joins the handle to the
        live owner turn, consumed provider response, current Jarvis source or
        admitted expert child, and its immutable tool closure.
        """
        if type(observed_call) is not ObservedNativeToolCall:
            raise CoreNativeObservationUnavailable("root observed native call is required")
        row = self._rpc("authorize-master-read-call", {
            "observed_call_handle": observed_call.handle,
        })
        fields = {"schema", "nonce", "ok", "observed_call_handle", "owner_turn_handle",
                  "tool_call_id", "tool_name", "arguments_sha256", "source_generation_sha256",
                  "mode", "expires_monotonic"}
        if (set(row) != fields or type(row.get("schema")) is not int or row["schema"] != 1
                or row["observed_call_handle"] != observed_call.handle
                or row["owner_turn_handle"] != observed_call.owner_turn_handle
                or row["tool_call_id"] != observed_call.tool_call_id
                or row["tool_name"] != observed_call.tool_name
                or row["arguments_sha256"] != observed_call.arguments_sha256):
            raise CoreNativeObservationUnavailable("root caller classification is malformed")
        try:
            receipt = RootVerifiedMasterReadCall(
                observed_call_handle=row["observed_call_handle"],
                owner_turn_handle=row["owner_turn_handle"], tool_call_id=row["tool_call_id"],
                tool_name=row["tool_name"], arguments_sha256=row["arguments_sha256"],
                source_generation_sha256=row["source_generation_sha256"], mode=row["mode"],
                expires_monotonic=row["expires_monotonic"], _seal=_MASTER_READ_CALL_SEAL)
        except Exception:
            raise CoreNativeObservationUnavailable("root caller classification is stale") from None
        if not receipt.matches_call(observed_call, tool_name=observed_call.tool_name,
                                   arguments_sha256=observed_call.arguments_sha256):
            raise CoreNativeObservationUnavailable("root caller classification changed")
        if (observed_call.tool_name in _MASTER_READ_TOOL_NAMES
                and receipt.mode not in {"master_read", "expert_read"}
                or observed_call.tool_name not in _MASTER_READ_TOOL_NAMES
                and receipt.mode != "master_effect"):
            raise CoreNativeObservationUnavailable("root caller classification has the wrong effect mode")
        return receipt

    def authorize_master_read_call(self, *, observed_call: ObservedNativeToolCall
                                   ) -> RootVerifiedMasterReadCall:
        """Compatibility spelling for the root current-caller classifier."""
        return self.authorize_current_tool_call(observed_call=observed_call)

    def bind_obsidian_native_vault(self):
        """Request the fixed selected-owner vault binding for this exact Core process."""
        from .obsidian_native_scope import _decode_startup_binding
        row = self._rpc("bind-obsidian-native-vault", {})
        binding = _decode_startup_binding(row)
        if (binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000):
            raise CoreNativeObservationUnavailable("root Obsidian binding names a different Core process")
        return binding

    def authorize_obsidian_call_scope(self, *, observed_call: ObservedNativeToolCall,
                                      binding: Any):
        """Obtain the exact root classification/mission/note scope for one call."""
        from .obsidian_native_scope import (
            RootSelectedObsidianVaultBinding, _decode_call_scope,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000):
            raise CoreNativeObservationUnavailable("current Core Obsidian binding and call are required")
        row = self._rpc("authorize-obsidian-call-scope", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id,
        })
        return _decode_call_scope(row, binding=binding, observed_call=observed_call)

    def record_obsidian_draft_origin(self, *, observed_call: ObservedNativeToolCall,
                                    binding: Any, draft_id: str) -> str:
        """Ask ROOT to join a just-created private draft to this exact native call."""
        from .obsidian_native_scope import RootSelectedObsidianVaultBinding
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)):
            raise CoreNativeObservationUnavailable("current Core draft call and binding are required")
        row = self._rpc("record-obsidian-draft-origin", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id, "draft_id": draft_id,
        })
        if (set(row) != {"schema", "nonce", "ok", "origin_record_sha256"}
                or type(row.get("schema")) is not int or row["schema"] != 1
                or not _HASH.fullmatch(row.get("origin_record_sha256", ""))):
            raise CoreNativeObservationUnavailable("root Obsidian draft origin receipt is malformed")
        return row["origin_record_sha256"]

    def resolve_obsidian_draft_origin(self, *, observed_call: ObservedNativeToolCall,
                                      binding: Any, draft_id: str,
                                      expected_content_sha256: str):
        """Resolve only an opaque existing draft under an exact current owner call."""
        from .obsidian_native_scope import (
            RootObsidianDraftOrigin, RootSelectedObsidianVaultBinding,
            _decode_draft_origin,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                or not _HASH.fullmatch(expected_content_sha256 or "")):
            raise CoreNativeObservationUnavailable("current Core promotion and binding are required")
        row = self._rpc("resolve-obsidian-draft-origin", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id, "draft_id": draft_id,
            "expected_content_sha256": expected_content_sha256,
        })
        origin = _decode_draft_origin(row)
        if (type(origin) is not RootObsidianDraftOrigin
                or origin.draft_id != draft_id
                or origin.owner_subject_sha256 != binding.owner_subject_sha256
                or origin.registration_sha256 != binding.registration_sha256
                or origin.content_sha256 != expected_content_sha256):
            raise CoreNativeObservationUnavailable("root Obsidian draft origin differs from the reviewed call")
        return origin

    def read_obsidian_private_draft(self, *, observed_call: ObservedNativeToolCall,
                                    binding: Any, draft_id: str,
                                    expected_content_sha256: str):
        """Read exact retained private-draft bytes for this current Jarvis turn only."""
        from .obsidian_native_scope import (
            RootObsidianDraftReview, RootSelectedObsidianVaultBinding,
            _decode_draft_review,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                or not _HASH.fullmatch(expected_content_sha256 or "")):
            raise CoreNativeObservationUnavailable("current Jarvis draft-review call and binding are required")
        row = self._rpc("read-obsidian-private-draft", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id, "draft_id": draft_id,
            "expected_content_sha256": expected_content_sha256,
        })
        review = _decode_draft_review(row)
        if (type(review) is not RootObsidianDraftReview or review.draft_id != draft_id
                or review.content_sha256 != expected_content_sha256):
            raise CoreNativeObservationUnavailable("root Obsidian draft review differs from this exact call")
        return review

    def confirm_obsidian_draft_read_delivery(self, *, observed_call: ObservedNativeToolCall,
                                             binding: Any,
                                             tool_result: Mapping[str, Any]) -> None:
        """Confirm the exact prepared native result only after its handler returned."""
        from .obsidian_native_scope import RootSelectedObsidianVaultBinding
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not isinstance(tool_result, Mapping)
                or type(tool_result.get("read_delivery")) is not dict
                or type(tool_result.get("review_complete")) is not bool):
            raise CoreNativeObservationUnavailable("native draft-review result is required")
        receipt = tool_result["read_delivery"]
        if (set(receipt) != {"receipt_id", "receipt_sha256", "complete", "covered_byte_length"}
                or receipt.get("complete") is not tool_result["review_complete"]
                or receipt.get("covered_byte_length") != (
                    tool_result["byte_length"] if tool_result["review_complete"] else 0)
                or not _OPAQUE.fullmatch(receipt.get("receipt_id", ""))
                or not _HASH.fullmatch(receipt.get("receipt_sha256", ""))):
            raise CoreNativeObservationUnavailable("draft-review result delivery receipt is incomplete")
        output_sha256 = hashlib.sha256(json.dumps(
            dict(tool_result), ensure_ascii=False, sort_keys=True, separators=(",", ":"),
            allow_nan=False).encode("utf-8", "strict")).hexdigest()
        row = self._rpc("confirm-obsidian-draft-read-delivery", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id,
            "receipt_id": receipt["receipt_id"],
            "receipt_sha256": receipt["receipt_sha256"],
            "tool_result_sha256": output_sha256,
        })
        if (set(row) != {"schema", "nonce", "ok", "confirmed", "receipt_sha256"}
                or type(row.get("schema")) is not int or row["schema"] != 1
                or row.get("ok") is not True or row.get("confirmed") is not True
                or row.get("receipt_sha256") != receipt["receipt_sha256"]):
            raise CoreNativeObservationUnavailable("root did not confirm the exact native draft-review result")

    def resolve_obsidian_review_proposal(self, *, observed_call: ObservedNativeToolCall,
                                         binding: Any, draft_id: str,
                                         expected_content_sha256: str):
        """Resolve the one root proposal created before owner approval for this exact call."""
        from .obsidian_native_scope import (
            RootJarvisDraftReviewProposal, RootSelectedObsidianVaultBinding,
            _decode_draft_review_proposal,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                or not _HASH.fullmatch(expected_content_sha256 or "")):
            raise CoreNativeObservationUnavailable("current Core promotion and binding are required")
        row = self._rpc("resolve-obsidian-review-proposal", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id, "draft_id": draft_id,
            "expected_content_sha256": expected_content_sha256,
        })
        proposal = _decode_draft_review_proposal(row)
        if (type(proposal) is not RootJarvisDraftReviewProposal
                or proposal.draft_id != draft_id
                or proposal.content_sha256 != expected_content_sha256
                or proposal.observed_call_handle != observed_call.handle):
            raise CoreNativeObservationUnavailable("root review proposal differs from this exact call")
        return proposal

    def reserve_obsidian_draft_completion(self, *, observed_call: ObservedNativeToolCall,
                                         binding: Any, origin: Any, proposal: Any,
                                         permit: Any, destination: str,
                                         expected_base_sha256: str | None) -> None:
        """Durably reserve archive and tombstone capacity before the public-note CAS."""
        from .jarvis_final_effects import FinalEffectPermit, review_digest
        from .obsidian_native_scope import (
            RootJarvisDraftReviewProposal, RootObsidianDraftOrigin,
            RootSelectedObsidianVaultBinding,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or type(origin) is not RootObsidianDraftOrigin
                or type(proposal) is not RootJarvisDraftReviewProposal
                or type(permit) is not FinalEffectPermit
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000
                or not proposal.matches(observed_call=observed_call, origin=origin,
                    owner_subject_sha256=binding.owner_subject_sha256,
                    owner_turn_handle=observed_call.owner_turn_handle)
                or permit.owner_turn_handle != proposal.owner_turn_handle
                or permit.owner_subject_sha256 != binding.owner_subject_sha256
                or not permit.matches_call(observed_call,
                    tool_name="obsidian_promote_reviewed_draft",
                    arguments_sha256=observed_call.arguments_sha256,
                    review_sha256=review_digest("obsidian_promote_reviewed_draft",
                                                observed_call.arguments_sha256))):
            raise CoreNativeObservationUnavailable("current approved Jarvis promotion is required for capacity reservation")
        row = self._rpc("reserve-obsidian-draft-completion", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id,
            "draft_id": origin.draft_id,
            "origin_record_sha256": origin.origin_record_sha256,
            "proposal_sha256": proposal.proposal_sha256,
            "pending_id": permit.pending_id,
            "review_sha256": permit.review_sha256,
            "destination": destination,
            "expected_base_sha256": expected_base_sha256,
        })
        if (set(row) != {"schema", "nonce", "ok", "reservation_record_sha256"}
                or type(row.get("schema")) is not int or row["schema"] != 1
                or row["ok"] is not True
                or not _HASH.fullmatch(row.get("reservation_record_sha256", ""))):
            raise CoreNativeObservationUnavailable("root Obsidian capacity reservation receipt is malformed")

    def complete_obsidian_draft_origin(self, *, observed_call: ObservedNativeToolCall,
                                       binding: Any, origin: Any, proposal: Any,
                                       permit: Any, destination: str,
                                       expected_base_sha256: str | None,
                                       saved_projection: Mapping[str, Any]) -> None:
        """Retire provenance only after ROOT independently verifies the committed result."""
        from .jarvis_final_effects import FinalEffectPermit, review_digest
        from .obsidian_native_scope import (
            RootJarvisDraftReviewProposal, RootObsidianDraftOrigin,
            RootSelectedObsidianVaultBinding,
        )
        if (type(observed_call) is not ObservedNativeToolCall
                or type(binding) is not RootSelectedObsidianVaultBinding
                or type(origin) is not RootObsidianDraftOrigin
                or type(proposal) is not RootJarvisDraftReviewProposal
                or type(permit) is not FinalEffectPermit
                or not isinstance(saved_projection, Mapping)
                or binding.core_pid != os.getpid() or binding.selected_owner_uid != os.geteuid()
                or os.geteuid() != 1000):
            raise CoreNativeObservationUnavailable("typed current promotion completion evidence is required")
        if (not proposal.matches(observed_call=observed_call, origin=origin,
                owner_subject_sha256=binding.owner_subject_sha256,
                owner_turn_handle=observed_call.owner_turn_handle)
                or permit.owner_turn_handle != proposal.owner_turn_handle
                or permit.owner_subject_sha256 != binding.owner_subject_sha256
                or not permit.matches_call(observed_call,
                    tool_name="obsidian_promote_reviewed_draft",
                    arguments_sha256=observed_call.arguments_sha256,
                    review_sha256=review_digest("obsidian_promote_reviewed_draft",
                                                observed_call.arguments_sha256))):
            raise CoreNativeObservationUnavailable("promotion completion differs from the approved Jarvis proposal")
        note_id = saved_projection.get("noteId")
        content_sha = saved_projection.get("contentSha256")
        title = saved_projection.get("title")
        if (not isinstance(note_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,96}", note_id)
                or not _HASH.fullmatch(content_sha or "") or not isinstance(title, str)
                or not 1 <= len(title) <= 160):
            raise CoreNativeObservationUnavailable("promoted note verification summary is malformed")
        row = self._rpc("complete-obsidian-draft-origin", {
            "observed_call_handle": observed_call.handle,
            "startup_binding_id": binding.binding_id,
            "draft_id": origin.draft_id,
            "origin_record_sha256": origin.origin_record_sha256,
            "proposal_sha256": proposal.proposal_sha256,
            "pending_id": permit.pending_id,
            "review_sha256": permit.review_sha256,
            "destination": destination,
            "expected_base_sha256": expected_base_sha256,
            "note_id": note_id, "content_sha256": content_sha, "title": title,
        })
        if (set(row) != {"schema", "nonce", "ok", "completed_record_sha256"}
                or type(row.get("schema")) is not int or row["schema"] != 1
                or row["ok"] is not True or not _HASH.fullmatch(row.get("completed_record_sha256", ""))):
            raise CoreNativeObservationUnavailable("root Obsidian completion receipt is malformed")


class RootCoreNativeObservationRegistry:
    """Root-memory issuer joining real owner turns to protected native observations.

    This registry is composed inside the existing inspector process. It accepts
    owner turns only from that process's independently validated gateway op;
    core worker frames are accepted only after a fresh current-process custody
    check on their Unix peer credentials.
    """

    def __init__(self, custody: Any, selected_profile_source: Any, *, config: Any):
        from hermes_installer.remote.core_gateway_inspector import CoreNativeObserverCustody
        from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        if type(custody) is not CoreNativeObserverCustody:
            raise CoreNativeObservationUnavailable("sealed current-core observer custody is required")
        if (selected_profile_source is not None
                and (type(selected_profile_source) is not RootVerifiedJarvisMasterSource
                     or selected_profile_source.profile_id != "hermes"
                     or selected_profile_source.native_profile_key != "default"
                     or selected_profile_source.display_name != "Jarvis")):
            raise CoreNativeObservationUnavailable("sealed current Jarvis master source is required")
        if (selected_profile_source is not None
                and not callable(getattr(selected_profile_source, "is_current_sealed", None))):
            raise CoreNativeObservationUnavailable("current active Resources source verifier is unavailable")
        self._custody = custody
        self._source = selected_profile_source
        self._config = config
        self._lock = threading.RLock()
        self._owners: dict[str, Any] = {}
        # Keep a bounded tombstone for planned sessions even if their owner-turn
        # record is retired; a later middleware lookup must not misclassify a
        # stale planned request as ordinary chat and restore its original tools.
        self._planning_sessions: dict[str, Any] = {}
        self._master_review_sessions: dict[str, Any] = {}
        self._owner_turn_bindings: dict[str, str] = {}
        self._policies: dict[str, dict[str, Any]] = {}
        self._owner_policy_handles: dict[str, str] = {}
        self._attempts: dict[str, dict[str, Any]] = {}
        self._calls: dict[str, dict[str, Any]] = {}
        self._claims: dict[str, dict[str, Any]] = {}
        self._mission_pending: dict[str, dict[str, Any]] = {}
        self._mission_authorized_claims: set[str] = set()
        self._consumed_dispatches: dict[str, dict[str, Any]] = {}
        self._child_sessions: dict[str, dict[str, Any]] = {}
        self._planning_completions: dict[str, dict[str, Any]] = {}
        self._master_review_completions: dict[str, dict[str, Any]] = {}
        self._expert_completions: dict[str, dict[str, Any]] = {}
        self._lifecycle_startup_probes: dict[str, dict[str, Any]] = {}
        self._lifecycle_startup_attempts: dict[str, dict[str, Any]] = {}
        self._team_completion_evidence: dict[str, dict[str, Any]] = {}
        self._team_bindings: dict[str, RootSelectedTeamBinding] = {}
        self._team_messages: dict[str, dict[str, Any]] = {}
        self._team_completion_counts: dict[str, int] = {}
        self._team_edge_issued: set[str] = set()
        # Unlike the gateway-owned mission SQLite rows, these records are retained
        # only after this root process observed and validated the native completion.
        self._master_plan_records: dict[tuple[str, str, int], RootObservedMasterPlanRecord] = {}
        self._master_selections: dict[str, dict[str, Any]] = {}
        self._selected_source_deliveries: dict[str, dict[str, Any]] = {}
        self._master_source_deliveries: dict[str, dict[str, Any]] = {}
        self._obsidian_bindings: dict[str, dict[str, Any]] = {}
        self._obsidian_scoped_calls: set[str] = set()
        self._obsidian_draft_origins: dict[tuple[str, str], dict[str, Any]] = {}
        self._obsidian_completed_drafts: dict[tuple[str, str], dict[str, Any]] = {}
        self._obsidian_resolved_origin_calls: set[str] = set()
        self._obsidian_draft_read_deliveries: dict[str, dict[str, Any]] = {}
        self._obsidian_draft_review_proposals: dict[str, dict[str, Any]] = {}
        self._obsidian_origin_history: list[dict[str, Any]] = []
        self._obsidian_origin_store_ok = True
        try:
            (self._obsidian_draft_origins,
             self._obsidian_completed_drafts) = _load_root_obsidian_origin_state()
            self._obsidian_origin_history = _load_root_obsidian_history()
            history_by_id = {row["record_id"]: row for row in self._obsidian_origin_history}
            if any((tomb["history_record_id"] not in history_by_id
                    or history_by_id[tomb["history_record_id"]]["record_sha256"]
                        != tomb["history_record_sha256"]
                    or history_by_id[tomb["history_record_id"]]["origin"]["origin_record_sha256"]
                        != tomb["origin_record_sha256"]
                    or history_by_id[tomb["history_record_id"]]["result"]["destination"]
                        != tomb["destination"]
                    or history_by_id[tomb["history_record_id"]]["result"]["note_id"]
                        != tomb["note_id"]
                    or history_by_id[tomb["history_record_id"]]["result"]["content_sha256"]
                        != tomb["content_sha256"])
                   for tomb in self._obsidian_completed_drafts.values()):
                raise ValueError("root Obsidian origin tombstone does not join archive")
        except Exception:
            self._obsidian_origin_store_ok = False
        self._master_source: Any = None
        self._final_effect_store: Any = None
        try:
            from hermes_installer.components.resources_active_profile_source import (
                RootVerifiedJarvisMasterSource,
            )
            self._master_source = RootVerifiedJarvisMasterSource.current_master_source(
                custody, config=config,
            )
        except Exception:
            # Ordinary ingress stays available; planning/child admission stays unavailable.
            self._master_source = None
        self._closed = False
        self._activity_started_at = time.time()
        self._activity_records: dict[str, dict[str, Any]] = {}
        self._activity_store_ok = True
        try:
            saved = _read_root_native_activity_bytes()
            if saved is not None:
                rows = _native_activity_snapshot_from_bytes(saved)
                if rows is None:
                    raise ValueError("native activity journal is malformed")
                self._activity_records = {row["execution_key"]: row for row in rows}
        except Exception:
            self._activity_store_ok = False
        if self._activity_store_ok:
            self._prune_activity_window()

    @staticmethod
    def _activity_role(profile_id: str) -> str:
        words = re.split(r"[-_]", profile_id)
        first = words[0].casefold() if words else profile_id.casefold()
        short = {"developer": "Dev", "dev": "Dev", "researcher": "Research",
                 "designer": "Design", "orchestrator": "Orchestrator"}.get(first)
        role = short or " ".join(word[:1].upper() + word[1:] for word in words if word)
        role = re.sub(r"[^A-Za-z0-9 ]", "", role)[:24].strip()
        return role or "Worker"

    def _new_activity_alias(self, owner_hash: str, profile_id: str, execution_key: str) -> str:
        names = ("Peter", "Sarah", "Alex", "Jamie", "Morgan", "Riley", "Taylor", "Jordan",
                 "Casey", "Quinn", "Avery", "Robin", "Sam", "Charlie", "Drew", "Harper")
        offset = int(hashlib.sha256(execution_key.encode("ascii")).hexdigest()[:8], 16) % len(names)
        role = self._activity_role(profile_id)
        used = {row["display_alias"] for row in self._activity_records.values()
                if row["owner_subject_sha256"] == owner_hash}
        for step in range(len(names)):
            base = f"{role} {names[(offset + step) % len(names)]}"
            if base not in used:
                return base
        base = f"{role} {names[offset]}"
        suffix = 2
        while f"{base} ·{suffix}" in used:
            suffix += 1
        return f"{base} ·{suffix}"

    def _prune_activity_window(self, observed_at: float | None = None) -> None:
        """Keep durable activity and dedupe state inside the declared read window."""
        cutoff = (time.time() if observed_at is None else observed_at) - _NATIVE_ACTIVITY_WINDOW_SECONDS
        expired = [key for key, row in self._activity_records.items()
                   if row.get("created_at", 0) < cutoff]
        if not expired:
            return
        for key in expired:
            self._activity_records.pop(key, None)
        self._persist_activity()

    def _bind_team_activity(self, child: dict[str, Any], row: dict[str, Any]) -> None:
        """Join a persisted activity key only to its actual retained Team admission."""
        owner = child.get("owner")
        source = child.get("source")
        binding_id = child.get("team_binding_id")
        binding = self._team_bindings.get(binding_id) if isinstance(binding_id, str) else None
        mission = getattr(owner, "mission_binding", None)
        now_mono, now_wall = time.monotonic(), time.time()
        if (type(binding) is not RootSelectedTeamBinding or binding._seal is not _TEAM_BINDING_SEAL
                or type(source) is not RootNativeSelectedSourceDelivery
                or source.team_binding is not binding
                or type(mission) is not MissionBinding
                or binding.owner_subject_sha256 != owner.owner_subject_sha256
                or binding.mission_id != mission.mission_id or binding.revision != mission.revision
                or binding.goal_sha256 != mission.task_sha256
                or binding.expires_monotonic <= now_mono
                or owner.core_generation != self._custody.core_generation
                or owner.core_source_generation != self._custody.core_source_generation
                or child.get("profile_id") not in binding.selected_expert_ids
                or source.profile_id != child.get("profile_id")
                or source.generation_sha256 != binding.bundle_generation_sha256
                or row["owner_subject_sha256"] != binding.owner_subject_sha256
                or row["mission_id"] != binding.mission_id
                or row["mission_revision"] != binding.revision):
            self._activity_store_ok = False
            return
        binding_digest = hashlib.sha256(
            b"jarvis-team-binding-lineage-v1\0" + binding.binding_id.encode("ascii")).hexdigest()
        if row.get("team_lineage") is not None:
            return
        prior = [item.get("team_lineage") for item in self._activity_records.values()
                 if item.get("team_lineage") is not None
                 and item["owner_subject_sha256"] == owner.owner_subject_sha256
                 and item["team_lineage"]["binding_id_sha256"] == binding_digest]
        lineage = prior[0] if prior else None
        if lineage is not None and any(
                value != lineage for value in prior[1:]):
            self._activity_store_ok = False
            return
        team_execution_key = (lineage["team_execution_key"] if lineage is not None
                              else secrets.token_urlsafe(24))
        admission_deadline = now_wall + max(0.0, float(child["expiry"]) - now_mono)
        binding_deadline = (lineage["binding_deadline_at"] if lineage is not None else
            now_wall + max(0.0, float(binding.expires_monotonic) - now_mono))
        team_lineage = {
            "team_execution_key": team_execution_key,
            "binding_id_sha256": binding_digest,
            "team_id": binding.team_id,
            "team_source_revision": binding.source_revision,
            "catalog_sha256": binding.catalog_sha256,
            "bundle_generation_sha256": binding.bundle_generation_sha256,
            "bundle_member_sha256": binding.bundle_member_sha256,
            "selected_expert_ids": list(binding.selected_expert_ids),
            "binding_deadline_at": binding_deadline,
            "admission_deadline_at": admission_deadline,
        }
        if lineage is not None:
            for key in team_lineage:
                if key not in {"admission_deadline_at"} and team_lineage[key] != lineage[key]:
                    self._activity_store_ok = False
                    return
        row["team_lineage"] = team_lineage

    def _record_team_discussion_relation(self, *, recipient: dict[str, Any],
                                         sender: dict[str, Any], team_message: dict[str, Any],
                                         sender_completion_handle: str,
                                         recipient_completion_handle: str,
                                         recipient_request_sha256: str,
                                         sender_response_sha256: str,
                                         recipient_response_sha256: str,
                                         sender_text_sha256: str,
                                         recipient_text_sha256: str) -> None:
        """Persist a directed edge only after root-verified recipient completion."""
        recipient_activity = recipient.get("activity")
        sender_execution_key = sender.get("execution_key")
        sender_activity = self._activity_records.get(sender_execution_key)
        lineage = (recipient_activity.get("team_lineage")
                   if isinstance(recipient_activity, dict) else None)
        sender_lineage = (sender_activity.get("team_lineage")
                          if isinstance(sender_activity, dict) else None)
        binding = self._team_bindings.get(recipient.get("team_binding_id"))
        if (not self._activity_store_ok or not isinstance(lineage, dict)
                or not isinstance(sender_lineage, dict)
                or type(binding) is not RootSelectedTeamBinding
                or binding._seal is not _TEAM_BINDING_SEAL
                or not isinstance(team_message, dict)
                or team_message.get("recipient_completion_handle") != recipient_completion_handle
                or team_message.get("recipient_profile_id") != recipient.get("profile_id")
                or team_message.get("recipient_goal_sha256") != recipient.get("goal_sha256")
                or sender.get("profile_id") != team_message.get("sender_profile_id")
                or sender.get("completion_handle") != sender_completion_handle
                or sender.get("team_binding_id") != recipient.get("team_binding_id")
                or lineage["binding_id_sha256"] != sender_lineage["binding_id_sha256"]
                or lineage["team_execution_key"] != sender_lineage["team_execution_key"]
                or sender_activity["profile_id"] != sender.get("profile_id")
                or recipient_activity["profile_id"] != recipient.get("profile_id")
                or sender_activity["owner_subject_sha256"] != recipient_activity["owner_subject_sha256"]
                or sender_activity["mission_id"] != recipient_activity["mission_id"]
                or sender_activity["mission_revision"] != recipient_activity["mission_revision"]
                or sender.get("owner") is not recipient.get("owner")
                or team_message.get("owner") is not recipient.get("owner")
                or sender.get("profile_id") == recipient.get("profile_id")):
            # This path runs only after the real recipient completion callback. If
            # its exact root joins cannot be retained, fail telemetry closed rather
            # than returning a deceptively complete topology.
            self._activity_store_ok = False
            return
        relation_dedupe = hashlib.sha256(b"jarvis-team-relation-v1\0" + b"\0".join(
            value.encode("ascii") for value in (binding.binding_id, sender_completion_handle,
                team_message["message_handle"], recipient_completion_handle,
                recipient_request_sha256, sender_response_sha256, recipient_response_sha256))).hexdigest()
        existing = [row.get("team_relation") for row in self._activity_records.values()
                    if isinstance(row.get("team_relation"), dict)
                    and row["team_relation"]["binding_id_sha256"] == lineage["binding_id_sha256"]]
        if existing:
            if len(existing) == 1 and existing[0]["dedupe_sha256"] == relation_dedupe:
                return
            self._activity_store_ok = False
            return
        event_at = time.time()
        relation = {
            "relation_key": secrets.token_urlsafe(24), "dedupe_sha256": relation_dedupe,
            "binding_id_sha256": lineage["binding_id_sha256"],
            "team_execution_key": lineage["team_execution_key"],
            "sender_execution_key": sender_execution_key,
            "recipient_execution_key": recipient_activity["execution_key"],
            "sender_profile_id": sender["profile_id"],
            "recipient_profile_id": recipient.get("profile_id"),
            "sender_completion_sha256": hashlib.sha256(sender_completion_handle.encode("ascii")).hexdigest(),
            "recipient_completion_sha256": hashlib.sha256(recipient_completion_handle.encode("ascii")).hexdigest(),
            "team_message_sha256": hashlib.sha256(team_message["message_handle"].encode("ascii")).hexdigest(),
            "excerpt_sha256": team_message["excerpt_sha256"],
            "recipient_request_sha256": recipient_request_sha256,
            "sender_response_sha256": sender_response_sha256,
            "recipient_response_sha256": recipient_response_sha256,
            "sender_text_sha256": sender_text_sha256,
            "recipient_text_sha256": recipient_text_sha256,
            "sender_source_generation_sha256": sender_activity["source_generation_sha256"],
            "recipient_source_generation_sha256": recipient_activity["source_generation_sha256"],
            "event_at": event_at,
        }
        recipient_activity["team_relation"] = relation
        recipient_activity["updated_at"] = max(recipient_activity["updated_at"], event_at)
        self._persist_activity()

    def _persist_activity(self) -> None:
        if not self._activity_store_ok:
            return
        rows = []
        for row in sorted(self._activity_records.values(), key=lambda item: item["created_at"]):
            serialized = dict(row)
            serialized.setdefault("team_lineage", None)
            serialized.setdefault("team_relation", None)
            serialized.setdefault("history_partial", False)
            rows.append(serialized)
        payload = {"schema": 2, "instances": rows}
        raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("utf-8")
        if len(raw) > _NATIVE_ACTIVITY_MAX_BYTES:
            self._activity_store_ok = False
            return
        try:
            _publish_root_native_activity_bytes(raw)
        except Exception:
            self._activity_store_ok = False

    def _record_child_activity(self, child: dict[str, Any], *, kind: str,
                               status: str, event_id: str, duration_ms: int | None = None,
                               tool_count: int = 0) -> None:
        """Persist only callback facts already checked by the root observer."""
        owner = child.get("owner")
        if owner is None or not self._activity_store_ok:
            return
        self._prune_activity_window()
        row = child.get("activity")
        if row is None:
            binding = owner.mission_binding
            mission_id = revision = None
            if type(binding) is MissionBinding:
                mission_id, revision = binding.mission_id, binding.revision
            elif owner.planning_context is not None:
                mission_id, revision = (owner.planning_context.mission_id,
                                        owner.planning_context.revision)
            source = child.get("source")
            if source is None:
                return
            execution_key = secrets.token_urlsafe(24)
            alias = self._new_activity_alias(owner.owner_subject_sha256,
                                             child["profile_id"], execution_key)
            row = {
                "execution_key": execution_key, "display_alias": alias,
                "owner_subject_sha256": owner.owner_subject_sha256,
                "mission_id": mission_id, "mission_revision": revision,
                "gateway_turn_id": owner.gateway_turn_id,
                "profile_id": child["profile_id"],
                "source_revision": source.source_revision,
                "source_generation_sha256": child["source_generation_sha256"],
                "source_manifest_sha256": child["source_manifest_sha256"],
                "core_generation": owner.core_generation,
                "core_source_generation": owner.core_source_generation,
                "child_lineage_sha256": hashlib.sha256(
                    b"jarvis-native-child-lineage-v1\0" + child["session_id"].encode("utf-8")).hexdigest(),
                "parent_lineage_sha256": hashlib.sha256(
                    b"jarvis-native-parent-lineage-v1\0" + child["parent_session_id"].encode("utf-8")
                    + b"\0" + child["parent_turn_id"].encode("utf-8")).hexdigest(),
                "created_at": time.time(), "updated_at": time.time(),
                "tool_count_total": 0, "seen_event_ids": [],
                "status": "admitted", "events": [],
                "team_lineage": None, "team_relation": None, "history_partial": False,
            }
            child["activity"] = row
            self._activity_records[execution_key] = row
            if len(self._activity_records) > _NATIVE_ACTIVITY_MAX_INSTANCES:
                oldest = min(self._activity_records.values(), key=lambda item: item["created_at"])
                if oldest is not row:
                    self._activity_records.pop(oldest["execution_key"], None)
                    for retained in self._activity_records.values():
                        retained["history_partial"] = True
            kind, status = "admitted", "accepted"
            event_id = hashlib.sha256(
                b"jarvis-native-activity-admitted-v1\0" + execution_key.encode("ascii")).hexdigest()
            if child.get("team_binding_id") is not None:
                self._bind_team_activity(child, row)
        events = row["events"]
        if kind == "tool_call" and (type(tool_count) is not int or not 0 <= tool_count <= 128):
            return
        if event_id in row["seen_event_ids"]:
            return
        row["seen_event_ids"].append(event_id)
        del row["seen_event_ids"][:-_NATIVE_ACTIVITY_MAX_DEDUP_IDS_PER_INSTANCE]
        events.append({"event_id": event_id, "kind": kind, "status": status,
                       "at": time.time(), "duration_ms": duration_ms,
                       "tool_count": tool_count})
        if kind == "tool_call":
            row["tool_count_total"] = min(1_000_000, row["tool_count_total"] + tool_count)
        del events[:-_NATIVE_ACTIVITY_MAX_EVENTS_PER_INSTANCE]
        row["updated_at"] = time.time()
        row["status"] = ("completed" if kind == "completed" and status == "completed" else
                         "responded" if kind == "response" and status == "completed" else
                         "unknown" if kind == "response" and status == "incomplete" else
                         "running" if kind == "attempt" else row["status"])
        self._persist_activity()

    def enroll_lifecycle_startup_probe(self, *, cohort: RootLifecycleStartupCohort) -> str:
        """Enroll one exact guarded-new process for one fixed startup chat attempt."""
        if (type(cohort) is not RootLifecycleStartupCohort or not cohort.is_root_selected()
                or self._closed or os.geteuid() != 0):
            raise CoreNativeObservationUnavailable("current guarded-new cohort is required")
        try:
            from .core_gateway_inspector import (
                CORE_SERVICE_UNIT, _boot_id, _current_core_source, _proc_start_ticks,
                _unit_properties,
            )
            now = time.monotonic()
            props = _unit_properties(CORE_SERVICE_UNIT, deadline=cohort.deadline_monotonic)
            if (int(props.get("MainPID", "0")) != cohort.peer_pid
                    or props.get("InvocationID") != cohort.invocation_id
                    or _boot_id() != cohort.boot_id
                    or _proc_start_ticks(cohort.peer_pid) != cohort.peer_start_ticks
                    or _current_core_source(self._config, deadline=cohort.deadline_monotonic)
                       != cohort.core_source_generation
                    or now >= cohort.deadline_monotonic):
                raise ValueError
            pidfd = os.pidfd_open(cohort.peer_pid, 0)
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0):
                os.close(pidfd)
                raise ValueError
            handle = secrets.token_urlsafe(32)
            probe_id = secrets.token_urlsafe(24)
            session_id = secrets.token_urlsafe(24)
            nonce = secrets.token_hex(16)
            expected_text_sha256 = hashlib.sha256(
                (_LIFECYCLE_STARTUP_RESPONSE_PREFIX + nonce).encode("ascii")).hexdigest()
            with self._lock:
                if len(self._lifecycle_startup_probes) >= 8 or handle in self._lifecycle_startup_probes:
                    os.close(pidfd)
                    raise ValueError
                self._lifecycle_startup_probes[handle] = {
                    "cohort": cohort, "pidfd": pidfd, "probe_id": probe_id,
                    "session_id": session_id, "nonce": nonce,
                    "expected_text_sha256": expected_text_sha256,
                    "expiry": cohort.deadline_monotonic, "claimed_peer": None,
                    "attempt_handle": None, "completion_handle": None,
                    "consumed": False,
                }
            return handle
        except Exception:
            raise CoreNativeObservationUnavailable("guarded startup probe enrollment failed") from None

    def consume_lifecycle_startup_completion(
        self, *, probe_handle: str, completion_handle: str,
        native_response_sha256: str,
    ) -> CoreVerifiedLifecycleStartupCompletion:
        """Consume a provider observation only after the actual native terminal agrees."""
        if (not _OPAQUE.fullmatch(probe_handle or "")
                or not _OPAQUE.fullmatch(completion_handle or "")
                or not _HASH.fullmatch(native_response_sha256 or "")):
            raise CoreNativeObservationUnavailable("startup completion reference is malformed")
        try:
            with self._lock:
                row = self._lifecycle_startup_probes.get(probe_handle)
                now = time.monotonic()
                if (not isinstance(row, dict) or row.get("consumed") is True
                        or row.get("completion_handle") != completion_handle
                        or now >= row.get("expiry", 0)):
                    raise ValueError
                provider = row.get("provider_terminal")
                cohort = row.get("cohort")
                if (not isinstance(provider, dict)
                        or type(cohort) is not RootLifecycleStartupCohort
                        or not cohort.is_root_selected()
                        or native_response_sha256 != provider.get("response_text_sha256")
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise ValueError
                proof = CoreVerifiedLifecycleStartupCompletion(
                    schema=1, purpose="lifecycle-startup",
                    probe_handle=probe_handle, completion_handle=completion_handle,
                    transaction_id=cohort.transaction_id,
                    starting_journal_sha256=cohort.starting_journal_sha256,
                    cohort_sha256=cohort.cohort_sha256,
                    core_generation=cohort.core_generation,
                    old_adapter_generation=cohort.old_adapter_generation,
                    new_adapter_generation=cohort.new_adapter_generation,
                    core_source_generation=cohort.core_source_generation,
                    generation_a1_sha256=cohort.generation_a1_sha256,
                    js_sha256=cohort.js_sha256, rs_sha256=cohort.rs_sha256,
                    u1_sha256=cohort.u1_sha256, l1_sha256=cohort.l1_sha256,
                    primary_source_sha256=cohort.primary_source_sha256,
                    active_soul_sha256=cohort.active_soul_sha256,
                    native_inventory_sha256=cohort.native_inventory_sha256,
                    peer_pid=cohort.peer_pid, peer_uid=cohort.peer_uid,
                    peer_gid=cohort.peer_gid, peer_start_ticks=cohort.peer_start_ticks,
                    boot_id=cohort.boot_id,
                    invocation_id=cohort.invocation_id, probe_id=row["probe_id"],
                    session_id=row["session_id"], turn_id=provider["turn_id"],
                    api_request_id=provider["api_request_id"],
                    provider_request_sha256=provider["request_sha256"],
                    provider_response_sha256=provider["response_sha256"],
                    provider_response_text_sha256=provider["response_text_sha256"],
                    native_response_sha256=native_response_sha256,
                    prompt_sha256=provider["prompt_sha256"],
                    provider=cohort.provider, api_mode=cohort.api_mode,
                    base_url=cohort.base_url, model=cohort.model,
                    account_fingerprint=cohort.account_fingerprint,
                    tools_sha256=hashlib.sha256(b"[]").hexdigest(),
                    deadline_monotonic=cohort.deadline_monotonic,
                    _seal=_LIFECYCLE_STARTUP_COMPLETION_SEAL,
                )
                if not proof.is_root_verified():
                    raise ValueError
                row["consumed"] = True
                return proof
        except Exception:
            raise CoreNativeObservationUnavailable("startup completion is stale, mismatched or replayed") from None

    def _lifecycle_startup_peer_current(self, row: Mapping[str, Any],
                                        cohort: RootLifecycleStartupCohort) -> bool:
        try:
            from .core_gateway_inspector import (
                CORE_SERVICE_UNIT, _boot_id, _current_core_source, _proc_start_ticks,
                _unit_properties,
            )
            poller = select.poll()
            poller.register(row["pidfd"], select.POLLIN | select.POLLHUP | select.POLLERR)
            if (poller.poll(0) or time.monotonic() >= min(
                    cohort.deadline_monotonic, row["expiry"])
                    or _boot_id() != cohort.boot_id
                    or _proc_start_ticks(cohort.peer_pid) != cohort.peer_start_ticks):
                return False
            props = _unit_properties(CORE_SERVICE_UNIT, deadline=cohort.deadline_monotonic)
            return (int(props.get("MainPID", "0")) == cohort.peer_pid
                    and props.get("InvocationID") == cohort.invocation_id
                    and _current_core_source(self._config, deadline=cohort.deadline_monotonic)
                       == cohort.core_source_generation)
        except Exception:
            return False

    def _lifecycle_startup_request_current(self, request: Mapping[str, Any],
                                          peer: tuple[int, int, int]) -> bool:
        try:
            handle = request.get("probe_handle")
            if not isinstance(handle, str):
                attempt = self._lifecycle_startup_attempts.get(request.get("attempt_handle"))
                handle = attempt.get("probe_handle") if isinstance(attempt, dict) else None
            row = self._lifecycle_startup_probes.get(handle)
            cohort = row.get("cohort") if isinstance(row, dict) else None
            return bool(row is not None and type(cohort) is RootLifecycleStartupCohort
                and row.get("claimed_peer") == peer
                and peer == (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid)
                and self._lifecycle_startup_peer_current(row, cohort))
        except Exception:
            return False

    def read_native_activity(self, *, owner_subject_sha256: str,
                             core_generation: str, core_source_generation: str,
                             now: float | None = None) -> dict[str, Any]:
        """Return a bounded sanitized projection for a JWT-derived owner only."""
        current = time.monotonic() if now is None else now
        with self._lock:
            self._ensure_open()
            observed_at = time.time()
            window_start = observed_at - _NATIVE_ACTIVITY_WINDOW_SECONDS
            self._prune_activity_window(observed_at)
            source = self._current_master_source()
            if (not _HASH.fullmatch(owner_subject_sha256 or "")
                    or core_generation != self._custody.core_generation
                    or core_source_generation != self._custody.core_source_generation
                    or source is None or source.is_current_sealed(self._custody, now=current) is not True
                    or not self._activity_store_ok):
                raise CoreNativeObservationUnavailable("current owner activity is unavailable")
            all_rows = [row for row in sorted(self._activity_records.values(),
                    key=lambda item: item["updated_at"], reverse=True)
                    if row["owner_subject_sha256"] == owner_subject_sha256
                    and row["core_generation"] == core_generation
                    and window_start <= row["created_at"] <= observed_at
                    and window_start <= row["updated_at"] <= observed_at]
            partial = len(all_rows) > _NATIVE_ACTIVITY_MAX_INSTANCES
            partial = partial or any(
                row.get("history_partial") is True
                for row in self._activity_records.values()
                if row.get("owner_subject_sha256") == owner_subject_sha256
                and row.get("core_generation") == core_generation
                and window_start <= row.get("created_at", 0) <= observed_at)
            rows = all_rows[:_NATIVE_ACTIVITY_MAX_INSTANCES]
            event_rows = [[event for event in row["events"]
                           if window_start <= event["at"] <= observed_at] for row in rows]
            event_counts = [min(1, len(events)) for events in event_rows]
            event_total = sum(event_counts)
            if any(count < len(available) for count, available in zip(event_counts, event_rows)):
                partial = True
            while event_total < _NATIVE_ACTIVITY_MAX_EVENTS_PER_READ:
                advanced = False
                for index, events in enumerate(event_rows):
                    if event_total >= _NATIVE_ACTIVITY_MAX_EVENTS_PER_READ:
                        break
                    if event_counts[index] < len(events):
                        event_counts[index] += 1
                        event_total += 1
                        advanced = True
                if not advanced:
                    break

            instances = []
            included_execution_keys: set[str] = set()
            for row, available_events, event_count in zip(rows, event_rows, event_counts):
                recent = available_events[-event_count:] if event_count else []
                stale_after_restart = (row["core_source_generation"] != core_source_generation
                    or (row["status"] != "completed"
                        and row["updated_at"] < self._activity_started_at))
                visible_status = "unknown" if stale_after_restart else row["status"]
                included_execution_keys.add(row["execution_key"])
                instances.append({
                    "execution_key": row["execution_key"], "display_alias": row["display_alias"],
                    "gateway_turn_id": row["gateway_turn_id"], "mission_id": row["mission_id"],
                    "mission_revision": row["mission_revision"], "profile_id": row["profile_id"],
                    "source_revision": row["source_revision"],
                    "source_generation_sha256": row["source_generation_sha256"],
                    "status": visible_status, "stale": stale_after_restart,
                    "created_at": row["created_at"], "updated_at": row["updated_at"],
                    "tool_count": row["tool_count_total"],
                    "events": [{key: event[key] for key in
                        ("kind", "status", "at", "duration_ms", "tool_count")} for event in recent],
                })
            try:
                from hermes_installer.remote.core_gateway_inspector import _read_root_planning_catalog
                current_catalog, current_catalog_sha = _read_root_planning_catalog(
                    self._custody.core_source_generation)
            except Exception:
                current_catalog, current_catalog_sha = None, None

            grouped: dict[str, dict[str, Any]] = {}
            all_team_rows: dict[str, list[dict[str, Any]]] = {}
            for row in all_rows:
                lineage = row.get("team_lineage")
                if isinstance(lineage, dict):
                    all_team_rows.setdefault(lineage["team_execution_key"], []).append(row)
            partial_team_keys: set[str] = set()
            for row in rows:
                lineage = row.get("team_lineage")
                if not isinstance(lineage, dict):
                    continue
                key = lineage["team_execution_key"]
                group = grouped.setdefault(key, {"lineage": lineage, "members": [],
                    "created_at": row["created_at"], "binding_deadline_at": lineage["binding_deadline_at"]})
                if group["lineage"] != lineage and any(
                        k != "admission_deadline_at" for k in lineage
                        if group["lineage"].get(k) != lineage.get(k)):
                    partial_team_keys.add(key)
                    partial = True
                group["members"].append(row["execution_key"])
                group["created_at"] = min(group["created_at"], row["created_at"])

            team_instances = []
            team_state_by_key: dict[str, str] = {}
            retained_bindings = getattr(self, "_team_bindings", None)
            binding_by_digest = {}
            if isinstance(retained_bindings, dict):
                binding_by_digest = {
                    hashlib.sha256(b"jarvis-team-binding-lineage-v1\0"
                        + binding.binding_id.encode("ascii")).hexdigest(): binding
                    for binding in retained_bindings.values()
                    if type(binding) is RootSelectedTeamBinding
                }
            for key, group in sorted(grouped.items(),
                    key=lambda item: item[1]["created_at"], reverse=True):
                lineage = group["lineage"]
                all_members = {row["execution_key"] for row in all_team_rows.get(key, [])}
                members = sorted(set(group["members"]))
                if (set(members) != all_members
                        or any(row.get("history_partial") is True
                               for row in all_team_rows.get(key, []))):
                    partial_team_keys.add(key)
                    partial = True
                binding = binding_by_digest.get(lineage["binding_id_sha256"])
                stale_member = any(row["core_source_generation"] != core_source_generation
                    for row in all_team_rows.get(key, []))
                active_team = None
                if current_catalog is not None:
                    active_team = current_catalog.get("teams", {}).get(lineage["team_id"])
                catalog_current = bool(current_catalog_sha == lineage["catalog_sha256"]
                    and isinstance(active_team, dict)
                    and active_team.get("source_revision") == lineage["team_source_revision"]
                    and active_team.get("bundle_generation_sha256") == lineage["bundle_generation_sha256"]
                    and active_team.get("bundle_member_sha256") == lineage["bundle_member_sha256"])
                binding_current = bool(binding is not None
                    and binding.expires_monotonic > current
                    and binding.owner_subject_sha256 == owner_subject_sha256
                    and binding.mission_id == (all_team_rows[key][0].get("mission_id"))
                    and binding.revision == all_team_rows[key][0].get("mission_revision")
                    and binding.team_id == lineage["team_id"]
                    and binding.catalog_sha256 == lineage["catalog_sha256"]
                    and binding.source_revision == lineage["team_source_revision"]
                    and binding.bundle_generation_sha256 == lineage["bundle_generation_sha256"]
                    and binding.bundle_member_sha256 == lineage["bundle_member_sha256"]
                    and list(binding.selected_expert_ids) == lineage["selected_expert_ids"])
                live_admission = bool(binding_current and any(
                    child.get("team_binding_id") == binding.binding_id
                    and child.get("complete") is not True
                    and getattr(child.get("owner"), "owner_subject_sha256", None)
                        == owner_subject_sha256
                    for child in getattr(self, "_child_sessions", {}).values()))
                if key in partial_team_keys:
                    state = "partial"
                elif stale_member or lineage["binding_deadline_at"] <= observed_at:
                    state = "stale"
                elif live_admission and catalog_current:
                    state = "current"
                elif catalog_current and lineage["binding_deadline_at"] > observed_at:
                    state = "historical"
                else:
                    state = "stale"
                team_state_by_key[key] = state
                team_instances.append({
                    "team_execution_key": key, "team_id": lineage["team_id"],
                    "source_revision": lineage["team_source_revision"],
                    "mission_id": all_team_rows[key][0]["mission_id"],
                    "mission_revision": all_team_rows[key][0]["mission_revision"],
                    "members": members, "state": state,
                    "coverage": "partial" if state == "partial" else "observed-callbacks",
                })

            relation_rows = []
            for row in all_rows:
                relation = row.get("team_relation")
                if (isinstance(relation, dict)
                        and window_start <= relation["event_at"] <= observed_at):
                    relation_rows.append((row, relation))
            relation_rows.sort(key=lambda item: item[1]["event_at"], reverse=True)
            if len(relation_rows) > _NATIVE_ACTIVITY_MAX_RELATIONS_PER_READ:
                partial = True
                partial_team_keys.update(
                    relation["team_execution_key"]
                    for _row, relation in relation_rows[_NATIVE_ACTIVITY_MAX_RELATIONS_PER_READ:])
            relations = []
            for _row, relation in relation_rows[:_NATIVE_ACTIVITY_MAX_RELATIONS_PER_READ]:
                key = relation["team_execution_key"]
                if (relation["sender_execution_key"] not in included_execution_keys
                        or relation["recipient_execution_key"] not in included_execution_keys
                        or key not in team_state_by_key):
                    partial = True
                    partial_team_keys.add(key)
                    continue
                state = team_state_by_key[key]
                if key in partial_team_keys:
                    state = "partial"
                relations.append({
                    "relation_key": relation["relation_key"],
                    "team_execution_key": key,
                    "mission_id": _row["mission_id"],
                    "mission_revision": _row["mission_revision"],
                    "sender_execution_key": relation["sender_execution_key"],
                    "recipient_execution_key": relation["recipient_execution_key"],
                    "kind": "completed_message", "event_at": relation["event_at"],
                    "state": state,
                    "coverage": "partial" if state == "partial" else "observed-callbacks",
                })
            if partial_team_keys:
                for team in team_instances:
                    if team["team_execution_key"] in partial_team_keys:
                        team["state"] = "partial"
                        team["coverage"] = "partial"
            return {"schema": 2, "observed_at": observed_at,
                    "window_seconds": _NATIVE_ACTIVITY_WINDOW_SECONDS,
                    "coverage": "observed-callbacks", "partial": partial,
                    "instances": instances, "team_instances": team_instances,
                    "relations": relations}

    @classmethod
    def from_current_core_custody(cls, custody: Any, *, selected_profile_source: Any = None,
                                  config: Any = None) -> "RootCoreNativeObservationRegistry":
        if config is None:
            raise CoreNativeObservationUnavailable("fixed inspector configuration is required")
        return cls(custody, selected_profile_source, config=config)

    def register_owner_turn(self, observation: Any) -> str:
        """Accept only the inspector's exact sealed, independently JWT-checked record."""
        from hermes_installer.remote.core_gateway_inspector import CoreVerifiedOwnerTurnObservation
        if type(observation) is not CoreVerifiedOwnerTurnObservation:
            raise CoreNativeObservationUnavailable("sealed root owner-turn observation is required")
        now = time.monotonic()
        if observation.is_current_sealed(self._config, custody=self._custody, now=now) is not True:
            self._close_fd(getattr(observation, "_core_pidfd", None))
            raise CoreNativeObservationUnavailable("owner-turn observation is stale or not current")
        handle = observation.owner_turn_handle
        with self._lock:
            self._ensure_open()
            if handle in self._owners:
                self._close_fd(getattr(observation, "_core_pidfd", None))
                raise CoreNativeObservationUnavailable("owner-turn observation was already registered")
            if len(self._owners) >= 256 and all(
                    row.planning_context is not None or row.master_review_context is not None
                    for row in self._owners.values()):
                self._close_fd(getattr(observation, "_core_pidfd", None))
                raise CoreNativeObservationUnavailable("retained owner-turn registry is full")
            if observation.planning_context is not None:
                existing = self._planning_sessions.get(observation.session_id)
                if existing is not None or len(self._planning_sessions) >= 512:
                    self._close_fd(getattr(observation, "_core_pidfd", None))
                    raise CoreNativeObservationUnavailable("planning session is already enrolled or registry is full")
                self._planning_sessions[observation.session_id] = observation
            if observation.master_review_context is not None:
                existing = self._master_review_sessions.get(observation.gateway_turn_id)
                if existing is not None or len(self._master_review_sessions) >= 512:
                    self._close_fd(getattr(observation, "_core_pidfd", None))
                    raise CoreNativeObservationUnavailable("review turn is already enrolled or registry is full")
                self._master_review_sessions[observation.gateway_turn_id] = observation
            self._owners[handle] = observation
            while len(self._owners) > 256:
                expired_handle = next((key for key, row in self._owners.items()
                                       if row.planning_context is None
                                       and row.master_review_context is None), None)
                if expired_handle is None:
                    raise CoreNativeObservationUnavailable("retained owner-turn registry is full")
                expired = self._owners.pop(expired_handle)
                self._owner_turn_bindings.pop(expired_handle, None)
                self._close_fd(getattr(expired, "_core_pidfd", None))
        return handle

    def enroll_master_decision(self, decision: Any) -> str:
        """Retain a current root-sealed plan and exactly its verified selected sources."""
        from hermes_installer.remote.jarvis_master_planning import CoreVerifiedJarvisMasterPlanDecision
        from hermes_installer.components.resources_active_profile_source import RootSelectedActiveProfileSource
        if (type(decision) is not CoreVerifiedJarvisMasterPlanDecision
                or decision.is_current_sealed(self._config, custody=self._custody,
                                              now=time.monotonic()) is not True):
            raise CoreNativeObservationUnavailable("current Jarvis master plan decision is required")
        with self._lock:
            self._ensure_open()
            owner = self._owners.get(decision.owner_turn_handle)
            if (owner is None or owner.gateway_turn_id != decision.gateway_turn_id
                    or owner.owner_subject_sha256 != decision.owner_subject_sha256
                    or owner.core_generation != decision.core_generation
                    or owner.core_source_generation != decision.core_source_generation):
                raise CoreNativeObservationUnavailable("master plan does not match a retained owner turn")
        resolver = getattr(RootSelectedActiveProfileSource, "resolve_selected", None)
        if not callable(resolver):
            raise CoreNativeObservationUnavailable("decision-bound Resources source resolver is unavailable")
        sources = resolver(decision, self._custody, config=self._config)
        if (not isinstance(sources, tuple) or len(sources) != len(decision.selected_source_ids)
                or tuple(getattr(item, "profile_id", None) for item in sources)
                    != tuple(decision.selected_source_ids)
                or any(type(item) is not RootSelectedActiveProfileSource
                       or item.is_current_sealed(self._custody, now=time.monotonic()) is not True
                       for item in sources)):
            raise CoreNativeObservationUnavailable("selected Resources sources are not current")
        team_binding = self._issue_team_binding(decision)
        enrollment_handle = secrets.token_urlsafe(32)
        # The source's short monotonic expiry is a readback freshness window,
        # not a child-authority lease. Every use re-reads that source; the
        # retained decision remains the authority deadline.
        expiry = float(decision.expires_monotonic)
        with self._lock:
            self._ensure_open()
            self._master_selections[enrollment_handle] = {
                "decision": decision, "owner": owner,
                "sources": {item.profile_id: item for item in sources},
                "expiry": expiry, "team_binding": team_binding,
            }
            while len(self._master_selections) > 128:
                self._master_selections.pop(next(iter(self._master_selections)))
        return enrollment_handle

    def _issue_team_binding(self, decision: Any) -> RootSelectedTeamBinding | None:
        """Mint Team authority only from the sealed plan and current protected Bundle projection."""
        selection = decision.plan.get("team_selection") if isinstance(decision.plan, Mapping) else None
        if selection is None:
            return None
        from hermes_installer.remote.core_gateway_inspector import _read_root_planning_catalog
        try:
            catalog, catalog_sha = _read_root_planning_catalog(decision.core_source_generation)
            team = catalog["teams"][selection["team_id"]]
            experts = tuple(selection["selected_expert_ids"])
            if (set(selection) != {"schema", "team_id", "bundle_generation_sha256",
                    "bundle_member_sha256", "ordered_member_ids", "selected_expert_ids"}
                    or type(selection["schema"]) is not int or selection["schema"] != 1
                    or selection["bundle_generation_sha256"] != team["bundle_generation_sha256"]
                    or selection["bundle_member_sha256"] != team["bundle_member_sha256"]
                    or selection["ordered_member_ids"] != team["ordered_member_ids"]
                    or len(experts) != 2 or experts != tuple(decision.selected_source_ids)
                    or any(item not in team["ordered_member_ids"] for item in experts)
                    or decision.core_source_generation != self._custody.core_source_generation):
                raise ValueError
            now = time.monotonic()
            binding = RootSelectedTeamBinding(
                schema=1, binding_id=secrets.token_urlsafe(32),
                owner_subject_sha256=decision.owner_subject_sha256,
                mission_id=decision.mission_id, revision=decision.revision,
                goal_sha256=decision.goal_sha256, plan_sha256=decision.plan_sha256,
                catalog_sha256=catalog_sha, team_id=selection["team_id"],
                source_revision=team["source_revision"],
                bundle_generation_sha256=team["bundle_generation_sha256"],
                bundle_member_sha256=team["bundle_member_sha256"],
                ordered_member_ids=tuple(team["ordered_member_ids"]),
                selected_expert_ids=experts, issued_monotonic=now,
                expires_monotonic=min(float(decision.expires_monotonic), now + 600.0),
                _seal=_TEAM_BINDING_SEAL,
            )
            self._team_bindings[binding.binding_id] = binding
            return binding
        except Exception:
            # A stale or incomplete current CAS join keeps Team dispatch unavailable.
            raise CoreNativeObservationUnavailable("current protected Team selection is unavailable") from None

    def enroll_current_orchestrator_policy(self, owner_turn_observation: Any,
                                           current_tool_configuration: Any
                                           ) -> RootSelectedOrchestratorDelegationPolicy:
        """Root-enroll the owner turn's current native parent inheritance policy.

        The configuration is a fixed sealed readback from the inspector, not a
        caller mapping.  This policy grants no additional tools: its allowlist is
        the already-selected native parent closure, and Hermes' own child builder
        continues to apply its blocked/disabled, pause, depth and lifecycle gates.
        """
        from hermes_installer.remote.core_gateway_inspector import (
            CoreVerifiedNativeToolConfiguration,
            CoreVerifiedOwnerTurnObservation,
        )
        if (type(owner_turn_observation) is not CoreVerifiedOwnerTurnObservation
                or type(current_tool_configuration) is not CoreVerifiedNativeToolConfiguration):
            raise CoreNativeObservationUnavailable("sealed owner and native tool configuration are required")
        now = time.monotonic()
        handle = owner_turn_observation.owner_turn_handle
        master_source = self._current_master_source()
        if (master_source is None
                or current_tool_configuration.is_current_sealed(
                    custody=self._custody, owner_turn=owner_turn_observation, now=now) is not True
                or not _configuration_has_fixed_resources_delegate(current_tool_configuration)
                or owner_turn_observation.is_current_sealed(
                    self._config, custody=self._custody, now=now) is not True
                or current_tool_configuration.core_generation != owner_turn_observation.core_generation
                or current_tool_configuration.core_source_generation != owner_turn_observation.core_source_generation
                or current_tool_configuration.owner_subject_sha256 != owner_turn_observation.owner_subject_sha256):
            raise CoreNativeObservationUnavailable("current native tool configuration is not owner-bound")
        names = current_tool_configuration.configured_parent_tool_names
        if (not isinstance(names, tuple) or not names or len(names) > 256
                or tuple(sorted(set(names))) != names
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in names)
                or "delegate_task" not in names or "resources_delegate" not in names):
            raise CoreNativeObservationUnavailable("selected native delegation policy is unavailable")
        issued = time.monotonic()
        expiry = min(float(owner_turn_observation.expires_monotonic), issued + 600.0)
        if expiry <= issued:
            raise CoreNativeObservationUnavailable("owner turn expires before policy enrollment")
        policy_handle = secrets.token_urlsafe(32)
        fields = {
            "schema": 1, "policy_handle": policy_handle,
            "core_generation": owner_turn_observation.core_generation,
            "core_source_generation": owner_turn_observation.core_source_generation,
            "owner_subject_sha256": owner_turn_observation.owner_subject_sha256,
            "profile_id": "hermes", "mode": "native-parent-inheritance",
            "parent_tool_configuration_sha256": current_tool_configuration.tool_configuration_sha256,
            "configured_parent_tool_names": list(names),
            "resources_delegate_schema_sha256": _RESOURCES_DELEGATE_SCHEMA_SHA256,
            "resources_delegate_source_sha256": _RESOURCES_DELEGATE_SOURCE_SHA256,
            # Fixed root-enrolled owner-only policy bits; neither selected by the
            # Hermes user config nor inferred from provider tools.list metadata.
            "allow_inherited_mcp": True,
            "allow_native_orchestrator_delegation": True,
            "additional_metered_budget": 0,
            "issued_monotonic": issued, "expires_monotonic": expiry,
        }
        policy = RootSelectedOrchestratorDelegationPolicy(
            schema=1, policy_handle=policy_handle,
            policy_sha256=_hash(fields),
            core_generation=owner_turn_observation.core_generation,
            core_source_generation=owner_turn_observation.core_source_generation,
            owner_subject_sha256=owner_turn_observation.owner_subject_sha256,
            profile_id="hermes", mode="native-parent-inheritance",
            parent_tool_configuration_sha256=current_tool_configuration.tool_configuration_sha256,
            configured_parent_tool_names=names,
            resources_delegate_schema_sha256=_RESOURCES_DELEGATE_SCHEMA_SHA256,
            resources_delegate_source_sha256=_RESOURCES_DELEGATE_SOURCE_SHA256,
            allow_inherited_mcp=True,
            allow_native_orchestrator_delegation=True,
            additional_metered_budget=0, issued_monotonic=issued,
            expires_monotonic=expiry, _seal=_NATIVE_INHERITANCE_POLICY_SEAL,
        )
        with self._lock:
            self._ensure_open()
            if self._owners.get(handle) is not owner_turn_observation:
                raise CoreNativeObservationUnavailable("owner turn was not registered by this root")
            old_handle = self._owner_policy_handles.pop(handle, None)
            if old_handle is not None:
                self._policies.pop(old_handle, None)
            self._policies[policy_handle] = {
                "policy": policy, "owner": owner_turn_observation,
                "configuration": current_tool_configuration,
            }
            self._owner_policy_handles[handle] = policy_handle
            while len(self._policies) > 256:
                stale_handle = next(iter(self._policies))
                stale = self._policies.pop(stale_handle)
                self._owner_policy_handles.pop(stale["owner"].owner_turn_handle, None)
        return policy

    @staticmethod
    def _close_fd(fd: Any) -> None:
        if type(fd) is int and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def _ensure_open(self) -> None:
        if self._closed:
            raise CoreNativeObservationUnavailable("root observer registry is closed")

    def _current_master_source(self) -> Any | None:
        """Re-read the sole Jarvis master source from protected current custody."""
        try:
            from hermes_installer.components.resources_active_profile_source import (
                RootVerifiedJarvisMasterSource,
            )
            source = RootVerifiedJarvisMasterSource.current_master_source(
                self._custody, config=self._config)
            if (type(source) is RootVerifiedJarvisMasterSource
                    and source.profile_id == "hermes"
                    and source.native_profile_key == "default"
                    and source.display_name == "Jarvis"
                    and source.is_current_sealed(self._custody, now=time.monotonic()) is True):
                self._master_source = source
                return source
        except Exception:
            pass
        self._master_source = None
        return None

    def _final_effect_ledger(self) -> Any:
        """Open the fixed root-owned chat ledger without following mutable paths."""
        if self._final_effect_store is not None:
            return self._final_effect_store
        from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
        expected = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        if CHAT_STORE_PATH != expected:
            raise CoreNativeObservationUnavailable("fixed root final-effect ledger path differs")
        parent = os.lstat(expected.parent)
        target = os.lstat(expected)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                or parent.st_mode & 0o022
                or not stat.S_ISREG(target.st_mode) or target.st_uid != 0
                or target.st_nlink != 1 or target.st_mode & 0o022):
            raise CoreNativeObservationUnavailable("fixed root final-effect ledger custody differs")

        def connect():
            db = sqlite3.connect(expected, timeout=2, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=2000")
            return db

        from hermes_installer.remote.jarvis_final_effects import RootFinalEffectLedger
        self._final_effect_store = RootFinalEffectLedger(connect)
        return self._final_effect_store

    def _classify_current_call(self, handle: str, peer: tuple[int, int, int], *,
                               now: float) -> tuple[dict[str, Any], Any, Any, str]:
        """Join a root call to either the current Jarvis master or admitted expert."""
        call = self._calls.get(handle)
        if (call is None or call["peer"] != peer or call["expiry"] <= now
                or call.get("claim") is not None):
            raise ValueError("observed call is not a live unclaimed native dispatch")
        owner = call.get("owner")
        attempt = self._attempts.get(call.get("attempt"))
        if (owner is None or attempt is None or attempt.get("response") is None
                or attempt.get("owner") is not owner
                or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                or self._policy_for_owner(owner, now) is None
                or attempt.get("account") is None or not _HASH.fullmatch(attempt["account"])):
            raise ValueError("observed call owner or provider attempt is not current")
        if (not isinstance(attempt.get("provider"), str)
                or (attempt.get("provider"), attempt.get("api_mode"), attempt.get("base_url"))
                    != (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT)):
            raise ValueError("observed call did not use the enrolled Codex subscription route")
        returned = attempt["response"][1].get(call["tool_call_id"])
        if (returned is None or returned.get("name") != call["tool_name"]
                or returned.get("arguments_sha256") != call["arguments_sha256"]):
            raise ValueError("observed call differs from the completed provider response")
        child = self._child_sessions.get(call.get("attempt_session_id"))
        if child is not None:
            source = child.get("source")
            if (child.get("mode") != "expert-read-research"
                    or child.get("owner") is not owner or child.get("peer") != peer
                    or child.get("expiry", 0) <= now or child.get("complete")
                    or attempt.get("child_admission_handle") != child.get("admission_handle")
                    or not callable(getattr(source, "is_current_sealed", None))
                    or source.is_current_sealed(self._custody, now=now) is not True
                    or source.profile_id in {"hermes"}
                    or call["tool_name"] not in child.get("tool_names", ())
                    or call["tool_name"] not in _MASTER_READ_TOOL_NAMES):
                raise ValueError("expert child call is outside its admitted read closure")
            return call, owner, child, "expert_read"
        source = self._current_master_source()
        if (call.get("attempt_session_id") != owner.session_id or source is None
                or source.is_current_sealed(custody=self._custody, now=now) is not True
                or source.profile_id != "hermes"
                or call["tool_name"] not in attempt.get("parent_tool_names", ())):
            raise ValueError("normal call is not from the current Jarvis master")
        mode = "master_read" if call["tool_name"] in _MASTER_READ_TOOL_NAMES else "master_effect"
        return call, owner, source, mode

    def _owner_for_review(self, owner_turn_handle: str, owner_subject_sha256: str,
                          gateway_peer: tuple[int, int, int], *, now: float) -> Any:
        if (not _OPAQUE.fullmatch(owner_turn_handle or "")
                or not _HASH.fullmatch(owner_subject_sha256 or "")):
            raise CoreNativeObservationUnavailable("current owner turn is unavailable")
        owner = self._owners.get(owner_turn_handle)
        if (owner is None or owner.owner_subject_sha256 != owner_subject_sha256
                or (owner.peer_gateway_pid, owner.peer_gateway_uid, owner.peer_gateway_gid) != gateway_peer
                or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                or self._policy_for_owner(owner, now) is None):
            raise CoreNativeObservationUnavailable("current owner turn is unavailable")
        source = self._current_master_source()
        if (source is None or source.profile_id != "hermes"
                or source.is_current_sealed(self._custody, now=now) is not True):
            raise CoreNativeObservationUnavailable("current Jarvis master source is unavailable")
        return owner

    def list_final_effects_for_owner(self, owner_turn_handle: str, owner_subject_sha256: str,
                                     gateway_peer: tuple[int, int, int]) -> tuple[Any, ...]:
        from hermes_installer.remote.jarvis_final_effects import FinalEffectReview
        now = time.monotonic()
        with self._lock:
            self._ensure_open()
            owner = self._owner_for_review(owner_turn_handle, owner_subject_sha256, gateway_peer, now=now)
            rows = self._final_effect_ledger().pending_for_owner(
                owner_subject_sha256=owner.owner_subject_sha256,
                gateway_turn_id=owner.gateway_turn_id,
                owner_turn_handle=owner.owner_turn_handle,
                core_generation=owner.core_generation)
            reviews = []
            for row in rows:
                if (not isinstance(row, dict)
                        or set(row) != {"pendingId", "turnId", "toolName", "reviewSha256",
                                        "preview", "status", "expiresInMs"}
                        or row["turnId"] != owner.gateway_turn_id):
                    raise CoreNativeObservationUnavailable("root review row shape is unavailable")
                preview = _canonical(row["preview"]).decode("utf-8", errors="strict")
                expiry = time.monotonic() + max(0, min(30_000, int(row["expiresInMs"]))) / 1000.0
                reviews.append(FinalEffectReview(
                    pending_id=row["pendingId"], review_sha256=row["reviewSha256"],
                    tool_name=row["toolName"], preview_json=preview,
                    status=row["status"], expires_monotonic=expiry))
            if self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                      gateway_peer, now=time.monotonic()) is not owner:
                raise CoreNativeObservationUnavailable("owner turn changed during effect listing")
            return tuple(reviews)

    def decide_final_effect_for_owner(self, owner_turn_handle: str, owner_subject_sha256: str,
                                      gateway_peer: tuple[int, int, int], *, pending_id: str,
                                      review_sha256: str, decision: str,
                                      idempotency_key: str) -> str:
        now = time.monotonic()
        with self._lock:
            self._ensure_open()
            owner = self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                           gateway_peer, now=now)
            status = self._final_effect_ledger().decide(
                owner_subject_sha256=owner.owner_subject_sha256,
                gateway_turn_id=owner.gateway_turn_id,
                owner_turn_handle=owner.owner_turn_handle,
                core_generation=owner.core_generation,
                pending_id=pending_id, review_sha256=review_sha256,
                decision=decision, idempotency_key=idempotency_key)
            if self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                      gateway_peer, now=time.monotonic()) is not owner:
                raise CoreNativeObservationUnavailable("owner turn changed during effect decision")
            return status

    def preflight_native_mission(self, binding: Any, *, owner_subject_sha256: str,
                                 gateway_turn_id: str) -> bool:
        """Check a just-spent launch row before the BFF queues its native prompt."""
        from hermes_installer.remote.core_gateway_inspector import _mission_binding_wire
        if (type(binding) is not MissionBinding or binding.schema != 2
                or binding.source_profile_id != "hermes"
                or binding.execution_mode not in {"oneshot", "kanban"}
                or not isinstance(owner_subject_sha256, str) or not _HASH.fullmatch(owner_subject_sha256)
                or not isinstance(gateway_turn_id, str) or not _ID.fullmatch(gateway_turn_id)):
            raise CoreNativeObservationUnavailable("typed current mission binding is required")
        try:
            wire = _mission_binding_wire(binding)
            if wire != binding.to_wire():
                raise ValueError
            from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
            from hermes_installer.remote.jarvis_mission_executor import (
                MissionLedgerReader, resolve_spent_mission_binding,
            )
            if CHAT_STORE_PATH != Path("/var/lib/hermes-jarvis-chat/chat.sqlite3"):
                raise ValueError
            with self._lock:
                self._ensure_open()
                now = time.monotonic()
                source = self._current_master_source()
                if (source is None or source.profile_id != "hermes"
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or self._custody.core_generation == ""
                        or resolve_spent_mission_binding(
                            MissionLedgerReader(path=CHAT_STORE_PATH), binding,
                            gateway_turn_id=gateway_turn_id,
                            owner_subject_sha256=owner_subject_sha256,
                            core_generation=self._custody.core_generation,
                            core_source_generation=self._custody.core_source_generation) is not True):
                    raise ValueError
                return True
        except Exception:
            raise CoreNativeObservationUnavailable("spent mission preflight is unavailable") from None

    def _prune(self, now: float) -> None:
        for handle, row in list(self._lifecycle_startup_probes.items()):
            if row["expiry"] <= now:
                self._lifecycle_startup_probes.pop(handle, None)
                try:
                    os.close(row["pidfd"])
                except Exception:
                    pass
        for handle, row in list(self._lifecycle_startup_attempts.items()):
            if row["expiry"] <= now:
                self._lifecycle_startup_attempts.pop(handle, None)
        for handle, row in list(self._obsidian_bindings.items()):
            if row["expiry"] <= now:
                self._obsidian_bindings.pop(handle, None)
        self._obsidian_scoped_calls = {handle for handle in self._obsidian_scoped_calls
                                       if handle in self._calls and self._calls[handle]["expiry"] > now}
        self._obsidian_draft_read_deliveries = {
            receipt_id: row for receipt_id, row in self._obsidian_draft_read_deliveries.items()
            if row["expires_monotonic"] > now}
        self._obsidian_draft_review_proposals = {
            handle: row for handle, row in self._obsidian_draft_review_proposals.items()
            if row["expires_monotonic"] > now}
        for handle, row in list(self._policies.items()):
            policy = row.get("policy")
            if not isinstance(policy, RootSelectedOrchestratorDelegationPolicy) or policy.expires_monotonic <= now:
                self._policies.pop(handle, None)
                owner = row.get("owner")
                if owner is not None:
                    self._owner_policy_handles.pop(owner.owner_turn_handle, None)
        for handle, row in list(self._attempts.items()):
            if row["expiry"] <= now:
                self._attempts.pop(handle, None)
        for handle, row in list(self._calls.items()):
            if row["expiry"] <= now:
                self._calls.pop(handle, None)
        for handle, row in list(self._claims.items()):
            if row["expiry"] <= now:
                self._claims.pop(handle, None)
        for handle, row in list(self._mission_pending.items()):
            if row["expiry"] <= now:
                self._mission_pending.pop(handle, None)
        for handle, row in list(self._consumed_dispatches.items()):
            if row["expiry"] <= now:
                self._consumed_dispatches.pop(handle, None)
        for session_id, row in list(self._child_sessions.items()):
            if (row["expiry"] <= now
                    or (row["mode"] == "planner" and row.get("turn_id") is None
                        and row.get("start_expires", row["expiry"]) <= now)):
                self._child_sessions.pop(session_id, None)
        for handle, row in list(self._planning_completions.items()):
            if row["expiry"] <= now:
                self._planning_completions.pop(handle, None)
        for handle, row in list(self._expert_completions.items()):
            if row["expiry"] <= now:
                self._expert_completions.pop(handle, None)
        # Team output is a separate DATA record. It carries no child admission,
        # final native attempt or source lease and expires at the original
        # Team/owner bound rather than the shorter child completion receipt.
        for handle, row in list(self._team_completion_evidence.items()):
            if row["data_expires_monotonic"] <= now:
                self._team_completion_evidence.pop(handle, None)
        for handle, row in list(self._team_messages.items()):
            if row["expiry"] <= now:
                self._team_messages.pop(handle, None)
        for handle, row in list(self._team_bindings.items()):
            if row.expires_monotonic <= now:
                self._team_bindings.pop(handle, None)
                self._team_completion_counts.pop(handle, None)
                self._team_edge_issued.discard(handle)
        for handle, row in list(self._master_selections.items()):
            if row["expiry"] <= now:
                self._master_selections.pop(handle, None)
        for handle, row in list(self._selected_source_deliveries.items()):
            if row["expiry"] <= now:
                self._selected_source_deliveries.pop(handle, None)
        for handle, row in list(self._master_source_deliveries.items()):
            if row["expiry"] <= now or row.get("consumed"):
                self._master_source_deliveries.pop(handle, None)

    def _owner_for(self, session_id: str, turn_id: str) -> Any:
        now = time.monotonic()
        child_row = self._child_sessions.get(session_id)
        if child_row is not None and child_row["expiry"] > now:
            owner = child_row["owner"]
            if (owner.core_generation == self._custody.core_generation
                    and owner.is_current_sealed(self._config, custody=self._custody, now=now) is True):
                bound = child_row.get("turn_id")
                if bound is None:
                    if now >= child_row.get("start_expires", child_row["expiry"]):
                        return None
                    return owner
                if bound == turn_id:
                    return owner
        for handle, owner in list(self._owners.items()):
            if owner.expires_monotonic <= now:
                self._owners.pop(handle, None)
                self._owner_turn_bindings.pop(handle, None)
                policy_handle = self._owner_policy_handles.pop(handle, None)
                if policy_handle is not None:
                    self._policies.pop(policy_handle, None)
                self._close_fd(getattr(owner, "_core_pidfd", None))
                continue
            if (owner.session_id == session_id
                    and owner.core_generation == self._custody.core_generation
                    and owner.is_current_sealed(self._config, custody=self._custody, now=now) is True):
                # The first middleware attempt binds the actual native turn ID;
                # subsequent attempts must retain that same ID.
                bound = self._owner_turn_bindings.get(handle)
                if bound is None:
                    self._owner_turn_bindings[handle] = turn_id
                    return owner
                if bound == turn_id:
                    return owner
        return None

    def _persist_master_plan_result(self, attempt: dict[str, Any], raw_output: str,
                                    response_text_sha256: str) -> None:
        """Persist only a root-observed, current, zero-tool master plan result."""
        owner = attempt.get("owner")
        context = getattr(owner, "planning_context", None)
        if (owner is None or context is None
                or attempt.get("provider") != _CODEX_PROVIDER
                or attempt.get("api_mode") != _CODEX_MODE
                or attempt.get("base_url") != _CODEX_ENDPOINT
                or attempt.get("retry_count") != 0
                or attempt.get("parent_tool_names") != ()
                or not _HASH.fullmatch(attempt.get("account", ""))
                or not _HASH.fullmatch(attempt.get("request_sha256", ""))
                or not isinstance(attempt.get("api_request_id"), str)
                or not _ID.fullmatch(attempt["api_request_id"])
                or not isinstance(attempt.get("attempt_handle"), str)
                or not _OPAQUE.fullmatch(attempt["attempt_handle"])
                or not isinstance(attempt.get("turn_id"), str)
                or not _ID.fullmatch(attempt["turn_id"])):
            raise ValueError("planning owner is unavailable")
        now = time.monotonic()
        if owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True:
            raise ValueError("planning owner turn is stale")
        from hermes_installer.remote.core_gateway_inspector import (
            _read_root_planning_catalog, _verify_planning_context,
        )
        from hermes_installer.remote.jarvis_master_planning import parse_master_plan_output
        _verify_planning_context(context, owner_subject_sha256=owner.owner_subject_sha256,
            core_generation=owner.core_generation,
            core_source_generation=owner.core_source_generation,
            prompt_sha256=context.planner_prompt_sha256, mission_id=context.mission_id,
            revision=context.revision, gateway_turn_id=owner.gateway_turn_id,
            conversation_id=owner.conversation_id, session_id=owner.session_id,
            config=self._config, custody=self._custody, preparing=False)
        catalog, catalog_sha = _read_root_planning_catalog(owner.core_source_generation)
        if catalog_sha != context.catalog_sha256:
            raise ValueError("master planning catalog changed")
        parsed = parse_master_plan_output(raw_output, allowed_source_ids=catalog["profiles"],
                                         verified_teams=catalog["teams"])
        if (not parsed["selected_source_ids"] and parsed["execution_mode"] != "oneshot"):
            raise ValueError("empty source selection is only valid for OneShot")
        if hashlib.sha256(raw_output.encode("utf-8", errors="strict")).hexdigest() != response_text_sha256:
            raise ValueError("master planning response digest changed")
        path = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        from hermes_installer.remote.core_gateway_inspector import _mission_store_identity
        ledger_identity = _mission_store_identity(self._config, path, include_sidecars=False)
        plan_json = json.dumps(parsed["plan"], ensure_ascii=False, sort_keys=True,
                               separators=(",", ":"), allow_nan=False)
        selected_json = json.dumps(list(parsed["selected_source_ids"]),
                                   ensure_ascii=False, separators=(",", ":"))
        with sqlite3.connect(path, timeout=2, isolation_level=None) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=2000")
            db.execute("BEGIN IMMEDIATE")
            try:
                mission = db.execute(
                    "SELECT id,owner,revision,status,execution_mode,master_plan_sha256 "
                    "FROM jarvis_missions WHERE id=? AND owner=? AND revision=?",
                    (context.mission_id, owner.owner_subject_sha256, context.revision)).fetchone()
                planning = db.execute(
                    "SELECT task_sha256,catalog_sha256,source_binding,planner_prompt_sha256,"
                    "master_source_generation_sha256,master_source_manifest_sha256,master_prompt_sha256,"
                    "gateway_turn_id,conversation_id,status FROM jarvis_mission_planning_turns "
                    "WHERE owner=? AND mission_id=? AND revision=?",
                    (owner.owner_subject_sha256, context.mission_id, context.revision)).fetchone()
                turn = db.execute(
                    "SELECT owner,conversation_id,status,runtime_session_id,core_generation "
                    "FROM turns WHERE id=?", (owner.gateway_turn_id,)).fetchone()
                if (mission is None or planning is None or turn is None
                        or mission["status"] != "draft" or mission["execution_mode"] != "pending"
                        or mission["master_plan_sha256"] is not None
                        or planning["status"] != "queued"
                        or planning["gateway_turn_id"] != owner.gateway_turn_id
                        or planning["conversation_id"] != owner.conversation_id
                        or planning["task_sha256"] != context.goal_sha256
                        or planning["catalog_sha256"] != context.catalog_sha256
                        or planning["planner_prompt_sha256"] != context.planner_prompt_sha256
                        or planning["master_source_generation_sha256"] != context.master_source_generation_sha256
                        or planning["master_source_manifest_sha256"] != context.master_source_manifest_sha256
                        or planning["master_prompt_sha256"] != context.master_prompt_sha256
                        or turn["owner"] != owner.owner_subject_sha256
                        or turn["conversation_id"] != owner.conversation_id
                        or turn["runtime_session_id"] != owner.session_id
                        or turn["core_generation"] != owner.core_generation
                        or turn["status"] not in {"queued", "running"}):
                    raise ValueError("planning ledger or actual owned turn changed")
                source_binding = json.loads(planning["source_binding"])
                if source_binding != {"core_generation": owner.core_generation,
                                      "core_source_generation": owner.core_source_generation}:
                    raise ValueError("planning source binding changed")
                changed = db.execute(
                    "UPDATE jarvis_missions SET execution_mode=?,selected_source_ids=?,master_plan_json=?,"
                    "master_plan_sha256=?,master_plan_response_sha256=?,master_plan_gateway_turn_id=?,"
                    "master_plan_owner_turn_handle=?,master_plan_core_generation=?,"
                    "master_plan_core_source_generation=?,master_plan_catalog_sha256=?,"
                    "master_plan_planner_prompt_sha256=?,master_plan_source_generation_sha256=?,"
                    "master_plan_source_manifest_sha256=?,master_plan_master_prompt_sha256=?,updated=? "
                    "WHERE id=? AND owner=? AND revision=? "
                    "AND status='draft' AND execution_mode='pending' AND master_plan_sha256 IS NULL",
                    (parsed["execution_mode"], selected_json, plan_json, parsed["plan_sha256"],
                     parsed["response_sha256"], owner.gateway_turn_id, owner.owner_turn_handle,
                     owner.core_generation, owner.core_source_generation, context.catalog_sha256,
                     context.planner_prompt_sha256, context.master_source_generation_sha256,
                     context.master_source_manifest_sha256, context.master_prompt_sha256, time.time(),
                     context.mission_id, owner.owner_subject_sha256, context.revision)).rowcount
                changed_row = db.execute(
                    "UPDATE jarvis_mission_planning_turns SET status='completed',updated=? "
                    "WHERE owner=? AND mission_id=? AND revision=? AND status='queued' "
                    "AND gateway_turn_id=?",
                    (time.time(), owner.owner_subject_sha256, context.mission_id,
                     context.revision, owner.gateway_turn_id)).rowcount
                if changed != 1 or changed_row != 1:
                    raise ValueError("planning result was already consumed or changed")
                if owner.is_current_sealed(self._config, custody=self._custody,
                                            now=time.monotonic()) is not True:
                    raise ValueError("planning owner expired during persistence")
                if _mission_store_identity(self._config, path, include_sidecars=False) != ledger_identity:
                    raise ValueError("mission ledger custody changed during persistence")
                db.commit()
            except Exception:
                db.rollback()
                raise
        record = RootObservedMasterPlanRecord(
            owner_subject_sha256=owner.owner_subject_sha256,
            mission_id=context.mission_id, revision=context.revision,
            gateway_turn_id=owner.gateway_turn_id, conversation_id=owner.conversation_id,
            session_id=owner.session_id, native_turn_id=attempt["turn_id"],
            owner_turn_handle=owner.owner_turn_handle,
            core_generation=owner.core_generation,
            core_source_generation=owner.core_source_generation,
            goal_sha256=context.goal_sha256, catalog_sha256=context.catalog_sha256,
            planner_prompt_sha256=context.planner_prompt_sha256,
            master_source_generation_sha256=context.master_source_generation_sha256,
            master_source_manifest_sha256=context.master_source_manifest_sha256,
            master_prompt_sha256=context.master_prompt_sha256,
            attempt_handle=attempt["attempt_handle"], api_request_id=attempt["api_request_id"],
            provider=attempt["provider"], api_mode=attempt["api_mode"],
            base_url=attempt["base_url"], model=attempt["model"],
            account_fingerprint=attempt["account"], request_sha256=attempt["request_sha256"],
            retry_count=attempt["retry_count"], completed=True,
            request_tool_count=len(attempt["parent_tool_names"]), tool_call_count=0,
            plan_json=plan_json, plan_sha256=parsed["plan_sha256"],
            response_sha256=response_text_sha256,
            selected_source_ids=tuple(parsed["selected_source_ids"]),
            execution_mode=parsed["execution_mode"], _seal=_MASTER_PLAN_RECORD_SEAL)
        key = (owner.owner_subject_sha256, context.mission_id, context.revision)
        with self._lock:
            current_owner = self._owners.get(owner.owner_turn_handle)
            if (current_owner is not owner
                    or owner.is_current_sealed(self._config, custody=self._custody,
                                                now=time.monotonic()) is not True):
                raise ValueError("planning owner changed before root result retention")
            _publish_root_master_plan_record(record)
            self._master_plan_records[key] = record
            while len(self._master_plan_records) > 256:
                self._master_plan_records.pop(next(iter(self._master_plan_records)))

    def _persist_master_review_response(self, attempt: dict[str, Any], raw_output: str,
                                        response_text_sha256: str) -> None:
        """Retain only the exact current zero-tool response for a root-bound review prompt."""
        owner = attempt.get("owner")
        context = getattr(owner, "master_review_context", None)
        if (owner is None or context is None
                or attempt.get("provider") != _CODEX_PROVIDER
                or attempt.get("api_mode") != _CODEX_MODE
                or attempt.get("base_url") != _CODEX_ENDPOINT
                or attempt.get("retry_count") != 0
                or attempt.get("parent_tool_names") != ()
                or not _HASH.fullmatch(attempt.get("account", ""))
                or not _HASH.fullmatch(attempt.get("request_sha256", ""))
                or not isinstance(attempt.get("attempt_handle"), str)
                or not _OPAQUE.fullmatch(attempt["attempt_handle"])
                or attempt.get("turn_id") != owner.gateway_turn_id
                or not isinstance(raw_output, str)
                or hashlib.sha256(raw_output.encode("utf-8", "strict")).hexdigest()
                    != response_text_sha256):
            raise ValueError("current master-review response is unavailable")
        from hermes_installer.remote.core_gateway_inspector import _verify_master_review_context
        _verify_master_review_context(context,
            owner_subject_sha256=owner.owner_subject_sha256,
            core_generation=owner.core_generation,
            core_source_generation=owner.core_source_generation,
            prompt_sha256=context.review_prompt_sha256,
            config=self._config, custody=self._custody)
        if (owner.is_current_sealed(self._config, custody=self._custody,
                                    now=time.monotonic()) is not True
                or self._current_master_source() is None
                or self._current_master_source().generation_sha256 != context.master_source_generation_sha256):
            raise ValueError("current master-review owner or source changed")
        attempt["master_review_response_text"] = raw_output
        attempt["master_review_response_sha256"] = response_text_sha256
        attempt["master_review_context"] = context

    def read_master_plan_record(self, *, owner_subject_sha256: str,
                                 mission_id: str, revision: int) -> RootObservedMasterPlanRecord | None:
        """Return only a root-retained completion; gateway rows cannot mint one."""
        if (not _HASH.fullmatch(owner_subject_sha256 or "")
                or not isinstance(mission_id, str) or not _ID.fullmatch(mission_id or "")
                or type(revision) is not int or revision < 1):
            return None
        raw = _read_root_master_plan_bytes(owner_subject_sha256, mission_id, revision)
        if raw is None:
            return None
        record = _root_master_plan_record_from_bytes(raw,
            owner_subject_sha256=owner_subject_sha256, mission_id=mission_id, revision=revision)
        if record is None:
            return None
        with self._lock:
            cached = self._master_plan_records.get((owner_subject_sha256, mission_id, revision))
            if cached is not None and _master_plan_record_bytes(cached) != raw:
                return None
            self._master_plan_records[(owner_subject_sha256, mission_id, revision)] = record
        return record

    def confirm_master_review_response(self, *, owner_subject_sha256: str,
                                      gateway_turn_id: str, response_sha256: str,
                                      gateway_peer: tuple[int, int, int]) -> dict[str, Any]:
        """Seal only the exact provider response retained for the admitted review turn."""
        if (not _HASH.fullmatch(owner_subject_sha256 or "")
                or not isinstance(gateway_turn_id, str) or not _ID.fullmatch(gateway_turn_id)
                or not _HASH.fullmatch(response_sha256 or "")):
            raise CoreNativeObservationUnavailable("master-review response identity is malformed")
        now = time.monotonic()
        with self._lock:
            self._ensure_open()
            owners = [owner for owner in self._owners.values()
                      if owner.owner_subject_sha256 == owner_subject_sha256
                      and owner.gateway_turn_id == gateway_turn_id
                      and owner.master_review_context is not None]
            if len(owners) != 1:
                raise CoreNativeObservationUnavailable("current admitted review turn is unavailable")
            owner = owners[0]
            if ((owner.peer_gateway_pid, owner.peer_gateway_uid, owner.peer_gateway_gid) != gateway_peer
                    or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                    or owner.core_generation != self._custody.core_generation
                    or owner.core_source_generation != self._custody.core_source_generation):
                raise CoreNativeObservationUnavailable("review owner or Core source changed")
            context = owner.master_review_context
            from hermes_installer.remote.core_gateway_inspector import _verify_master_review_context
            _verify_master_review_context(context,
                owner_subject_sha256=owner.owner_subject_sha256,
                core_generation=owner.core_generation,
                core_source_generation=owner.core_source_generation,
                prompt_sha256=context.review_prompt_sha256,
                config=self._config, custody=self._custody)
            attempts = [row for row in self._attempts.values()
                if row.get("owner") is owner and row.get("turn_id") == gateway_turn_id
                and row.get("master_review_response_text") is not None]
            if len(attempts) != 1:
                raise CoreNativeObservationUnavailable("review provider response is missing or ambiguous")
            attempt = attempts[0]
            text = attempt["master_review_response_text"]
            if (attempt.get("response") is None or attempt["response"][1]
                    or attempt.get("response")[2] != response_sha256
                    or attempt.get("master_review_response_sha256") != response_sha256
                    or hashlib.sha256(text.encode("utf-8", "strict")).hexdigest() != response_sha256
                    or attempt.get("master_review_context") is not context
                    or attempt.get("parent_tool_names") != ()
                    or attempt.get("retry_count") != 0
                    or attempt.get("provider") != _CODEX_PROVIDER
                    or attempt.get("api_mode") != _CODEX_MODE
                    or attempt.get("base_url") != _CODEX_ENDPOINT
                    or not _HASH.fullmatch(attempt.get("request_sha256", ""))
                    or attempt.get("turn_id") != owner.gateway_turn_id):
                raise CoreNativeObservationUnavailable("review response differs from the root-captured result")
            handle = secrets.token_urlsafe(32)
            expiry = min(owner.expires_monotonic, now + 30.0)
            self._master_review_completions[handle] = {
                "owner": owner, "attempt": attempt, "context": context,
                "response_sha256": response_sha256, "expiry": expiry,
                "peer": gateway_peer,
            }
            while len(self._master_review_completions) > 128:
                self._master_review_completions.pop(next(iter(self._master_review_completions)))
            return {"completion_handle": handle,
                "owner_subject_sha256": owner.owner_subject_sha256,
                "owner_turn_handle": owner.owner_turn_handle,
                "gateway_turn_id": owner.gateway_turn_id,
                "core_generation": owner.core_generation,
                "core_source_generation": owner.core_source_generation,
                "prompt_sha256": context.review_prompt_sha256,
                "response_sha256": response_sha256,
                "mission_id": context.mission_id, "revision": context.revision,
                "run_id": context.run_id, "result_sha256": context.result_sha256,
                "execution_core_generation": context.execution_core_generation,
                "execution_core_source_generation": context.execution_core_source_generation,
                "expires_monotonic": expiry,
                "owner_turn_expires_monotonic": owner.expires_monotonic}

    def verify_master_review_completion(self, receipt: Any,
                                        gateway_peer: tuple[int, int, int]) -> bool:
        now = time.monotonic()
        handle = getattr(receipt, "completion_handle", None)
        if not isinstance(handle, str):
            return False
        with self._lock:
            record = self._master_review_completions.get(handle)
            if record is None or record["expiry"] <= now or record["peer"] != gateway_peer:
                return False
            owner, context, attempt = record["owner"], record["context"], record["attempt"]
            observed_text = attempt.get("master_review_response_text")
            if not isinstance(observed_text, str):
                return False
            try:
                observed_text_sha256 = hashlib.sha256(
                    observed_text.encode("utf-8", errors="strict")).hexdigest()
            except UnicodeError:
                return False
            supplied_text = getattr(receipt, "response_text", None)
            if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                    or owner.owner_turn_handle != getattr(receipt, "owner_turn_handle", None)
                    or owner.gateway_turn_id != getattr(receipt, "gateway_turn_id", None)
                    or owner.owner_subject_sha256 != getattr(receipt, "owner_subject_sha256", None)
                    or owner.core_generation != getattr(receipt, "core_generation", None)
                    or owner.core_source_generation != getattr(receipt, "core_source_generation", None)
                    or context.review_prompt_sha256 != getattr(receipt, "prompt_sha256", None)
                    or context.mission_id != getattr(receipt, "mission_id", None)
                    or context.revision != getattr(receipt, "revision", None)
                    or context.run_id != getattr(receipt, "run_id", None)
                    or context.result_sha256 != getattr(receipt, "result_sha256", None)
                    or context.execution_core_generation != getattr(receipt, "execution_core_generation", None)
                    or context.execution_core_source_generation != getattr(receipt, "execution_core_source_generation", None)
                    or record["response_sha256"] != getattr(receipt, "response_sha256", None)
                    or observed_text_sha256 != record["response_sha256"]
                    or (supplied_text is not None and supplied_text != observed_text)
                    or attempt.get("response") is None or attempt["response"][1]
                    or attempt.get("response")[2] != record["response_sha256"]):
                return False
            try:
                from hermes_installer.remote.core_gateway_inspector import _verify_master_review_context
                _verify_master_review_context(context,
                    owner_subject_sha256=owner.owner_subject_sha256,
                    core_generation=owner.core_generation,
                    core_source_generation=owner.core_source_generation,
                    prompt_sha256=context.review_prompt_sha256,
                    config=self._config, custody=self._custody)
                return True
            except Exception:
                return False

    def _policy_for_owner(self, owner: Any, now: float) -> RootSelectedOrchestratorDelegationPolicy | None:
        from hermes_installer.remote.core_gateway_inspector import CoreVerifiedNativeToolConfiguration
        handle = self._owner_policy_handles.get(owner.owner_turn_handle)
        row = self._policies.get(handle) if isinstance(handle, str) else None
        if row is None or row.get("owner") is not owner:
            return None
        policy = row.get("policy")
        configuration = row.get("configuration")
        if (type(policy) is not RootSelectedOrchestratorDelegationPolicy
                or type(configuration) is not CoreVerifiedNativeToolConfiguration
                or policy._seal is not _NATIVE_INHERITANCE_POLICY_SEAL
                or policy.expires_monotonic <= now
                or policy.core_generation != self._custody.core_generation
                or policy.core_generation != owner.core_generation
                or policy.core_source_generation != self._custody.core_source_generation
                or policy.owner_subject_sha256 != owner.owner_subject_sha256
                or _hash(_native_policy_digest_fields(policy)) != policy.policy_sha256
                or configuration.is_current_sealed(
                    custody=self._custody, owner_turn=owner, now=now) is not True
                or not _configuration_has_fixed_resources_delegate(configuration)):
            self._policies.pop(handle, None)
            self._owner_policy_handles.pop(owner.owner_turn_handle, None)
            return None
        return policy

    def _selection_for_mission(self, owner: Any, source_id: str, now: float) -> tuple[Any, Any] | None:
        """Join a spent schema-2 mission binding to one live sealed master decision."""
        from hermes_installer.components.resources_active_profile_source import RootSelectedActiveProfileSource
        binding = getattr(owner, "mission_binding", None)
        if type(binding) is not MissionBinding or binding.schema != 2:
            return None
        matches = []
        for row in self._master_selections.values():
            decision = row.get("decision")
            source = row.get("sources", {}).get(source_id)
            team_selection = (decision.plan.get("team_selection")
                              if isinstance(getattr(decision, "plan", None), Mapping) else None)
            team_binding = row.get("team_binding")
            if team_selection is None:
                team_current = team_binding is None
            else:
                try:
                    from hermes_installer.remote.core_gateway_inspector import _read_root_planning_catalog
                    catalog, current_catalog_sha = _read_root_planning_catalog(
                        decision.core_source_generation)
                    team_row = catalog["teams"][team_selection["team_id"]]
                    team_current = bool(
                        type(team_binding) is RootSelectedTeamBinding
                        and team_binding._seal is _TEAM_BINDING_SEAL
                        and self._team_bindings.get(team_binding.binding_id) is team_binding
                        and team_binding.owner_subject_sha256 == owner.owner_subject_sha256
                        and team_binding.mission_id == decision.mission_id
                        and team_binding.revision == decision.revision
                        and team_binding.plan_sha256 == decision.plan_sha256
                        and team_binding.catalog_sha256 == current_catalog_sha
                        and team_binding.team_id == team_selection["team_id"]
                        and team_binding.bundle_generation_sha256 == team_row["bundle_generation_sha256"]
                        and team_binding.bundle_member_sha256 == team_row["bundle_member_sha256"]
                        and team_binding.source_revision == team_row["source_revision"]
                        and list(team_binding.ordered_member_ids) == team_row["ordered_member_ids"]
                        and list(team_binding.selected_expert_ids) == team_selection["selected_expert_ids"]
                        and time.monotonic() < team_binding.expires_monotonic)
                except Exception:
                    team_current = False
            if (row["expiry"] <= now or source is None
                    or not team_current
                    or decision.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                    or decision.owner_subject_sha256 != owner.owner_subject_sha256
                    or decision.core_generation != owner.core_generation
                    or decision.core_source_generation != owner.core_source_generation
                    or row.get("owner") is None
                    or row["owner"].owner_subject_sha256 != owner.owner_subject_sha256
                    or decision.mission_id != binding.mission_id
                    or decision.revision != binding.revision
                    or decision.plan_sha256 != binding.plan_sha256
                    or decision.execution_mode != binding.execution_mode
                    or tuple(decision.selected_source_ids) != tuple(binding.selected_source_ids)
                    or source_id not in binding.selected_source_ids
                    or type(source) is not RootSelectedActiveProfileSource
                    or source.is_current_sealed(self._custody, now=now) is not True):
                continue
            matches.append((row, source))
        return matches[0] if len(matches) == 1 else None

    def is_current_orchestrator_policy(self, policy: Any, owner_turn_observation: Any) -> bool:
        """Verify the exact root-retained policy before the gateway op returns."""
        if type(policy) is not RootSelectedOrchestratorDelegationPolicy:
            return False
        with self._lock:
            now = time.monotonic()
            if (self._closed
                    or self._owners.get(getattr(owner_turn_observation, "owner_turn_handle", None))
                        is not owner_turn_observation
                    or self._policy_for_owner(owner_turn_observation, now) is not policy):
                return False
            return True

    def _persist_obsidian_origin(self, records: dict[tuple[str, str], dict[str, Any]],
                                 completed: dict[tuple[str, str], dict[str, Any]] | None = None) -> None:
        completed = self._obsidian_completed_drafts if completed is None else completed
        if (not self._obsidian_origin_store_ok
                or len(records) > _OBSIDIAN_ORIGIN_MAX_RECORDS
                or len(completed) > _OBSIDIAN_ORIGIN_MAX_RECORDS):
            raise ValueError("root Obsidian origin journal is unavailable or full")
        ordered = [records[key] for key in sorted(records)]
        completed_ordered = [completed[key] for key in sorted(completed)]
        raw = _canonical({"schema": 2, "records": ordered, "completed": completed_ordered})
        projected = dict(completed)
        reserved_keys: set[tuple[str, str]] = set()
        for history_row in self._obsidian_origin_history:
            tombstone = _reserved_origin_tombstone(history_row)
            if tombstone is None:
                continue
            key = (tombstone["owner_subject_sha256"], tombstone["draft_id"])
            if key not in records and key not in projected:
                continue
            if key in projected and projected[key] != tombstone:
                self._obsidian_origin_store_ok = False
                raise ValueError("root Obsidian history reservation conflicts with completion index")
            projected[key] = tombstone
            if key in records:
                reserved_keys.add(key)
        projected_records = [records[key] for key in sorted(records) if key not in reserved_keys]
        projected_raw = _canonical({"schema": 2, "records": projected_records,
                                    "completed": [projected[key] for key in sorted(projected)]})
        if (len(raw) > _OBSIDIAN_ORIGIN_MAX_BYTES
                or len(projected_records) + len(projected) > _OBSIDIAN_ORIGIN_MAX_RECORDS
                or len(projected_raw) > _OBSIDIAN_ORIGIN_MAX_BYTES):
            self._obsidian_origin_store_ok = False
            raise ValueError("root Obsidian origin journal lacks reserved completion capacity")
        try:
            _publish_root_obsidian_origin_bytes(raw)
            verified = _obsidian_origin_state_from_bytes(_read_root_obsidian_origin_bytes() or b"")
            if verified != (records, completed):
                raise OSError("root Obsidian origin journal readback differs")
        except Exception:
            self._obsidian_origin_store_ok = False
            raise ValueError("root Obsidian origin journal could not be persisted") from None

    def _persist_obsidian_history(self, records: list[dict[str, Any]]) -> None:
        if (not self._obsidian_origin_store_ok
                or len(records) > _OBSIDIAN_ORIGIN_HISTORY_MAX_RECORDS):
            raise ValueError("root Obsidian origin history is full or unavailable")
        raw = _canonical({"schema": 1, "records": records})
        if len(raw) > _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES:
            raise ValueError("root Obsidian origin history reached its fixed size bound")
        try:
            _publish_root_obsidian_history_bytes(raw)
            verified = _obsidian_history_from_bytes(_read_root_obsidian_history_bytes() or b"")
            if verified != records:
                raise OSError("root Obsidian origin history readback differs")
        except Exception:
            self._obsidian_origin_store_ok = False
            raise ValueError("root Obsidian origin history could not be persisted") from None

    def _obsidian_store_for_origin(self, data_root: Path, owner_sha: str) -> Any:
        from .obsidian_second_brain import ObsidianVaultConfig, ObsidianVaultStore
        if data_root.as_posix() != "/home/admin/.hermes/jarvis-second-brain":
            raise ValueError("Obsidian origin store root differs from the enrolled fixed owner")
        return ObsidianVaultStore(ObsidianVaultConfig(data_root, owner_sha, owner_uid=1000))

    def _validate_obsidian_origin_binding(self, *, peer: tuple[int, int, int],
                                          binding_id: str, owner: Any,
                                          now: float) -> tuple[Path, str, str, dict[str, Any]]:
        if not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id):
            raise ValueError("Obsidian origin binding ID is malformed")
        startup = self._obsidian_bindings.get(binding_id)
        from .obsidian_owner_lifecycle import read_registration
        data_root, registered_owner, registration_sha = read_registration()
        if (startup is None or startup["peer"] != peer or startup["expiry"] <= now
                or startup["owner_subject_sha256"] != owner.owner_subject_sha256
                or startup["registration_sha256"] != registration_sha
                or registered_owner != owner.owner_subject_sha256
                or startup["core_generation"] != owner.core_generation
                or startup["core_source_generation"] != owner.core_source_generation
                or startup["core_pid"] != self._custody.core_pid
                or startup["core_start_ticks"] != self._custody.core_start_ticks
                or self._config.core_uid != 1000 or self._config.core_gid != 1000):
            raise ValueError("Obsidian owner registration or startup binding changed")
        return data_root, registered_owner, registration_sha, startup

    def _read_obsidian_owner_draft(self, data_root: Path, owner_sha: str, draft_id: str) -> Any:
        return self._obsidian_store_for_origin(data_root, owner_sha).read_owner_draft(draft_id=draft_id)

    def _record_obsidian_draft_read_delivery(self, *, call: dict[str, Any], owner: Any,
                                            master_source: Any, startup: dict[str, Any],
                                            startup_binding_id: str,
                                            draft_id: str, content_sha256: str,
                                            origin_record_sha256: str,
                                            returned_markdown: str | None,
                                            complete: bool, delivered_monotonic: float) -> dict[str, Any]:
        """Retain bounded same-turn data proving exactly what the pinned master read returned."""
        if (len(self._obsidian_draft_read_deliveries) >= _OBSIDIAN_DELIVERY_MAX_RECORDS
                or type(complete) is not bool or (complete != (returned_markdown is not None))):
            raise ValueError("Obsidian read-delivery state is unavailable")
        returned_bytes = (returned_markdown.encode("utf-8", "strict")
                          if returned_markdown is not None else b"")
        row = {
            "receipt_id": secrets.token_urlsafe(32),
            "owner_subject_sha256": owner.owner_subject_sha256,
            "owner_turn_handle": owner.owner_turn_handle,
            "draft_id": draft_id, "content_sha256": content_sha256,
            "origin_record_sha256": origin_record_sha256,
            "source_generation_sha256": master_source.generation_sha256,
            "startup_binding_id": startup_binding_id,
            "startup_binding_facts_sha256": _obsidian_startup_facts_sha256(startup),
            "observed_call_handle": call["handle"],
            "tool_call_id": call["tool_call_id"],
            "arguments_sha256": call["arguments_sha256"],
            "returned_byte_length": len(returned_bytes),
            "returned_content_sha256": hashlib.sha256(returned_bytes).hexdigest(),
            "complete": complete, "covered_byte_length": len(returned_bytes),
            "delivered_monotonic": delivered_monotonic,
            "expires_monotonic": min(float(owner.expires_monotonic),
                                      delivered_monotonic + 600.0),
        }
        if not row["complete"]:
            row["covered_byte_length"] = 0
        row["receipt_sha256"] = hashlib.sha256(_canonical(row)).hexdigest()
        # These two root-only fields are deliberately outside the sealed wire
        # receipt: one is the exact prepared public tool result, the other is
        # filled only after the native middleware receives that returned value.
        row["tool_result_sha256"] = None
        row["native_returned_sha256"] = None
        if row["receipt_id"] in self._obsidian_draft_read_deliveries:
            raise ValueError("Obsidian read-delivery receipt ID collided")
        self._obsidian_draft_read_deliveries[row["receipt_id"]] = dict(row)
        return row

    def _propose_obsidian_draft_review(self, *, call: dict[str, Any], owner: Any,
                                       source: Any, peer: tuple[int, int, int],
                                       startup_binding_id: str) -> dict[str, Any]:
        """Bind Jarvis's exact promote invocation to a full same-turn draft delivery."""
        if call["handle"] in self._obsidian_draft_review_proposals:
            raise ValueError("Obsidian promotion review proposal was already recorded")
        try:
            arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                   object_pairs_hook=_unique_json_pairs)
        except Exception:
            raise ValueError("observed Obsidian promotion arguments are malformed") from None
        expected_fields = {"draft_id", "expected_draft_sha256", "destination",
                           "expected_base_sha256", "review_disposition"}
        if type(arguments) is not dict or set(arguments) not in (
                expected_fields, expected_fields | {"review_rationale"}) or _canonical(arguments) != call["arguments"]:
            raise ValueError("observed Obsidian promotion schema differs")
        draft_id = arguments["draft_id"]
        content_sha = arguments["expected_draft_sha256"]
        destination = arguments["destination"]
        base_sha = arguments["expected_base_sha256"]
        rationale = arguments.get("review_rationale")
        if (arguments["review_disposition"] != "approve"
                or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                or not _HASH.fullmatch(content_sha or "")
                or (base_sha is not None and not _HASH.fullmatch(base_sha or ""))
                or not isinstance(destination, str) or not 1 <= len(destination) <= 240
                or (rationale is not None and (not isinstance(rationale, str)
                    or len(rationale) > 512
                    or any(ord(char) < 0x20 and char not in "\n\t" for char in rationale)))):
            raise ValueError("Jarvis did not explicitly propose approval for a valid draft promotion")
        if not self._obsidian_origin_store_ok:
            raise ValueError("root Obsidian origin journal is unavailable")
        key = (owner.owner_subject_sha256, draft_id)
        origin = self._obsidian_draft_origins.get(key)
        delivery = None
        data_root = registered_owner = registration_sha = startup = None
        data_root, registered_owner, registration_sha, startup = \
            self._validate_obsidian_origin_binding(
                peer=peer, binding_id=startup_binding_id, owner=owner, now=time.monotonic())
        for candidate in self._obsidian_draft_read_deliveries.values():
            if (candidate["owner_subject_sha256"] != owner.owner_subject_sha256
                    or candidate["owner_turn_handle"] != owner.owner_turn_handle
                    or candidate["draft_id"] != draft_id
                    or candidate["content_sha256"] != content_sha
                    or candidate["complete"] is not True
                    or candidate["covered_byte_length"] != candidate["returned_byte_length"]
                    or candidate["expires_monotonic"] <= time.monotonic()
                    or candidate["source_generation_sha256"] != source.generation_sha256
                    or candidate["observed_call_handle"] == call["handle"]):
                continue
            if (candidate["origin_record_sha256"] != (origin or {}).get("origin_record_sha256")
                    or candidate["startup_binding_facts_sha256"]
                        != _obsidian_startup_facts_sha256(startup)
                    or hashlib.sha256(_canonical({key: value for key, value in candidate.items()
                        if key not in {"receipt_sha256", "tool_result_sha256",
                                       "native_returned_sha256"}})).hexdigest()
                        != candidate["receipt_sha256"]
                    or not isinstance(candidate.get("tool_result_sha256"), str)
                    or candidate.get("native_returned_sha256")
                        != candidate.get("tool_result_sha256")):
                continue
            delivery = candidate
            break
        if (origin is None or origin["state"] != "private-draft"
                or origin["registration_sha256"] != registration_sha
                or origin["content_sha256"] != content_sha
                or origin["base_sha256"] != base_sha
                or origin["origin_record_sha256"] != _obsidian_origin_record_digest(origin)
                or delivery is None
                or delivery["origin_record_sha256"] != origin["origin_record_sha256"]
                or registered_owner != owner.owner_subject_sha256):
            raise ValueError("exact complete draft bytes were not delivered in this Jarvis owner turn")
        try:
            from hermes_installer.remote.obsidian_second_brain import _note_relative_path
            if _note_relative_path(destination) != destination:
                raise ValueError
        except Exception:
            raise ValueError("Obsidian promotion destination is not a normalized owner note path") from None
        try:
            reviewed = self._read_obsidian_owner_draft(data_root, registered_owner, draft_id)
        except Exception:
            reservation = next((row for row in self._obsidian_origin_history
                if row.get("phase") in {None, "reserved", "completed"}
                and row["origin"].get("origin_record_sha256") == origin["origin_record_sha256"]
                and row["result"].get("content_sha256") == content_sha
                and row["result"].get("destination") == destination), None)
            if reservation is None:
                raise ValueError("draft has no exact pending or recoverable promotion record") from None
            from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id, _draft_projection
            store = self._obsidian_store_for_origin(data_root, registered_owner)
            private = store.read_private_draft(
                execution_id=origin["origin_execution_id"], draft_id=draft_id,
                source_instance_id=origin["origin_source_id"])
            relative = _note_relative_path(destination)
            saved = store._read_optional_note(relative)
            if (private.get("state") != "promoted"
                    or private.get("contentSha256") != content_sha
                    or private.get("promotedSha256") != content_sha
                    or private.get("baseSha256") != base_sha
                    or private.get("destinationId") != _opaque_id(relative)
                    or saved is None or saved[1] != content_sha
                    or saved[0] != private.get("markdown")
                    or not store._has_exact_promotion_revision(relative, base_sha, content_sha)):
                raise ValueError("prior public note is not the exact reserved revision outcome") from None
            reviewed = SimpleNamespace(draft=_draft_projection(draft_id, private),
                                       markdown=private["markdown"])
        reviewed_bytes = reviewed.markdown.encode("utf-8", "strict")
        if (reviewed.draft.content_sha256 != content_sha
                or reviewed.draft.base_sha256 != base_sha
                or hashlib.sha256(reviewed_bytes).hexdigest() != content_sha
                or delivery["returned_byte_length"] != len(reviewed_bytes)
                or delivery["returned_content_sha256"] != content_sha):
            raise ValueError("pending draft bytes changed after Jarvis received the complete review content")
        after_call, after_owner, after_source, after_mode = self._classify_current_call(
            call["handle"], peer, now=time.monotonic())
        now = time.monotonic()
        data_root2, registered_owner2, registration_sha2, startup2 = self._validate_obsidian_origin_binding(
            peer=peer, binding_id=startup["binding_id"], owner=owner, now=now)
        if (after_call is not call or after_owner is not owner or after_mode != "master_effect"
                or after_source is None or after_source.profile_id != "hermes"
                or after_source.generation_sha256 != source.generation_sha256
                or data_root2 != data_root or registered_owner2 != registered_owner
                or registration_sha2 != registration_sha or startup2 is not startup
                or now >= min(call["expiry"], owner.expires_monotonic, startup["expiry"])):
            raise ValueError("current owner call, source, or registration changed during proposal verification")
        issued = time.monotonic()
        proposal = {
            "proposal_id": secrets.token_urlsafe(32),
            "owner_subject_sha256": owner.owner_subject_sha256,
            "owner_turn_handle": owner.owner_turn_handle,
            "draft_id": draft_id, "content_sha256": content_sha,
            "destination": destination, "expected_base_sha256": base_sha,
            "disposition": "approve", "rationale": rationale,
            "observed_call_handle": call["handle"], "tool_call_id": call["tool_call_id"],
            "arguments_sha256": call["arguments_sha256"],
            "source_generation_sha256": source.generation_sha256,
            "read_delivery_receipt_id": delivery["receipt_id"],
            "read_delivery_sha256": delivery["receipt_sha256"],
            "read_delivery_output_sha256": delivery["native_returned_sha256"],
            "origin_record_sha256": origin["origin_record_sha256"],
            "created_monotonic": issued,
            "owner_expires_monotonic": float(owner.expires_monotonic),
            "call_expires_monotonic": float(call["expiry"]),
            "expires_monotonic": min(float(owner.expires_monotonic), float(call["expiry"]), issued + 600.0),
        }
        proposal["proposal_sha256"] = hashlib.sha256(_canonical(proposal)).hexdigest()
        if len(self._obsidian_draft_review_proposals) >= _OBSIDIAN_PROPOSAL_MAX_RECORDS:
            self._obsidian_draft_review_proposals = {
                handle: row for handle, row in self._obsidian_draft_review_proposals.items()
                if row["expires_monotonic"] > issued}
        if len(self._obsidian_draft_review_proposals) >= _OBSIDIAN_PROPOSAL_MAX_RECORDS:
            raise ValueError("root Jarvis review proposal capacity is full")
        return proposal

    def _handle(self, peer: tuple[int, int, int], request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        nonce = request.get("nonce")
        if type(request.get("schema")) is not int or request["schema"] != 1 or not isinstance(nonce, str):
            raise ValueError("invalid observer request")
        with self._lock:
            self._ensure_open()
            self._prune(time.monotonic())
            if op == "claim-lifecycle-startup-probe":
                if set(request) != {"schema", "op", "nonce", "probe_handle"}:
                    raise ValueError("lifecycle startup claim schema mismatch")
                handle = request["probe_handle"]
                row = self._lifecycle_startup_probes.get(handle)
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or row is None or row.get("claimed_peer") is not None
                        or not self._lifecycle_startup_peer_current(row, row["cohort"])
                        or peer != (row["cohort"].peer_pid, row["cohort"].peer_uid,
                                    row["cohort"].peer_gid)):
                    raise ValueError("lifecycle probe is unavailable to this native peer")
                cohort = row["cohort"]
                row["claimed_peer"] = peer
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "probe_handle": handle, "probe_id": row["probe_id"],
                    "session_id": row["session_id"], "startup_nonce": row["nonce"],
                    "deadline_monotonic": cohort.deadline_monotonic,
                    "cohort_sha256": cohort.cohort_sha256,
                    "core_generation": cohort.core_generation,
                    "core_source_generation": cohort.core_source_generation,
                    "generation_a1_sha256": cohort.generation_a1_sha256,
                    "js_sha256": cohort.js_sha256, "rs_sha256": cohort.rs_sha256,
                    "u1_sha256": cohort.u1_sha256, "l1_sha256": cohort.l1_sha256,
                    "primary_source_sha256": cohort.primary_source_sha256,
                    "active_soul_sha256": cohort.active_soul_sha256,
                    "native_inventory_sha256": cohort.native_inventory_sha256,
                    "provider": cohort.provider, "api_mode": cohort.api_mode,
                    "base_url": cohort.base_url, "model": cohort.model,
                    "account_fingerprint": cohort.account_fingerprint}
            if op == "register-lifecycle-startup-attempt":
                required = {"schema", "op", "nonce", "probe_handle", "probe_id", "session_id",
                    "turn_id", "api_request_id", "provider", "api_mode", "base_url", "model",
                    "account_fingerprint", "request_sha256", "prompt_sha256", "tool_names",
                    "retry_count"}
                if set(request) != required:
                    raise ValueError("lifecycle attempt schema mismatch")
                row = self._lifecycle_startup_probes.get(request["probe_handle"])
                cohort = row.get("cohort") if isinstance(row, dict) else None
                expected_prompt = (hashlib.sha256((_LIFECYCLE_STARTUP_PROMPT_PREFIX + row["nonce"]
                    + _LIFECYCLE_STARTUP_PROMPT_SUFFIX).encode("ascii")).hexdigest()
                    if isinstance(row, dict) else None)
                if (row is None or type(cohort) is not RootLifecycleStartupCohort
                        or row.get("claimed_peer") != peer or row.get("attempt_handle") is not None
                        or request["probe_id"] != row["probe_id"]
                        or request["session_id"] != row["session_id"]
                        or request["provider"] != cohort.provider
                        or request["api_mode"] != cohort.api_mode
                        or request["base_url"] != cohort.base_url
                        or request["model"] != cohort.model
                        or request["account_fingerprint"] != cohort.account_fingerprint
                        or request["prompt_sha256"] != expected_prompt
                        or request["tool_names"] != []
                        or type(request["retry_count"]) is not int or request["retry_count"] != 0
                        or not _HASH.fullmatch(request.get("request_sha256", ""))
                        or not _ID.fullmatch(request.get("turn_id", ""))
                        or not _ID.fullmatch(request.get("api_request_id", ""))
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise ValueError("lifecycle provider attempt differs from enrolled cohort")
                attempt_handle = secrets.token_urlsafe(32)
                row["attempt_handle"] = attempt_handle
                self._lifecycle_startup_attempts[attempt_handle] = {
                    "probe_handle": request["probe_handle"], "peer": peer,
                    "turn_id": request["turn_id"], "api_request_id": request["api_request_id"],
                    "request_sha256": request["request_sha256"],
                    "prompt_sha256": request["prompt_sha256"],
                    "expiry": min(cohort.deadline_monotonic, time.monotonic() + 120.0),
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "attempt_handle": attempt_handle}
            if op == "register-lifecycle-startup-response":
                required = {"schema", "op", "nonce", "probe_handle", "attempt_handle",
                    "turn_id", "api_request_id", "request_sha256", "response_sha256",
                    "response_text", "response_text_sha256", "completed", "tool_call_count"}
                if set(request) != required:
                    raise ValueError("lifecycle response schema mismatch")
                row = self._lifecycle_startup_probes.get(request["probe_handle"])
                attempt = self._lifecycle_startup_attempts.get(request["attempt_handle"])
                cohort = row.get("cohort") if isinstance(row, dict) else None
                text = request.get("response_text")
                if (row is None or attempt is None or type(cohort) is not RootLifecycleStartupCohort
                        or row.get("claimed_peer") != peer or row.get("completion_handle") is not None
                        or attempt.get("probe_handle") != request["probe_handle"]
                        or attempt.get("peer") != peer or attempt.get("expiry", 0) <= time.monotonic()
                        or attempt.get("turn_id") != request["turn_id"]
                        or attempt.get("api_request_id") != request["api_request_id"]
                        or attempt.get("request_sha256") != request["request_sha256"]
                        or request.get("completed") is not True
                        or type(request.get("tool_call_count")) is not int
                        or request.get("tool_call_count") != 0
                        or not isinstance(text, str) or not 1 <= len(text) <= 1024
                        or hashlib.sha256(text.encode("utf-8", "strict")).hexdigest()
                           != request.get("response_text_sha256")
                        or text != _LIFECYCLE_STARTUP_RESPONSE_PREFIX + row["nonce"]
                        or not _HASH.fullmatch(request.get("response_sha256", ""))
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise ValueError("lifecycle terminal differs from exact startup challenge")
                completion_handle = secrets.token_urlsafe(32)
                row["completion_handle"] = completion_handle
                row["provider_terminal"] = {
                    "turn_id": attempt["turn_id"], "api_request_id": attempt["api_request_id"],
                    "request_sha256": attempt["request_sha256"],
                    "prompt_sha256": attempt["prompt_sha256"],
                    "response_sha256": request["response_sha256"],
                    "response_text_sha256": request["response_text_sha256"],
                }
                self._lifecycle_startup_attempts.pop(request["attempt_handle"], None)
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "completion_handle": completion_handle}
            if op == "bind-obsidian-native-vault":
                if set(request) != {"schema", "op", "nonce"}:
                    raise ValueError("Obsidian startup binding schema mismatch")
                # The listener verified SO_PEERCRED plus live process custody.
                if peer != (self._custody.core_pid, self._custody.core_uid, self._custody.core_gid):
                    raise ValueError("Obsidian startup binding peer differs from current Core")
                from .obsidian_owner_lifecycle import OWNER_DATA_ROOT, read_registration
                data_root, owner_sha, registration_sha = read_registration()
                if (data_root != OWNER_DATA_ROOT or self._config.core_uid != 1000
                        or self._config.core_gid != 1000):
                    raise ValueError("selected owner vault registration or Core identity differs")
                now = time.monotonic()
                binding_id = secrets.token_urlsafe(32)
                expiry = now + 30.0
                self._obsidian_bindings[binding_id] = {
                    "peer": peer, "owner_subject_sha256": owner_sha,
                    "registration_sha256": registration_sha,
                    "core_generation": self._custody.core_generation,
                    "core_source_generation": self._custody.core_source_generation,
                    "core_pid": self._custody.core_pid,
                    "core_start_ticks": self._custody.core_start_ticks,
                    "issued": now, "expiry": expiry,
                }
                while len(self._obsidian_bindings) > 64:
                    oldest = min(self._obsidian_bindings, key=lambda key: self._obsidian_bindings[key]["issued"])
                    self._obsidian_bindings.pop(oldest, None)
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "binding_id": binding_id, "registration_sha256": registration_sha,
                    "owner_subject_sha256": owner_sha,
                    "core_generation": self._custody.core_generation,
                    "core_source_generation": self._custody.core_source_generation,
                    "core_pid": self._custody.core_pid,
                    "core_start_ticks": self._custody.core_start_ticks,
                    "selected_owner_uid": 1000, "vault_root": str(data_root),
                    "issued_monotonic": now, "expires_monotonic": expiry}
            if op == "authorize-obsidian-call-scope":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle", "startup_binding_id"}:
                    raise ValueError("Obsidian call scope schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id)
                        or handle in self._obsidian_scoped_calls):
                    raise ValueError("Obsidian call scope handle is invalid or replayed")
                call, owner, source, mode = self._classify_current_call(handle, peer, now=time.monotonic())
                if call["tool_name"] not in _OBSIDIAN_TOOL_NAMES:
                    raise ValueError("observed native call is outside fixed Obsidian tools")
                now = time.monotonic()
                startup = self._obsidian_bindings.get(binding_id)
                from .obsidian_owner_lifecycle import read_registration
                data_root, registered_owner, registration_sha = read_registration()
                if (startup is None or startup["peer"] != peer or startup["expiry"] <= now
                        or startup["owner_subject_sha256"] != owner.owner_subject_sha256
                        or startup["registration_sha256"] != registration_sha
                        or registered_owner != owner.owner_subject_sha256
                        or data_root.as_posix() != "/home/admin/.hermes/jarvis-second-brain"
                        or startup["core_generation"] != owner.core_generation
                        or startup["core_source_generation"] != owner.core_source_generation
                        or startup["core_pid"] != self._custody.core_pid
                        or startup["core_start_ticks"] != self._custody.core_start_ticks):
                    raise ValueError("Obsidian owner registration or startup binding changed")
                mission = None
                selected_notes = None
                if mode == "expert_read":
                    binding = owner.mission_binding
                    child = source
                    selected_source = child.get("source") if isinstance(child, dict) else None
                    source_id = child.get("profile_id") if isinstance(child, dict) else None
                    selected = (self._selection_for_mission(owner, source_id, now)
                                if isinstance(source_id, str) else None)
                    if (type(binding) is not MissionBinding or binding.schema != 2
                            or selected is None or selected_source is None
                            or not callable(getattr(selected_source, "is_current_sealed", None))
                            or selected_source.is_current_sealed(self._custody, now=now) is not True
                            or source_id not in (binding.selected_source_ids or ())
                            or call.get("attempt_session_id") not in self._child_sessions
                            or self._child_sessions[call["attempt_session_id"]].get("owner") is not owner
                            or call["tool_name"] not in self._child_sessions[
                                call["attempt_session_id"]].get("tool_names", ())):
                        raise ValueError("Expert Obsidian call is not joined to its current mission/source")
                    mission = binding.to_wire()
                    selected_notes = []
                    execution_id = child["session_id"]
                    source_instance_id = source_id
                    source_generation = child["source_generation_sha256"]
                else:
                    if mode == "master_effect" and call["tool_name"] != "obsidian_promote_reviewed_draft":
                        raise ValueError("only exact owner promotion is an Obsidian final effect")
                    if mode == "master_read" and call["tool_name"] not in _OBSIDIAN_MASTER_READ_TOOL_NAMES:
                        raise ValueError("Obsidian call mode differs from its fixed read/draft tool")
                    execution_id, source_instance_id = owner.owner_turn_handle, "hermes"
                    source_generation = source.generation_sha256
                if mode == "master_effect" and call["tool_name"] != "obsidian_promote_reviewed_draft":
                    raise ValueError("only exact owner promotion can receive a final-effect scope")
                self._obsidian_scoped_calls.add(handle)
                if len(self._obsidian_scoped_calls) > 4096:
                    # Live calls are separately retained for at most their short leases.
                    self._obsidian_scoped_calls = {item for item in self._obsidian_scoped_calls
                        if item in self._calls and self._calls[item].get("expiry", 0) > now}
                expiry = min(float(call["expiry"]), float(owner.expires_monotonic),
                             float(startup["expiry"]), now + 5.0)
                child_row = self._child_sessions.get(call.get("attempt_session_id"))
                if mode == "expert_read" and child_row is not None:
                    expiry = min(expiry, float(child_row["expiry"]))
                if not now < expiry <= now + 5.0:
                    raise ValueError("Obsidian call scope lease is unavailable")
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "observed_call_handle": call["handle"],
                    "owner_turn_handle": owner.owner_turn_handle,
                    "tool_call_id": call["tool_call_id"], "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "registration_sha256": registration_sha,
                    "startup_binding_id": binding_id,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source_generation,
                    "mode": mode, "execution_id": execution_id,
                    "source_instance_id": source_instance_id,
                    "mission_binding": mission, "selected_note_ids": selected_notes,
                    "issued_monotonic": now, "expires_monotonic": expiry}
            if op == "record-obsidian-draft-origin":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "startup_binding_id", "draft_id"}:
                    raise ValueError("Obsidian origin record schema mismatch")
                handle, binding_id, draft_id = (request["observed_call_handle"],
                    request["startup_binding_id"], request["draft_id"])
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(draft_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not self._obsidian_origin_store_ok):
                    raise ValueError("Obsidian origin record identity or journal is unavailable")
                call, owner, origin, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if (call["tool_name"] != "obsidian_create_private_draft"
                        or mode not in {"expert_read", "master_read"}):
                    raise ValueError("draft origin is not attached to an admitted create call")
                now = time.monotonic()
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=now)
                if self._config.core_uid != 1000 or self._config.core_gid != 1000:
                    raise ValueError("Obsidian origin registration requires the selected Core identity")
                try:
                    arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                           object_pairs_hook=_unique_json_pairs)
                except Exception:
                    raise ValueError("observed draft creation arguments are malformed") from None
                allowed = {"title", "markdown", "base_note_id", "base_sha256", "citations"}
                if (type(arguments) is not dict or set(arguments) - allowed
                        or not {"title", "markdown"}.issubset(arguments)
                        or _canonical(arguments) != call["arguments"]):
                    raise ValueError("observed draft creation call differs from fixed arguments")
                reviewed = self._read_obsidian_owner_draft(data_root, registered_owner, draft_id)
                from .obsidian_second_brain import _citations, _title_text
                draft = reviewed.draft
                expected_base_id = arguments.get("base_note_id")
                expected_base_sha = arguments.get("base_sha256")
                try:
                    expected_citations = _citations(arguments.get("citations", ()))
                    expected_title = _title_text(arguments["title"])
                except Exception:
                    raise ValueError("observed draft metadata is malformed") from None
                if (reviewed.markdown != arguments["markdown"] or draft.title != expected_title
                        or draft.base_note_id != expected_base_id or draft.base_sha256 != expected_base_sha
                        or tuple(draft.citations) != tuple(expected_citations)
                        or hashlib.sha256(reviewed.markdown.encode("utf-8", "strict")).hexdigest()
                            != draft.content_sha256):
                    raise ValueError("private draft bytes do not match the observed create call")
                if mode == "expert_read":
                    child = origin
                    mission_binding = owner.mission_binding
                    source = child.get("source") if isinstance(child, dict) else None
                    source_id = child.get("profile_id") if isinstance(child, dict) else None
                    if (child.get("session_id") != draft.execution_id
                            or source_id != draft.source_instance_id
                            or source is None or type(mission_binding) is not MissionBinding
                            or mission_binding.schema != 2
                            or source.is_current_sealed(self._custody, now=now) is not True):
                        raise ValueError("Expert draft origin does not match its current selected child/source")
                    execution_id = child["session_id"]
                    source_generation = child["source_generation_sha256"]
                    source_revision = source.source_revision
                    mission_sha = hashlib.sha256(_canonical(mission_binding.to_wire())).hexdigest()
                else:
                    source = origin
                    if (draft.execution_id != owner.owner_turn_handle
                            or draft.source_instance_id != "hermes"
                            or source.is_current_sealed(self._custody, now=now) is not True):
                        raise ValueError("Jarvis draft origin does not match its current owner turn/source")
                    execution_id = owner.owner_turn_handle
                    source_generation = source.generation_sha256
                    source_revision = source.source_revision
                    mission_sha = None
                if (draft.execution_id != execution_id or not isinstance(source_revision, str)
                        or not source_revision or len(source_revision) > 128):
                    raise ValueError("private draft identity differs from the root-observed creator")
                key = (owner.owner_subject_sha256, draft_id)
                if key in self._obsidian_draft_origins or key in self._obsidian_completed_drafts:
                    raise ValueError("private draft origin was already recorded or completed")
                record = {
                    "draft_id": draft_id, "owner_subject_sha256": owner.owner_subject_sha256,
                    "registration_sha256": registration_sha, "origin_execution_id": execution_id,
                    "origin_source_id": draft.source_instance_id,
                    "origin_source_revision": source_revision,
                    "source_generation_sha256": source_generation, "mission_sha256": mission_sha,
                    "content_sha256": draft.content_sha256, "base_sha256": draft.base_sha256,
                    "state": "private-draft",
                }
                record["origin_record_sha256"] = _obsidian_origin_record_digest(record)
                proposed = dict(self._obsidian_draft_origins)
                proposed[key] = record
                self._persist_obsidian_origin(proposed)
                self._obsidian_draft_origins = proposed
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "origin_record_sha256": record["origin_record_sha256"]}
            if op == "resolve-obsidian-draft-origin":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "startup_binding_id", "draft_id", "expected_content_sha256"}:
                    raise ValueError("Obsidian origin resolution schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                draft_id, content_sha = request["draft_id"], request["expected_content_sha256"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(draft_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not _HASH.fullmatch(content_sha or "")
                        or not self._obsidian_origin_store_ok):
                    raise ValueError("Obsidian origin lookup identity or journal is unavailable")
                if handle in self._obsidian_resolved_origin_calls:
                    raise ValueError("Obsidian origin lookup call was already used (replayed)")
                if len(self._obsidian_resolved_origin_calls) >= 4096:
                    self._obsidian_resolved_origin_calls = {
                        item for item in self._obsidian_resolved_origin_calls
                        if item in self._calls and self._calls[item].get("expiry", 0) > time.monotonic()}
                if len(self._obsidian_resolved_origin_calls) >= 4096:
                    raise ValueError("Obsidian origin lookup replay window is full")
                self._obsidian_resolved_origin_calls.add(handle)
                call, owner, _source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if call["tool_name"] != "obsidian_promote_reviewed_draft" or mode != "master_effect":
                    raise ValueError("only the current Jarvis owner promotion can resolve a draft origin")
                try:
                    arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                           object_pairs_hook=_unique_json_pairs)
                except Exception:
                    raise ValueError("observed promotion arguments are malformed") from None
                if (type(arguments) is not dict
                        or set(arguments) not in (
                            {"draft_id", "expected_draft_sha256", "destination",
                             "expected_base_sha256", "review_disposition"},
                            {"draft_id", "expected_draft_sha256", "destination",
                             "expected_base_sha256", "review_disposition", "review_rationale"})
                        or _canonical(arguments) != call["arguments"]
                        or arguments["draft_id"] != draft_id
                        or arguments["expected_draft_sha256"] != content_sha
                        or arguments["review_disposition"] != "approve"):
                    raise ValueError("draft lookup differs from the exact observed owner review call")
                now = time.monotonic()
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=now)
                key = (owner.owner_subject_sha256, draft_id)
                record = self._obsidian_draft_origins.get(key)
                if (record is None or record["state"] != "private-draft"
                        or record["registration_sha256"] != registration_sha
                        or record["content_sha256"] != content_sha
                        or record["base_sha256"] != arguments["expected_base_sha256"]):
                    raise ValueError("draft has no current root-retained private origin")
                try:
                    reviewed = self._read_obsidian_owner_draft(data_root, registered_owner, draft_id)
                except Exception:
                    reservation = next((row for row in self._obsidian_origin_history
                        if row.get("phase") in {None, "reserved", "completed"}
                        and row["origin"].get("origin_record_sha256") == record["origin_record_sha256"]
                        and row["result"].get("content_sha256") == content_sha
                        and row["result"].get("destination") == arguments["destination"]), None)
                    if reservation is None:
                        raise ValueError("origin has no exact recoverable promotion reservation") from None
                    from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id, _draft_projection
                    store = self._obsidian_store_for_origin(data_root, registered_owner)
                    private = store.read_private_draft(
                        execution_id=record["origin_execution_id"], draft_id=draft_id,
                        source_instance_id=record["origin_source_id"])
                    relative = _note_relative_path(reservation["result"]["destination"])
                    saved = store._read_optional_note(relative)
                    if (private.get("state") != "promoted"
                            or private.get("contentSha256") != content_sha
                            or private.get("promotedSha256") != content_sha
                            or private.get("baseSha256") != record["base_sha256"]
                            or private.get("destinationId") != _opaque_id(relative)
                            or saved is None or saved[1] != content_sha
                            or saved[0] != private.get("markdown")
                            or not store._has_exact_promotion_revision(
                                relative, record["base_sha256"], content_sha)):
                        raise ValueError("promoted bytes do not match the exact durable revision intent") from None
                    reviewed = SimpleNamespace(
                        draft=_draft_projection(draft_id, private), markdown=private["markdown"])
                if (reviewed.draft.execution_id != record["origin_execution_id"]
                        or reviewed.draft.source_instance_id != record["origin_source_id"]
                        or reviewed.draft.content_sha256 != record["content_sha256"]
                        or reviewed.draft.base_sha256 != record["base_sha256"]
                        or hashlib.sha256(reviewed.markdown.encode("utf-8", "strict")).hexdigest()
                            != record["content_sha256"]):
                    raise ValueError("retained draft origin no longer matches private owner bytes")
                origin_record_sha = _obsidian_origin_record_digest(record)
                if origin_record_sha != record["origin_record_sha256"]:
                    raise ValueError("retained Obsidian origin record digest changed")
                issued = time.monotonic()
                expiry = min(float(call["expiry"]), float(owner.expires_monotonic),
                             float(startup["expiry"]), issued + 5.0)
                if not issued < expiry <= issued + 5.0:
                    raise ValueError("current Obsidian draft origin proof lease is unavailable")
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "draft_id": draft_id, "owner_subject_sha256": owner.owner_subject_sha256,
                    "registration_sha256": registration_sha,
                    "origin_execution_id": record["origin_execution_id"],
                    "origin_source_id": record["origin_source_id"],
                    "origin_source_revision": record["origin_source_revision"],
                    "source_generation_sha256": record["source_generation_sha256"],
                    "mission_sha256": record["mission_sha256"],
                    "content_sha256": record["content_sha256"],
                    "base_sha256": record["base_sha256"],
                    "origin_record_sha256": origin_record_sha, "state": record["state"],
                    "issued_monotonic": issued, "expires_monotonic": expiry}
            if op == "reserve-obsidian-draft-completion":
                required = {"schema", "op", "nonce", "observed_call_handle", "startup_binding_id",
                    "draft_id", "origin_record_sha256", "proposal_sha256", "pending_id",
                    "review_sha256", "destination", "expected_base_sha256"}
                if set(request) != required:
                    raise ValueError("Obsidian completion reservation schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                draft_id = request["draft_id"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id)
                        or not isinstance(draft_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not all(_HASH.fullmatch(request[name] or "") for name in (
                            "origin_record_sha256", "proposal_sha256", "review_sha256"))
                        or not isinstance(request["pending_id"], str)
                        or not _OPAQUE.fullmatch(request["pending_id"])
                        or not isinstance(request["destination"], str)
                        or (request["expected_base_sha256"] is not None
                            and not _HASH.fullmatch(request["expected_base_sha256"] or ""))):
                    raise ValueError("Obsidian completion reservation identity is malformed")
                call, owner, source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if call["tool_name"] != "obsidian_promote_reviewed_draft" or mode != "master_effect":
                    raise ValueError("only current Jarvis promotion can reserve completion capacity")
                proposal = self._obsidian_draft_review_proposals.get(handle)
                if (proposal is None or proposal["draft_id"] != draft_id
                        or proposal["proposal_sha256"] != request["proposal_sha256"]
                        or proposal["origin_record_sha256"] != request["origin_record_sha256"]
                        or proposal["arguments_sha256"] != call["arguments_sha256"]
                        or proposal["expires_monotonic"] <= time.monotonic()):
                    raise ValueError("completion reservation differs from the exact current Jarvis proposal")
                arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                       object_pairs_hook=_unique_json_pairs)
                if (type(arguments) is not dict or _canonical(arguments) != call["arguments"]
                        or arguments.get("review_disposition") != "approve"
                        or arguments.get("draft_id") != draft_id
                        or arguments.get("expected_draft_sha256") != proposal["content_sha256"]
                        or arguments.get("destination") != request["destination"]
                        or arguments.get("expected_base_sha256") != request["expected_base_sha256"]):
                    raise ValueError("completion reservation does not match exact observed owner arguments")
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                origin_key = (owner.owner_subject_sha256, draft_id)
                origin = self._obsidian_draft_origins.get(origin_key)
                if (origin is None or origin["origin_record_sha256"] != request["origin_record_sha256"]
                        or origin["registration_sha256"] != registration_sha
                        or _obsidian_origin_record_digest(origin) != origin["origin_record_sha256"]
                        or origin["content_sha256"] != proposal["content_sha256"]
                        or origin["base_sha256"] != request["expected_base_sha256"]):
                    raise ValueError("active root draft origin differs from completion reservation")
                expected_ledger = {
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                }
                if (proposal["_pending_id"] != request["pending_id"]
                        or proposal["_review_sha256"] != request["review_sha256"]
                        or self._final_effect_ledger().poll(
                            request["pending_id"], request["review_sha256"],
                            expected=expected_ledger) != "spent"):
                    raise ValueError("exact current owner approval is not spent for the capacity reservation")
                store = self._obsidian_store_for_origin(data_root, registered_owner)
                private = store.read_private_draft(
                    execution_id=origin["origin_execution_id"], draft_id=draft_id,
                    source_instance_id=origin["origin_source_id"])
                if (private.get("contentSha256") != proposal["content_sha256"]
                        or private.get("baseSha256") != origin["base_sha256"]
                        or private.get("title") is None):
                    raise ValueError("independent private draft readback differs from the approved reservation")
                from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id
                relative = _note_relative_path(request["destination"])
                observed_note = store._read_optional_note(relative)
                observed_digest = None if observed_note is None else observed_note[1]
                if observed_digest not in {origin["base_sha256"], proposal["content_sha256"]}:
                    raise ValueError("destination changed outside the exact retryable promotion intent")
                note_id = _opaque_id(relative)
                result = {"destination": relative, "note_id": note_id,
                    "title": private["title"], "content_sha256": proposal["content_sha256"],
                    "state": "promoted"}
                archived_proposal = _obsidian_archive_proposal(proposal)
                archived_approval = _obsidian_archive_approval(
                    pending_id=request["pending_id"], review_sha256=request["review_sha256"],
                    owner=owner, source_generation_sha256=source.generation_sha256, call=call)
                existing_index = next((index for index, row in enumerate(self._obsidian_origin_history)
                    if row["origin"]["origin_record_sha256"] == origin["origin_record_sha256"]), None)
                history = list(self._obsidian_origin_history)
                if existing_index is not None:
                    prior_result = history[existing_index]["result"]
                    if any(prior_result.get(key) != result.get(key) for key in (
                            "content_sha256", "destination", "note_id", "title")):
                        raise ValueError(
                            "Obsidian draft already has a durable reservation for another exact destination")
                if existing_index is None:
                    if len(history) >= _OBSIDIAN_ORIGIN_HISTORY_MAX_RECORDS:
                        raise ValueError("root Obsidian history capacity is full before note write")
                    record_id = secrets.token_urlsafe(32)
                    attempts = [{"proposal": archived_proposal, "approval": archived_approval}]
                    completed_at = time.time()
                    phase = "reserved"
                else:
                    prior = history[existing_index]
                    if prior.get("phase") not in {None, "reserved", "completed"}:
                        raise ValueError("Obsidian archive cannot reserve a new write attempt")
                    attempts = list(prior.get("attempts", ({
                        "proposal": prior["proposal"], "approval": prior["approval"]},)))
                    current_attempt = {"proposal": archived_proposal, "approval": archived_approval}
                    if not attempts or attempts[-1] != current_attempt:
                        if len(attempts) >= 8:
                            raise ValueError("root Obsidian completion retry history is full")
                        attempts.append(current_attempt)
                    record_id = prior["record_id"]
                    completed_at = prior["completed_at"]
                    phase = prior.get("phase", "completed")
                reserved = _obsidian_archive_row(record_id=record_id, phase=phase,
                    origin=origin, proposal=archived_proposal, approval=archived_approval,
                    result=result, completed_at=completed_at, attempts=attempts)
                final = _obsidian_archive_row(record_id=record_id, phase="completed",
                    origin=origin, proposal=archived_proposal, approval=archived_approval,
                    result=result, completed_at=completed_at, attempts=attempts)
                candidate = list(history)
                if existing_index is None:
                    candidate.append(reserved)
                else:
                    candidate[existing_index] = reserved
                projected_history = list(candidate)
                projected_history[-1 if existing_index is None else existing_index] = final
                if (len(projected_history) > _OBSIDIAN_ORIGIN_HISTORY_MAX_RECORDS
                        or len(_canonical({"schema": 1, "records": projected_history}))
                            > _OBSIDIAN_ORIGIN_HISTORY_MAX_BYTES):
                    raise ValueError("root Obsidian archive lacks exact completion capacity before note write")
                projected_tombstone = _reserved_origin_tombstone(final)
                if projected_tombstone is None:
                    raise ValueError("root Obsidian completion tombstone could not be reserved")
                projected_completed = dict(self._obsidian_completed_drafts)
                projected_records = dict(self._obsidian_draft_origins)
                reserved_keys: set[tuple[str, str]] = set()
                for history_row in candidate:
                    tombstone = _reserved_origin_tombstone(history_row)
                    if tombstone is None:
                        continue
                    tombstone_key = (tombstone["owner_subject_sha256"], tombstone["draft_id"])
                    if tombstone_key not in projected_records and tombstone_key not in projected_completed:
                        continue
                    existing_tombstone = projected_completed.get(tombstone_key)
                    if existing_tombstone is not None and existing_tombstone != tombstone:
                        raise ValueError("root Obsidian draft has a different completed tombstone")
                    projected_completed[tombstone_key] = tombstone
                    if tombstone_key in projected_records:
                        reserved_keys.add(tombstone_key)
                projected_records.pop((owner.owner_subject_sha256, draft_id), None)
                projected_record_rows = [projected_records[key]
                    for key in sorted(projected_records) if key not in reserved_keys]
                projected_origin_raw = _canonical({"schema": 2,
                    "records": projected_record_rows,
                    "completed": [projected_completed[key] for key in sorted(projected_completed)]})
                if (len(projected_record_rows) + len(projected_completed)
                        > _OBSIDIAN_ORIGIN_MAX_RECORDS
                        or len(projected_origin_raw) > _OBSIDIAN_ORIGIN_MAX_BYTES):
                    raise ValueError("root Obsidian completion tombstone capacity is full before note write")
                if existing_index is None:
                    history.append(reserved)
                else:
                    history[existing_index] = reserved
                self._persist_obsidian_history(history)
                self._obsidian_origin_history = history
                latest = history[existing_index if existing_index is not None else -1]
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "reservation_record_sha256": latest["record_sha256"]}
            if op == "complete-obsidian-draft-origin":
                required = {"schema", "op", "nonce", "observed_call_handle", "startup_binding_id",
                    "draft_id", "origin_record_sha256", "proposal_sha256", "pending_id",
                    "review_sha256", "destination", "expected_base_sha256", "note_id",
                    "content_sha256", "title"}
                if set(request) != required:
                    raise ValueError("Obsidian promotion completion schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                draft_id = request["draft_id"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id)
                        or not isinstance(draft_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not all(_HASH.fullmatch(request[name] or "") for name in (
                            "origin_record_sha256", "proposal_sha256", "review_sha256",
                            "content_sha256"))
                        or not isinstance(request["pending_id"], str)
                        or not _OPAQUE.fullmatch(request["pending_id"])
                        or not isinstance(request["destination"], str)
                        or not isinstance(request["title"], str)
                        or not 1 <= len(request["title"]) <= 160
                        or (request["expected_base_sha256"] is not None
                            and not _HASH.fullmatch(request["expected_base_sha256"] or ""))
                        or not _ID.fullmatch(request["note_id"])):
                    raise ValueError("Obsidian promotion completion identity is malformed")
                call, owner, source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if call["tool_name"] != "obsidian_promote_reviewed_draft" or mode != "master_effect":
                    raise ValueError("only current Jarvis promotion can complete a retained draft")
                proposal = self._obsidian_draft_review_proposals.get(handle)
                if (proposal is None or proposal["draft_id"] != draft_id
                        or proposal["proposal_sha256"] != request["proposal_sha256"]
                        or proposal["origin_record_sha256"] != request["origin_record_sha256"]
                        or proposal["content_sha256"] != request["content_sha256"]
                        or proposal["destination"] != request["destination"]
                        or proposal["expected_base_sha256"] != request["expected_base_sha256"]
                        or proposal["arguments_sha256"] != call["arguments_sha256"]
                        or proposal["expires_monotonic"] <= time.monotonic()):
                    raise ValueError("completed write differs from the retained Jarvis proposal")
                arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                       object_pairs_hook=_unique_json_pairs)
                if (type(arguments) is not dict or _canonical(arguments) != call["arguments"]
                        or arguments.get("review_disposition") != "approve"
                        or arguments.get("draft_id") != draft_id
                        or arguments.get("expected_draft_sha256") != request["content_sha256"]
                        or arguments.get("destination") != request["destination"]
                        or arguments.get("expected_base_sha256") != request["expected_base_sha256"]):
                    raise ValueError("promotion completion does not match exact observed owner arguments")
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                origin_key = (owner.owner_subject_sha256, draft_id)
                origin = self._obsidian_draft_origins.get(origin_key)
                if (origin is None or origin["origin_record_sha256"] != request["origin_record_sha256"]
                        or origin["registration_sha256"] != registration_sha
                        or _obsidian_origin_record_digest(origin) != origin["origin_record_sha256"]
                        or origin["state"] != "private-draft"):
                    raise ValueError("active root origin changed before verified completion")
                expected_ledger = {
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                }
                if (proposal["_pending_id"] != request["pending_id"]
                        or proposal["_review_sha256"] != request["review_sha256"]
                        or self._final_effect_ledger().poll(
                            request["pending_id"], request["review_sha256"],
                            expected=expected_ledger) != "spent"):
                    raise ValueError("the exact owner approval was not spent for this completed promotion")
                store = self._obsidian_store_for_origin(data_root, registered_owner)
                private = store.read_private_draft(
                    execution_id=origin["origin_execution_id"], draft_id=draft_id,
                    source_instance_id=origin["origin_source_id"])
                if (private.get("state") != "promoted"
                        or private.get("contentSha256") != request["content_sha256"]
                        or private.get("promotedSha256") != request["content_sha256"]
                        or private.get("baseSha256") != request["expected_base_sha256"]
                        or private.get("destinationId") != request["note_id"]
                        or private.get("title") != request["title"]
                        or hashlib.sha256(private.get("markdown", "").encode("utf-8", "strict")).hexdigest()
                            != request["content_sha256"]):
                    raise ValueError("independent private promoted-record readback differs")
                try:
                    from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id
                    relative = _note_relative_path(request["destination"])
                except Exception:
                    raise ValueError("verified promotion destination is not a valid owner note path") from None
                saved_note = store._read_optional_note(relative)
                if (saved_note is None or _opaque_id(relative) != request["note_id"]
                        or saved_note[1] != request["content_sha256"]
                        or saved_note[0] != private["markdown"]):
                    raise ValueError("independent public note readback differs from the promoted private record")
                after_call, after_owner, after_source, after_mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                after_root, after_registered_owner, after_registration, after_startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                verified_at = time.monotonic()
                if (after_call is not call or after_owner is not owner or after_mode != "master_effect"
                        or after_source is None or after_source.profile_id != "hermes"
                        or after_source.generation_sha256 != source.generation_sha256
                        or after_source.is_current_sealed(self._custody, now=verified_at) is not True
                        or after_root != data_root or after_registered_owner != registered_owner
                        or after_registration != registration_sha or after_startup is not startup
                        or proposal["expires_monotonic"] <= verified_at
                        or verified_at >= min(float(call["expiry"]), float(owner.expires_monotonic),
                                              float(startup["expiry"]))):
                    raise ValueError("current owner, source, registration, or original deadline changed during readback")
                archive_row = next((row for row in self._obsidian_origin_history
                    if row["origin"]["origin_record_sha256"] == origin["origin_record_sha256"]
                    and row["proposal"].get("proposal_sha256") == proposal["proposal_sha256"]), None)
                if archive_row is None:
                    raise ValueError("root completion reservation is missing; active draft retained")
                if (archive_row.get("phase") not in {"reserved", "completed"}
                        or archive_row["approval"]["pending_id"] != request["pending_id"]
                            or archive_row["approval"]["review_sha256"] != request["review_sha256"]
                            or archive_row["result"]["content_sha256"] != request["content_sha256"]
                            or archive_row["result"]["note_id"] != request["note_id"]
                            or archive_row["result"]["destination"] != relative
                            or archive_row["result"]["title"] != request["title"]):
                    raise ValueError("completion differs from the exact durable capacity reservation")
                if archive_row.get("phase") != "completed":
                    final_row = _obsidian_archive_row(
                        record_id=archive_row["record_id"], phase="completed",
                        origin=archive_row["origin"], proposal=archive_row["proposal"],
                        approval=archive_row["approval"], result=archive_row["result"],
                        completed_at=archive_row["completed_at"],
                        attempts=list(archive_row.get("attempts", ())))
                    history = list(self._obsidian_origin_history)
                    history[history.index(archive_row)] = final_row
                    self._persist_obsidian_history(history)
                    self._obsidian_origin_history = history
                    archive_row = final_row
                tombstone = _reserved_origin_tombstone(archive_row)
                if tombstone is None:
                    raise ValueError("verified archive cannot produce its reserved completion tombstone")
                remaining = dict(self._obsidian_draft_origins)
                remaining.pop(origin_key)
                completed = dict(self._obsidian_completed_drafts)
                existing = completed.get(origin_key)
                if existing is not None and existing != tombstone:
                    raise ValueError("draft already completed with a different verified result")
                completed[origin_key] = tombstone
                self._persist_obsidian_origin(remaining, completed)
                self._obsidian_draft_origins = remaining
                self._obsidian_completed_drafts = completed
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "completed_record_sha256": tombstone["completed_record_sha256"]}
            if op == "resolve-obsidian-review-proposal":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "startup_binding_id", "draft_id", "expected_content_sha256"}:
                    raise ValueError("Obsidian review proposal schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                draft_id, content_sha = request["draft_id"], request["expected_content_sha256"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id)
                        or not isinstance(draft_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not _HASH.fullmatch(content_sha or "")):
                    raise ValueError("Obsidian review proposal identity is malformed")
                call, owner, source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if call["tool_name"] != "obsidian_promote_reviewed_draft" or mode != "master_effect":
                    raise ValueError("only current Jarvis promotion can resolve its proposal")
                proposal = self._obsidian_draft_review_proposals.get(handle)
                if (proposal is None or proposal["draft_id"] != draft_id
                        or proposal["content_sha256"] != content_sha
                        or proposal["owner_turn_handle"] != owner.owner_turn_handle
                        or proposal["owner_subject_sha256"] != owner.owner_subject_sha256
                        or proposal["arguments_sha256"] != call["arguments_sha256"]
                        or proposal["expires_monotonic"] <= time.monotonic()):
                    raise ValueError("current promotion has no matching Jarvis proposal")
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                if (startup["binding_id"] != binding_id
                        or proposal["source_generation_sha256"] != source.generation_sha256):
                    raise ValueError("Jarvis proposal belongs to another current source or binding")
                ledger_expected = {
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": proposal["_review_sha256"],
                }
                if self._final_effect_ledger().poll(
                        proposal["_pending_id"], proposal["_review_sha256"],
                        expected=ledger_expected) != "spent":
                    raise ValueError("owner approval has not been consumed for this exact proposal")
                record = self._obsidian_draft_origins.get(
                    (owner.owner_subject_sha256, draft_id))
                if (record is None or record["registration_sha256"] != registration_sha
                        or record["origin_record_sha256"] != proposal["origin_record_sha256"]
                        or _obsidian_origin_record_digest(record) != record["origin_record_sha256"]):
                    raise ValueError("proposal origin no longer joins current root provenance")
                try:
                    reviewed = self._read_obsidian_owner_draft(data_root, registered_owner, draft_id)
                except Exception:
                    reservation = next((row for row in self._obsidian_origin_history
                        if row.get("phase") in {None, "reserved", "completed"}
                        and row["origin"].get("origin_record_sha256") == record["origin_record_sha256"]
                        and row["result"].get("content_sha256") == content_sha
                        and row["result"].get("destination") == proposal["destination"]), None)
                    if reservation is None:
                        raise ValueError("proposal has no exact recoverable promotion reservation") from None
                    from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id, _draft_projection
                    store = self._obsidian_store_for_origin(data_root, registered_owner)
                    private = store.read_private_draft(
                        execution_id=record["origin_execution_id"], draft_id=draft_id,
                        source_instance_id=record["origin_source_id"])
                    relative = _note_relative_path(proposal["destination"])
                    saved = store._read_optional_note(relative)
                    if (private.get("state") != "promoted"
                            or private.get("contentSha256") != content_sha
                            or private.get("promotedSha256") != content_sha
                            or private.get("baseSha256") != proposal["expected_base_sha256"]
                            or private.get("destinationId") != _opaque_id(relative)
                            or saved is None or saved[1] != content_sha
                            or saved[0] != private.get("markdown")
                            or not store._has_exact_promotion_revision(
                                relative, proposal["expected_base_sha256"], content_sha)):
                        raise ValueError("proposal bytes do not match the exact reserved revision intent") from None
                    reviewed = SimpleNamespace(
                        draft=_draft_projection(draft_id, private), markdown=private["markdown"])
                if (reviewed.draft.content_sha256 != content_sha
                        or reviewed.draft.base_sha256 != proposal["expected_base_sha256"]
                        or hashlib.sha256(reviewed.markdown.encode("utf-8", "strict")).hexdigest()
                            != content_sha):
                    raise ValueError("proposal draft bytes changed before permitted promotion")
                issued = time.monotonic()
                if issued >= min(float(call["expiry"]), float(owner.expires_monotonic),
                                 float(startup["expiry"])):
                    raise ValueError("Jarvis proposal's original authority deadlines expired")
                response = {key: value for key, value in proposal.items() if not key.startswith("_")}
                return {"schema": 1, "nonce": nonce, "ok": True,
                    **response}
            if op == "read-obsidian-private-draft":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "startup_binding_id", "draft_id", "expected_content_sha256"}:
                    raise ValueError("Obsidian draft review schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                draft_id, content_sha = request["draft_id"], request["expected_content_sha256"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(draft_id, str)
                        or not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id)
                        or not _HASH.fullmatch(content_sha or "")
                        or not self._obsidian_origin_store_ok):
                    raise ValueError("Obsidian draft review identity or journal is unavailable")
                call, owner, master_source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if (call["tool_name"] != "obsidian_read_private_draft" or mode != "master_read"
                        or handle not in self._obsidian_scoped_calls):
                    raise ValueError("only the current Jarvis master read can inspect a private draft")
                try:
                    arguments = json.loads(call["arguments"].decode("utf-8", "strict"),
                                           object_pairs_hook=_unique_json_pairs)
                except Exception:
                    raise ValueError("observed draft review arguments are malformed") from None
                if (type(arguments) is not dict
                        or set(arguments) != {"draft_id", "expected_draft_sha256"}
                        or _canonical(arguments) != call["arguments"]
                        or arguments["draft_id"] != draft_id
                        or arguments["expected_draft_sha256"] != content_sha):
                    raise ValueError("draft review differs from the exact observed master call")
                now = time.monotonic()
                data_root, registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=now)
                if (master_source is None or master_source.is_current_sealed(
                        self._custody, now=now) is not True):
                    raise ValueError("current master source changed before draft review")
                key = (owner.owner_subject_sha256, draft_id)
                record = self._obsidian_draft_origins.get(key)
                if (record is None or record["state"] != "private-draft"
                        or record["registration_sha256"] != registration_sha
                        or record["content_sha256"] != content_sha):
                    raise ValueError("draft has no retained pending private origin")
                try:
                    reviewed = self._read_obsidian_owner_draft(data_root, registered_owner, draft_id)
                except Exception:
                    # A prior exact promotion may have committed the public CAS
                    # and private marker but lost the root archive/tombstone
                    # write. Permit a fresh Jarvis review only when the durable
                    # reservation and exact revision journal join all bytes.
                    reservation = next((row for row in self._obsidian_origin_history
                        if row.get("phase") in {None, "reserved", "completed"}
                        and row["origin"].get("origin_record_sha256")
                            == record["origin_record_sha256"]
                        and row["result"].get("content_sha256") == content_sha), None)
                    if reservation is None:
                        raise ValueError("draft has no pending origin or exact recoverable promotion reservation") from None
                    from hermes_installer.remote.obsidian_second_brain import _note_relative_path, _opaque_id, _draft_projection
                    store = self._obsidian_store_for_origin(data_root, registered_owner)
                    private = store.read_private_draft(
                        execution_id=record["origin_execution_id"], draft_id=draft_id,
                        source_instance_id=record["origin_source_id"])
                    relative = _note_relative_path(reservation["result"]["destination"])
                    saved = store._read_optional_note(relative)
                    if (private.get("state") != "promoted"
                            or private.get("contentSha256") != content_sha
                            or private.get("promotedSha256") != content_sha
                            or private.get("baseSha256") != record["base_sha256"]
                            or private.get("destinationId") != _opaque_id(relative)
                            or saved is None or saved[1] != content_sha
                            or saved[0] != private.get("markdown")
                            or not store._has_exact_promotion_revision(
                                relative, record["base_sha256"], content_sha)):
                        raise ValueError("prior promotion does not join its exact reserved revision intent") from None
                    reviewed = SimpleNamespace(
                        draft=_draft_projection(draft_id, private), markdown=private["markdown"])
                draft = reviewed.draft
                markdown = reviewed.markdown
                markdown_bytes = markdown.encode("utf-8", "strict")
                if (draft.execution_id != record["origin_execution_id"]
                        or draft.source_instance_id != record["origin_source_id"]
                        or draft.content_sha256 != content_sha
                        or hashlib.sha256(markdown_bytes).hexdigest() != content_sha
                        or draft.base_sha256 != record["base_sha256"]
                        or _obsidian_origin_record_digest(record) != record["origin_record_sha256"]):
                    raise ValueError("retained origin does not match the independently read pending draft")
                # The source call, owner, binding and original expiry remain the
                # same across the owner-byte read. A slow read cannot refresh or
                # extend this observed call's authority.
                after_call, after_owner, after_source, after_mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                after_root, after_registered_owner, after_registration, after_startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                completed = time.monotonic()
                if (after_call is not call or after_owner is not owner
                        or after_source is None or master_source is None
                        or after_source.profile_id != master_source.profile_id
                        or after_source.source_revision != master_source.source_revision
                        or after_source.generation_sha256 != master_source.generation_sha256
                        or after_mode != "master_read"
                        or after_root != data_root or after_registered_owner != registered_owner
                        or after_registration != registration_sha or after_startup is not startup
                        or handle not in self._obsidian_scoped_calls
                        or completed >= min(float(call["expiry"]), float(owner.expires_monotonic),
                                            float(startup["expiry"]))):
                    raise ValueError("current Jarvis draft-review call expired during readback")
                complete = len(markdown_bytes) <= 32 * 1024
                issued = completed
                expiry = min(float(call["expiry"]), float(owner.expires_monotonic),
                             float(startup["expiry"]), issued + 5.0)
                if not issued < expiry <= issued + 5.0:
                    raise ValueError("current Jarvis draft-review lease is unavailable")
                if len(self._obsidian_draft_read_deliveries) >= _OBSIDIAN_DELIVERY_MAX_RECORDS:
                    self._obsidian_draft_read_deliveries = {
                        receipt_id: row for receipt_id, row
                        in self._obsidian_draft_read_deliveries.items()
                        if row["expires_monotonic"] > issued}
                if len(self._obsidian_draft_read_deliveries) >= _OBSIDIAN_DELIVERY_MAX_RECORDS:
                    raise ValueError("current-turn Obsidian read-delivery receipt capacity is full")
                delivery = self._record_obsidian_draft_read_delivery(
                    call=call, owner=owner, master_source=master_source,
                    startup=startup, startup_binding_id=binding_id,
                    draft_id=draft_id, content_sha256=content_sha,
                    origin_record_sha256=record["origin_record_sha256"],
                    returned_markdown=markdown if complete else None,
                    complete=complete, delivered_monotonic=issued)
                delivery_wire = {key: delivery[key] for key in (
                    "receipt_id", "owner_subject_sha256", "owner_turn_handle", "draft_id",
                    "content_sha256", "origin_record_sha256", "source_generation_sha256",
                    "startup_binding_id", "startup_binding_facts_sha256",
                    "observed_call_handle", "tool_call_id",
                    "arguments_sha256", "returned_byte_length", "returned_content_sha256",
                    "complete", "covered_byte_length", "delivered_monotonic",
                    "expires_monotonic", "receipt_sha256")}
                from .obsidian_native_scope import obsidian_draft_read_public_result
                tool_result = obsidian_draft_read_public_result(
                    draft_id=draft_id, title=draft.title,
                    markdown=markdown if complete else None,
                    content_sha256=content_sha, byte_length=len(markdown_bytes),
                    review_complete=complete, next_step=None if complete else
                        "Use the owner draft review flow to reduce the draft before Jarvis reviews it.",
                    base_note_id=draft.base_note_id, base_sha256=draft.base_sha256,
                    origin_source_id=record["origin_source_id"],
                    origin_source_revision=record["origin_source_revision"],
                    origin_execution_id=record["origin_execution_id"],
                    mission_sha256=record["mission_sha256"],
                    source_generation_sha256=record["source_generation_sha256"],
                    receipt_id=delivery["receipt_id"],
                    receipt_sha256=delivery["receipt_sha256"],
                    delivery_complete=delivery["complete"],
                    covered_byte_length=delivery["covered_byte_length"])
                delivery["tool_result_sha256"] = hashlib.sha256(
                    _canonical(tool_result)).hexdigest()
                self._obsidian_draft_read_deliveries[
                    delivery["receipt_id"]]["tool_result_sha256"] = delivery["tool_result_sha256"]
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "draft_id": draft_id, "title": draft.title,
                    "markdown": markdown if complete else None,
                    "content_sha256": content_sha, "byte_length": len(markdown_bytes),
                    "review_complete": complete,
                    "next_step": None if complete else
                        "Use the owner draft review flow to reduce the draft before Jarvis reviews it.",
                    "base_note_id": draft.base_note_id, "base_sha256": draft.base_sha256,
                    "origin_source_id": record["origin_source_id"],
                    "origin_source_revision": record["origin_source_revision"],
                    "origin_execution_id": record["origin_execution_id"],
                    "mission_sha256": record["mission_sha256"],
                    "source_generation_sha256": record["source_generation_sha256"],
                    "origin_record_sha256": record["origin_record_sha256"],
                    "delivery": delivery_wire,
                    "issued_monotonic": issued, "expires_monotonic": expiry}
            if op == "confirm-obsidian-draft-read-delivery":
                required = {"schema", "op", "nonce", "observed_call_handle", "startup_binding_id",
                    "receipt_id", "receipt_sha256", "tool_result_sha256"}
                if set(request) != required:
                    raise ValueError("Obsidian returned-result confirmation schema mismatch")
                handle, binding_id = request["observed_call_handle"], request["startup_binding_id"]
                receipt_id = request["receipt_id"]
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or not isinstance(binding_id, str) or not _OPAQUE.fullmatch(binding_id)
                        or not isinstance(receipt_id, str) or not _OPAQUE.fullmatch(receipt_id)
                        or not _HASH.fullmatch(request["receipt_sha256"] or "")
                        or not _HASH.fullmatch(request["tool_result_sha256"] or "")):
                    raise ValueError("Obsidian returned-result identity is malformed")
                call, owner, master_source, mode = self._classify_current_call(
                    handle, peer, now=time.monotonic())
                if (call["tool_name"] != "obsidian_read_private_draft" or mode != "master_read"):
                    raise ValueError("only current Jarvis exact-draft result can be confirmed")
                row = self._obsidian_draft_read_deliveries.get(receipt_id)
                if (row is None or row["observed_call_handle"] != handle
                        or row["owner_turn_handle"] != owner.owner_turn_handle
                        or row["owner_subject_sha256"] != owner.owner_subject_sha256
                        or row["receipt_sha256"] != request["receipt_sha256"]
                        or row.get("tool_result_sha256") != request["tool_result_sha256"]
                        or row["expires_monotonic"] <= time.monotonic()):
                    raise ValueError("native result differs from the exact root-prepared draft output")
                _data_root, _registered_owner, registration_sha, startup = \
                    self._validate_obsidian_origin_binding(
                        peer=peer, binding_id=binding_id, owner=owner, now=time.monotonic())
                current_origin = self._obsidian_draft_origins.get(
                    (owner.owner_subject_sha256, row["draft_id"]))
                if (startup["binding_id"] != row["startup_binding_id"]
                        or current_origin is None
                        or registration_sha != current_origin["registration_sha256"]
                        or current_origin["origin_record_sha256"] != row["origin_record_sha256"]
                        or master_source is None
                        or master_source.is_current_sealed(self._custody, now=time.monotonic()) is not True
                        or master_source.generation_sha256 != row["source_generation_sha256"]):
                    raise ValueError("current Jarvis source or owner registration changed before result confirmation")
                if row.get("native_returned_sha256") not in (None, request["tool_result_sha256"]):
                    raise ValueError("a different native draft result was already returned")
                row["native_returned_sha256"] = request["tool_result_sha256"]
                return {"schema": 1, "nonce": nonce, "ok": True, "confirmed": True,
                    "receipt_sha256": row["receipt_sha256"]}
            if op == "planning-turn-context":
                if set(request) != {"schema", "op", "nonce", "session_id", "turn_id", "prompt_sha256"}:
                    raise ValueError("planning-turn lookup schema mismatch")
                session_id, turn_id = request["session_id"], request["turn_id"]
                prompt_sha256 = request["prompt_sha256"]
                if (not isinstance(session_id, str) or not isinstance(turn_id, str)
                        or not _HASH.fullmatch(prompt_sha256 or "")):
                    raise ValueError("planning-turn lookup is malformed")
                owner = self._planning_sessions.get(session_id)
                if owner is None:
                    owner = next((item for item in self._owners.values()
                                  if item.session_id == session_id), None)
                if owner is None or owner.planning_context is None:
                    return {"schema": 1, "nonce": nonce, "ok": True,
                            "planning": False, "planning_context": None}
                now = time.monotonic()
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.planning_context.planner_prompt_sha256 != prompt_sha256
                        or owner.core_generation != self._custody.core_generation
                        or owner.core_source_generation != self._custody.core_source_generation):
                    raise ValueError("registered planning turn is stale or mismatched")
                from hermes_installer.remote.core_gateway_inspector import _verify_planning_context
                _verify_planning_context(owner.planning_context,
                    owner_subject_sha256=owner.owner_subject_sha256,
                    core_generation=owner.core_generation,
                    core_source_generation=owner.core_source_generation,
                    prompt_sha256=prompt_sha256,
                    mission_id=owner.planning_context.mission_id,
                    revision=owner.planning_context.revision,
                    gateway_turn_id=owner.gateway_turn_id,
                    conversation_id=owner.conversation_id, session_id=owner.session_id,
                    config=self._config, custody=self._custody, preparing=False)
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "planning": True, "planning_context": owner.planning_context.to_wire()}
            if op == "master-review-turn-context":
                if set(request) != {"schema", "op", "nonce", "session_id", "turn_id", "prompt_sha256"}:
                    raise ValueError("master-review lookup schema mismatch")
                session_id, turn_id = request["session_id"], request["turn_id"]
                prompt_sha256 = request["prompt_sha256"]
                if (not isinstance(session_id, str) or not isinstance(turn_id, str)
                        or not _HASH.fullmatch(prompt_sha256 or "")):
                    raise ValueError("master-review lookup is malformed")
                owner = self._master_review_sessions.get(turn_id)
                if owner is None:
                    owner = next((item for item in self._owners.values()
                                  if item.session_id == session_id), None)
                if owner is None or owner.master_review_context is None:
                    return {"schema": 1, "nonce": nonce, "ok": True,
                            "reviewing": False, "review_context": None}
                now = time.monotonic()
                context = owner.master_review_context
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.gateway_turn_id != turn_id
                        or context.review_prompt_sha256 != prompt_sha256
                        or owner.core_generation != self._custody.core_generation
                        or owner.core_source_generation != self._custody.core_source_generation):
                    raise ValueError("registered master review turn is stale or mismatched")
                from hermes_installer.remote.core_gateway_inspector import _verify_master_review_context
                _verify_master_review_context(context,
                    owner_subject_sha256=owner.owner_subject_sha256,
                    core_generation=owner.core_generation,
                    core_source_generation=owner.core_source_generation,
                    prompt_sha256=prompt_sha256,
                    config=self._config, custody=self._custody)
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "reviewing": True, "review_context": context.to_wire()}
            if op == "verify-master-review-completion":
                required = {"schema", "op", "nonce", "completion_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "prompt_sha256", "response_sha256",
                    "mission_id", "revision", "run_id", "result_sha256",
                    "execution_core_generation", "execution_core_source_generation",
                    "owner_turn_expires_monotonic"}
                if set(request) != required:
                    raise ValueError("master-review completion verification schema mismatch")
                receipt = SimpleNamespace(**{key: value for key, value in request.items()
                    if key not in {"schema", "op", "nonce"}})
                if not self.verify_master_review_completion(receipt, gateway_peer=peer):
                    raise ValueError("master-review completion is stale, replayed or mismatched")
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "current-project-context":
                if set(request) != {"schema", "op", "nonce", "session_id", "prompt_sha256"}:
                    raise ValueError("project-context lookup schema mismatch")
                session_id, prompt_sha256 = request["session_id"], request["prompt_sha256"]
                if (not isinstance(session_id, str) or not 1 <= len(session_id) <= 512
                        or not session_id.isascii() or any(ord(char) < 0x20 for char in session_id)
                        or not _HASH.fullmatch(prompt_sha256 or "")):
                    raise ValueError("project-context lookup is malformed")
                matches = [item for item in self._owners.values()
                           if item.session_id == session_id and item.prompt_sha256 == prompt_sha256]
                empty = {"conversation_id": None, "gateway_turn_id": None,
                         "owner_turn_handle": None,
                         "owner_subject_sha256": None, "core_generation": None,
                         "context_sha256": None, "text": None, "project_source_refs": None}
                if len(matches) != 1:
                    return {"schema": 1, "nonce": nonce, "ok": True,
                        "available": False, "session_id": session_id,
                        "prompt_sha256": prompt_sha256, **empty}
                owner = matches[0]
                now = time.monotonic()
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.core_generation != self._custody.core_generation
                        or owner.core_source_generation != self._custody.core_source_generation):
                    raise ValueError("registered owner project context is stale")
                from hermes_installer.remote.core_gateway_inspector import _root_project_context_for_owner_turn
                current_text, current_refs = _root_project_context_for_owner_turn(
                    owner_subject_sha256=owner.owner_subject_sha256,
                    conversation_id=owner.conversation_id,
                    gateway_turn_id=owner.gateway_turn_id,
                    session_id=owner.session_id,
                    core_generation=owner.core_generation,
                    gateway_uid=self._config.gateway_uid)
                current_digest = hashlib.sha256(current_text.encode("utf-8", "strict")).hexdigest()
                if (current_digest != owner.project_context_sha256
                        or current_text != owner.project_context
                        or current_refs != owner.project_source_refs
                        or owner.is_current_sealed(self._config, custody=self._custody,
                                                   now=time.monotonic()) is not True):
                    raise ValueError("current owner project context changed after turn registration")
                if not current_text:
                    return {"schema": 1, "nonce": nonce, "ok": True,
                        "available": False, "session_id": session_id,
                        "prompt_sha256": prompt_sha256,
                        "owner_turn_handle": None,
                        "conversation_id": None, "gateway_turn_id": None,
                        "owner_subject_sha256": None, "core_generation": None,
                        "context_sha256": None, "text": None, "project_source_refs": None}
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "available": True, "session_id": owner.session_id,
                    "prompt_sha256": owner.prompt_sha256,
                    "owner_turn_handle": owner.owner_turn_handle,
                    "conversation_id": owner.conversation_id,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "context_sha256": current_digest, "text": current_text,
                    "project_source_refs": list(current_refs)}
            if op == "authorize-master-read-call":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle"}:
                    raise ValueError("caller classification schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "observed_call_handle": call["handle"],
                    "owner_turn_handle": owner.owner_turn_handle,
                    "tool_call_id": call["tool_call_id"], "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "source_generation_sha256": source.generation_sha256,
                    "mode": mode, "expires_monotonic": min(
                        call["expiry"], owner.expires_monotonic, time.monotonic() + 30.0)}
            if op == "request-final-effect":
                required = {"schema", "op", "nonce", "observed_call_handle", "review_sha256"}
                if set(request) not in (required, required | {"startup_binding_id"}):
                    raise ValueError("final-effect request schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                from hermes_installer.remote.jarvis_final_effects import review_digest
                if (mode != "master_effect" or source.profile_id != "hermes"
                        or call["tool_name"] in _MASTER_READ_TOOL_NAMES
                        or review_digest(call["tool_name"], call["arguments_sha256"])
                            != request["review_sha256"]):
                    raise ValueError("only a current Jarvis master effect can request approval")
                proposal_row = None
                if call["tool_name"] == "obsidian_promote_reviewed_draft":
                    if "startup_binding_id" not in request:
                        raise ValueError("current Obsidian promotion binding is required")
                    proposal_row = self._propose_obsidian_draft_review(
                        call=call, owner=owner, source=source, peer=peer,
                        startup_binding_id=request["startup_binding_id"])
                elif "startup_binding_id" in request:
                    raise ValueError("unexpected Obsidian promotion binding")
                pending = self._final_effect_ledger().issue_pending(
                    owner_subject_sha256=owner.owner_subject_sha256,
                    gateway_turn_id=owner.gateway_turn_id,
                    owner_turn_handle=owner.owner_turn_handle,
                    core_generation=owner.core_generation,
                    core_source_generation=owner.core_source_generation,
                    source_generation_sha256=source.generation_sha256,
                    tool_call_id=call["tool_call_id"], tool_name=call["tool_name"],
                    arguments_sha256=call["arguments_sha256"],
                    review_sha256=request["review_sha256"],
                    expires_monotonic=min(call["expiry"], owner.expires_monotonic,
                                          time.monotonic() + 30.0),
                    canonical_arguments=call["arguments"])
                if proposal_row is not None:
                    proposal_row["_pending_id"] = pending.pending_id
                    proposal_row["_review_sha256"] = pending.review_sha256
                    self._obsidian_draft_review_proposals[call["handle"]] = proposal_row
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "pending_id": pending.pending_id,
                    "review_sha256": pending.review_sha256,
                    "expires_monotonic": pending.expires_monotonic}
            if op == "poll-final-effect":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "pending_id", "review_sha256"}:
                    raise ValueError("final-effect poll schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                if mode != "master_effect" or source.profile_id != "hermes":
                    raise ValueError("experts and non-master callers cannot consume final effects")
                ledger = self._final_effect_ledger()
                expected = {
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                }
                state = ledger.poll(request["pending_id"], request["review_sha256"], expected=expected)
                if state != "approved" or not ledger.consume_approval(
                        request["pending_id"], request["review_sha256"], expected=expected):
                    if state == "pending":
                        return {"schema": 1, "nonce": nonce, "ok": True, "state": "pending"}
                    raise ValueError("final-effect approval is denied, stale, or already spent")
                permit = {
                    "pending_id": request["pending_id"],
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                    "expires_monotonic": min(call["expiry"], owner.expires_monotonic,
                                              time.monotonic() + 30.0),
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "state": "permit", "permit": permit}
            if op == "read-selected-expert-source":
                required = {"schema", "op", "nonce", "claim_handle", "owner_turn_handle", "source_id"}
                if set(request) != required:
                    raise ValueError("selected source request schema mismatch")
                now = time.monotonic()
                claim = self._consumed_dispatches.get(request["claim_handle"])
                owner = claim.get("owner") if claim is not None else None
                call = claim.get("call") if claim is not None else None
                if (claim is None or owner is None or call is None
                        or claim["expiry"] <= now or call["peer"] != peer
                        or owner.owner_turn_handle != request["owner_turn_handle"]
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or type(owner.mission_binding) is not MissionBinding
                        or owner.mission_binding.execution_mode not in {"oneshot", "kanban"}
                        or request["source_id"] not in owner.mission_binding.selected_source_ids
                        or call["tool_name"] != "resources_delegate"):
                    raise ValueError("selected source is not bound to this live mission claim")
                try:
                    args = json.loads(call["arguments"].decode("utf-8", errors="strict"))
                except Exception:
                    raise ValueError("selected source arguments are malformed") from None
                if (not isinstance(args, dict) or set(args) != {"goal"}
                        or not isinstance(args["goal"], str)
                        or _hash({"goal": args["goal"]}) != owner.mission_binding.task_sha256
                        or call["arguments_sha256"] != owner.mission_binding.task_sha256):
                    raise ValueError("selected source goal differs from the spent mission task")
                selected = self._selection_for_mission(owner, request["source_id"], now)
                if selected is None:
                    raise ValueError("current master decision does not select this source")
                selection, source = selected
                if (selection.get("owner") is None
                        or selection["owner"].owner_subject_sha256 != owner.owner_subject_sha256
                        or selection["owner"].core_generation != owner.core_generation
                        or selection["owner"].core_source_generation != owner.core_source_generation
                        or source.is_current_sealed(self._custody, now=now) is not True):
                    raise ValueError("selected source or owner decision is stale")
                handle = secrets.token_urlsafe(32)
                expiry = min(float(claim["expiry"]), float(owner.expires_monotonic), now + 30.0)
                self._selected_source_deliveries[handle] = {
                    "source": source, "selection": selection, "claim": claim,
                    "owner": owner, "peer": peer, "expiry": expiry, "consumed": False,
                }
                team_binding = selection.get("team_binding")
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "source_handle": handle, "profile_id": source.profile_id,
                    "source_revision": source.source_revision,
                    "generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256,
                    "team_binding": team_binding.to_wire() if team_binding is not None else None,
                    "expires_monotonic": expiry}
            if op == "prepare-team-message":
                required = {"schema", "op", "nonce", "claim_handle", "owner_turn_handle",
                    "team_binding_id", "sender_completion_handle", "recipient_source_handle",
                    "original_goal_sha256", "original_goal", "excerpt"}
                if set(request) != required:
                    raise ValueError("Team message schema mismatch")
                claim = self._consumed_dispatches.get(request["claim_handle"])
                owner = claim.get("owner") if claim is not None else None
                binding = self._team_bindings.get(request["team_binding_id"])
                sender = self._team_completion_evidence.get(request["sender_completion_handle"])
                recipient = self._selected_source_deliveries.get(request["recipient_source_handle"])
                now = time.monotonic()
                completed_round_zero_profiles = {
                    row.get("profile_id")
                    for row in self._team_completion_evidence.values()
                    if row.get("team_binding_id") == request["team_binding_id"]
                    and row.get("team_message_handle") is None
                }
                if (claim is None or owner is None or binding is None or sender is None or recipient is None
                        or claim["expiry"] <= now or claim["call"]["peer"] != peer
                        or owner.owner_turn_handle != request["owner_turn_handle"]
                        or recipient["consumed"] or recipient["expiry"] <= now
                        or recipient["peer"] != peer or recipient["claim"] is not claim
                        or recipient["owner"] is not owner
                        or recipient["selection"].get("team_binding") is not binding
                        or recipient["source"].is_current_sealed(self._custody, now=now) is not True
                        or sender["data_expires_monotonic"] <= now
                        or sender["peer"] != peer
                        or sender.get("team_binding_id") != binding.binding_id
                        or sender.get("owner") is not owner
                        or sender.get("completion_handle") != request["sender_completion_handle"]
                        or sender.get("profile_id") not in binding.selected_expert_ids
                        or completed_round_zero_profiles != set(binding.selected_expert_ids)
                        or recipient["source"].profile_id not in binding.selected_expert_ids
                        or sender["profile_id"] == recipient["source"].profile_id
                        or not _HASH.fullmatch(request["original_goal_sha256"] or "")
                        or request["original_goal_sha256"] != binding.goal_sha256
                        or not isinstance(request["original_goal"], str)
                        or hashlib.sha256(request["original_goal"].encode("utf-8", "strict")).hexdigest()
                            != binding.goal_sha256
                        or not isinstance(request["excerpt"], str)
                        or not 1 <= len(request["excerpt"].encode("utf-8", "strict")) <= 8192
                        or not sender["response_text"].startswith(request["excerpt"])
                        or hashlib.sha256(sender["response_text"].encode("utf-8", "strict")).hexdigest()
                            != sender["response_text_sha256"]
                        or binding.expires_monotonic <= now
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True):
                    raise ValueError("Team message sender/recipient lineage is stale or mismatched")
                if binding.binding_id in self._team_edge_issued:
                    raise ValueError("Team binding already has its one permitted discussion edge")
                excerpt = request["excerpt"]
                recipient_goal = (request["original_goal"] + "\n\nExact excerpt from Team member "
                    + sender["profile_id"] + " (root-observed completion "
                    + request["sender_completion_handle"] + "):\n" + excerpt)
                if (len(recipient_goal) > 1200
                        or len(recipient_goal.encode("utf-8", "strict")) > 32 * 1024):
                    raise ValueError("Team recipient request exceeds its bound")
                message_handle = secrets.token_urlsafe(32)
                self._team_edge_issued.add(binding.binding_id)
                expiry = min(binding.expires_monotonic,
                    sender["data_expires_monotonic"], recipient["expiry"],
                    claim["expiry"], owner.expires_monotonic, now + 30.0)
                self._team_messages[message_handle] = {
                    "message_handle": message_handle,
                    "binding_id": binding.binding_id, "binding": binding, "owner": owner,
                    "claim": claim, "sender": sender,
                    "sender_completion_handle": request["sender_completion_handle"],
                    "sender_profile_id": sender["profile_id"],
                    "recipient_source": recipient["source"],
                    "recipient_source_handle": request["recipient_source_handle"],
                    "recipient_profile_id": recipient["source"].profile_id,
                    "original_goal_sha256": binding.goal_sha256,
                    "excerpt": excerpt,
                    "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8", "strict")).hexdigest(),
                    "recipient_goal": recipient_goal,
                    "recipient_goal_sha256": hashlib.sha256(recipient_goal.encode("utf-8", "strict")).hexdigest(),
                    "expiry": expiry, "consumed": False, "recipient_completion_handle": None,
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "message_handle": message_handle, "binding_id": binding.binding_id,
                    "sender_completion_handle": request["sender_completion_handle"],
                    "sender_profile_id": sender["child"]["profile_id"],
                    "recipient_profile_id": recipient["source"].profile_id,
                    "excerpt": excerpt,
                    "excerpt_sha256": hashlib.sha256(excerpt.encode("utf-8", "strict")).hexdigest(),
                    "recipient_goal": recipient_goal,
                    "recipient_goal_sha256": hashlib.sha256(recipient_goal.encode("utf-8", "strict")).hexdigest(),
                    "expires_monotonic": expiry}
            if op == "admit-selected-expert-child":
                required = {"schema", "op", "nonce", "claim_handle", "owner_turn_handle",
                            "source_handle", "source_id", "child_session_id", "child_turn_id",
                            "goal_sha256", "team_message_handle", "tool_names", "tool_closure_sha256", "provider",
                            "api_mode", "base_url", "model"}
                if set(request) != required:
                    raise ValueError("selected child admission schema mismatch")
                now = time.monotonic()
                delivered = self._selected_source_deliveries.get(request["source_handle"])
                claim = self._consumed_dispatches.get(request["claim_handle"])
                owner = claim.get("owner") if claim is not None else None
                call = claim.get("call") if claim is not None else None
                source = delivered.get("source") if delivered is not None else None
                team_binding = delivered.get("selection", {}).get("team_binding") if delivered is not None else None
                message = (self._team_messages.get(request["team_message_handle"])
                           if request["team_message_handle"] is not None else None)
                if (delivered is None or delivered["consumed"] or delivered["expiry"] <= now
                        or delivered["peer"] != peer or claim is None or owner is None or call is None
                        or delivered["claim"] is not claim or delivered["owner"] is not owner
                        or owner.owner_turn_handle != request["owner_turn_handle"]
                        or call["peer"] != peer or call["tool_name"] != "resources_delegate"
                        or type(owner.mission_binding) is not MissionBinding
                        or request["source_id"] != source.profile_id
                        or source.profile_id not in owner.mission_binding.selected_source_ids
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is not claim["policy"]):
                    raise ValueError("selected child is not bound to current owner/source authority")
                try:
                    args = json.loads(call["arguments"].decode("utf-8", errors="strict"))
                except Exception:
                    raise ValueError("selected child arguments are malformed") from None
                if (not isinstance(args, dict) or set(args) != {"goal"}
                        or not isinstance(args["goal"], str)
                        or _hash({"goal": args["goal"]}) != owner.mission_binding.task_sha256
                        or call["arguments_sha256"] != owner.mission_binding.task_sha256):
                    raise ValueError("selected child task does not match the approved mission")
                if team_binding is None:
                    if (message is not None
                            or request["goal_sha256"] != hashlib.sha256(
                                args["goal"].encode("utf-8", "strict")).hexdigest()):
                        raise ValueError("individual child cannot claim Team message lineage")
                elif message is None:
                    prior_round_zero_profiles = {
                        row.get("profile_id")
                        for row in self._team_completion_evidence.values()
                        if row.get("team_binding_id") == team_binding.binding_id
                        and row.get("team_message_handle") is None
                    }
                    open_round_zero_profiles = {
                        child_row.get("profile_id")
                        for child_row in self._child_sessions.values()
                        if child_row.get("team_binding_id") == team_binding.binding_id
                        and not child_row.get("complete")
                        and child_row.get("team_message_handle") is None
                    }
                    if (request["team_message_handle"] is not None
                            or request["goal_sha256"] != hashlib.sha256(
                                args["goal"].encode("utf-8", "strict")).hexdigest()
                            or team_binding.goal_sha256 != owner.mission_binding.task_sha256
                            or source.profile_id not in team_binding.selected_expert_ids
                            or source.profile_id in prior_round_zero_profiles
                            or source.profile_id in open_round_zero_profiles
                            or self._team_completion_counts.get(team_binding.binding_id, 0)
                                + sum(1 for child_row in self._child_sessions.values()
                                    if child_row.get("team_binding_id") == team_binding.binding_id
                                    and not child_row.get("complete")
                                    and child_row.get("team_message_handle") is None) >= 2):
                        raise ValueError("Team round-zero admission is stale or exceeds two Experts")
                else:
                    if (message.get("consumed") or message.get("expiry", 0) <= now
                            or message.get("binding") is not team_binding
                            or message.get("owner") is not owner or message.get("claim") is not claim
                            or message.get("recipient_source") is not source
                            or message.get("recipient_profile_id") != source.profile_id
                            or message.get("recipient_goal_sha256") != request["goal_sha256"]
                            or message.get("original_goal_sha256") != owner.mission_binding.task_sha256):
                        raise ValueError("Team recipient message is stale, spent or mismatched")
                allowed = {"web_search", "web_extract", "skills_list", "skill_view"} | _OBSIDIAN_READ_TOOL_NAMES
                names = request["tool_names"]
                if (not isinstance(names, list) or len(names) > len(allowed)
                        or any(not isinstance(name, str) or name not in allowed for name in names)
                        or len(set(names)) != len(names) or names != sorted(names)
                        or request["tool_closure_sha256"] != _hash(names)
                        or request["provider"] != _CODEX_PROVIDER
                        or request["api_mode"] != _CODEX_MODE or request["base_url"] != _CODEX_ENDPOINT):
                    raise ValueError("selected child route or fixed safe tool closure is invalid")
                attempt = self._attempts.get(call["attempt"])
                if (attempt is None or attempt["response"] is None
                        or attempt["owner"] is not owner or attempt["session_id"] != owner.session_id
                        or request["model"] != attempt["model"]
                        or not _HASH.fullmatch(attempt["account"] or "")):
                    raise ValueError("selected child has no current observed parent route")
                child_session = _require_id(request["child_session_id"], "child session ID")
                if child_session in self._child_sessions or child_session == owner.session_id:
                    raise ValueError("selected child session is already bound")
                child_turn = request["child_turn_id"]
                if child_turn and not _ID.fullmatch(child_turn):
                    raise ValueError("selected child turn ID is malformed")
                delivered["consumed"] = True
                if message is not None:
                    message["consumed"] = True
                admission = secrets.token_urlsafe(32)
                expiry = min(float(delivered["expiry"]), float(owner.expires_monotonic),
                             float(claim["policy"].expires_monotonic), now + 30.0)
                child = {"admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "owner": owner, "policy": claim["policy"], "parent_session_id": owner.session_id,
                    "parent_turn_id": call["attempt_turn_id"], "session_id": child_session,
                    "turn_id": child_turn or None, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account": attempt["account"],
                    "mode": "expert-read-research", "tool_names": tuple(names),
                    "tool_closure_sha256": _hash(names), "provider": _CODEX_PROVIDER,
                    "api_mode": _CODEX_MODE, "base_url": _CODEX_ENDPOINT, "model": attempt["model"],
                    "source": source, "attempts": [], "peer": peer, "expiry": expiry,
                    "complete": False, "response_text_sha256": None,
                    "team_binding_id": team_binding.binding_id if team_binding is not None else None,
                    "team_message_handle": request["team_message_handle"],
                    "team_message": message}
                self._child_sessions[child_session] = child
                self._record_child_activity(child, kind="admitted", status="accepted",
                    event_id=hashlib.sha256(("admitted\0" + child["admission_handle"]).encode()).hexdigest())
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "parent_session_id": owner.session_id,
                    "parent_turn_id": child["parent_turn_id"], "child_session_id": child_session,
                    "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account_fingerprint": attempt["account"],
                    "mode": "expert-read-research", "tool_names": names,
                    "tool_closure_sha256": _hash(names), "additional_metered_budget": 0,
                    "expires_monotonic": expiry}
            if op == "admit-master-planner-child":
                from hermes_installer.components.resources_active_profile_source import (
                    RootVerifiedJarvisMasterSource,
                )
                required = {"schema", "op", "nonce", "owner_turn_handle", "parent_session_id",
                            "parent_turn_id", "child_session_id", "child_turn_id",
                            "source_generation_sha256", "source_manifest_sha256", "prompt_sha256",
                            "goal_sha256", "provider", "api_mode", "base_url", "model",
                            "tool_names", "tool_closure_sha256"}
                if set(request) != required:
                    raise ValueError("master planner admission schema mismatch")
                now = time.monotonic()
                owner = self._owners.get(request["owner_turn_handle"])
                source = self._master_source
                if (owner is None or owner.expires_monotonic <= now
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.session_id != request["parent_session_id"]
                        or self._owner_turn_bindings.get(owner.owner_turn_handle) != request["parent_turn_id"]
                        or type(source) is not RootVerifiedJarvisMasterSource
                        or source.profile_id != "hermes"
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is None
                        or request["provider"] != _CODEX_PROVIDER or request["api_mode"] != _CODEX_MODE
                        or request["base_url"] != _CODEX_ENDPOINT
                        or not _ID.fullmatch(request["model"] or "")
                        or request["tool_names"] != [] or request["tool_closure_sha256"] != _hash([])
                        or not _HASH.fullmatch(request["goal_sha256"] or "")):
                    raise ValueError("current owner turn or master source is unavailable")
                attempt = next((row for row in reversed(tuple(self._attempts.values()))
                                if row["owner"] is owner and row["session_id"] == owner.session_id
                                and row["turn_id"] == request["parent_turn_id"]
                                and row["response"] is not None
                                and row["account"] and row.get("model")), None)
                if (attempt is None or attempt["account"] == ""
                        or request["model"] != attempt["model"]
                        or request["source_generation_sha256"] != source.generation_sha256
                        or request["source_manifest_sha256"] != source.source_member_manifest_sha256
                        or request["prompt_sha256"] != source.effective_prompt_sha256):
                    raise ValueError("planner route/source does not match a completed owner turn")
                child_session = _require_id(request["child_session_id"], "child session ID")
                if child_session in self._child_sessions or child_session == owner.session_id:
                    raise ValueError("planner child session is already bound")
                child_turn = request["child_turn_id"]
                if child_turn and not _ID.fullmatch(child_turn):
                    raise ValueError("planner child turn ID is malformed")
                policy = self._policy_for_owner(owner, now)
                admission = secrets.token_urlsafe(32)
                # Source freshness is checked again before every dispatch and
                # completion; it must not shorten the owner/decision lease.
                expiry = min(float(owner.expires_monotonic),
                             float(policy.expires_monotonic), now + 30.0)
                child = {"admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "owner": owner, "policy": policy, "parent_session_id": owner.session_id,
                    "parent_turn_id": request["parent_turn_id"], "session_id": child_session,
                    "turn_id": child_turn or None, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account": attempt["account"],
                    "mode": "planner", "tool_names": (), "tool_closure_sha256": _hash([]),
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE,
                    "base_url": _CODEX_ENDPOINT, "model": attempt["model"],
                    "source": source, "attempts": [], "peer": peer, "expiry": expiry,
                    "complete": False, "response_text_sha256": None}
                self._child_sessions[child_session] = child
                self._record_child_activity(child, kind="admitted", status="accepted",
                    event_id=hashlib.sha256(("admitted\0" + child["admission_handle"]).encode()).hexdigest())
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "parent_session_id": owner.session_id,
                    "parent_turn_id": request["parent_turn_id"],
                    "child_session_id": child_session, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account_fingerprint": attempt["account"],
                    "mode": "planner", "tool_names": [], "tool_closure_sha256": _hash([]),
                    "additional_metered_budget": 0, "expires_monotonic": expiry}
            if op == "read-current-master-source":
                if set(request) != {"schema", "op", "nonce", "owner_turn_handle"}:
                    raise ValueError("current master source request schema mismatch")
                now = time.monotonic()
                owner = self._owners.get(request["owner_turn_handle"])
                source = self._current_master_source()
                if (owner is None or owner.expires_monotonic <= now
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is None
                        or source is None or source.profile_id != "hermes"
                        or source.native_profile_key != "default" or source.display_name != "Jarvis"
                        or source.is_current_sealed(self._custody, now=now) is not True):
                    raise ValueError("registered owner and current Jarvis source are unavailable")
                handle = secrets.token_urlsafe(32)
                expiry = min(float(source.expires_monotonic), float(owner.expires_monotonic), now + 5.0)
                if expiry <= now:
                    raise ValueError("current Jarvis source readback expired")
                self._master_source_deliveries[handle] = {
                    "source": source, "owner": owner, "peer": peer,
                    "expiry": expiry, "consumed": False,
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "source_handle": handle, "profile_id": "hermes",
                    "source_revision": source.source_revision,
                    "generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256,
                    "expires_monotonic": expiry}
            if op == "admit-initial-master-plan":
                required = {"schema", "op", "nonce", "owner_turn_handle", "parent_session_id",
                    "child_session_id", "child_turn_id", "source_handle", "source_generation_sha256",
                    "source_manifest_sha256", "profile_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "provider", "api_mode", "base_url", "model", "account_fingerprint",
                    "tool_names", "tool_closure_sha256"}
                if set(request) != required:
                    raise ValueError("initial master plan admission schema mismatch")
                now = time.monotonic()
                owner = self._owners.get(request["owner_turn_handle"])
                delivered = self._master_source_deliveries.get(request["source_handle"])
                source = delivered.get("source") if delivered is not None else None
                policy = self._policy_for_owner(owner, now) if owner is not None else None
                if (owner is None or owner.expires_monotonic <= now
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.session_id != request["parent_session_id"]
                        or self._owner_turn_bindings.get(owner.owner_turn_handle) is not None
                        or any(row.get("owner") is owner and row.get("mode") == "planner"
                               for row in self._child_sessions.values())
                        or delivered is None or delivered["consumed"] or delivered["expiry"] <= now
                        or delivered["peer"] != peer or delivered["owner"] is not owner
                        or source is None or source.is_current_sealed(self._custody, now=now) is not True
                        or source.profile_id != "hermes" or source.native_profile_key != "default"
                        or source.display_name != "Jarvis"
                        or request["source_generation_sha256"] != source.generation_sha256
                        or request["source_manifest_sha256"] != source.source_member_manifest_sha256
                        or request["profile_manifest_sha256"] != source.profile_manifest_sha256
                        or request["prompt_sha256"] != source.effective_prompt_sha256
                        or request["provider"] != _CODEX_PROVIDER or request["api_mode"] != _CODEX_MODE
                        or request["base_url"] != _CODEX_ENDPOINT
                        or not isinstance(request["model"], str) or not _ID.fullmatch(request["model"])
                        or not _HASH.fullmatch(request["account_fingerprint"] or "")
                        or request["child_turn_id"] != ""
                        or request["tool_names"] != [] or request["tool_closure_sha256"] != _hash([])
                        or not _HASH.fullmatch(request["goal_sha256"] or "")
                        or policy is None or policy.additional_metered_budget != 0):
                    raise ValueError("initial master plan is not bound to current owner and source")
                child_session = _require_id(request["child_session_id"], "planner child session ID")
                if child_session == owner.session_id or child_session in self._child_sessions:
                    raise ValueError("planner child session is already bound")
                delivered["consumed"] = True
                start_expiry = min(float(owner.expires_monotonic), float(policy.expires_monotonic), now + 30.0)
                run_expiry = min(float(owner.expires_monotonic), float(policy.expires_monotonic))
                if not now < start_expiry <= run_expiry <= now + 600.0:
                    raise ValueError("initial planner owner lease is unavailable")
                admission = secrets.token_urlsafe(32)
                child = {"admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "owner": owner, "policy": policy, "parent_session_id": owner.session_id,
                    "parent_turn_id": "", "session_id": child_session,
                    "turn_id": None, "start_expires": start_expiry,
                    "profile_id": "hermes", "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"],
                    "account": request["account_fingerprint"], "mode": "planner",
                    "tool_names": (), "tool_closure_sha256": _hash([]),
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE,
                    "base_url": _CODEX_ENDPOINT, "model": request["model"],
                    "source": source, "attempts": [], "peer": peer,
                    "expiry": run_expiry, "complete": False, "response_text_sha256": None}
                self._child_sessions[child_session] = child
                self._record_child_activity(child, kind="admitted", status="accepted",
                    event_id=hashlib.sha256(("admitted\0" + child["admission_handle"]).encode()).hexdigest())
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "parent_session_id": owner.session_id, "parent_turn_id": "",
                    "child_session_id": child_session, "profile_id": "hermes",
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"],
                    "account_fingerprint": request["account_fingerprint"],
                    "mode": "planner", "tool_names": [], "tool_closure_sha256": _hash([]),
                    "additional_metered_budget": 0, "expires_monotonic": start_expiry,
                    "owner_turn_expires_monotonic": owner.expires_monotonic}
            if op == "admit-native-child":
                raise ValueError("legacy Resources-parent child admission is disabled")
            if op == "complete-native-child":
                if set(request) != {"schema", "op", "nonce", "admission_handle", "status", "response_sha256"}:
                    raise ValueError("child completion schema mismatch")
                child = next((row for row in self._child_sessions.values()
                              if row["admission_handle"] == request["admission_handle"]), None)
                now = time.monotonic()
                if (child is None or child["peer"] != peer or child["expiry"] <= now
                        or child["complete"] or request["status"] != "completed"
                        or not _HASH.fullmatch(request["response_sha256"] or "")):
                    raise ValueError("child completion is not a live admitted result")
                owner, policy = child["owner"], child["policy"]
                source = child.get("source")
                attempts = [self._attempts.get(handle) for handle in child["attempts"]]
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is not policy
                        or not callable(getattr(source, "is_current_sealed", None))
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or source.profile_id != child["profile_id"]
                        or source.generation_sha256 != child["source_generation_sha256"]
                        or source.effective_prompt_sha256 != child["prompt_sha256"]
                        or child["turn_id"] is None or len(attempts) != 1
                        or any(row is None or row["child_admission_handle"] != child["admission_handle"]
                               or row["response"] is None for row in attempts)
                        or child["mode"] != "planner"
                        or attempts[0]["response"][1]
                        or attempts[0]["response"][2] != request["response_sha256"]
                        or attempts[0]["account"] != child["account"]):
                    raise ValueError("planner completion lacks a current zero-tool provider result")
                child["complete"] = True
                child["response_text_sha256"] = request["response_sha256"]
                self._record_child_activity(child, kind="completed", status="completed",
                    event_id=hashlib.sha256(("completed\0" + child["admission_handle"]).encode()).hexdigest())
                completion_handle = secrets.token_urlsafe(32)
                expiry = min(child["expiry"], now + 30.0)
                self._planning_completions[completion_handle] = {
                    "child": child, "response_sha256": request["response_sha256"],
                    "expiry": expiry}
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "completion_handle": completion_handle,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "prompt_sha256": child["goal_sha256"],
                    "response_sha256": request["response_sha256"],
                    "expires_monotonic": expiry,
                    "owner_turn_expires_monotonic": owner.expires_monotonic}
            if op == "complete-selected-expert-child":
                required = {"schema", "op", "nonce", "admission_handle",
                            "owner_turn_handle", "child_session_id"}
                if set(request) != required:
                    raise ValueError("Expert completion schema mismatch")
                child = self._child_sessions.get(request["child_session_id"])
                now = time.monotonic()
                if (child is None or child["admission_handle"] != request["admission_handle"]
                        or child["owner_turn_handle"] != request["owner_turn_handle"]
                        or child["peer"] != peer or child["expiry"] <= now or child["complete"]
                        or child["mode"] != "expert-read-research" or child["turn_id"] is None
                        or not child["attempts"]):
                    raise ValueError("Expert completion is not a live admitted child")
                owner, policy, source = child["owner"], child["policy"], child.get("source")
                attempts = [self._attempts.get(handle) for handle in child["attempts"]]
                final = attempts[-1] if attempts else None
                raw_text = final.get("response_text") if final is not None else None
                response = final.get("response") if final is not None else None
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is not policy
                        or not callable(getattr(source, "is_current_sealed", None))
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or source.profile_id != child["profile_id"]
                        or source.generation_sha256 != child["source_generation_sha256"]
                        or source.source_member_manifest_sha256 != child["source_manifest_sha256"]
                        or source.effective_prompt_sha256 != child["prompt_sha256"]
                        or any(row is None or row["child_admission_handle"] != child["admission_handle"]
                               or row["response"] is None or row["expiry"] <= now
                               or row["account"] != child["account"] for row in attempts)
                        or final is None or final["session_id"] != child["session_id"]
                        or final["turn_id"] != child["turn_id"]
                        or response is None or response[1]
                        or not _HASH.fullmatch(response[2] or "")
                        or not isinstance(raw_text, str)
                        or hashlib.sha256(raw_text.encode("utf-8", errors="strict")).hexdigest()
                            != response[2]
                        or not 1 <= len(raw_text.encode("utf-8", errors="strict")) <= 32 * 1024):
                    raise ValueError("Expert completion lacks current root-observed provider output")
                team_binding_id = child.get("team_binding_id")
                team_message = child.get("team_message")
                team_lineage = None
                prior_team_completions = 0
                if team_binding_id is not None:
                    binding = self._team_bindings.get(team_binding_id)
                    prior_team_completions = self._team_completion_counts.get(team_binding_id, 0)
                    if (binding is None or binding.expires_monotonic <= now
                            or binding.owner_subject_sha256 != owner.owner_subject_sha256
                            or binding.mission_id != owner.mission_binding.mission_id
                            or binding.goal_sha256 != owner.mission_binding.task_sha256
                            or child["profile_id"] not in binding.selected_expert_ids
                            or prior_team_completions >= 4):
                        raise ValueError("Team completion exceeds current bound")
                    if team_message is not None and (
                            team_message.get("recipient_completion_handle") is not None
                            or team_message.get("recipient_profile_id") != child["profile_id"]
                            or team_message.get("recipient_goal_sha256") != child["goal_sha256"]
                            or team_message.get("consumed") is not True
                            or team_message.get("sender_completion_handle") not in self._team_completion_evidence
                            or team_message.get("expiry", 0) <= now):
                        raise ValueError("Team recipient is detached from its sender message")
                    if team_message is None and any(
                            prior.get("team_binding_id") == team_binding_id
                            and prior.get("team_message_handle") is not None
                            for prior in self._team_completion_evidence.values()):
                        raise ValueError("Team discussion result lacks its admitted recipient message")
                child["complete"] = True
                child["response_text_sha256"] = response[2]
                self._record_child_activity(child, kind="completed", status="completed",
                    event_id=hashlib.sha256(("completed\0" + child["admission_handle"]).encode()).hexdigest())
                completion_handle = secrets.token_urlsafe(32)
                completion_expiry = min(child["expiry"], owner.expires_monotonic, now + 30.0)
                completion_data_expiry = completion_expiry
                if team_binding_id is not None:
                    completion_data_expiry = min(binding.expires_monotonic, owner.expires_monotonic)
                    if completion_data_expiry <= now:
                        raise ValueError("Team completion retention exceeds its owner or Team deadline")
                if team_binding_id is not None:
                    self._team_completion_counts[team_binding_id] = prior_team_completions + 1
                if team_message is not None:
                    team_message["recipient_completion_handle"] = completion_handle
                    team_lineage = {
                        "sender_completion_handle": team_message["sender_completion_handle"],
                        "sender_profile_id": team_message["sender_profile_id"],
                        "recipient_profile_id": child["profile_id"],
                        "excerpt_sha256": team_message["excerpt_sha256"],
                        "recipient_request_sha256": final["request_sha256"],
                        "recipient_response_sha256": response[0],
                        "recipient_text_sha256": response[2],
                        "recipient_completion_handle": completion_handle,
                    }
                self._expert_completions[completion_handle] = {
                    "child": child, "final_attempt": final, "response_sha256": response[0],
                    "response_text_sha256": response[2], "response_text": raw_text,
                    "expiry": completion_expiry, "peer": peer, "consumed": False,
                    "team_binding_id": team_binding_id,
                    "team_message_handle": child.get("team_message_handle"),
                }
                if team_binding_id is not None:
                    self._team_completion_evidence[completion_handle] = {
                        "completion_handle": completion_handle,
                        "owner": owner,
                        "team_binding_id": team_binding_id,
                        "profile_id": child["profile_id"],
                        "execution_key": (child.get("activity", {}).get("execution_key")
                                          if isinstance(child.get("activity"), dict) else None),
                        "response_text": raw_text,
                        "response_sha256": response[0],
                        "response_text_sha256": response[2],
                        "peer": peer,
                        "team_message_handle": child.get("team_message_handle"),
                        "data_expires_monotonic": completion_data_expiry,
                    }
                if team_message is not None:
                    team_message["recipient_completion_handle"] = completion_handle
                    sender_evidence = self._team_completion_evidence.get(
                        team_message.get("sender_completion_handle"))
                    if sender_evidence is not None:
                        self._record_team_discussion_relation(
                            recipient=child, sender=sender_evidence, team_message=team_message,
                            sender_completion_handle=team_message["sender_completion_handle"],
                            recipient_completion_handle=completion_handle,
                            recipient_request_sha256=final["request_sha256"],
                            sender_response_sha256=sender_evidence.get("response_sha256", ""),
                            recipient_response_sha256=response[0],
                            sender_text_sha256=sender_evidence.get("response_text_sha256", ""),
                            recipient_text_sha256=response[2])
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "completion_handle": completion_handle,
                    "owner_turn_handle": owner.owner_turn_handle,
                    "child_session_id": child["session_id"], "profile_id": child["profile_id"],
                    "source_revision": source.source_revision,
                    "source_generation_sha256": child["source_generation_sha256"],
                    "source_manifest_sha256": child["source_manifest_sha256"],
                    "goal_sha256": child["goal_sha256"],
                    "provider_attempt_handle": final["attempt_handle"],
                    "request_sha256": final["request_sha256"],
                    "response_sha256": response[0], "response_text_sha256": response[2],
                    "response_text": raw_text,
                    "team_message_handle": child.get("team_message_handle"),
                    "team_lineage": team_lineage, "expires_monotonic": completion_expiry}
            if op == "verify-planning-completion":
                fields = {"schema", "op", "nonce", "completion_handle", "owner_turn_handle",
                          "gateway_turn_id", "owner_subject_sha256", "core_generation",
                          "core_source_generation", "prompt_sha256", "response_sha256",
                          "owner_turn_expires_monotonic"}
                if set(request) != fields:
                    raise ValueError("planning completion schema mismatch")
                record = self._planning_completions.get(request["completion_handle"])
                if record is None or record["expiry"] <= time.monotonic():
                    raise ValueError("planning completion expired")
                child, owner = record["child"], record["child"]["owner"]
                source = child.get("source")
                if (child["complete"] is not True or child["peer"] != peer
                        or owner.is_current_sealed(self._config, custody=self._custody,
                                                   now=time.monotonic()) is not True
                        or not callable(getattr(source, "is_current_sealed", None))
                        or source.is_current_sealed(self._custody, now=time.monotonic()) is not True
                        or request["owner_turn_handle"] != owner.owner_turn_handle
                        or request["gateway_turn_id"] != owner.gateway_turn_id
                        or request["owner_subject_sha256"] != owner.owner_subject_sha256
                        or request["core_generation"] != owner.core_generation
                        or request["core_source_generation"] != owner.core_source_generation
                        or request["prompt_sha256"] != child["goal_sha256"]
                        or request["response_sha256"] != record["response_sha256"]
                        or request["owner_turn_expires_monotonic"] != owner.expires_monotonic):
                    raise ValueError("planning completion is stale or mismatched")
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "register-attempt":
                required = {"schema", "op", "nonce", "session_id", "turn_id", "api_request_id",
                            "provider", "model", "base_url", "api_mode", "account_fingerprint",
                            "request_sha256", "prompt_sha256", "parent_tool_names", "retry_count"}
                if set(request) != required:
                    raise ValueError("attempt schema mismatch")
                owner = self._owner_for(request["session_id"], request["turn_id"])
                policy = self._policy_for_owner(owner, time.monotonic()) if owner is not None else None
                child = self._child_sessions.get(request["session_id"])
                child_tools = tuple(child["tool_names"]) if child is not None else None
                is_child_attempt = child is not None
                planning_owner = owner is not None and owner.planning_context is not None
                review_owner = owner is not None and owner.master_review_context is not None
                planning_current = False
                review_current = False
                if planning_owner:
                    from hermes_installer.remote.core_gateway_inspector import _verify_planning_context
                    try:
                        _verify_planning_context(
                            owner.planning_context,
                            owner_subject_sha256=owner.owner_subject_sha256,
                            core_generation=owner.core_generation,
                            core_source_generation=owner.core_source_generation,
                            prompt_sha256=request["prompt_sha256"],
                            mission_id=owner.planning_context.mission_id,
                            revision=owner.planning_context.revision,
                            gateway_turn_id=owner.gateway_turn_id,
                            conversation_id=owner.conversation_id,
                            session_id=request["session_id"], config=self._config,
                            custody=self._custody, preparing=False)
                        planning_current = True
                    except Exception:
                        planning_current = False
                if review_owner:
                    from hermes_installer.remote.core_gateway_inspector import _verify_master_review_context
                    try:
                        _verify_master_review_context(owner.master_review_context,
                            owner_subject_sha256=owner.owner_subject_sha256,
                            core_generation=owner.core_generation,
                            core_source_generation=owner.core_source_generation,
                            prompt_sha256=request["prompt_sha256"],
                            config=self._config, custody=self._custody)
                        review_current = True
                    except Exception:
                        review_current = False
                if (owner is None or request["provider"] != _CODEX_PROVIDER
                        or request["api_mode"] != _CODEX_MODE or request["base_url"] != _CODEX_ENDPOINT
                        or type(request["retry_count"]) is not int or request["retry_count"] != 0
                        or not _HASH.fullmatch(request["account_fingerprint"])
                        or not _HASH.fullmatch(request["request_sha256"])
                        or not _HASH.fullmatch(request["prompt_sha256"])
                        or request["prompt_sha256"] != (child["goal_sha256"] if is_child_attempt
                                                          else owner.prompt_sha256)
                        or not isinstance(request["parent_tool_names"], list)
                        or len(request["parent_tool_names"]) > 512
                        or any(not isinstance(name, str) or not _ID.fullmatch(name)
                               for name in request["parent_tool_names"])
                        or len(set(request["parent_tool_names"])) != len(request["parent_tool_names"])
                        or policy is None
                        or (planning_owner and (not planning_current
                            or request["prompt_sha256"] != owner.planning_context.planner_prompt_sha256
                            or request["parent_tool_names"] != []))
                        or (review_owner and (not review_current
                            or request["prompt_sha256"] != owner.master_review_context.review_prompt_sha256
                            or request["parent_tool_names"] != []))
                        or (is_child_attempt and (
                            child["owner"] is not owner or child["expiry"] <= time.monotonic()
                            or child["peer"] != peer
                            or not callable(getattr(child.get("source"), "is_current_sealed", None))
                            or child["source"].is_current_sealed(
                                self._custody, now=time.monotonic()) is not True
                            or child["turn_id"] not in (None, request["turn_id"])
                            or request["account_fingerprint"] != child["account"]
                            or tuple(request["parent_tool_names"]) != child_tools
                            or (child["mode"] == "planner" and bool(request["parent_tool_names"]))
                        ))
                        or (not is_child_attempt and not planning_owner and (
                            not 1 <= len(request["parent_tool_names"])
                            or not set(request["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                            or "resources_delegate" not in request["parent_tool_names"]
                            or (not policy.allow_inherited_mcp
                                and any(name.startswith("mcp__") for name in request["parent_tool_names"]))
                        ))):
                    raise ValueError("attempt is not an enrolled current subscription turn")
                if is_child_attempt and child["turn_id"] is None:
                    child["turn_id"] = request["turn_id"]
                handle = secrets.token_urlsafe(32)
                if len(self._attempts) >= 2048:
                    raise ValueError("native attempt registry is full")
                if planning_owner or review_owner or (is_child_attempt and child["mode"] == "planner"):
                    # The start receipt only authorizes beginning within 30s.
                    # Protected no-tools master turns remain bounded by the original
                    # owner/policy lease, not a 30-second response timeout.
                    expiry = min(float(owner.expires_monotonic), float(policy.expires_monotonic))
                    if is_child_attempt:
                        child["expiry"] = expiry
                else:
                    expiry = min(float(owner.expires_monotonic), time.monotonic() + 30.0)
                self._attempts[handle] = {"attempt_handle": handle, "owner": owner,
                    "session_id": request["session_id"],
                    "turn_id": request["turn_id"], "api_request_id": request["api_request_id"],
                    "account": request["account_fingerprint"], "expiry": expiry, "response": None,
                    "parent_tool_names": tuple(request["parent_tool_names"]),
                    "provider": request["provider"], "api_mode": request["api_mode"],
                    "base_url": request["base_url"],
                    "policy_handle": policy.policy_handle, "model": request["model"],
                    "request_sha256": request["request_sha256"],
                    "retry_count": request["retry_count"],
                    "child_admission_handle": child["admission_handle"] if is_child_attempt else None,
                    "response_text_sha256": None,
                    "activity_started_monotonic": time.monotonic() if is_child_attempt else None}
                if is_child_attempt:
                    if child["turn_id"] is None:
                        # Bind only after every attempt field/source/route check
                        # succeeds; an invalid first frame cannot reserve a turn.
                        child["turn_id"] = request["turn_id"]
                    child["attempts"].append(handle)
                    self._record_child_activity(child, kind="attempt", status="started",
                        event_id=hashlib.sha256(("attempt\0" + handle).encode()).hexdigest())
                return {"schema": 1, "nonce": nonce, "ok": True, "attempt_handle": handle,
                        "owner_turn_handle": owner.owner_turn_handle, "expires_monotonic": expiry,
                        "capture_child_output": bool(is_child_attempt and child["mode"] == "expert-read-research")}
            if op == "register-response":
                required_response = {"schema", "op", "nonce", "attempt_handle", "response_sha256",
                                     "response_text_sha256", "tool_calls", "completed"}
                if set(request) not in (required_response, required_response | {"response_text"}):
                    raise ValueError("response schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if (row is None or row["expiry"] <= time.monotonic() or row["response"] is not None
                        or type(request["completed"]) is not bool or not _HASH.fullmatch(request["response_sha256"])
                        or (request["response_text_sha256"] is not None
                            and not _HASH.fullmatch(request["response_text_sha256"]))
                        or not isinstance(request["tool_calls"], list) or len(request["tool_calls"]) > 128):
                    raise ValueError("response is not a live unique attempt result")
                calls = {}
                for item in request["tool_calls"]:
                    if (not isinstance(item, dict) or set(item) != {"id", "name", "arguments_sha256"}
                            or not _ID.fullmatch(item["id"]) or not _ID.fullmatch(item["name"])
                            or not _HASH.fullmatch(item["arguments_sha256"]) or item["id"] in calls):
                        raise ValueError("provider call inventory is malformed")
                    calls[item["id"]] = item
                child = self._child_sessions.get(row["session_id"])
                if child is not None:
                    if (any(item["name"] not in child["tool_names"] for item in calls.values())
                            or (child["mode"] == "planner" and calls)
                            or (child["mode"] == "planner" and request["completed"]
                                and not _HASH.fullmatch(request["response_text_sha256"] or ""))
                            or (child["mode"] == "expert-read-research" and request["completed"]
                                and not calls and (not isinstance(request.get("response_text"), str)
                                    or not _HASH.fullmatch(request["response_text_sha256"] or "")))):
                        raise ValueError("child response exceeds its admitted tool or text closure")
                elif row["owner"].planning_context is not None:
                    raw_plan = request.get("response_text")
                    if (calls or not request["completed"]
                            or not _HASH.fullmatch(request["response_text_sha256"] or "")
                            or not isinstance(raw_plan, str)
                            or hashlib.sha256(raw_plan.encode("utf-8", errors="strict")).hexdigest()
                                != request["response_text_sha256"]):
                        raise ValueError("planning response is not a completed zero-tool result")
                    self._persist_master_plan_result(row, raw_plan, request["response_text_sha256"])
                elif row["owner"].master_review_context is not None:
                    raw_review = request.get("response_text")
                    if (calls or not request["completed"]
                            or not _HASH.fullmatch(request["response_text_sha256"] or "")
                            or not isinstance(raw_review, str)
                            or hashlib.sha256(raw_review.encode("utf-8", errors="strict")).hexdigest()
                                != request["response_text_sha256"]):
                        raise ValueError("master-review response is not a completed zero-tool result")
                    self._persist_master_review_response(row, raw_review,
                                                        request["response_text_sha256"])
                elif "response_text" in request:
                    raise ValueError("ordinary response cannot carry private planning output")
                if "response_text" in request:
                    text = request["response_text"]
                    if (not isinstance(text, str) or not 1 <= len(text.encode("utf-8", errors="strict"))
                            <= 32 * 1024
                            or hashlib.sha256(text.encode("utf-8", errors="strict")).hexdigest()
                                != request["response_text_sha256"]
                            or (child is None and row["owner"].planning_context is None
                                and row["owner"].master_review_context is None)):
                        raise ValueError("provider text is not permitted or digest-bound")
                row["response"] = ((request["response_sha256"], calls,
                                    request["response_text_sha256"])
                                   if request["completed"] else (None, {}, None))
                row["response_text"] = (request.get("response_text")
                                        if request["completed"] else None)
                child = self._child_sessions.get(row["session_id"])
                if child is not None:
                    started = row.get("activity_started_monotonic")
                    elapsed = (max(0, round((time.monotonic() - started) * 1000))
                               if isinstance(started, (int, float)) else None)
                    complete_status = "completed" if request["completed"] else "incomplete"
                    self._record_child_activity(child, kind="response", status=complete_status,
                        event_id=hashlib.sha256(("response\0" + request["attempt_handle"]
                            + ("\0completed" if request["completed"] else "\0incomplete")).encode()).hexdigest(),
                        duration_ms=elapsed)
                if request["completed"]:
                    row["response_text_sha256"] = request["response_text_sha256"]
                    if child is not None:
                        child["response_text_sha256"] = request["response_text_sha256"]
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "register-tool-call":
                if set(request) != {"schema", "op", "nonce", "attempt_handle", "tool_call_id", "canonical_arguments_b64"}:
                    raise ValueError("tool-call schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if row is None or row["expiry"] <= time.monotonic() or row["response"] is None:
                    raise ValueError("tool call has no completed live response")
                returned = row["response"][1].get(request["tool_call_id"])
                child = self._child_sessions.get(row["session_id"])
                if child is not None and (returned is None or returned["name"] not in child["tool_names"]):
                    raise ValueError("child tool call is outside its admitted finite closure")
                args = base64.b64decode(request["canonical_arguments_b64"], validate=True)
                if (returned is None or hashlib.sha256(args).hexdigest() != returned["arguments_sha256"]
                        or not _ID.fullmatch(returned["name"])):
                    raise ValueError("tool call differs from consumed provider output")
                call_handle = secrets.token_urlsafe(32)
                if len(self._calls) >= 2048:
                    raise ValueError("native call registry is full")
                self._calls[call_handle] = {"owner": row["owner"], "attempt": request["attempt_handle"],
                    "handle": call_handle, "attempt_session_id": row["session_id"],
                    "attempt_turn_id": row["turn_id"],
                    "parent_tool_names": row["parent_tool_names"],
                    "policy_handle": row["policy_handle"],
                    "tool_call_id": request["tool_call_id"], "tool_name": returned["name"],
                    "arguments": args, "arguments_sha256": returned["arguments_sha256"],
                    "expiry": row["expiry"], "peer": peer, "claim": None}
                if child is not None:
                    self._record_child_activity(child, kind="tool_call", status="observed",
                        event_id=hashlib.sha256(("tool-call\0" + request["attempt_handle"]
                            + "\0" + request["tool_call_id"]).encode()).hexdigest(), tool_count=1)
                return {"schema": 1, "nonce": nonce, "ok": True, "observed_call_handle": call_handle,
                        "attempt_handle": request["attempt_handle"],
                        "owner_turn_handle": row["owner"].owner_turn_handle,
                        "tool_call_id": request["tool_call_id"], "tool_name": returned["name"],
                        "arguments_sha256": returned["arguments_sha256"], "expires_monotonic": row["expiry"]}
            if op == "prepare-dispatch":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle"}:
                    raise ValueError("prepare schema mismatch")
                call = self._calls.get(request["observed_call_handle"])
                source = self._current_master_source()
                policy_row = self._policies.get(call["policy_handle"]) if call is not None else None
                policy = policy_row.get("policy") if policy_row is not None else None
                try:
                    call_args = json.loads(call["arguments"].decode("utf-8", errors="strict")) if call else None
                    parent_tools = frozenset(call["parent_tool_names"]) if call else frozenset()
                except Exception:
                    call_args, parent_tools = None, frozenset()
                if (call is None or call["expiry"] <= time.monotonic() or call["claim"] is not None
                        or call["tool_name"] != "resources_delegate"
                        or call["peer"] != peer
                        or policy is None
                        or type(policy) is not RootSelectedOrchestratorDelegationPolicy
                        or self._policy_for_owner(call["owner"], time.monotonic()) is not policy
                        or not parent_tools.issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in parent_tools))
                        or policy.additional_metered_budget != 0
                        or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or source.profile_id != "hermes"
                        or not isinstance(call_args, dict) or set(call_args) != {"goal"}
                        or not isinstance(call_args.get("goal"), str)
                        or not call_args["goal"].strip() or len(call_args["goal"]) > 1200
                        or any(ord(char) < 0x20 and char not in "\n\t" for char in call_args["goal"])):
                    raise ValueError("selected profile or native call is unavailable")
                claim_handle = secrets.token_urlsafe(32)
                if len(self._claims) >= 2048:
                    raise ValueError("dispatch claim registry is full")
                call["claim"] = claim_handle
                self._claims[claim_handle] = {"call": call,
                    "owner": call["owner"], "policy": policy,
                    # The profile object's short TTL is readback freshness, not
                    # the authority deadline. Its exact currentness is re-read
                    # at consume and immediately before native child admission.
                    "expiry": min(call["expiry"], policy.expires_monotonic,
                                  time.monotonic() + 30.0)}
                return {"schema": 1, "nonce": nonce, "ok": True, "claim_handle": claim_handle}
            if op == "consume-dispatch":
                if set(request) != {"schema", "op", "nonce", "claim_handle"}:
                    raise ValueError("consume schema mismatch")
                claim = self._claims.pop(request["claim_handle"], None)
                if claim is None or claim["expiry"] <= time.monotonic():
                    raise ValueError("dispatch claim expired or was already consumed")
                call, owner = claim["call"], claim["owner"]
                policy = claim["policy"]
                source = self._current_master_source()
                if (call["peer"] != peer or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=time.monotonic()) is not True
                        or self._policy_for_owner(owner, time.monotonic()) is not policy
                        or not set(call["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in call["parent_tool_names"]))):
                    raise ValueError("dispatch lineage is no longer current")
                if owner.mission_binding is not None and owner.mission_binding.execution_mode == "pending":
                    raise ValueError("pending mission mode cannot dispatch")
                self._consumed_dispatches[request["claim_handle"]] = {
                    **claim, "expiry": min(claim["expiry"], time.monotonic() + 30.0),
                }
                # Source/tool/privacy intersection is completed by the consumer against
                # the exact locally injected parent Agent; no Agent crosses this socket.
                manifest = [{"path": item.path, "sha256": item.sha256, "size": item.size}
                            for item in source.source_member_manifest]
                body = {"schema": 1, "claim_handle": request["claim_handle"],
                    "owner_turn_handle": owner.owner_turn_handle, "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "observed_call_handle": call["handle"],
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "session_id": call["attempt_session_id"],
                    "generation_sha256": source.generation_sha256,
                    "turn_id": call["attempt_turn_id"], "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "account_fingerprint": self._attempts[call["attempt"]]["account"],
                    "profile_id": source.profile_id, "source_revision": source.source_revision,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "profile_tool_names": [],
                    "profile_privacy_requirements": [],
                    "source_manifest": manifest, "source_manifest_sha256": _hash(manifest),
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256, "prompt_revision": source.source_revision,
                    "parent_tool_names": list(call["parent_tool_names"]), "parent_privacy_grants": [],
                    "delegation_policy_handle": policy.policy_handle,
                    "delegation_policy_sha256": policy.policy_sha256,
                    "parent_tool_configuration_sha256": policy.parent_tool_configuration_sha256,
                    "configured_parent_tool_names": list(policy.configured_parent_tool_names),
                    "allow_inherited_mcp": policy.allow_inherited_mcp,
                    "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
                    "mission_binding": (owner.mission_binding.to_wire()
                                        if owner.mission_binding is not None else None),
                    "expires_monotonic": claim["expiry"], "evidence_class": "protected-core-process-observation",
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE, "base_url": _CODEX_ENDPOINT,
                    "additional_metered_budget": 0}
                if owner.mission_binding is not None:
                    if len(self._mission_pending) >= 128:
                        raise ValueError("pending mission authorization registry is full")
                    self._mission_pending[request["claim_handle"]] = claim
                return {"schema": 1, "nonce": nonce, "ok": True, "dispatch_claim": body}
            if op == "authorize-mission-dispatch":
                if set(request) != {"schema", "op", "nonce", "claim_handle"}:
                    raise ValueError("mission authorization schema mismatch")
                pending = self._mission_pending.pop(request["claim_handle"], None)
                if pending is None or pending["expiry"] <= time.monotonic():
                    raise ValueError("mission authorization is expired or already consumed")
                call, owner = pending["call"], pending["owner"]
                policy = pending["policy"]
                source = self._current_master_source()
                if (call["peer"] != peer
                        or call.get("claim") != request["claim_handle"]
                        or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=time.monotonic()) is not True
                        or self._policy_for_owner(owner, time.monotonic()) is not policy
                        or policy.additional_metered_budget != 0
                        or not set(call["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in call["parent_tool_names"]))
                        or type(owner.mission_binding) is not MissionBinding
                        or source.profile_id != "hermes"
                        or call["tool_name"] != "resources_delegate"):
                    raise ValueError("mission dispatch lineage is no longer current")
                from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
                from hermes_installer.remote.jarvis_mission_executor import (
                    MissionLedgerReader, resolve_spent_mission_claim,
                )
                if CHAT_STORE_PATH != Path("/var/lib/hermes-jarvis-chat/chat.sqlite3"):
                    raise ValueError("fixed mission ledger path differs")
                arguments_sha256 = call["arguments_sha256"]
                if resolve_spent_mission_claim(
                        MissionLedgerReader(path=CHAT_STORE_PATH), owner.mission_binding,
                        owner.gateway_turn_id, owner.owner_subject_sha256,
                        owner.core_generation, owner.core_source_generation,
                        source.profile_id, arguments_sha256) is not True:
                    raise ValueError("spent mission approval no longer matches the native call")
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "claim_handle": request["claim_handle"],
                    "mission_binding_sha256": _hash(owner.mission_binding.to_wire()),
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_profile_id": owner.mission_binding.source_profile_id,
                    "canonical_arguments_sha256": arguments_sha256,
                    "expires_monotonic": min(pending["expiry"], owner.expires_monotonic)}
        raise ValueError("unsupported observer operation")

    def serve_connection(self, connection: socket.socket) -> None:
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        request = _read_frame(connection)
        nonce = request.get("nonce") if isinstance(request, dict) else None
        try:
            operation = request.get("op")
            if isinstance(operation, str) and operation.startswith("claim-lifecycle-startup-"):
                handle = request.get("probe_handle")
                row = self._lifecycle_startup_probes.get(handle)
                cohort = row.get("cohort") if isinstance(row, dict) else None
                if (type(cohort) is not RootLifecycleStartupCohort
                        or peer_pid != cohort.peer_pid or peer_uid != cohort.peer_uid
                        or peer_gid != cohort.peer_gid
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise PermissionError("selected new Core peer custody did not verify")
            elif isinstance(operation, str) and operation.startswith("register-lifecycle-startup-"):
                if not self._lifecycle_startup_request_current(request, (peer_pid, peer_uid, peer_gid)):
                    raise PermissionError("claimed startup peer custody did not verify")
            elif operation == "bind-obsidian-native-vault":
                if self._custody.verify_current_core_peer(self._config, connection) is not True:
                    raise PermissionError("current Core startup peer custody did not verify")
            else:
                if self._custody.verify_peer(self._config, self._owner_for_peer(request), connection) is not True:
                    raise PermissionError("core peer custody did not verify")
            result = self._handle((peer_pid, peer_uid, peer_gid), request)
        except Exception:
            result = {"schema": 1, "nonce": nonce, "ok": False}
        raw = _canonical(result)
        connection.sendall(struct.pack("!I", len(raw)) + raw)

    def _owner_for_peer(self, request: dict[str, Any]) -> Any:
        with self._lock:
            for owner in self._owners.values():
                if owner.core_pid == self._custody.core_pid and owner.core_start_ticks == self._custody.core_start_ticks:
                    return owner
        raise CoreNativeObservationUnavailable("current authenticated core owner turn is unavailable")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for owner in self._owners.values():
                self._close_fd(getattr(owner, "_core_pidfd", None))
            self._owners.clear()
            self._owner_turn_bindings.clear()
            self._policies.clear()
            self._owner_policy_handles.clear()
            self._attempts.clear()
            self._calls.clear()
            self._claims.clear()
            self._mission_pending.clear()
            self._consumed_dispatches.clear()
            self._child_sessions.clear()
            self._planning_completions.clear()
            self._master_review_sessions.clear()
            self._master_review_completions.clear()
            self._expert_completions.clear()
            for row in self._lifecycle_startup_probes.values():
                try:
                    os.close(row["pidfd"])
                except Exception:
                    pass
            self._lifecycle_startup_probes.clear()
            self._lifecycle_startup_attempts.clear()
            self._team_completion_evidence.clear()
            self._team_messages.clear()
            self._team_bindings.clear()
            self._team_completion_counts.clear()
            self._team_edge_issued.clear()
            self._master_selections.clear()
            self._selected_source_deliveries.clear()
            self._obsidian_bindings.clear()
            self._obsidian_scoped_calls.clear()


class RootLifecycleNativeObservationRegistry:
    """Root CLI-local issuer for only the guarded startup-chat wire protocol.

    This registry is deliberately separate from the long-lived Inspector
    registry. Its custody is issued by CoreRuntime while the new source is in
    ``source-starting`` and remains valid only inside that exact updater scope.
    """

    _OPERATIONS = frozenset({
        "claim-lifecycle-startup-probe",
        "register-lifecycle-startup-attempt",
        "register-lifecycle-startup-response",
    })

    @classmethod
    def from_starting_custody(cls, custody: Any) -> "RootLifecycleNativeObservationRegistry":
        try:
            from hermes_installer.core_runtime import (
                StartingLifecycleObserverCustody,
                verify_starting_lifecycle_observer_custody,
            )
            if (type(custody) is not StartingLifecycleObserverCustody
                    or verify_starting_lifecycle_observer_custody(custody) is not True):
                raise ValueError
            cohort = custody.cohort
            if (type(cohort) is not RootLifecycleStartupCohort
                    or not cohort.is_root_selected()
                    or (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid,
                        cohort.peer_start_ticks, cohort.boot_id, cohort.invocation_id)
                       != (custody.peer_pid, custody.peer_uid, custody.peer_gid,
                           custody.peer_start_ticks, custody.boot_id, custody.invocation_id)):
                raise ValueError
            pidfd = os.dup(custody.pidfd)
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
            if poller.poll(0):
                os.close(pidfd)
                raise ValueError
            return cls(custody, pidfd, _seal=_ROOT_LIFECYCLE_REGISTRY_SEAL)
        except Exception:
            raise CoreNativeObservationUnavailable(
                "Root starting lifecycle custody is unavailable") from None

    def __init__(self, custody: Any, pidfd: int, *, _seal: object):
        if _seal is not _ROOT_LIFECYCLE_REGISTRY_SEAL:
            raise CoreNativeObservationUnavailable("Root lifecycle registry issuer is required")
        self._custody = custody
        self._cohort = custody.cohort
        self._pidfd = pidfd
        self._lock = threading.RLock()
        self._closed = False
        self._lifecycle_startup_probes: dict[str, dict[str, Any]] = {}
        self._lifecycle_startup_attempts: dict[str, dict[str, Any]] = {}

    def _custody_current(self) -> bool:
        try:
            from hermes_installer.core_runtime import verify_starting_lifecycle_observer_custody
            cohort = self._cohort
            poller = select.poll()
            poller.register(self._pidfd,
                            select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
            return bool(not self._closed and os.geteuid() == 0
                and type(cohort) is RootLifecycleStartupCohort and cohort.is_root_selected()
                and time.monotonic() < min(cohort.deadline_monotonic,
                                           self._custody.expires_monotonic)
                and verify_starting_lifecycle_observer_custody(self._custody) is True
                and not poller.poll(0))
        except Exception:
            return False

    def _lifecycle_startup_peer_current(self, row: Mapping[str, Any],
                                        cohort: RootLifecycleStartupCohort) -> bool:
        return bool(cohort is self._cohort and row.get("pidfd") == self._pidfd
                    and self._custody_current()
                    and row.get("expiry", 0) > time.monotonic())

    def enroll_lifecycle_startup_probe(self, *, cohort: RootLifecycleStartupCohort) -> str:
        """Enroll exactly the cohort already issued by the active CoreRuntime."""
        if (cohort is not self._cohort or not self._custody_current()
                or os.geteuid() != 0):
            raise CoreNativeObservationUnavailable("guarded new-source cohort is not current")
        try:
            handle = secrets.token_urlsafe(32)
            probe_id = secrets.token_urlsafe(24)
            session_id = secrets.token_urlsafe(24)
            nonce = secrets.token_hex(16)
            expected_text_sha256 = hashlib.sha256(
                (_LIFECYCLE_STARTUP_RESPONSE_PREFIX + nonce).encode("ascii")).hexdigest()
            row = {
                "cohort": cohort, "pidfd": self._pidfd, "probe_id": probe_id,
                "session_id": session_id, "nonce": nonce,
                "expected_text_sha256": expected_text_sha256,
                "expiry": min(cohort.deadline_monotonic, self._custody.expires_monotonic),
                "claimed_peer": None, "attempt_handle": None,
                "completion_handle": None, "consumed": False,
            }
            with self._lock:
                if len(self._lifecycle_startup_probes) >= 1 or not self._custody_current():
                    raise ValueError
                self._lifecycle_startup_probes[handle] = row
            return handle
        except Exception:
            raise CoreNativeObservationUnavailable("guarded startup probe enrollment failed") from None

    def consume_lifecycle_startup_completion(
        self, *, probe_handle: str, completion_handle: str,
        native_response_sha256: str,
    ) -> CoreVerifiedLifecycleStartupCompletion:
        """Seal and consume the exact no-tool provider response after native terminal."""
        if (not _OPAQUE.fullmatch(probe_handle or "")
                or not _OPAQUE.fullmatch(completion_handle or "")
                or not _HASH.fullmatch(native_response_sha256 or "")):
            raise CoreNativeObservationUnavailable("startup completion reference is malformed")
        try:
            with self._lock:
                row = self._lifecycle_startup_probes.get(probe_handle)
                provider = row.get("provider_terminal") if isinstance(row, dict) else None
                cohort = row.get("cohort") if isinstance(row, dict) else None
                if (not isinstance(row, dict) or row.get("consumed") is True
                        or row.get("completion_handle") != completion_handle
                        or row.get("expiry", 0) <= time.monotonic()
                        or not isinstance(provider, dict)
                        or cohort is not self._cohort
                        or native_response_sha256 != provider.get("response_text_sha256")
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise ValueError
                proof = CoreVerifiedLifecycleStartupCompletion(
                    schema=1, purpose="lifecycle-startup", probe_handle=probe_handle,
                    completion_handle=completion_handle, transaction_id=cohort.transaction_id,
                    starting_journal_sha256=cohort.starting_journal_sha256,
                    cohort_sha256=cohort.cohort_sha256, core_generation=cohort.core_generation,
                    old_adapter_generation=cohort.old_adapter_generation,
                    new_adapter_generation=cohort.new_adapter_generation,
                    core_source_generation=cohort.core_source_generation,
                    generation_a1_sha256=cohort.generation_a1_sha256,
                    js_sha256=cohort.js_sha256, rs_sha256=cohort.rs_sha256,
                    u1_sha256=cohort.u1_sha256, l1_sha256=cohort.l1_sha256,
                    primary_source_sha256=cohort.primary_source_sha256,
                    active_soul_sha256=cohort.active_soul_sha256,
                    native_inventory_sha256=cohort.native_inventory_sha256,
                    peer_pid=cohort.peer_pid, peer_uid=cohort.peer_uid,
                    peer_gid=cohort.peer_gid, peer_start_ticks=cohort.peer_start_ticks,
                    boot_id=cohort.boot_id, invocation_id=cohort.invocation_id,
                    probe_id=row["probe_id"], session_id=row["session_id"],
                    turn_id=provider["turn_id"], api_request_id=provider["api_request_id"],
                    provider_request_sha256=provider["request_sha256"],
                    provider_response_sha256=provider["response_sha256"],
                    provider_response_text_sha256=provider["response_text_sha256"],
                    native_response_sha256=native_response_sha256,
                    prompt_sha256=provider["prompt_sha256"], provider=cohort.provider,
                    api_mode=cohort.api_mode, base_url=cohort.base_url, model=cohort.model,
                    account_fingerprint=cohort.account_fingerprint,
                    tools_sha256=hashlib.sha256(b"[]").hexdigest(),
                    deadline_monotonic=row["expiry"], _seal=_LIFECYCLE_STARTUP_COMPLETION_SEAL,
                )
                if not proof.is_root_verified() or not self._lifecycle_startup_peer_current(row, cohort):
                    raise ValueError
                row["consumed"] = True
                return proof
        except Exception:
            raise CoreNativeObservationUnavailable(
                "startup completion is stale, mismatched or replayed") from None

    def _handle_lifecycle(self, peer: tuple[int, int, int], request: dict[str, Any]) -> dict[str, Any]:
        if (type(request) is not dict or type(request.get("schema")) is not int
                or request.get("schema") != 1 or not isinstance(request.get("nonce"), str)
                or request.get("op") not in self._OPERATIONS):
            raise ValueError("unsupported lifecycle observer operation")
        op, nonce = request["op"], request["nonce"]
        with self._lock:
            if not self._custody_current():
                raise PermissionError("starting Core custody is no longer current")
            if op == "claim-lifecycle-startup-probe":
                if set(request) != {"schema", "op", "nonce", "probe_handle"}:
                    raise ValueError("lifecycle startup claim schema mismatch")
                handle = request["probe_handle"]
                row = self._lifecycle_startup_probes.get(handle)
                cohort = row.get("cohort") if isinstance(row, dict) else None
                if (not isinstance(handle, str) or not _OPAQUE.fullmatch(handle)
                        or row is None or row.get("claimed_peer") is not None
                        or not self._lifecycle_startup_peer_current(row, cohort)
                        or peer != (cohort.peer_pid, cohort.peer_uid, cohort.peer_gid)):
                    raise ValueError("lifecycle probe is unavailable to this native peer")
                row["claimed_peer"] = peer
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "probe_handle": handle, "probe_id": row["probe_id"],
                    "session_id": row["session_id"], "startup_nonce": row["nonce"],
                    "deadline_monotonic": row["expiry"],
                    "cohort_sha256": cohort.cohort_sha256,
                    "core_generation": cohort.core_generation,
                    "core_source_generation": cohort.core_source_generation,
                    "generation_a1_sha256": cohort.generation_a1_sha256,
                    "js_sha256": cohort.js_sha256, "rs_sha256": cohort.rs_sha256,
                    "u1_sha256": cohort.u1_sha256, "l1_sha256": cohort.l1_sha256,
                    "primary_source_sha256": cohort.primary_source_sha256,
                    "active_soul_sha256": cohort.active_soul_sha256,
                    "native_inventory_sha256": cohort.native_inventory_sha256,
                    "provider": cohort.provider, "api_mode": cohort.api_mode,
                    "base_url": cohort.base_url, "model": cohort.model,
                    "account_fingerprint": cohort.account_fingerprint}
            if op == "register-lifecycle-startup-attempt":
                required = {"schema", "op", "nonce", "probe_handle", "probe_id", "session_id",
                    "turn_id", "api_request_id", "provider", "api_mode", "base_url", "model",
                    "account_fingerprint", "request_sha256", "prompt_sha256", "tool_names",
                    "retry_count"}
                if set(request) != required:
                    raise ValueError("lifecycle attempt schema mismatch")
                row = self._lifecycle_startup_probes.get(request["probe_handle"])
                cohort = row.get("cohort") if isinstance(row, dict) else None
                expected_prompt = (hashlib.sha256((_LIFECYCLE_STARTUP_PROMPT_PREFIX + row["nonce"]
                    + _LIFECYCLE_STARTUP_PROMPT_SUFFIX).encode("ascii")).hexdigest()
                    if isinstance(row, dict) else None)
                if (row is None or cohort is not self._cohort
                        or row.get("claimed_peer") != peer or row.get("attempt_handle") is not None
                        or request["probe_id"] != row["probe_id"]
                        or request["session_id"] != row["session_id"]
                        or request["provider"] != cohort.provider
                        or request["api_mode"] != cohort.api_mode
                        or request["base_url"] != cohort.base_url
                        or request["model"] != cohort.model
                        or request["account_fingerprint"] != cohort.account_fingerprint
                        or request["prompt_sha256"] != expected_prompt
                        or request["tool_names"] != []
                        or type(request["retry_count"]) is not int or request["retry_count"] != 0
                        or not _HASH.fullmatch(request.get("request_sha256", ""))
                        or not _ID.fullmatch(request.get("turn_id", ""))
                        or not _ID.fullmatch(request.get("api_request_id", ""))
                        or not self._lifecycle_startup_peer_current(row, cohort)):
                    raise ValueError("lifecycle provider attempt differs from enrolled cohort")
                attempt_handle = secrets.token_urlsafe(32)
                row["attempt_handle"] = attempt_handle
                self._lifecycle_startup_attempts[attempt_handle] = {
                    "probe_handle": request["probe_handle"], "peer": peer,
                    "turn_id": request["turn_id"], "api_request_id": request["api_request_id"],
                    "request_sha256": request["request_sha256"],
                    "prompt_sha256": request["prompt_sha256"],
                    "expiry": min(row["expiry"], time.monotonic() + 120.0),
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                        "attempt_handle": attempt_handle}
            required = {"schema", "op", "nonce", "probe_handle", "attempt_handle",
                "turn_id", "api_request_id", "request_sha256", "response_sha256",
                "response_text", "response_text_sha256", "completed", "tool_call_count"}
            if set(request) != required:
                raise ValueError("lifecycle response schema mismatch")
            row = self._lifecycle_startup_probes.get(request["probe_handle"])
            attempt = self._lifecycle_startup_attempts.get(request["attempt_handle"])
            cohort = row.get("cohort") if isinstance(row, dict) else None
            text = request.get("response_text")
            if (row is None or attempt is None or cohort is not self._cohort
                    or row.get("claimed_peer") != peer or row.get("completion_handle") is not None
                    or attempt.get("probe_handle") != request["probe_handle"]
                    or attempt.get("peer") != peer or attempt.get("expiry", 0) <= time.monotonic()
                    or attempt.get("turn_id") != request["turn_id"]
                    or attempt.get("api_request_id") != request["api_request_id"]
                    or attempt.get("request_sha256") != request["request_sha256"]
                    or request.get("completed") is not True
                    or type(request.get("tool_call_count")) is not int
                    or request.get("tool_call_count") != 0
                    or not isinstance(text, str) or not 1 <= len(text) <= 1024
                    or hashlib.sha256(text.encode("utf-8", "strict")).hexdigest()
                       != request.get("response_text_sha256")
                    or text != _LIFECYCLE_STARTUP_RESPONSE_PREFIX + row["nonce"]
                    or not _HASH.fullmatch(request.get("response_sha256", ""))
                    or not self._lifecycle_startup_peer_current(row, cohort)):
                raise ValueError("lifecycle terminal differs from exact startup challenge")
            completion_handle = secrets.token_urlsafe(32)
            row["completion_handle"] = completion_handle
            row["provider_terminal"] = {
                "turn_id": attempt["turn_id"], "api_request_id": attempt["api_request_id"],
                "request_sha256": attempt["request_sha256"],
                "prompt_sha256": attempt["prompt_sha256"],
                "response_sha256": request["response_sha256"],
                "response_text_sha256": request["response_text_sha256"],
            }
            self._lifecycle_startup_attempts.pop(request["attempt_handle"], None)
            return {"schema": 1, "nonce": nonce, "ok": True,
                    "completion_handle": completion_handle}

    def serve_connection(self, connection: socket.socket) -> None:
        peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET,
                                                          socket.SO_PEERCRED, 12))
        request = _read_frame(connection)
        nonce = request.get("nonce") if isinstance(request, dict) else None
        try:
            if (peer != (self._cohort.peer_pid, self._cohort.peer_uid, self._cohort.peer_gid)
                    or not self._custody_current()):
                raise PermissionError("new Core peer custody did not verify")
            result = self._handle_lifecycle(peer, request)
            if not self._custody_current():
                raise PermissionError("new Core custody changed during lifecycle operation")
        except Exception:
            result = {"schema": 1, "nonce": nonce, "ok": False}
        raw = _canonical(result)
        connection.sendall(struct.pack("!I", len(raw)) + raw)

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._lifecycle_startup_probes.clear()
            self._lifecycle_startup_attempts.clear()
            try:
                os.close(self._pidfd)
            except OSError:
                pass


class RootLifecycleNativeObservationServer:
    """Short-lived fixed Root CLI listener isolated from the Inspector socket."""

    def __init__(self, registry: RootLifecycleNativeObservationRegistry):
        if type(registry) is not RootLifecycleNativeObservationRegistry:
            raise CoreNativeObservationUnavailable("fixed Root lifecycle registry is required")
        self._registry = registry
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._listener: socket.socket | None = None
        self._error: BaseException | None = None
        self._socket_identity: tuple[int, int] | None = None
        self._owner_identity: tuple[int, int] | None = None
        self._owner_record: dict[str, Any] | None = None
        self._lock_fd: int | None = None

    @staticmethod
    def _process_identity(pid: int) -> tuple[str, str]:
        from hermes_installer.remote.core_gateway_inspector import _boot_id, _proc_start_ticks
        return _boot_id(), _proc_start_ticks(pid)

    @staticmethod
    def _read_owner_record() -> tuple[dict[str, Any] | None, tuple[int, int] | None]:
        fd = -1
        try:
            fd = os.open(_LIFECYCLE_NATIVE_OBSERVER_OWNER,
                         os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise CoreNativeObservationUnavailable("lifecycle owner record custody differs")
            raw = os.read(fd, 4097)
            if len(raw) > 4096:
                raise CoreNativeObservationUnavailable("lifecycle owner record exceeded its bound")
            value = json.loads(raw)
            expected = {"schema", "pid", "boot_id", "start_ticks", "socket_dev", "socket_ino"}
            if (type(value) is not dict or set(value) != expected
                    or type(value.get("schema")) is not int or value["schema"] != 1
                    or type(value.get("pid")) is not int or value["pid"] <= 1
                    or not isinstance(value.get("boot_id"), str)
                    or not isinstance(value.get("start_ticks"), str)
                    or not value["start_ticks"].isdecimal()
                    or type(value.get("socket_dev")) is not int
                    or type(value.get("socket_ino")) is not int):
                raise CoreNativeObservationUnavailable("lifecycle owner record is malformed")
            return value, (info.st_dev, info.st_ino)
        except FileNotFoundError:
            return None, None
        finally:
            if fd >= 0:
                os.close(fd)

    def start(self) -> None:
        if self._thread is not None:
            raise CoreNativeObservationUnavailable("Root lifecycle observer server already started")
        context = contextvars.copy_context()
        self._thread = threading.Thread(target=lambda: context.run(self._serve),
                                        name="root-lifecycle-observer", daemon=True)
        self._thread.start()

    def wait_ready(self, timeout: float = 3.0) -> bool:
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= 10.0):
            return False
        if not self._ready.wait(timeout):
            return False
        return self._error is None

    def _serve(self) -> None:
        parent = LIFECYCLE_NATIVE_OBSERVER_SOCKET.parent
        try:
            try:
                os.mkdir(parent, 0o750)
            except FileExistsError:
                pass
            else:
                os.chown(parent, 0, _CORE_NATIVE_OBSERVER_GROUP)
                os.chmod(parent, 0o750)
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or info.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(info.st_mode) != 0o750):
                raise CoreNativeObservationUnavailable("Root lifecycle runtime directory custody differs")
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
            lock_fd = os.open(_LIFECYCLE_NATIVE_OBSERVER_LOCK, flags, 0o600)
            lock_info = os.fstat(lock_fd)
            if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != 0
                    or lock_info.st_gid != 0 or stat.S_IMODE(lock_info.st_mode) != 0o600
                    or lock_info.st_nlink != 1):
                os.close(lock_fd)
                raise CoreNativeObservationUnavailable("lifecycle observer lock custody differs")
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(lock_fd)
                raise CoreNativeObservationUnavailable("another lifecycle observer owns the listener") from None
            self._lock_fd = lock_fd
            old_owner, old_owner_identity = self._read_owner_record()
            try:
                old_socket = LIFECYCLE_NATIVE_OBSERVER_SOCKET.lstat()
            except FileNotFoundError:
                old_socket = None
            if old_socket is not None:
                if (not stat.S_ISSOCK(old_socket.st_mode) or old_owner is None
                        or old_socket.st_uid != 0
                        or old_socket.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                        or stat.S_IMODE(old_socket.st_mode) != 0o660
                        or old_owner_identity is None
                        or (old_socket.st_dev, old_socket.st_ino)
                           != (old_owner.get("socket_dev"), old_owner.get("socket_ino"))):
                    raise CoreNativeObservationUnavailable("existing lifecycle socket is not owned by its exact record")
                old_alive = False
                try:
                    boot, started = self._process_identity(old_owner["pid"])
                    old_alive = boot == old_owner["boot_id"] and started == old_owner["start_ticks"]
                except Exception:
                    old_alive = False
                if old_alive:
                    raise CoreNativeObservationUnavailable("prior Root lifecycle observer is still alive")
                LIFECYCLE_NATIVE_OBSERVER_SOCKET.unlink()
                owner_info = _LIFECYCLE_NATIVE_OBSERVER_OWNER.lstat()
                if (owner_info.st_dev, owner_info.st_ino) != old_owner_identity:
                    raise CoreNativeObservationUnavailable("lifecycle owner record changed during recovery")
                _LIFECYCLE_NATIVE_OBSERVER_OWNER.unlink()
            elif old_owner is not None:
                try:
                    boot, started = self._process_identity(old_owner["pid"])
                    old_alive = boot == old_owner["boot_id"] and started == old_owner["start_ticks"]
                except Exception:
                    old_alive = False
                if old_alive:
                    raise CoreNativeObservationUnavailable("prior Root lifecycle observer is still alive")
                owner_info = _LIFECYCLE_NATIVE_OBSERVER_OWNER.lstat()
                if (old_owner_identity != (owner_info.st_dev, owner_info.st_ino)):
                    raise CoreNativeObservationUnavailable("lifecycle owner record changed during recovery")
                _LIFECYCLE_NATIVE_OBSERVER_OWNER.unlink()

            boot_id, start_ticks = self._process_identity(os.getpid())
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            self._listener = listener
            listener.bind(str(LIFECYCLE_NATIVE_OBSERVER_SOCKET))
            os.chown(LIFECYCLE_NATIVE_OBSERVER_SOCKET, 0, _CORE_NATIVE_OBSERVER_GROUP)
            os.chmod(LIFECYCLE_NATIVE_OBSERVER_SOCKET, 0o660)
            bound = LIFECYCLE_NATIVE_OBSERVER_SOCKET.lstat()
            if (not stat.S_ISSOCK(bound.st_mode) or bound.st_uid != 0
                    or bound.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(bound.st_mode) != 0o660):
                raise CoreNativeObservationUnavailable("new lifecycle socket custody differs")
            self._socket_identity = (bound.st_dev, bound.st_ino)
            listener.listen(8)
            listener.settimeout(0.25)
            owner_record = {"schema": 1, "pid": os.getpid(), "boot_id": boot_id,
                "start_ticks": start_ticks, "socket_dev": bound.st_dev, "socket_ino": bound.st_ino}
            owner_fd = os.open(_LIFECYCLE_NATIVE_OBSERVER_OWNER,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                owner_info = os.fstat(owner_fd)
                if (not stat.S_ISREG(owner_info.st_mode) or owner_info.st_uid != 0
                        or owner_info.st_gid != 0 or stat.S_IMODE(owner_info.st_mode) != 0o600
                        or owner_info.st_nlink != 1):
                    raise CoreNativeObservationUnavailable("new lifecycle owner record custody differs")
                raw = _canonical(owner_record)
                self._owner_identity = (owner_info.st_dev, owner_info.st_ino)
                self._owner_record = owner_record
                view = memoryview(raw)
                while view:
                    written = os.write(owner_fd, view)
                    if written <= 0:
                        raise OSError("short lifecycle owner-record write")
                    view = view[written:]
                os.fsync(owner_fd)
            finally:
                os.close(owner_fd)
            self._ready.set()
            while not self._stop.is_set():
                try:
                    connection, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                with connection:
                    connection.settimeout(2.0)
                    try:
                        self._registry.serve_connection(connection)
                    except Exception:
                        continue
        except BaseException as exc:
            self._error = exc
            self._ready.set()
        finally:
            listener = self._listener
            self._listener = None
            if listener is not None:
                try:
                    listener.close()
                except OSError:
                    pass
            self._remove_own_paths()
            if self._lock_fd is not None:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                    os.close(self._lock_fd)
                except OSError:
                    pass
                self._lock_fd = None

    def _remove_own_paths(self) -> None:
        try:
            if self._socket_identity is not None:
                info = LIFECYCLE_NATIVE_OBSERVER_SOCKET.lstat()
                if (stat.S_ISSOCK(info.st_mode)
                        and (info.st_dev, info.st_ino) == self._socket_identity):
                    LIFECYCLE_NATIVE_OBSERVER_SOCKET.unlink()
        except FileNotFoundError:
            pass
        try:
            if self._owner_identity is not None and self._owner_record is not None:
                record, identity = self._read_owner_record()
                if identity == self._owner_identity and record == self._owner_record:
                    _LIFECYCLE_NATIVE_OBSERVER_OWNER.unlink()
        except FileNotFoundError:
            pass
        except Exception:
            if self._owner_identity is not None:
                try:
                    info = _LIFECYCLE_NATIVE_OBSERVER_OWNER.lstat()
                    if (info.st_dev, info.st_ino) == self._owner_identity:
                        _LIFECYCLE_NATIVE_OBSERVER_OWNER.unlink()
                except OSError:
                    pass

    def close(self) -> None:
        self._stop.set()
        if self._listener is not None:
            try:
                self._listener.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=3.0)
            if self._thread.is_alive():
                raise CoreNativeObservationUnavailable("Root lifecycle observer did not stop")
            self._thread = None
        self._registry.close()


def serve_core_native_observer(registry: RootCoreNativeObservationRegistry, *,
                               socket_path: Path = CORE_NATIVE_OBSERVER_SOCKET,
                               admin_gid: int = _CORE_NATIVE_OBSERVER_GROUP,
                               stop_event: threading.Event | None = None) -> None:
    """Serve fixed bounded IPC in the already-running inspector process."""
    if type(registry) is not RootCoreNativeObservationRegistry or socket_path != CORE_NATIVE_OBSERVER_SOCKET:
        raise CoreNativeObservationUnavailable("fixed root observer registry and socket are required")
    runtime = _OBSERVER_RUNTIME_DIR
    info = runtime.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != admin_gid
            or stat.S_IMODE(info.st_mode) != 0o750):
        raise CoreNativeObservationUnavailable("root observer runtime directory custody differs")
    try:
        old = socket_path.lstat()
    except FileNotFoundError:
        old = None
    if old is not None:
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0 or old.st_gid != admin_gid:
            raise CoreNativeObservationUnavailable("existing observer socket is not root-owned")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chown(socket_path, 0, admin_gid)
        os.chmod(socket_path, 0o660)
        listener.listen(16)
        listener.settimeout(0.5)
        while stop_event is None or not stop_event.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(2.0)
                try:
                    registry.serve_connection(connection)
                except Exception:
                    # Malformed peers cannot stop the root inspector's worker listener.
                    continue
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass


def _codex_account_fingerprint(credential_resolver: Callable[[], Mapping[str, Any]]) -> str:
    """Resolve the retained OAuth identity, then discard its bearer without exporting it."""
    if not callable(credential_resolver):
        raise CoreNativeObservationUnavailable("retained Codex auth resolver is unavailable")
    try:
        credentials = credential_resolver()
        token = credentials.get("api_key") if isinstance(credentials, Mapping) else None
        base_url = credentials.get("base_url") if isinstance(credentials, Mapping) else None
        provider = credentials.get("provider") if isinstance(credentials, Mapping) else None
        source = credentials.get("source") if isinstance(credentials, Mapping) else None
        auth_mode = credentials.get("auth_mode") if isinstance(credentials, Mapping) else None
        if (provider != _CODEX_PROVIDER or source != "hermes-auth-store"
                or auth_mode != "chatgpt" or not isinstance(base_url, str)
                or base_url.rstrip("/") != _CODEX_ENDPOINT or not isinstance(token, str) or not token):
            raise ValueError
        from agent.credential_pool import _codex_principal_identity
        identity = _codex_principal_identity(token)
        if (not isinstance(identity, tuple) or len(identity) != 2
                or any(not isinstance(value, str) or not value for value in identity)):
            raise ValueError
        return hashlib.sha256(b"hermes-codex-subscription-account-v1\0" +
                              (identity[0] + "\0" + identity[1]).encode("utf-8")).hexdigest()
    except Exception:
        raise CoreNativeObservationUnavailable("current Codex subscription identity is unavailable") from None


def _response_tool_calls(response: Any) -> list[tuple[str, str, bytes]]:
    """Extract exact function-call arguments from the consumed native Responses result."""
    output = getattr(response, "output", None)
    if not isinstance(output, (tuple, list)):
        return []
    calls: list[tuple[str, str, bytes]] = []
    for item in output:
        if getattr(item, "type", None) != "function_call":
            continue
        call_id, name, arguments = (getattr(item, "call_id", None), getattr(item, "name", None),
                                    getattr(item, "arguments", None))
        if not isinstance(call_id, str) or not isinstance(name, str) or not isinstance(arguments, str):
            raise CoreNativeObservationUnavailable("Codex function-call response is malformed")
        try:
            parsed = json.loads(arguments, object_pairs_hook=_unique_pairs)
            if not isinstance(parsed, dict):
                raise ValueError
            canonical = _canonical(parsed)
        except Exception:
            raise CoreNativeObservationUnavailable("Codex function-call arguments are malformed") from None
        calls.append((call_id, name, canonical))
    return calls


def _request_tool_names(request: Mapping[str, Any]) -> tuple[str, ...]:
    """Read the exact function-tool inventory sent to the provider."""
    tools = request.get("tools")
    if not isinstance(tools, list) or len(tools) > 512:
        raise CoreNativeObservationUnavailable("native parent tool inventory is unavailable")
    names: list[str] = []
    for item in tools:
        if not isinstance(item, Mapping):
            raise CoreNativeObservationUnavailable("native parent tool inventory is malformed")
        name = item.get("name")
        if name is None and isinstance(item.get("function"), Mapping):
            name = item["function"].get("name")
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise CoreNativeObservationUnavailable("native parent tool inventory is malformed")
        names.append(name)
    if len(set(names)) != len(names):
        raise CoreNativeObservationUnavailable("native parent tool inventory is ambiguous")
    return tuple(sorted(names))


def _native_prompt_sha256(request: Mapping[str, Any]) -> str:
    """Hash the exact final user text in the Codex Responses request.

    Multimodal or transformed prompts that cannot be proven byte-identical to
    the accepted ingress prompt do not produce an owner-turn attempt receipt.
    """
    items = request.get("input")
    if not isinstance(items, list):
        raise CoreNativeObservationUnavailable("native user prompt is unavailable")
    users = [item for item in items if isinstance(item, Mapping)
             and item.get("type") == "message" and item.get("role") == "user"]
    if not users:
        raise CoreNativeObservationUnavailable("native user prompt is unavailable")
    content = users[-1].get("content")
    if (not isinstance(content, list) or len(content) != 1
            or not isinstance(content[0], Mapping) or content[0].get("type") != "input_text"
            or not isinstance(content[0].get("text"), str)):
        raise CoreNativeObservationUnavailable("native user prompt cannot be bound byte-for-byte")
    return hashlib.sha256(content[0]["text"].encode("utf-8", errors="strict")).hexdigest()


def _native_delegate_execution_gate(*, tool_name: str, args: Any,
                                    next_call: Callable[[Any], Any], **_event: Any) -> Any:
    """Block model-issued direct delegation while preserving the Resources adapter.

    Official PluginContext.dispatch_tool calls tools.registry.dispatch directly and
    therefore does not traverse tool_execution middleware. The fixed Resources
    handler is the only approved internal caller; ordinary model tool execution
    reaches this middleware and is denied without invoking downstream dispatch.
    """
    if tool_name == "delegate_task":
        return json.dumps({"success": False, "state": "native-delegation-requires-resources-policy",
                           "message": "Use the owner-authorized Resources delegation route."})
    return next_call(args)


def install_native_codex_process_observer(ctx: Any, *, client: CoreNativeObservationClient,
                                          credential_resolver: Callable[[], Mapping[str, Any]] | None = None) -> Any:
    """Install the supported additive LLM execution middleware in the selected core.

    Hermes' official ``llm_execution`` middleware wraps ``_perform_api_call``.  The
    single-use downstream callback is the real Codex provider execution and does not
    return until the Responses SSE stream has reached its terminal response.  This
    reports protected process observations, not root-captured TLS bytes.
    """
    register = getattr(ctx, "register_middleware", None)
    if not callable(register) or type(client) is not CoreNativeObservationClient:
        raise CoreNativeObservationUnavailable("pinned Hermes middleware seam is unavailable")

    request_attempts: OrderedDict[tuple[str, str], ObservedProviderAttempt | None] = OrderedDict()
    call_lineage = register_tool_call_from_current_parent._lineage
    lineage_lock = register_tool_call_from_current_parent._lock

    def resolve_credentials() -> Mapping[str, Any]:
        if credential_resolver is not None:
            return credential_resolver()
        from hermes_cli.auth_codex import resolve_codex_runtime_credentials
        return resolve_codex_runtime_credentials(read_only=True)

    def no_tool_request(request: dict[str, Any]) -> dict[str, Any]:
        safe = dict(request)
        safe["tools"] = []
        safe["tool_choice"] = "none"
        return safe

    def denied_response() -> Any:
        # Hermes' Codex normalizer accepts the provider's ordinary Responses
        # shape. Returning a completed text response stops its retry/failover
        # loop without invoking another provider or exposing a tool call.
        message = "This request was not sent because its current Jarvis authority could not be verified."
        return SimpleNamespace(
            id="jarvis-authority-unavailable", status="completed", error=None,
            incomplete_details=None, usage=None, output_text=message,
            output=[SimpleNamespace(type="message", role="assistant", status="completed",
                content=[SimpleNamespace(type="output_text", text=message)])],
        )

    def observe_lifecycle_startup(event: Mapping[str, Any], context: LifecycleStartupProbeContext) -> Any:
        next_call, request = event.get("next_call"), event.get("request")
        if (not callable(next_call) or not isinstance(request, dict)
                or type(context) is not LifecycleStartupProbeContext
                or not context.is_root_issued()):
            return denied_response()
        try:
            route = (event.get("provider"), event.get("api_mode"),
                     str(event.get("base_url", "")).rstrip("/"))
            if route != (context.provider, context.api_mode, context.base_url):
                return denied_response()
            if event.get("model") != context.model or event.get("middleware_trace"):
                return denied_response()
            session_id = event.get("session_id")
            turn_id = _require_id(event.get("turn_id"), "lifecycle turn ID")
            api_request_id = _require_id(event.get("api_request_id"), "lifecycle request ID")
            if session_id != context.session_id:
                return denied_response()
            prompt_digest = _native_prompt_sha256(request)
            expected_prompt = hashlib.sha256(
                (_LIFECYCLE_STARTUP_PROMPT_PREFIX + context.nonce
                 + _LIFECYCLE_STARTUP_PROMPT_SUFFIX).encode("ascii")).hexdigest()
            identity = _CURRENT_LIFECYCLE_STARTUP_IDENTITY.get()
            expected_instructions_sha256 = _CURRENT_LIFECYCLE_STARTUP_INSTRUCTIONS_SHA256.get()
            instructions = request.get("instructions")
            if (prompt_digest != expected_prompt or not isinstance(identity, str)
                    or not isinstance(instructions, str)
                    or not isinstance(expected_instructions_sha256, str)
                    or hashlib.sha256(instructions.encode("utf-8", "strict")).hexdigest()
                       != expected_instructions_sha256
                    or identity not in instructions):
                return denied_response()
            input_items = request.get("input")
            if (not isinstance(input_items, list) or len(input_items) != 1
                    or not isinstance(input_items[0], Mapping)
                    or input_items[0].get("type") != "message"
                    or input_items[0].get("role") != "user"
                    or _request_tool_names(request) != ()):
                return denied_response()
            request_key = (context.session_id, api_request_id)
            with lineage_lock:
                if request_key in request_attempts:
                    return denied_response()
                request_attempts[request_key] = None
                request_attempts.move_to_end(request_key)
                while len(request_attempts) > 64:
                    request_attempts.popitem(last=False)
            account = _codex_account_fingerprint(resolve_credentials)
            if account != context.account_fingerprint:
                return denied_response()
            provider_request = no_tool_request(request)
            attempt_handle = client.register_lifecycle_startup_attempt(
                context, turn_id=turn_id, api_request_id=api_request_id,
                provider=route[0], api_mode=route[1], base_url=route[2], model=context.model,
                account_fingerprint=account, request_sha256=_hash(provider_request),
                prompt_sha256=prompt_digest, tool_names=(), retry_count=0)
            with lineage_lock:
                request_attempts[request_key] = None
            response = next_call(provider_request)
            if (_codex_account_fingerprint(resolve_credentials) != account
                    or getattr(response, "status", None) != "completed"
                    or getattr(response, "error", None) is not None
                    or getattr(response, "incomplete_details", None) is not None):
                return denied_response()
            calls = _response_tool_calls(response)
            output_text = getattr(response, "output_text", None)
            if (calls or not isinstance(output_text, str) or not 1 <= len(output_text) <= 1024
                    or output_text != _LIFECYCLE_STARTUP_RESPONSE_PREFIX + context.nonce):
                return denied_response()
            response_bytes = _canonical(response.model_dump(mode="json"))
            if not 1 <= len(response_bytes) <= MAX_FRAME:
                return denied_response()
            response_sha256 = hashlib.sha256(response_bytes).hexdigest()
            completion_handle = client.register_lifecycle_startup_response(
                context, attempt_handle=attempt_handle, turn_id=turn_id,
                api_request_id=api_request_id, request_sha256=_hash(provider_request),
                response_sha256=response_sha256, response_text=output_text,
                completed=True, tool_call_count=0)
            context._terminal.append({
                "completion_handle": completion_handle,
                "response_text_sha256": hashlib.sha256(
                    output_text.encode("utf-8", "strict")).hexdigest(),
            })
            return response
        except Exception:
            return denied_response()

    def observe(**event: Any) -> Any:
        next_call = event.get("next_call")
        request = event.get("request")
        lifecycle_context = _CURRENT_LIFECYCLE_STARTUP_PROBE.get()
        if lifecycle_context is not None:
            return observe_lifecycle_startup(event, lifecycle_context)
        route = (event.get("provider"), event.get("api_mode"), event.get("base_url"))
        if route != (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT):
            if isinstance(request, dict) and callable(next_call):
                # Unrelated provider calls that are not attached to an observed
                # owner turn remain ordinary Hermes traffic. Once a concrete
                # turn is present, however, route uncertainty must not become a
                # paid fallback for a root-enrolled zero-budget planning turn.
                if not all(isinstance(event.get(name), str) and event.get(name)
                           for name in ("session_id", "turn_id")):
                    return next_call(request)
                try:
                    prompt_digest = _native_prompt_sha256(request)
                    planned = client.planning_context_for_attempt(
                        session_id=event.get("session_id"), turn_id=event.get("turn_id"),
                        prompt_sha256=prompt_digest)
                    review = client.master_review_context_for_attempt(
                        session_id=event.get("session_id"), turn_id=event.get("turn_id"),
                        prompt_sha256=prompt_digest)
                except Exception:
                    # Do not spend on an alternate provider when a planned
                    # turn cannot be distinguished from ordinary chat.
                    return denied_response()
                if planned is not None or review is not None:
                    return denied_response()
                return next_call(request)
            return denied_response()
        if not callable(next_call) or not isinstance(request, dict):
            return denied_response()
        provider_request = request
        force_no_tools = False
        session_id, turn_id, api_request_id = (event.get("session_id"), event.get("turn_id"),
                                                event.get("api_request_id"))
        try:
            request_key = (_require_id(session_id, "session ID"),
                           _require_id(api_request_id, "API request ID"))
            _require_id(turn_id, "turn ID")
        except CoreNativeObservationUnavailable:
            return denied_response()
        try:
            prompt_sha256 = _native_prompt_sha256(request)
            planning_context = client.planning_context_for_attempt(
                session_id=session_id, turn_id=turn_id, prompt_sha256=prompt_sha256)
            master_review_context = client.master_review_context_for_attempt(
                session_id=session_id, turn_id=turn_id, prompt_sha256=prompt_sha256)
        except Exception:
            # Hook failures normally fall through to the original request. A
            # completed local denial prevents provider retries/failover for an
            # unknown mode without pretending to be a root receipt.
            planning_context = None
            master_review_context = None
            force_no_tools = True
            return denied_response()
        protected_context = planning_context is not None or master_review_context is not None
        if protected_context:
            force_no_tools = True
        if force_no_tools:
            provider_request = no_tool_request(request)
        if force_no_tools and (not callable(next_call) or not isinstance(request, dict)):
            return None
        if protected_context:
            if event.get("middleware_trace"):
                return denied_response()
        with lineage_lock:
            # Hermes re-enters this supported middleware for an outer retry with the
            # same api_request_id. The first observation is logical-attempt-only; a
            # second call is allowed to proceed for ordinary chat but cannot mint proof.
            if request_key in request_attempts:
                return denied_response() if protected_context else next_call(provider_request)
            request_attempts[request_key] = None  # reserved before any provider effect
            request_attempts.move_to_end(request_key)
            while len(request_attempts) > 1024:
                request_attempts.popitem(last=False)
        if event.get("middleware_trace"):
            return denied_response() if protected_context else next_call(provider_request)
        try:
            account = _codex_account_fingerprint(resolve_credentials)
            attempt = client.register_attempt(
                session_id=session_id, turn_id=turn_id, api_request_id=api_request_id,
                provider=event.get("provider"), model=event.get("model"),
                base_url=event.get("base_url"), api_mode=event.get("api_mode"),
                account_fingerprint=account, request_sha256=_hash(provider_request),
                parent_tool_names=_request_tool_names(provider_request),
                prompt_sha256=prompt_sha256, retry_count=0,
            )
        except CoreNativeObservationUnavailable:
            return denied_response()
        with lineage_lock:
            request_attempts[request_key] = attempt
        try:
            response = next_call(provider_request)
        except BaseException:
            # Retire the root attempt as an unsuccessful logical observation. This
            # receipt can never authorize a tool call or delegation.
            try:
                failure_bytes = _canonical({"completed": False})
                client.register_response(attempt=attempt,
                    response_sha256=hashlib.sha256(failure_bytes).hexdigest(),
                    response_text_sha256=None, tool_calls=[], completed=False)
            except Exception:
                pass
            if protected_context:
                return denied_response()
            raise
        try:
            # Verify the retained current resolver still selects the same identity after
            # response completion, while never sending the credential itself to root.
            try:
                same_account = _codex_account_fingerprint(resolve_credentials) == account
            except CoreNativeObservationUnavailable:
                same_account = False
            if not same_account:
                if protected_context:
                    return denied_response()
                return response
            calls = _response_tool_calls(response)
            if protected_context and calls:
                # No downstream Hermes tool dispatcher may consume a tool call
                # returned to a request whose root-enrolled closure was empty.
                return denied_response()
            output_text = getattr(response, "output_text", None)
            response_text_sha256 = None
            if isinstance(output_text, str):
                output_bytes = output_text.encode("utf-8", errors="strict")
                if output_bytes and len(output_bytes) <= 32 * 1024:
                    response_text_sha256 = hashlib.sha256(output_bytes).hexdigest()
            response_bytes = _canonical(response.model_dump(mode="json"))
            if not 1 <= len(response_bytes) <= MAX_FRAME:
                return response
            try:
                client.register_response(
                    attempt=attempt, response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                    response_text_sha256=response_text_sha256,
                    response_text=(output_text if (protected_context or attempt.capture_child_output)
                                   and isinstance(output_text, str) else None),
                    tool_calls=[{"id": call_id, "name": name,
                                 "arguments_sha256": hashlib.sha256(arguments).hexdigest()}
                                for call_id, name, arguments in calls],
                    completed=True,
                )
            except CoreNativeObservationUnavailable:
                if protected_context:
                    return denied_response()
                return response
            with lineage_lock:
                for call_id, name, arguments in calls:
                    call_lineage[call_id] = (attempt, session_id, turn_id, name, arguments, None)
                    call_lineage.move_to_end(call_id)
                while len(call_lineage) > 1024:
                    call_lineage.popitem(last=False)
            return response
        except Exception:
            # Observation failure must not discard a successfully consumed answer.
            # Without its root response receipt, Resources delegation has no call handle.
            if protected_context:
                return denied_response()
            return response

    registrations = []
    try:
        registrations.append(register("llm_execution", observe))
        # This is a model-call gate, not the trusted Resources wrapper path:
        # PluginContext.dispatch_tool bypasses tool_execution middleware.
        registrations.append(register("tool_execution", _native_delegate_execution_gate))
        return tuple(registrations)
    except Exception:
        raise CoreNativeObservationUnavailable("native Codex observer registration failed") from None


def register_tool_call_from_current_parent(*, client: CoreNativeObservationClient,
                                           parent_agent: Any, tool_call_id: str,
                                           tool_name: str, arguments: Mapping[str, Any]
                                           ) -> ObservedNativeToolCall:
    """Join a returned provider call to Hermes' live injected parent Agent.

    Resource handlers call this before preparing a claim. The response-side
    observer retained the exact provider call ID, tool name, canonical argument
    bytes, core session, and turn. The first use binds that record to the live
    Agent instance; later uses require object identity, not a serialized Agent.
    """
    if type(client) is not CoreNativeObservationClient or not isinstance(arguments, Mapping):
        raise CoreNativeObservationUnavailable("selected live parent and native observer are required")
    try:
        canonical = _canonical(dict(arguments))
        session_id = _require_id(getattr(parent_agent, "session_id", None), "parent session ID")
        turn_id = _require_id(getattr(parent_agent, "_current_turn_id", None), "parent turn ID")
        tool_call_id = _require_id(tool_call_id, "provider tool-call ID")
        tool_name = _require_id(tool_name, "native tool name")
        parent_ref = weakref.ref(parent_agent)
    except Exception:
        raise CoreNativeObservationUnavailable("live Hermes parent lineage is unavailable") from None
    # The registry is populated only by the source-enrolled middleware after its
    # actual downstream Codex response completed. It is process-local and bounded.
    table = getattr(register_tool_call_from_current_parent, "_lineage", None)
    lock = getattr(register_tool_call_from_current_parent, "_lock", None)
    if not isinstance(table, OrderedDict) or not isinstance(lock, type(threading.RLock())):
        raise CoreNativeObservationUnavailable("native response lineage registry is unavailable")
    with lock:
        row = table.get(tool_call_id)
        if row is None:
            raise CoreNativeObservationUnavailable("tool call has no completed provider response")
        attempt, observed_session, observed_turn, observed_name, observed_args, bound_parent = row
        if (session_id != observed_session or turn_id != observed_turn or tool_name != observed_name
                or canonical != observed_args):
            raise CoreNativeObservationUnavailable("live native call differs from its provider response")
        old_parent = bound_parent() if callable(bound_parent) else None
        if old_parent is not None and old_parent is not parent_agent:
            raise CoreNativeObservationUnavailable("native tool call belongs to another parent Agent")
        if old_parent is None:
            # The supported PluginContext dispatch injects the actual current Agent;
            # store only a weak reference so this lineage cannot keep a turn alive.
            table[tool_call_id] = (attempt, observed_session, observed_turn, observed_name,
                                   observed_args, parent_ref)
        table.move_to_end(tool_call_id)
        # Consume local lineage before crossing IPC. If the reply is lost, root
        # replay protection keeps a second request from minting another handle.
        del table[tool_call_id]
    return client.register_tool_call(attempt=attempt, tool_call_id=tool_call_id,
                                     canonical_arguments=canonical)


class RootInternalProfileClaimSource:
    """Resources-side adapter joining exact live handler metadata to root claims."""

    def __init__(self, client: CoreNativeObservationClient):
        if type(client) is not CoreNativeObservationClient:
            raise CoreNativeObservationUnavailable("fixed native observation client is required")
        self._client = client
        self._lock = threading.RLock()
        self._mission_claims: OrderedDict[str, tuple[object, RootSelectedInternalProfileDispatchClaim]] = OrderedDict()
        self._authorized_mission_claims: set[str] = set()

    def read_selected_expert_source(
            self, *, resources_claim: object, source_id: str) -> RootNativeSelectedSourceDelivery:
        """Resolve only a source selected by this root-sealed mission claim."""
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims
                or resources_claim.mission_binding is None
                or source_id not in resources_claim.mission_binding.selected_source_ids):
            raise CoreNativeObservationUnavailable("source is not selected by the sealed owner intent")
        return self._client.read_selected_expert_source(
            native_claim=retained[1], source_id=source_id)

    def admit_selected_expert_child(
            self, *, resources_claim: object, child: Any,
            source: RootNativeSelectedSourceDelivery, goal: str,
            team_message: RootTeamMessageDelivery | None = None
            ) -> RootVerifiedNativeChildAuthorization:
        """Forward the exact consumed claim/source to root admission."""
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims):
            raise CoreNativeObservationUnavailable("typed consumed Resources claim is required")
        return self._client.admit_selected_expert_child(
            native_claim=retained[1], child=child, source=source, goal=goal,
            team_message=team_message)

    def prepare_team_message(self, *, resources_claim: object,
                             binding: RootSelectedTeamBinding,
                             sender: RootObservedExpertCompletion,
                             recipient: RootNativeSelectedSourceDelivery,
                             original_goal: str, excerpt: str) -> RootTeamMessageDelivery:
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims):
            raise CoreNativeObservationUnavailable("typed current Resources claim is required")
        return self._client.prepare_team_message(
            native_claim=retained[1], binding=binding, sender=sender,
            recipient=recipient, original_goal=original_goal, excerpt=excerpt)

    def complete_selected_expert_child(self, *, resources_claim: object,
                                       authorization: RootVerifiedNativeChildAuthorization
                                       ) -> RootObservedExpertCompletion:
        """Return root-captured provider output for this one admitted Expert child."""
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims):
            raise CoreNativeObservationUnavailable("typed consumed Resources claim is required")
        if (type(authorization) is not RootVerifiedNativeChildAuthorization
                or authorization.owner_turn_handle != retained[1].owner_turn_handle
                or authorization.parent_session_id != retained[1].session_id
                or authorization.mode != "expert-read-research"):
            raise CoreNativeObservationUnavailable("Expert admission belongs to another owner claim")
        return self._client.complete_selected_expert_child(authorization=authorization)

    def consume_current_claim(self, profile_id: str, parent_agent: object, *,
                              tool_call_id: str, tool_name: str,
                              arguments: Mapping[str, Any], turn_id: str):
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        if profile_id != "hermes" or tool_name != "resources_delegate":
            raise CoreNativeObservationUnavailable("only the fixed Jarvis master tool may be claimed")
        observed_turn = _require_id(getattr(parent_agent, "_current_turn_id", None), "native turn ID")
        if turn_id != observed_turn:
            raise CoreNativeObservationUnavailable("handler turn differs from the current parent turn")
        observed_call = register_tool_call_from_current_parent(
            client=self._client, parent_agent=parent_agent, tool_call_id=tool_call_id,
            tool_name=tool_name, arguments=arguments)
        claim_handle = self._client.prepare_dispatch(observed_call=observed_call)
        claim = self._client.consume_dispatch(claim_handle=claim_handle)
        try:
            parent_tools = frozenset(getattr(parent_agent, "valid_tool_names"))
            if (type(claim) is not RootSelectedInternalProfileDispatchClaim
                    or claim.profile_id != profile_id or claim.tool_name != tool_name
                    or claim.tool_call_id != tool_call_id or claim.turn_id != observed_turn
                    or claim.session_id != getattr(parent_agent, "session_id")
                    or claim.arguments_sha256 != hashlib.sha256(_canonical(dict(arguments))).hexdigest()
                    or set(claim.parent_tool_names) != set(parent_tools)
                    or not set(claim.parent_tool_names).issubset(claim.configured_parent_tool_names)
                    or (not claim.allow_inherited_mcp and any(name.startswith("mcp__") for name in parent_tools))
                    or claim.profile_privacy_requirements or claim.parent_privacy_grants):
                raise ValueError
            route_receipt = _hash({
                "evidence_class": claim.evidence_class, "provider": claim.provider,
                "api_mode": claim.api_mode, "base_url": claim.base_url,
                "account_fingerprint": claim.account_fingerprint,
                "owner_turn_handle": claim.owner_turn_handle,
                "gateway_turn_id": claim.gateway_turn_id,
                "tool_call_id": claim.tool_call_id,
                "delegation_policy_sha256": claim.delegation_policy_sha256,
                "parent_tool_configuration_sha256": claim.parent_tool_configuration_sha256,
            })
            resources_claim = ResourcesDispatchClaim(
                claim_id=claim.claim_handle, profile_id=claim.profile_id,
                source_revision=claim.source_revision,
                generation_sha256=claim.generation_sha256,
                profile_manifest_sha256=claim.profile_manifest_sha256,
                effective_prompt=claim.prompt_bytes,
                effective_prompt_sha256=claim.prompt_sha256,
                parent_agent=parent_agent, parent_session_id=claim.session_id,
                owner_subject_sha256=claim.owner_subject_sha256,
                parent_tool_names=parent_tools,
                profile_tool_names=frozenset(claim.profile_tool_names),
                # This is native parent inheritance authorized by the distinct
                # root policy, not a Resources profile tool grant.
                inherited_child_tool_names=parent_tools,
                parent_privacy_grants=frozenset(),
                profile_privacy_requirements=frozenset(),
                delegation_policy_handle=claim.delegation_policy_handle,
                delegation_policy_sha256=claim.delegation_policy_sha256,
                parent_tool_configuration_sha256=claim.parent_tool_configuration_sha256,
                configured_parent_tool_names=frozenset(claim.configured_parent_tool_names),
                allow_inherited_mcp=claim.allow_inherited_mcp,
                allow_native_orchestrator_delegation=claim.allow_native_orchestrator_delegation,
                route_class="existing-owner-codex-zero-additional-metered",
                route_receipt_sha256=route_receipt,
                max_additional_metered_microusd=0,
                expires_monotonic=claim.expires_monotonic,
                gateway_turn_id=claim.gateway_turn_id,
                core_generation=claim.core_generation,
                core_source_generation=claim.core_source_generation,
                mission_binding=claim.mission_binding,
            )
            if claim.mission_binding is not None:
                with self._lock:
                    if len(self._mission_claims) >= 128:
                        self._mission_claims.popitem(last=False)
                    self._mission_claims[claim.claim_handle] = (resources_claim, claim)
            return resources_claim
        except Exception:
            raise CoreNativeObservationUnavailable("root claim does not match the live native parent") from None

    def authorize_mission_claim(self, resources_claim: object, *, task_sha256: str
                                ) -> RootVerifiedMissionDispatchAuthorization:
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        if (type(resources_claim) is not ResourcesDispatchClaim
                or resources_claim.mission_binding is None
                or not _HASH.fullmatch(task_sha256 or "")):
            raise CoreNativeObservationUnavailable("typed bound mission claim is required")
        with self._lock:
            row = self._mission_claims.get(resources_claim.claim_id)
            if resources_claim.claim_id in self._authorized_mission_claims:
                raise CoreNativeObservationUnavailable("mission claim authorization was already consumed")
        if row is None or row[0] is not resources_claim or row[1].mission_binding != resources_claim.mission_binding:
            raise CoreNativeObservationUnavailable("mission claim was not issued by this root client")
        native_claim = row[1]
        if (native_claim.arguments_sha256 != task_sha256
                or native_claim.gateway_turn_id != resources_claim.gateway_turn_id
                or native_claim.owner_subject_sha256 != resources_claim.owner_subject_sha256
                or native_claim.core_generation != resources_claim.core_generation
                or native_claim.core_source_generation != resources_claim.core_source_generation
                or native_claim.mission_binding.task_sha256 != task_sha256):
            raise CoreNativeObservationUnavailable("mission claim does not bind the approved goal")
        authorization = self._client.authorize_mission_dispatch(claim=native_claim)
        if not authorization.matches_claim(native_claim, task_sha256, now=time.monotonic()):
            raise CoreNativeObservationUnavailable("root mission authorization is not current")
        with self._lock:
            self._authorized_mission_claims.add(resources_claim.claim_id)
        return authorization


def register_native_resources_observer(ctx: Any, runtime_context: Any, *,
                                       credential_resolver: Callable[[], Mapping[str, Any]] | None = None) -> tuple[Any, ...]:
    """Register the fixed Resources handler and additive Codex middleware together.

    The plugin runtime may inject only the exact fixed socket client; it cannot
    replace route evidence, select a profile, or mint claims.
    """
    client = getattr(runtime_context, "core_native_observation_client", None)
    if client is None:
        client = CoreNativeObservationClient()
    if type(client) is not CoreNativeObservationClient:
        raise CoreNativeObservationUnavailable("fixed root observer client is unavailable")
    from hermes_installer.components.resources_internal_dispatch import register_resources_delegate
    middleware = install_native_codex_process_observer(
        ctx, client=client, credential_resolver=credential_resolver)
    tool = register_resources_delegate(ctx, RootInternalProfileClaimSource(client))
    return (*middleware, tool)


# Function attributes keep the local parent/call join private to this imported
# source module and avoid a process-global registry object exposed to plugins.
register_tool_call_from_current_parent._lineage = OrderedDict()
register_tool_call_from_current_parent._lock = threading.RLock()


__all__ = [
    "CORE_NATIVE_OBSERVER_SOCKET", "CoreNativeObservationClient",
    "CoreNativeObservationUnavailable", "ObservedNativeToolCall",
    "CoreNativeResourcesDelegateRegistration", "current_resources_delegate_registration",
    "NativeSourceMember", "ObservedProviderAttempt", "OwnerTurnHandle",
    "RootSelectedInternalProfileDispatchClaim", "RootVerifiedMissionDispatchAuthorization",
    "RootVerifiedNativeChildAuthorization", "RootVerifiedMasterReadCall",
    "CoreVerifiedJarvisMasterPlanningCompletion",
    "RootCoreNativeObservationRegistry", "_native_delegate_execution_gate",
    "RootInternalProfileClaimSource", "serve_core_native_observer",
    "install_native_codex_process_observer", "register_native_resources_observer",
    "register_tool_call_from_current_parent",
]
