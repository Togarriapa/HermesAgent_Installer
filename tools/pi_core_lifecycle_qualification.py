#!/usr/bin/env python3
"""Run one fixed root Core adapter update and emit digest-only before/after evidence.

This is a Pi-only qualification command. It consumes a source generation already
staged by ``pi_native_core_stage.py``; it does not download, install, select, or
rollback arbitrary paths. The only mutation is the fixed Core adapter update
through the candidate's normal ``core-service adapter-update`` CLI dispatch.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import sys
from pathlib import Path
from types import MappingProxyType
from typing import Any

_NATIVE_PLUGIN_MEMBER_NAMES = ("plugin.yaml", "__init__.py")
_NATIVE_PLUGIN_BACKUP_NAMES = {
    "plugin.yaml": "native-plugin-plugin.yaml",
    "__init__.py": "native-plugin-__init__.py",
}
_ADAPTER_BACKUP_BASE_MEMBERS = frozenset({
    "journal.json", "unit", "launcher", "plugin-selection.json", "resources-record.json",
    "overlay-record.json", "primary-record.json", "obsidian-registration.json", "cohort.json",
})


def _candidate_source(commit: str) -> Path:
    if re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        raise ValueError("candidate commit must be a full lowercase SHA")
    return Path(f"/opt/hermes-installer-core-{commit[:9]}/src")


def _open_root_dir(parent_fd: int, name: str) -> int:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                 dir_fd=parent_fd)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        os.close(fd)
        raise RuntimeError("fixed staged source ancestor custody differs")
    return fd


def _read_held_helper(generation_fd: int) -> tuple[bytes, list[int]]:
    """Read, but never execute, the helper beneath a verified tools directory."""
    fds: list[int] = []
    try:
        generation = os.fstat(generation_fd)
        if (not stat.S_ISDIR(generation.st_mode) or generation.st_uid != 0
                or generation.st_gid != 0 or stat.S_IMODE(generation.st_mode) & 0o022):
            raise RuntimeError("fixed staged source ancestor custody differs")
        tools_fd = _open_root_dir(generation_fd, "tools")
        fds.append(tools_fd)
        helper_fd = os.open("pi_native_core_adopt.py", os.O_RDONLY
                            | getattr(os, "O_NOFOLLOW", 0)
                            | getattr(os, "O_CLOEXEC", 0), dir_fd=tools_fd)
        fds.append(helper_fd)
        before = os.fstat(helper_fd)
        named = os.stat("pi_native_core_adopt.py", dir_fd=tools_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                or stat.S_IMODE(before.st_mode) & 0o022 or before.st_nlink != 1
                or not 1 <= before.st_size <= 2 * 1024 * 1024
                or (before.st_dev, before.st_ino, before.st_mode, before.st_uid,
                    before.st_gid, before.st_nlink, before.st_size)
                != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                    named.st_gid, named.st_nlink, named.st_size)):
            raise RuntimeError("fixed staged provenance verifier custody differs")
        helper = bytearray()
        while len(helper) <= 2 * 1024 * 1024:
            chunk = os.read(helper_fd, min(65536, 2 * 1024 * 1024 + 1 - len(helper)))
            if not chunk:
                break
            helper.extend(chunk)
        after = os.fstat(helper_fd)
        if (len(helper) != before.st_size or len(helper) > 2 * 1024 * 1024
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                    before.st_ctime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                             after.st_mtime_ns, after.st_ctime_ns)):
            raise RuntimeError("fixed staged verifier changed during held read")
        return bytes(helper), fds
    except BaseException:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _load_stage_verifier(commit: str):
    """Check ancestors, tools and a held helper inode before executing it."""
    generation_name = f"hermes-installer-core-{commit[:9]}"
    fds: list[int] = []
    root_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                      | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    fds.append(root_fd)
    try:
        opt_fd = _open_root_dir(root_fd, "opt"); fds.append(opt_fd)
        generation_fd = _open_root_dir(opt_fd, generation_name); fds.append(generation_fd)
        src_fd = _open_root_dir(generation_fd, "src"); fds.append(src_fd)
        helper, helper_fds = _read_held_helper(generation_fd)
        fds.extend(helper_fds)
        return helper, fds, src_fd
    except BaseException:
        for fd in reversed(fds):
            try:
                os.close(fd)
            except OSError:
                pass
        raise


def _execute_stage_verifier(commit: str, helper_bytes: bytes):
    import types
    module = types.ModuleType("_pi_native_core_adopt_for_qualification")
    module.__file__ = f"/opt/hermes-installer-core-{commit[:9]}/tools/pi_native_core_adopt.py"
    exec(compile(helper_bytes, module.__file__, "exec"), module.__dict__)
    return module


def _verify_held_source_path(generation_fd: int, source_fd: int) -> None:
    held = os.fstat(source_fd)
    named = os.stat("src", dir_fd=generation_fd, follow_symlinks=False)
    if (not stat.S_ISDIR(held.st_mode) or held.st_uid != 0 or held.st_gid != 0
            or stat.S_IMODE(held.st_mode) & 0o022
            or (held.st_dev, held.st_ino, held.st_mode, held.st_uid, held.st_gid)
            != (named.st_dev, named.st_ino, named.st_mode, named.st_uid, named.st_gid)):
        raise RuntimeError("fixed staged source directory changed after custody check")


def _read_source_receipt(generation_fd: int) -> dict[str, Any]:
    fd = os.open(".source-provenance.json", os.O_RDONLY
                 | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                 dir_fd=generation_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_nlink != 1
                or not 1 <= info.st_size <= 1024):
            raise RuntimeError("source provenance receipt custody differs")
        raw = bytearray()
        while len(raw) <= 1024:
            block = os.read(fd, min(512, 1025 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        named = os.stat(".source-provenance.json", dir_fd=generation_fd,
                        follow_symlinks=False)
        identity = (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                    info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        if (len(raw) != info.st_size or len(raw) > 1024
                or identity != (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                                after.st_gid, after.st_nlink, after.st_size,
                                after.st_mtime_ns, after.st_ctime_ns)
                or identity != (named.st_dev, named.st_ino, named.st_mode, named.st_uid,
                                named.st_gid, named.st_nlink, named.st_size,
                                named.st_mtime_ns, named.st_ctime_ns)):
            raise RuntimeError("source provenance receipt changed during read")
    finally:
        os.close(fd)
    try:
        def unique(pairs):
            value = {}
            for key, item in pairs:
                if key in value:
                    raise ValueError("duplicate receipt key")
                value[key] = item
            return value
        receipt = json.loads(bytes(raw).decode("utf-8", "strict"), object_pairs_hook=unique)
    except (ValueError, UnicodeError):
        raise RuntimeError("source provenance receipt is malformed") from None
    if (type(receipt) is not dict or set(receipt) != {"schema", "source_commit", "archive_sha256"}
            or type(receipt.get("schema")) is not int or receipt["schema"] != 1
            or not re.fullmatch(r"[0-9a-f]{40}", str(receipt.get("source_commit", "")))
            or not re.fullmatch(r"[0-9a-f]{64}", str(receipt.get("archive_sha256", "")))):
        raise RuntimeError("source provenance receipt fields differ")
    return receipt


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


class _DigestSink(io.TextIOBase):
    """Discard CLI text while retaining bounded count/hash metadata only."""
    def __init__(self) -> None:
        self._hash = hashlib.sha256()
        self.byte_count = 0

    def write(self, value: str) -> int:
        if not isinstance(value, str):
            raise TypeError("text sink accepts strings only")
        raw = value.encode("utf-8", "replace")
        self._hash.update(raw)
        self.byte_count += len(raw)
        return len(value)

    def flush(self) -> None:
        return None

    @property
    def sha256(self) -> str:
        return self._hash.hexdigest()


def _native_plugin_transition_valid(value: object) -> bool:
    fields = {"schema", "purpose", "old_adapter_generation", "new_adapter_generation",
              "plugin_selection_sha256", "old_members", "new_members"}
    if type(value) is not dict or set(value) != fields:
        return False
    def member_map(row: object) -> bool:
        return (type(row) is dict and set(row) == {"plugin.yaml", "__init__.py"}
                and all(isinstance(row[name], str)
                        and re.fullmatch(r"[0-9a-f]{64}", row[name]) is not None
                        for name in ("plugin.yaml", "__init__.py")))
    return (type(value["schema"]) is int and value["schema"] == 1
            and value["purpose"] == "fixed-native-resources-plugin"
            and isinstance(value["old_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["old_adapter_generation"]) is not None
            and isinstance(value["new_adapter_generation"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["new_adapter_generation"]) is not None
            and value["old_adapter_generation"] != value["new_adapter_generation"]
            and isinstance(value["plugin_selection_sha256"], str)
            and re.fullmatch(r"[0-9a-f]{64}", value["plugin_selection_sha256"]) is not None
            and member_map(value["old_members"]) and member_map(value["new_members"])
            and value["old_members"]["plugin.yaml"] == value["new_members"]["plugin.yaml"]
            and value["old_members"]["__init__.py"] != value["new_members"]["__init__.py"])


def _snapshot(runtime: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    """Ask CoreRuntime's real protected readers to validate active state."""
    record, raw_journal, files = runtime._read_active_adapter_runtime()
    bindings = runtime._snapshot_adapter_update_bindings(
        core_source_generation=record["core_source_generation"])
    _overlay_record, overlay_contents, _overlay_raw = runtime._read_adapter_overlay_snapshot()
    from hermes_installer.remote.native_plugin_bootstrap import verify_native_resources_plugin_selection
    selection = verify_native_resources_plugin_selection()
    selection_sha = getattr(selection, "selection_sha256", None)
    if not isinstance(selection_sha, str) or re.fullmatch(r"[0-9a-f]{64}", selection_sha) is None:
        raise RuntimeError("selected native plugin receipt is unavailable")
    plugin_snapshot = runtime._read_installed_native_resources_plugin_members()
    plugin_members = getattr(plugin_snapshot, "members", None)
    plugin_signatures = getattr(plugin_snapshot, "signatures", None)
    plugin_names = {"plugin.yaml", "__init__.py"}
    if (type(plugin_members) not in {dict, MappingProxyType}
            or set(plugin_members) != plugin_names
            or type(plugin_signatures) not in {dict, MappingProxyType}
            or set(plugin_signatures) != plugin_names):
        raise RuntimeError("fixed native plugin member snapshot is not closed")
    plugin_members = dict(plugin_members)
    plugin_signatures = dict(plugin_signatures)
    for name, data in plugin_members.items():
        signature = plugin_signatures[name]
        if (type(data) is not bytes
                or type(signature) is not tuple or len(signature) != 9
                or any(type(item) is not int for item in signature)
                or any(item < 0 for item in signature)
                or signature[2] != 0o444 or signature[3] != 0 or signature[4] != 0
                or signature[5] != 1 or signature[6] != len(data)
                or not 1 <= len(data) <= 64 * 1024):
            raise RuntimeError("fixed native plugin member custody is invalid")
    plugin_member_sha = {name: _digest(plugin_members[name]) for name in sorted(plugin_names)}
    cohort, _cohort_raw = runtime._read_adapter_update_cohort(allow_absent=True)
    plugin_transition = cohort.get("native_plugin_transition") if cohort is not None else None
    if plugin_transition is not None:
        if (not _native_plugin_transition_valid(plugin_transition)
                or plugin_transition.get("purpose") != "fixed-native-resources-plugin"
                or plugin_transition.get("new_adapter_generation") != record.get("adapter_generation")
                or plugin_transition.get("plugin_selection_sha256") != selection_sha
                or plugin_transition.get("new_members") != plugin_member_sha):
            raise RuntimeError("fixed native plugin transition is not bound to installed members")
    primary = _primary_prompt_state(runtime)
    public = {
        "journal_sha256": _digest(raw_journal),
        "unit_sha256": _digest(files[runtime.UNIT]),
        "launcher_sha256": _digest(files[runtime.LAUNCHER]),
        "token_custody_verified": True,
        "token_sha256": _digest(files[runtime.TOKEN]),
        "adapter_source": record["adapter_source"],
        "adapter_generation": record["adapter_generation"],
        "core_source_generation": record["core_source_generation"],
        "plugin_selection_sha256": selection_sha,
        "native_plugin_members_sha256": plugin_member_sha,
        "native_plugin_transition": plugin_transition,
        "resources_record_sha256": bindings["resources_record_sha256"],
        "overlay_record_sha256": bindings["overlay_record_sha256"],
        "overlay_content_count": len(overlay_contents),
        "overlay_contents_sha256": _digest(json.dumps(
            [(key, _digest(value)) for key, value in sorted(overlay_contents.items())],
            ensure_ascii=True, separators=(",", ":")).encode("ascii")),
        "primary_record_sha256": bindings["primary_record_sha256"],
        "obsidian_registration_state": bindings["obsidian_registration_state"],
        "obsidian_registration_sha256": bindings["obsidian_registration_sha256"],
        "obsidian_vault_tree_sha256": bindings["obsidian_vault_tree_sha256"],
        "adapter_update_state": record.get("adapter_update_state"),
        "adapter_update_previous_source": record.get("adapter_update_previous_source"),
        "adapter_update_backup_source_generation": (
            record.get("adapter_update_backup", {}).get("source_generation")
            if isinstance(record.get("adapter_update_backup"), dict) else None
        ),
        "primary_prompt_soul_sha256": primary["soul_sha256"],
        "primary_prompt_state": primary["state"],
        "primary_owner_prefix_sha256": primary["owner_prefix_sha256"],
        "primary_owner_prefix_length": primary["owner_prefix_length"],
        "primary_immutable_backup_sha256": primary["immutable_backup_sha256"],
    }
    retained = {
        "journal": raw_journal,
        "unit": files[runtime.UNIT],
        "launcher": files[runtime.LAUNCHER],
        "token_sha256": _digest(files[runtime.TOKEN]),
        "resources_record": bindings.get("resources_record"),
        "overlay_record": bindings.get("overlay_record"),
        "primary_record": bindings.get("primary_record"),
        "obsidian_registration": bindings.get("obsidian_registration"),
        "prior_cohort": bindings.get("prior_cohort"),
        "adapter_generation": record["adapter_generation"],
        "plugin_selection_sha256": selection_sha,
        "native_plugin_members_sha256": plugin_member_sha,
        "native_plugin_members": plugin_members,
        "native_plugin_signatures": plugin_signatures,
        "native_plugin_transition": plugin_transition,
        "adapter_update_backup": record.get("adapter_update_backup"),
        "primary": primary,
    }
    return public, retained


def _primary_prompt_state(runtime: Any) -> dict[str, Any]:
    """Validate adopted SOUL and immutable owner backup; retain bytes privately."""
    from hermes_installer import primary_prompt_manager as manager
    from hermes_installer.registry.primary_prompt import render_managed_block, split_managed_block

    soul, signature = manager._read_soul(runtime)
    record = manager._read_record(runtime)
    if record is None:
        return {"soul_sha256": _digest(soul), "state": "unmanaged",
                "owner_prefix_sha256": _digest(soul), "owner_prefix_length": len(soul),
                "immutable_backup_sha256": None, "owner_prefix": soul,
                "backup": None, "soul": soul, "record": None, "signature": signature,
                "separator": b"", "managed_block": b""}
    if record.get("state") != "adopted":
        raise RuntimeError("primary prompt is not in its stable adopted state")
    source_generation, _discovery, artifact_sha, manifest, files, _prompt = manager._fixed_bundle(runtime)
    source = manifest.get("source") if isinstance(manifest, dict) else None
    if (source_generation != runtime._core_source_generation()
            or record.get("core_source_generation") != source_generation
            or record.get("artifact_sha256") != artifact_sha
            or not isinstance(source, dict)
            or record.get("resources_revision") != source.get("revision")
            or record.get("resources_tree") != source.get("git_tree")):
        raise RuntimeError("adopted primary prompt source/artifact binding is stale")
    prefix, separator, block = split_managed_block(
        soul, owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]))
    backup = manager._backup_read(runtime, record)
    source_prompt = files.get("registry/profiles/hermes/SOUL.md")
    if (_digest(prefix) != record["owner_prefix_sha256"]
            or _digest(backup) != record["owner_backup_name"]
            or _digest(backup) != record["prior_soul_sha256"]
            or _digest(soul) != record["result_soul_sha256"]
            or signature != record["result_soul_signature"]
            or _digest(block) != record["managed_block_sha256"]
            or not isinstance(source_prompt, bytes)
            or _digest(source_prompt) != record.get("source_prompt_sha256")
            or block != render_managed_block(source_prompt)):
        raise RuntimeError("adopted primary prompt or immutable owner backup differs")
    return {"soul_sha256": _digest(soul), "state": "adopted",
            "owner_prefix_sha256": _digest(prefix), "owner_prefix_length": len(prefix),
            "immutable_backup_sha256": _digest(backup), "owner_prefix": prefix,
            "backup": backup, "soul": soul, "record": record, "signature": signature,
            "separator": separator, "managed_block": block}


def _backup_matches_before(runtime: Any, before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Compare the protected transaction backup to exact retained old bytes."""
    try:
        current = json.loads(after["journal"])
        reference = current.get("adapter_update_backup")
        prior, contents = runtime._read_adapter_update_backup(reference)
        saved_journal = json.loads(contents["journal.json"])
        selection = json.loads(contents["plugin-selection.json"])
    except Exception:
        return False
    transition = after.get("native_plugin_transition")
    expected_members = set(_ADAPTER_BACKUP_BASE_MEMBERS)
    if transition is not None:
        if (not _native_plugin_transition_valid(transition)
                or transition["old_adapter_generation"] != before.get("adapter_generation")
                or transition["new_adapter_generation"] != after.get("adapter_generation")
                or transition["plugin_selection_sha256"] != before.get("plugin_selection_sha256")
                or transition["plugin_selection_sha256"] != after.get("plugin_selection_sha256")
                or transition["old_members"] != before.get("native_plugin_members_sha256")
                or transition["new_members"] != after.get("native_plugin_members_sha256")):
            return False
        expected_members.update(_NATIVE_PLUGIN_BACKUP_NAMES.values())
    elif (before.get("native_plugin_members_sha256")
          != after.get("native_plugin_members_sha256")):
        return False
    files = reference.get("files") if type(reference) is dict else None
    if (type(files) is not dict or set(files) != expected_members
            or set(contents) != expected_members
            or any(not isinstance(files[name], str)
                   or re.fullmatch(r"[0-9a-f]{64}", files[name]) is None
                   or not isinstance(contents[name], bytes)
                   or hashlib.sha256(contents[name]).hexdigest() != files[name]
                   for name in expected_members)):
        return False
    exact = (
        ("journal.json", "journal"), ("unit", "unit"), ("launcher", "launcher"),
        ("resources-record.json", "resources_record"),
        ("overlay-record.json", "overlay_record"),
        ("primary-record.json", "primary_record"),
        ("obsidian-registration.json", "obsidian_registration"),
        ("cohort.json", "prior_cohort"),
    )
    if not all(type(before.get(field)) is bytes and contents.get(name) == before[field]
               for name, field in exact):
        return False
    if transition is not None:
        if any(contents.get(_NATIVE_PLUGIN_BACKUP_NAMES[name])
               != before.get("native_plugin_members", {}).get(name)
               for name in _NATIVE_PLUGIN_MEMBER_NAMES):
            return False
    if (saved_journal != json.loads(before["journal"])
            or prior.get("adapter_generation") != saved_journal.get("adapter_generation")
            or selection != {"schema": 1,
                             "selection_sha256": before["plugin_selection_sha256"]}
            or before["token_sha256"] != after["token_sha256"]):
        return False
    return True


def _primary_prompt_matches_before(before: dict[str, Any], after: dict[str, Any]) -> bool:
    """Require a valid adopted result and preserve owner-authored bytes exactly."""
    old = before["primary"]
    new = after["primary"]
    if new["state"] != "adopted":
        return False
    if old["state"] == "adopted":
        return (new["soul"] == old["soul"]
                and new["owner_prefix"] == old["owner_prefix"]
                and new["backup"] == old["backup"]
                and new["record"] == old["record"]
                and new["signature"] == old["signature"])
    record = new["record"]
    return bool(record and record.get("state") == "adopted"
                and new["owner_prefix"] == old["soul"]
                and new["backup"] == old["soul"]
                and new["soul"] == (old["soul"] + new["separator"] + new["managed_block"])
                and record.get("owner_prefix_length") == len(old["soul"]))


def _success_checks(before: dict[str, Any], after: dict[str, Any], candidate_src: str,
                    *, cohort_phase: str, listener_current: bool) -> dict[str, bool]:
    """Check only outcomes established by the protected runtime's live readbacks."""
    transition = after.get("native_plugin_transition")
    if transition is None:
        plugin_transition_proven = (
            before.get("native_plugin_members_sha256")
            == after.get("native_plugin_members_sha256")
        )
    else:
        plugin_transition_proven = (
            _native_plugin_transition_valid(transition)
            and transition["old_adapter_generation"] == before.get("adapter_generation")
            and transition["new_adapter_generation"] == after.get("adapter_generation")
            and transition["plugin_selection_sha256"] == before.get("plugin_selection_sha256")
            and transition["plugin_selection_sha256"] == after.get("plugin_selection_sha256")
            and transition["old_members"] == before.get("native_plugin_members_sha256")
            and transition["new_members"] == after.get("native_plugin_members_sha256")
        )
    return {
        "candidate_adapter_is_active": after.get("adapter_source") == candidate_src,
        "adapter_generation_changed": (
            isinstance(before.get("adapter_generation"), str)
            and after.get("adapter_generation") != before.get("adapter_generation")
        ),
        "prior_source_bound": (
            after.get("adapter_update_previous_source") == before.get("adapter_source")
        ),
        "Core_generation_preserved": (
            after.get("core_source_generation") == before.get("core_source_generation")
        ),
        "selected_plugin_preserved": (
            after.get("plugin_selection_sha256") == before.get("plugin_selection_sha256")
        ),
        "native_plugin_transition_proven": plugin_transition_proven,
        "overlay_skill_bytes_preserved": (
            after.get("overlay_content_count") == before.get("overlay_content_count")
            and after.get("overlay_contents_sha256") == before.get("overlay_contents_sha256")
        ),
        "Obsidian_registration_and_vault_preserved": (
            after.get("obsidian_registration_state") == before.get("obsidian_registration_state")
            and after.get("obsidian_registration_sha256") == before.get("obsidian_registration_sha256")
            and after.get("obsidian_vault_tree_sha256") == before.get("obsidian_vault_tree_sha256")
        ),
        "committed_update_cohort": (
            after.get("adapter_update_state") == "active" and cohort_phase == "committed"
        ),
        "protected_prior_backup_bound": (
            after.get("adapter_update_backup_source_generation") == before.get("adapter_generation")
        ),
        "candidate_listener_current": listener_current is True,
    }


def _root_setup_exception_origin(exc_type: type, tb, candidate_src: Path) -> dict | None:
    name = getattr(exc_type, "__name__", None)
    if (not isinstance(name, str)
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name) is None):
        return None
    frames = []
    visited = 0
    while tb is not None and visited < 128 and len(frames) < 12:
        visited += 1
        frame = tb.tb_frame
        try:
            filename = os.path.abspath(frame.f_code.co_filename)
            relative = os.path.relpath(filename, str(candidate_src))
            relative_path = Path(relative)
            function = frame.f_code.co_name
            line = tb.tb_lineno
            if (relative == "." or os.path.isabs(relative)
                    or any(part in {"", ".", ".."} for part in relative_path.parts)
                    or re.fullmatch(r"[A-Za-z0-9_./-]{1,512}", relative) is None
                    or not isinstance(function, str)
                    or re.fullmatch(r"[A-Za-z0-9_<>.$-]{1,256}", function) is None
                    or type(line) is not int or line < 1):
                tb = tb.tb_next
                continue
            frames.append({"source_relative_path": relative_path.as_posix(),
                           "function": function, "line": line})
        except (OSError, ValueError, TypeError):
            pass
        tb = tb.tb_next
    if not frames:
        return None
    return {"exception_type": name, "frames": frames}


def _run_fixed_root_adapter_update(root_setup, candidate_src: Path) -> tuple[int, dict | None]:
    if sys.gettrace() is not None:
        raise RuntimeError("qualification runner requires an untraced root CLI context")
    main = root_setup.main
    main_code = getattr(main, "__code__", None)
    if main_code is None:
        raise RuntimeError("fixed root CLI entry point has no verified code object")
    captured: dict[str, dict | None] = {"origin": None}

    def trace(frame, event, arg):
        if event == "exception" and frame.f_code is main_code:
            try:
                if type(arg) is not tuple or len(arg) != 3:
                    captured["origin"] = None
                    return trace
                exc_type, tb = arg[0], arg[2]
                captured["origin"] = _root_setup_exception_origin(
                    exc_type, tb, candidate_src)
            except (TypeError, ValueError):
                captured["origin"] = None
        return trace

    sys.settrace(trace)
    try:
        try:
            result = main(["core-service", "adapter-update"])
            cli_exit = result if type(result) is int and 0 <= result <= 255 else 1
        except Exception:
            # The trace retains only type and source locations; never inspect
            # or serialize the exception object or its arguments.
            cli_exit = 1
    finally:
        sys.settrace(None)
    origin = captured["origin"] if cli_exit != 0 else None
    return cli_exit, origin


def _load_candidate_runtime(source_root: Path):
    if "hermes_installer" in sys.modules:
        raise RuntimeError("unexpected installer module was loaded before source selection")
    sys.path.insert(0, str(source_root))
    from hermes_installer import core_runtime
    from hermes_installer import root_setup
    expected_root = source_root / "hermes_installer"
    if (Path(core_runtime.__file__).resolve(strict=True).parent != expected_root
            or Path(root_setup.__file__).resolve(strict=True).parent != expected_root):
        raise RuntimeError("fixed Core CLI did not load from the selected candidate")
    if core_runtime.ADAPTER_SOURCE != source_root:
        raise RuntimeError("Core adapter source does not match the selected candidate")
    return core_runtime, root_setup


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-sha", required=True,
                        help="full SHA already staged beneath the fixed /opt source root")
    parser.add_argument("--archive-sha256", required=True,
                        help="full archive digest paired by the fixed staging receipt")
    args = parser.parse_args(argv)
    if re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha) is None:
        parser.error("--candidate-sha must be 40 lowercase hexadecimal characters")
    if re.fullmatch(r"[0-9a-f]{64}", args.archive_sha256) is None:
        parser.error("--archive-sha256 must be 64 lowercase hexadecimal characters")
    if os.geteuid() != 0 or not sys.platform.startswith("linux"):
        parser.error("run this qualification on the identified Linux Pi as root")
    if sys.executable != "/usr/bin/python3" or not sys.flags.isolated:
        parser.error("run with /usr/bin/python3 -I")

    candidate_src = _candidate_source(args.candidate_sha)
    helper_bytes, custody_fds, source_fd = _load_stage_verifier(args.candidate_sha)
    try:
        provenance = _read_source_receipt(custody_fds[2])
        if (provenance.get("source_commit") != args.candidate_sha
                or provenance.get("archive_sha256") != args.archive_sha256):
            raise RuntimeError("staged source/archive receipt differs from the reviewed request")
        _verify_held_source_path(custody_fds[2], source_fd)
        stage = _execute_stage_verifier(args.candidate_sha, helper_bytes)
        stage._verify_source_provenance(args.candidate_sha, candidate_src)

        runtime, root_setup = _load_candidate_runtime(candidate_src)
        _verify_held_source_path(custody_fds[2], source_fd)
        before_public, before_private = _snapshot(runtime)
        if before_public["adapter_source"] == str(candidate_src):
            raise RuntimeError("candidate adapter is already active; no update was attempted")

        # Invoke only the existing finite root CLI verb, with no target, path,
        # command, credential, or failure-injection selector from the caller.
        cli_stdout, cli_stderr = _DigestSink(), _DigestSink()
        with contextlib.redirect_stdout(cli_stdout), contextlib.redirect_stderr(cli_stderr):
            cli_exit, cli_failure_origin = _run_fixed_root_adapter_update(
                root_setup, candidate_src)
        after_public = None
        after_private = None
        after_error = None
        cohort_phase = None
        listener_current = False
        try:
            after_public, after_private = _snapshot(runtime)
            cohort, _cohort_raw = runtime._read_adapter_update_cohort()
            cohort_phase = cohort.get("phase")
            runtime._validate_adapter_update_history(runtime._journal())
            listener_current = runtime._owned_listener_pidfd(adapter_source=candidate_src)
        except Exception as exc:
            after_error = type(exc).__name__

        checks = (_success_checks(before_public, after_public, str(candidate_src),
                                  cohort_phase=cohort_phase,
                                  listener_current=listener_current)
                  if after_public is not None else {})
        if after_public is not None and after_private is not None:
            checks["protected_prior_backup_matches_exact_bytes"] = _backup_matches_before(
                runtime, before_private, after_private)
            checks["runtime_token_digest_preserved"] = (
                before_public["token_sha256"] == after_public["token_sha256"])
            checks["primary_prompt_owner_bytes_and_adopted_record_preserved"] = (
                _primary_prompt_matches_before(before_private, after_private))
        success = cli_exit == 0 and bool(checks) and all(checks.values())
        report = {
            "schema": 1,
            "action": "core-service adapter-update",
            "candidate_commit": args.candidate_sha,
            "candidate_archive_sha256": args.archive_sha256,
            "source_receipt_is_operator_paired_not_signature": True,
            "ancestor_and_verifier_custody_checked_before_execution": True,
            "cli_exit_code": cli_exit,
            "cli_failure_origin": cli_failure_origin,
            "cli_output": {
                "stdout_bytes": cli_stdout.byte_count, "stdout_sha256": cli_stdout.sha256,
                "stderr_bytes": cli_stderr.byte_count, "stderr_sha256": cli_stderr.sha256,
            },
            "before": before_public,
            "after": after_public,
            "after_readback_error_type": after_error,
            "cohort_phase": cohort_phase,
            "checks": checks,
            "outcome": "verified_adapter_update" if success else "pending_or_failed",
            "rollback_qualification": "not_run",
            "interruption_recovery_qualification": "not_run",
            "acceptance": "not_claimed",
        }
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0 if success else 4
    finally:
        for fd in reversed(custody_fds):
            try:
                os.close(fd)
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
