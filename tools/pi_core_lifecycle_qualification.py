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
from typing import Any


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
        "plugin_selection_sha256": selection_sha,
        "primary": primary,
    }
    return public, retained


def _primary_prompt_state(runtime: Any) -> dict[str, Any]:
    """Validate adopted SOUL and immutable owner backup; retain bytes privately."""
    from hermes_installer import primary_prompt_manager as manager
    from hermes_installer.registry.primary_prompt import split_managed_block

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
    prefix, separator, block = split_managed_block(
        soul, owner_prefix_length=record["owner_prefix_length"],
        separator=bytes.fromhex(record["owner_separator_hex"]))
    backup = manager._backup_read(runtime, record)
    if (_digest(prefix) != record["owner_prefix_sha256"] or prefix != backup
            or _digest(soul) != record["result_soul_sha256"]
            or _digest(block) != record["managed_block_sha256"]):
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
    if (saved_journal != json.loads(before["journal"])
            or prior.get("adapter_generation") != saved_journal.get("adapter_generation")
            or selection != {"schema": 1,
                             "selection_sha256": before["plugin_selection_sha256"]}
            or before["token_sha256"] != after["token_sha256"]):
        return False
    old_primary = before["primary"]
    new_primary = after["primary"]
    if old_primary["state"] == "adopted":
        return (new_primary["state"] == "adopted"
                and new_primary["soul"] == old_primary["soul"]
                and new_primary["owner_prefix"] == old_primary["owner_prefix"]
                and new_primary["backup"] == old_primary["backup"])
    if new_primary["state"] == "unmanaged":
        return new_primary["soul"] == old_primary["soul"]
    record = new_primary["record"]
    return bool(record and record.get("state") == "adopted"
                and new_primary["owner_prefix"] == old_primary["soul"]
                and new_primary["backup"] == old_primary["soul"]
                and new_primary["soul"] == (old_primary["soul"]
                     + new_primary["separator"] + new_primary["managed_block"])
                and record.get("owner_prefix_length") == len(old_primary["soul"]))


def _success_checks(before: dict[str, Any], after: dict[str, Any], candidate_src: str,
                    *, cohort_phase: str, listener_current: bool) -> dict[str, bool]:
    """Check only outcomes established by the protected runtime's live readbacks."""
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
            cli_exit = root_setup.main(["core-service", "adapter-update"])
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
            checks["primary_prompt_owner_bytes_preserved"] = (
                before_public["primary_owner_prefix_sha256"]
                == after_public["primary_owner_prefix_sha256"]
                and before_public["primary_owner_prefix_length"]
                == after_public["primary_owner_prefix_length"])
        success = cli_exit == 0 and bool(checks) and all(checks.values())
        report = {
            "schema": 1,
            "action": "core-service adapter-update",
            "candidate_commit": args.candidate_sha,
            "candidate_archive_sha256": args.archive_sha256,
            "source_receipt_is_operator_paired_not_signature": True,
            "ancestor_and_verifier_custody_checked_before_execution": True,
            "cli_exit_code": cli_exit,
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
