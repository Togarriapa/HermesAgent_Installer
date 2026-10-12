#!/usr/bin/env python3
"""Run one fixed root Core adapter update and emit digest-only before/after evidence.

This is a Pi-only qualification command. It consumes a source generation already
staged by ``pi_native_core_stage.py``; it does not download, install, select, or
rollback arbitrary paths. The only mutation is the fixed Core adapter update
through the candidate's normal ``core-service adapter-update`` CLI dispatch.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
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


def _load_stage_verifier(source_root: Path):
    helper_path = source_root.parent / "tools" / "pi_native_core_adopt.py"
    info = helper_path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) & 0o022 or info.st_nlink != 1):
        raise RuntimeError("fixed staged provenance verifier custody differs")
    spec = importlib.util.spec_from_file_location("_pi_native_core_adopt_for_qualification",
                                                  helper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("fixed staged provenance verifier is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _read_source_receipt(source_root: Path) -> dict[str, Any]:
    fd = os.open(source_root.parent / ".source-provenance.json",
                 os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
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
        if len(raw) != info.st_size or len(raw) > 1024:
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


def _snapshot(runtime: Any) -> dict[str, Any]:
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
    return {
        "journal_sha256": _digest(raw_journal),
        "unit_sha256": _digest(files[runtime.UNIT]),
        "launcher_sha256": _digest(files[runtime.LAUNCHER]),
        "token_custody_verified": True,
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
    }


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
    candidate_info = candidate_src.lstat()
    if (not stat.S_ISDIR(candidate_info.st_mode) or candidate_info.st_uid != 0
            or candidate_info.st_gid != 0 or stat.S_IMODE(candidate_info.st_mode) & 0o022):
        raise RuntimeError("fixed staged source custody differs")
    stage = _load_stage_verifier(candidate_src)
    stage._verify_source_provenance(args.candidate_sha, candidate_src)
    provenance = _read_source_receipt(candidate_src)
    if provenance.get("archive_sha256") != args.archive_sha256:
        raise RuntimeError("staged archive digest differs from the reviewed request")

    runtime, root_setup = _load_candidate_runtime(candidate_src)
    before = _snapshot(runtime)
    if before["adapter_source"] == str(candidate_src):
        raise RuntimeError("candidate adapter is already active; no update was attempted")

    # Invoke only the existing finite root CLI verb, with no target, path,
    # command, credential, or failure-injection selector from the caller.
    cli_exit = root_setup.main(["core-service", "adapter-update"])
    after = None
    after_error = None
    cohort_phase = None
    listener_current = False
    try:
        after = _snapshot(runtime)
        cohort, _cohort_raw = runtime._read_adapter_update_cohort()
        cohort_phase = cohort.get("phase")
        runtime._validate_adapter_update_history(runtime._journal())
        listener_current = runtime._owned_listener_pidfd(adapter_source=candidate_src)
    except Exception as exc:
        after_error = type(exc).__name__

    checks = (_success_checks(before, after, str(candidate_src),
                              cohort_phase=cohort_phase,
                              listener_current=listener_current)
              if after is not None else {})
    success = cli_exit == 0 and bool(checks) and all(checks.values())
    report = {
        "schema": 1,
        "action": "core-service adapter-update",
        "candidate_commit": args.candidate_sha,
        "candidate_archive_sha256": args.archive_sha256,
        "source_receipt_is_operator_paired_not_signature": True,
        "cli_exit_code": cli_exit,
        "before": before,
        "after": after,
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


if __name__ == "__main__":
    raise SystemExit(main())
