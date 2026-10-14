"""Pure result-classification contracts for the Pi-only Core adapter runner.

These fixtures verify the runner's evidence gate only; they do not represent a
live source update, protected backup, native process, or Pi acceptance result.
"""
from __future__ import annotations

import importlib.util
import builtins
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest


TOOL = Path(__file__).resolve().parents[2] / "tools" / "pi_core_lifecycle_qualification.py"
SPEC = importlib.util.spec_from_file_location("pi_core_lifecycle_qualification", TOOL)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)


def _snapshots():
    old_members = {"plugin.yaml": "8" * 64, "__init__.py": "1" * 64}
    new_members = {"plugin.yaml": "8" * 64, "__init__.py": "2" * 64}
    transition = {
        "schema": 1, "purpose": "fixed-native-resources-plugin",
        "old_adapter_generation": "a" * 64, "new_adapter_generation": "9" * 64,
        "plugin_selection_sha256": "c" * 64,
        "old_members": old_members, "new_members": new_members,
    }
    before = {
        "adapter_source": "/opt/hermes-installer-core-aaaaaaaaa/src",
        "adapter_generation": "a" * 64,
        "core_source_generation": "b" * 64,
        "plugin_selection_sha256": "c" * 64,
        "native_plugin_members_sha256": old_members,
        "native_plugin_transition": None,
        "overlay_content_count": 2,
        "overlay_contents_sha256": "d" * 64,
        "obsidian_registration_state": "registered",
        "obsidian_registration_sha256": "e" * 64,
        "obsidian_vault_tree_sha256": "f" * 64,
    }
    after = {
        **before,
        "adapter_source": "/opt/hermes-installer-core-bbbbbbbbb/src",
        "adapter_generation": "9" * 64,
        "native_plugin_members_sha256": new_members,
        "native_plugin_transition": transition,
        "adapter_update_state": "active",
        "adapter_update_previous_source": before["adapter_source"],
        "adapter_update_backup_source_generation": before["adapter_generation"],
    }
    return before, after


def test_candidate_identity_requires_full_lowercase_commit_sha():
    assert qualification._candidate_source("a" * 40) == Path(
        "/opt/hermes-installer-core-aaaaaaaaa/src")
    for invalid in ("a" * 39, "A" * 40, "../" + "a" * 37, "a" * 40 + "b"):
        with pytest.raises(ValueError, match="full lowercase SHA"):
            qualification._candidate_source(invalid)


def test_fixed_phase_checkpoints_flush_to_held_stderr_with_closed_order(monkeypatch):
    class HeldSink:
        def __init__(self):
            self.lines = []
            self.flushes = 0

        def write(self, value):
            self.lines.append(value)
            return len(value)

        def flush(self):
            self.flushes += 1

    held = HeldSink()
    redirected = io.StringIO()
    monkeypatch.setattr(qualification, "_QUALIFICATION_CHECKPOINT_STREAM", held)
    state = {"last_elapsed_ms": -1}
    started = qualification.time.monotonic()
    with qualification.contextlib.redirect_stderr(redirected):
        for sequence, phase in enumerate(qualification._QUALIFICATION_CHECKPOINT_PHASES, 1):
            qualification._emit_qualification_checkpoint(
                "b" * 40, "c" * 64, sequence, phase, started, state)

    assert redirected.getvalue() == ""
    assert held.flushes == len(qualification._QUALIFICATION_CHECKPOINT_PHASES)
    assert len(held.lines) == len(qualification._QUALIFICATION_CHECKPOINT_PHASES)
    records = []
    for line in held.lines:
        assert line.startswith(qualification._QUALIFICATION_CHECKPOINT_PREFIX)
        encoded = line[len(qualification._QUALIFICATION_CHECKPOINT_PREFIX):].rstrip("\n")
        record = json.loads(encoded)
        assert encoded == json.dumps(record, sort_keys=True, separators=(",", ":"))
        assert set(record) == {
            "schema", "candidate_commit", "candidate_archive_sha256",
            "sequence", "phase", "elapsed_ms",
        }
        records.append(record)
    assert [record["phase"] for record in records] == list(
        qualification._QUALIFICATION_CHECKPOINT_PHASES)
    assert [record["sequence"] for record in records] == list(
        range(1, len(records) + 1))
    assert all(type(record["elapsed_ms"]) is int
               and 0 <= record["elapsed_ms"] <= 300_000 for record in records)
    assert all(a["elapsed_ms"] <= b["elapsed_ms"]
               for a, b in zip(records, records[1:]))


def test_main_flushes_phase_checkpoint_before_each_fixed_operation(monkeypatch, capsys):
    class HeldSink:
        def __init__(self):
            self.lines = []
            self.flushed_lines = []

        def write(self, value):
            self.lines.append(value)
            return len(value)

        def flush(self):
            self.flushed_lines.append(self.lines[-1])

        def latest_phase(self):
            line = self.flushed_lines[-1]
            record = json.loads(line[len(qualification._QUALIFICATION_CHECKPOINT_PREFIX):])
            return record["phase"]

    held = HeldSink()
    monkeypatch.setattr(qualification, "_QUALIFICATION_CHECKPOINT_STREAM", held)
    monkeypatch.setattr(qualification.os, "geteuid", lambda: 0)
    monkeypatch.setattr(qualification.sys, "platform", "linux")
    monkeypatch.setattr(qualification.sys, "executable", "/usr/bin/python3")
    monkeypatch.setattr(qualification.sys, "flags", SimpleNamespace(isolated=True))
    source = Path("/opt/hermes-installer-core-" + "b" * 9 + "/src")

    class Stage:
        @staticmethod
        def _verify_source_provenance(_candidate, _source):
            assert held.latest_phase() == "stage_verifier"

    class Runtime:
        @staticmethod
        def _read_adapter_update_cohort():
            return {"phase": "committed"}, b""

        @staticmethod
        def _validate_adapter_update_history(_journal):
            assert held.latest_phase() == "history_validation"

        @staticmethod
        def _journal():
            return object()

        @staticmethod
        def _owned_listener_pidfd(*, adapter_source):
            assert adapter_source == source
            assert held.latest_phase() == "listener_verification"
            return True

    before = {"adapter_source": "/old/source", "token_sha256": "a" * 64}
    after = {"adapter_source": str(source), "token_sha256": "a" * 64}
    snapshots = iter(((before, {}), (after, {})))
    monkeypatch.setattr(qualification, "_candidate_source", lambda _sha: source)
    monkeypatch.setattr(qualification, "_load_stage_verifier", lambda _sha: (
        b"helper", [os.dup(0), os.dup(1), os.dup(2)], -1))
    monkeypatch.setattr(qualification, "_read_source_receipt", lambda _fd: {
        "source_commit": "b" * 40, "archive_sha256": "c" * 64})
    monkeypatch.setattr(qualification, "_verify_held_source_path", lambda *_args: None)

    def execute_stage(*_args):
        assert_phase(held, "stage_verifier")
        return Stage()

    def load_runtime(_src):
        assert_phase(held, "runtime_load")
        return Runtime(), object()

    def success_checks(*_args, **_kwargs):
        assert_phase(held, "success_checks")
        return {"candidate_adapter_is_active": True}

    monkeypatch.setattr(qualification, "_execute_stage_verifier", execute_stage)
    monkeypatch.setattr(qualification, "_load_candidate_runtime", load_runtime)
    monkeypatch.setattr(qualification, "_run_fixed_root_adapter_update",
                        lambda *_args: fixed_update_result(held))
    monkeypatch.setattr(qualification, "_success_checks", success_checks)
    monkeypatch.setattr(qualification, "_backup_matches_before", lambda *_args: True)
    monkeypatch.setattr(qualification, "_primary_prompt_matches_before", lambda *_args: True)
    original_print = builtins.print

    def checked_print(*args, **kwargs):
        if len(args) == 1 and type(args[0]) is str and args[0].startswith("{"):
            assert_phase(held, "report_emission")
        return original_print(*args, **kwargs)

    monkeypatch.setattr(builtins, "print", checked_print)

    snapshot_calls = {"count": 0}

    def snapshot(_runtime):
        snapshot_calls["count"] += 1
        expected = "before_snapshot" if snapshot_calls["count"] == 1 else "after_snapshot"
        assert held.latest_phase() == expected
        return next(snapshots)

    monkeypatch.setattr(qualification, "_snapshot", snapshot)
    assert qualification.main([
        "--candidate-sha", "b" * 40, "--archive-sha256", "c" * 64,
    ]) == 0
    assert held.latest_phase() == "report_emission"
    records = [json.loads(line[len(qualification._QUALIFICATION_CHECKPOINT_PREFIX):])
               for line in held.lines]
    assert len(held.flushed_lines) == 9
    assert [record["phase"] for record in records] == list(
        qualification._QUALIFICATION_CHECKPOINT_PHASES)
    assert [record["sequence"] for record in records] == list(range(1, 10))
    captured = capsys.readouterr()
    assert captured.err == ""
    assert json.loads(captured.out)["outcome"] == "verified_adapter_update"


def assert_phase(sink, expected):
    assert sink.latest_phase() == expected


def fixed_update_result(sink):
    assert_phase(sink, "adapter_update")
    return 0, None


def test_only_current_candidate_commit_and_preserved_bindings_qualify():
    before, after = _snapshots()
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks and all(checks.values())

    changed = dict(after, plugin_selection_sha256="0" * 64)
    checks = qualification._success_checks(
        before, changed, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["candidate_adapter_is_active"] is True
    assert checks["selected_plugin_preserved"] is False
    assert checks["native_plugin_transition_proven"] is False


def test_plugin_change_requires_exact_cohort_transition_and_unchanged_selection():
    before, after = _snapshots()
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["native_plugin_transition_proven"] is True

    changed = dict(after)
    changed["native_plugin_members_sha256"] = {
        **after["native_plugin_members_sha256"], "__init__.py": "f" * 64}
    checks = qualification._success_checks(
        before, changed, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["native_plugin_transition_proven"] is False

    no_transition = dict(after, native_plugin_transition=None,
                         native_plugin_members_sha256=before["native_plugin_members_sha256"])
    checks = qualification._success_checks(
        before, no_transition, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["native_plugin_transition_proven"] is True

    changed_without_row = dict(after, native_plugin_transition=None)
    checks = qualification._success_checks(
        before, changed_without_row, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)
    assert checks["native_plugin_transition_proven"] is False

    changed_manifest = dict(after)
    changed_manifest["native_plugin_transition"] = {
        **after["native_plugin_transition"],
        "new_members": {**after["native_plugin_transition"]["new_members"],
                        "plugin.yaml": "f" * 64},
    }
    assert qualification._success_checks(
        before, changed_manifest, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase="committed", listener_current=True)["native_plugin_transition_proven"] is False


@pytest.mark.parametrize("mutation,phase,listener", [
    ({"adapter_source": "/opt/hermes-installer-core-ccccccccc/src"}, "committed", True),
    ({"overlay_contents_sha256": "0" * 64}, "committed", True),
    ({"obsidian_vault_tree_sha256": "0" * 64}, "committed", True),
    ({}, "bindings-verified", True),
    ({}, "committed", False),
])
def test_partial_or_mismatched_update_readback_stays_pending(mutation, phase, listener):
    before, after = _snapshots()
    after.update(mutation)
    checks = qualification._success_checks(
        before, after, "/opt/hermes-installer-core-bbbbbbbbb/src",
        cohort_phase=phase, listener_current=listener)
    assert any(value is False for value in checks.values())


def test_fixed_cli_trace_retains_only_candidate_relative_exception_metadata():
    class RootSetup:
        @staticmethod
        def main(argv):
            assert argv == ["core-service", "adapter-update"]
            try:
                raise RuntimeError("PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE")
            except RuntimeError:
                return 4

    cli_exit, origin = qualification._run_fixed_root_adapter_update(
        RootSetup, Path(__file__).resolve().parent)
    assert cli_exit == 4
    assert origin["exception_type"] == "RuntimeError"
    assert len(origin["frames"]) == 1
    frame = origin["frames"][0]
    assert frame["source_relative_path"] == Path(__file__).name
    assert frame["function"] == "main" and frame["line"] > 0
    assert "PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert qualification.sys.gettrace() is None


def test_fixed_cli_trace_drops_caught_exception_when_cli_succeeds():
    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                raise RuntimeError("PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE")
            except RuntimeError:
                return 0

    cli_exit, origin = qualification._run_fixed_root_adapter_update(
        RootSetup, Path(__file__).resolve().parent)
    assert cli_exit == 0
    assert origin is None


def test_fixed_cli_trace_limits_local_events_to_main_but_keeps_nested_origin(monkeypatch):
    def ordinary_calls(depth):
        if depth:
            return ordinary_calls(depth - 1)
        return "completed"

    def nested_failure():
        raise LookupError("PRIVATE_NESTED_EXCEPTION_TEXT_MUST_NOT_ESCAPE")

    class RootSetup:
        @staticmethod
        def main(argv):
            assert argv == ["core-service", "adapter-update"]
            assert ordinary_calls(32) == "completed"
            nested_failure()

    main_code = RootSetup.main.__code__
    real_settrace = qualification.sys.settrace
    events = []

    def observe_settrace(callback):
        if callback is None:
            real_settrace(None)
            return

        def observe(frame, event, arg):
            local = callback(frame, event, arg)
            if event == "call":
                events.append((frame.f_code is main_code, local is not None))
            return observe if local is not None else None

        real_settrace(observe)

    monkeypatch.setattr(qualification.sys, "settrace", observe_settrace)
    cli_exit, origin = qualification._run_fixed_root_adapter_update(
        RootSetup, Path(__file__).resolve().parent)
    assert cli_exit == 1
    assert origin["exception_type"] == "LookupError"
    functions = [frame["function"] for frame in origin["frames"]]
    assert "main" in functions and "nested_failure" in functions
    assert "ordinary_calls" not in functions
    assert "PRIVATE_NESTED_EXCEPTION_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert any(is_main and local_enabled for is_main, local_enabled in events)
    assert any(not is_main and not local_enabled for is_main, local_enabled in events)
    assert not any(not is_main and local_enabled for is_main, local_enabled in events)
    assert qualification.sys.gettrace() is None


def test_fixed_cli_trace_keeps_suppressed_context_frames_without_exception_text():
    def nested_failure():
        raise LookupError("PRIVATE_SUPPRESSED_CONTEXT_TEXT_MUST_NOT_ESCAPE")

    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                nested_failure()
            except LookupError:
                raise RuntimeError("PRIVATE_OUTER_EXCEPTION_TEXT_MUST_NOT_ESCAPE") from None

    cli_exit, origin = qualification._run_fixed_root_adapter_update(
        RootSetup, Path(__file__).resolve().parent)
    assert cli_exit == 1
    assert set(origin) == {"exception_type", "frames"}
    assert origin["exception_type"] == "RuntimeError"
    assert any(frame["function"] == "nested_failure" for frame in origin["frames"])
    assert len(origin["frames"]) <= 12
    assert all(set(frame) == {"source_relative_path", "function", "line"}
               for frame in origin["frames"])
    assert "PRIVATE_SUPPRESSED_CONTEXT_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert "PRIVATE_OUTER_EXCEPTION_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert qualification.sys.gettrace() is None


def test_exception_origin_bounds_and_breaks_cause_cycles():
    def captured_error(text):
        try:
            raise RuntimeError(text)
        except RuntimeError as exc:
            return exc

    errors = [captured_error(f"PRIVATE_CHAIN_TEXT_{index}") for index in range(8)]
    for index, exc in enumerate(errors):
        exc.__cause__ = errors[(index + 1) % len(errors)]
    origin = qualification._root_setup_exception_origin(
        errors[0], Path(__file__).resolve().parent)
    assert origin is not None
    assert origin["exception_type"] == "RuntimeError"
    assert len(origin["frames"]) == 4
    assert len(origin["frames"]) <= 12
    assert "PRIVATE_CHAIN_TEXT_" not in repr(origin)


def test_exception_origin_breaks_two_object_cause_cycle():
    def captured_error(text):
        try:
            raise RuntimeError(text)
        except RuntimeError as exc:
            return exc

    first = captured_error("PRIVATE_TWO_CYCLE_FIRST")
    second = captured_error("PRIVATE_TWO_CYCLE_SECOND")
    first.__cause__ = second
    second.__cause__ = first

    origin = qualification._root_setup_exception_origin(
        first, Path(__file__).resolve().parent)
    assert origin is not None
    assert origin["exception_type"] == "RuntimeError"
    assert len(origin["frames"]) == 2
    assert "PRIVATE_TWO_CYCLE_" not in repr(origin)


def test_exception_origin_caps_aggregated_traceback_frames():
    def descend(depth):
        if depth:
            return descend(depth - 1)
        raise RuntimeError("PRIVATE_DEEP_TRACEBACK_TEXT")

    try:
        descend(20)
    except RuntimeError as exc:
        origin = qualification._root_setup_exception_origin(
            exc, Path(__file__).resolve().parent)

    assert origin is not None
    assert origin["exception_type"] == "RuntimeError"
    assert len(origin["frames"]) == 12
    assert "PRIVATE_DEEP_TRACEBACK_TEXT" not in repr(origin)


def test_fixed_cli_trace_refuses_a_preexisting_trace():
    def prior_trace(_frame, _event, _arg):
        return prior_trace

    sys.settrace(prior_trace)
    try:
        with pytest.raises(RuntimeError, match="untraced root CLI context"):
            qualification._run_fixed_root_adapter_update(object(), Path(__file__).parent)
    finally:
        sys.settrace(None)
    assert sys.gettrace() is None


def _backup_fixture():
    journal = b'{"adapter_generation":"' + b"a" * 64 + b'"}'
    raw = {
        "journal": journal,
        "adapter_generation": "a" * 64,
        "unit": b"prior-unit-bytes",
        "launcher": b"prior-launcher-bytes",
        "resources_record": b"prior-resources-binding",
        "overlay_record": b"prior-overlay-binding",
        "primary_record": b"prior-primary-record",
        "obsidian_registration": b"prior-obsidian-registration",
        "prior_cohort": b"prior-cohort",
        "plugin_selection_sha256": "c" * 64,
        "token_sha256": "d" * 64,
        "primary": {"state": "adopted", "owner_prefix": b"edited owner bytes",
                    "backup": b"original immutable owner bytes",
                    "soul": b"edited owner bytes\n<managed block>",
                    "separator": b"\n", "managed_block": b"<managed block>",
                    "signature": [1, 2, 3],
                    "record": {"state": "adopted", "result_soul_sha256": "e" * 64}},
    }
    contents = {
        "journal.json": raw["journal"], "unit": raw["unit"],
        "launcher": raw["launcher"], "resources-record.json": raw["resources_record"],
        "overlay-record.json": raw["overlay_record"],
        "primary-record.json": raw["primary_record"],
        "obsidian-registration.json": raw["obsidian_registration"],
        "cohort.json": raw["prior_cohort"],
        "plugin-selection.json": b'{"schema":1,"selection_sha256":"' + b"c" * 64 + b'"}',
    }
    backup_files = {name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
    old_plugin_members = {"plugin.yaml": b"prior plugin manifest", "__init__.py": b"prior plugin module"}
    raw["native_plugin_members"] = old_plugin_members
    raw["native_plugin_members_sha256"] = {
        name: hashlib.sha256(value).hexdigest() for name, value in old_plugin_members.items()}
    after_journal = (b'{"adapter_update_backup":{"files":' +
                     json.dumps(backup_files, sort_keys=True).encode() +
                     b',"path":"fixed","source_generation":"' + b"a" * 64 + b'"}}')
    after = {"journal": after_journal, "token_sha256": raw["token_sha256"],
             "adapter_generation": "b" * 64,
             "plugin_selection_sha256": raw["plugin_selection_sha256"],
             "native_plugin_members": old_plugin_members,
             "native_plugin_members_sha256": raw["native_plugin_members_sha256"],
             "native_plugin_transition": None,
             "primary": {"state": "adopted", "owner_prefix": b"edited owner bytes",
                         "backup": b"original immutable owner bytes",
                         "soul": b"edited owner bytes\n<managed block>",
                         "separator": b"\n", "managed_block": b"<managed block>",
                         "signature": [1, 2, 3],
                         "record": {"state": "adopted", "result_soul_sha256": "e" * 64}}}
    prior = {"adapter_generation": "a" * 64}

    class Runtime:
        @staticmethod
        def _read_adapter_update_backup(reference):
            assert reference == {"files": {
                name: hashlib.sha256(value).hexdigest() for name, value in contents.items()},
                "path": "fixed", "source_generation": "a" * 64}
            return prior, contents

    return Runtime(), raw, after, contents


def test_protected_backup_requires_exact_old_journal_unit_launcher_and_bindings():
    runtime, before, after, _contents = _backup_fixture()
    assert qualification._backup_matches_before(runtime, before, after) is True


def test_native_plugin_transition_backup_retains_old_member_bytes_and_exact_manifest(tmp_path):
    runtime, before, after, contents = _backup_fixture()
    old_members = before["native_plugin_members"]
    new_members = {"plugin.yaml": old_members["plugin.yaml"],
                   "__init__.py": b"new verified plugin module"}
    row = {
        "schema": 1, "purpose": "fixed-native-resources-plugin",
        "old_adapter_generation": "a" * 64, "new_adapter_generation": "b" * 64,
        "plugin_selection_sha256": before["plugin_selection_sha256"],
        "old_members": {name: hashlib.sha256(data).hexdigest()
                        for name, data in old_members.items()},
        "new_members": {name: hashlib.sha256(data).hexdigest()
                        for name, data in new_members.items()},
    }
    after["native_plugin_members"] = new_members
    after["native_plugin_members_sha256"] = row["new_members"]
    after["native_plugin_transition"] = row
    for name, backup_name in qualification._NATIVE_PLUGIN_BACKUP_NAMES.items():
        contents[backup_name] = old_members[name]
    files = {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}
    backup = tmp_path / "adapter-backup"
    backup.mkdir()
    for name, data in contents.items():
        (backup / name).write_bytes(data)
    after["journal"] = (json.dumps({"adapter_update_backup": {
        "files": files, "path": "fixed", "source_generation": "a" * 64}},
        sort_keys=True, separators=(",", ":"))).encode()

    class FilesystemRuntime:
        @staticmethod
        def _read_adapter_update_backup(reference):
            assert reference["path"] == "fixed"
            found = {path.name: path.read_bytes() for path in backup.iterdir()}
            assert reference["files"] == {
                name: hashlib.sha256(data).hexdigest() for name, data in found.items()}
            return {"adapter_generation": "a" * 64}, found

    assert qualification._backup_matches_before(FilesystemRuntime(), before, after) is True

    member = backup / "native-plugin-__init__.py"
    member.write_bytes(member.read_bytes() + b" changed")
    assert qualification._backup_matches_before(FilesystemRuntime(), before, after) is False

    member.write_bytes(contents["native-plugin-__init__.py"])
    (backup / "unowned-extra.py").write_bytes(b"unowned")
    assert qualification._backup_matches_before(FilesystemRuntime(), before, after) is False


def test_legacy_nine_member_backup_cannot_smuggle_plugin_transition_files():
    runtime, before, after, contents = _backup_fixture()
    contents["native-plugin-__init__.py"] = b"unbound transition member"
    reference = json.loads(after["journal"])["adapter_update_backup"]
    reference["files"] = {
        name: hashlib.sha256(value).hexdigest() for name, value in contents.items()}
    after["journal"] = (json.dumps({"adapter_update_backup": reference},
                                   sort_keys=True, separators=(",", ":"))).encode()
    assert qualification._backup_matches_before(runtime, before, after) is False


@pytest.mark.parametrize("field", [
    "journal", "unit", "launcher", "resources_record", "overlay_record",
    "primary_record", "obsidian_registration", "prior_cohort", "plugin-selection.json",
])
def test_protected_backup_byte_change_is_not_a_generation_name_match(field):
    runtime, before, after, contents = _backup_fixture()
    filename = {
        "journal": "journal.json", "unit": "unit", "launcher": "launcher",
        "plugin-selection.json": "plugin-selection.json",
        "resources_record": "resources-record.json",
        "overlay_record": "overlay-record.json", "primary_record": "primary-record.json",
        "obsidian_registration": "obsidian-registration.json", "prior_cohort": "cohort.json",
    }[field]
    contents[filename] += b" altered"
    assert qualification._backup_matches_before(runtime, before, after) is False


def test_update_proof_rejects_changed_token_and_primary_owner_prefix_or_backup():
    runtime, before, after, _contents = _backup_fixture()
    after["token_sha256"] = "e" * 64
    assert qualification._backup_matches_before(runtime, before, after) is False
    after["token_sha256"] = before["token_sha256"]
    assert qualification._primary_prompt_matches_before(before, after) is True
    after["primary"]["owner_prefix"] = b"altered owner bytes"
    assert qualification._primary_prompt_matches_before(before, after) is False
    after["primary"]["owner_prefix"] = before["primary"]["owner_prefix"]
    after["primary"]["backup"] = b"altered immutable backup"
    assert qualification._primary_prompt_matches_before(before, after) is False
    after["primary"]["backup"] = before["primary"]["backup"]
    after["primary"]["soul"] += b" altered managed block"
    assert qualification._primary_prompt_matches_before(before, after) is False


def test_approved_owner_prefix_can_differ_from_immutable_original_backup():
    runtime, before, after, _contents = _backup_fixture()
    assert before["primary"]["owner_prefix"] != before["primary"]["backup"]
    assert qualification._primary_prompt_matches_before(before, after) is True


def test_update_proof_allows_only_exact_initial_primary_append():
    runtime, before, after, _contents = _backup_fixture()
    initial = b"original owner SOUL\n"
    separator = b"\n"
    managed = b"<verified managed block>"
    before["primary"] = {"state": "unmanaged", "soul": initial}
    after["primary"] = {
        "state": "adopted", "owner_prefix": initial, "backup": initial,
        "separator": separator, "managed_block": managed,
        "soul": initial + separator + managed,
        "signature": [1, 2, 3],
        "record": {"state": "adopted", "owner_prefix_length": len(initial)},
    }
    assert qualification._primary_prompt_matches_before(before, after) is True
    after["primary"]["soul"] = initial + b"unexpected bytes"
    assert qualification._primary_prompt_matches_before(before, after) is False


def test_update_proof_cannot_pass_without_adopted_post_state():
    before, _after = _snapshots()
    before_primary = {"primary": {"state": "unmanaged", "soul": b"owner prefix"}}
    after_primary = {"primary": {"state": "unmanaged", "soul": b"owner prefix"}}
    assert qualification._primary_prompt_matches_before(before_primary, after_primary) is False


@pytest.mark.skipif(os.geteuid() != 0, reason="staged helper custody fixture requires root")
def test_held_helper_is_custody_checked_and_read_without_execution(tmp_path):
    generation = tmp_path / "generation"
    tools = generation / "tools"
    tools.mkdir(parents=True, mode=0o755)
    marker = tmp_path / "unexpected-import-effect"
    helper = tools / "pi_native_core_adopt.py"
    helper.write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    helper.chmod(0o644)
    generation.chmod(0o755)
    generation_fd = os.open(generation, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        source, held_fds = qualification._read_held_helper(generation_fd)
        try:
            assert b"unexpected-import-effect" in source
            assert not marker.exists()
        finally:
            for fd in reversed(held_fds):
                os.close(fd)
        tools.chmod(0o777)
        with pytest.raises(RuntimeError, match="ancestor custody"):
            qualification._read_held_helper(generation_fd)
        assert not marker.exists()
    finally:
        os.close(generation_fd)
