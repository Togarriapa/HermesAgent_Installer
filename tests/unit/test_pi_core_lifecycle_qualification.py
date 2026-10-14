"""Pure result-classification contracts for the Pi-only Core adapter runner.

These fixtures verify the runner's evidence gate only; they do not represent a
live source update, protected backup, native process, or Pi acceptance result.
"""
from __future__ import annotations

import importlib.util
import builtins
import asyncio
import contextlib
import fcntl
import hashlib
import io
import json
import os
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


TOOL = Path(__file__).resolve().parents[2] / "tools" / "pi_core_lifecycle_qualification.py"
SPEC = importlib.util.spec_from_file_location("pi_core_lifecycle_qualification", TOOL)
assert SPEC is not None and SPEC.loader is not None
qualification = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(qualification)

from hermes_installer.remote.core_client import CoreRpcClient
import hermes_installer.core_runtime as core_runtime


class _FakeMonitoring:
    class Events:
        EXCEPTION_HANDLED = 1
        PY_RETURN = 2

    events = Events()

    def __init__(self, *, occupied=False, fail_local_setup=False):
        self.tools = {qualification._QUALIFICATION_MONITORING_TOOL_ID:
                      ("foreign-tool" if occupied else None)}
        self.callbacks = {}
        self.global_events = {}
        self.local_events = {}
        self.fail_local_setup = fail_local_setup
        self.operations = []

    def get_tool(self, tool_id):
        return self.tools.get(tool_id)

    def use_tool_id(self, tool_id, name):
        self.operations.append(("use", tool_id, name))
        if self.tools.get(tool_id) is not None:
            raise ValueError("monitoring tool id is occupied")
        self.tools[tool_id] = name

    def register_callback(self, tool_id, event, callback):
        self.operations.append(("register", tool_id, event, callback is None))
        if self.tools.get(tool_id) is None:
            raise ValueError("monitoring tool id is not owned")
        if callback is None:
            self.callbacks.pop((tool_id, event), None)
        else:
            self.callbacks[(tool_id, event)] = callback

    def set_events(self, tool_id, events):
        self.operations.append(("global", tool_id, events))
        if self.tools.get(tool_id) is None:
            raise ValueError("monitoring tool id is not owned")
        self.global_events[tool_id] = events

    def set_local_events(self, tool_id, code, events):
        self.operations.append(("local", tool_id, code, events))
        if self.fail_local_setup:
            raise RuntimeError("partial monitoring setup refusal")
        self.local_events[(tool_id, code)] = events

    def free_tool_id(self, tool_id):
        self.operations.append(("free", tool_id))
        if self.tools.get(tool_id) == "foreign-tool":
            raise ValueError("foreign monitoring tool cannot be freed")
        self.tools[tool_id] = None
        self.global_events.pop(tool_id, None)
        self.local_events = {key: value for key, value in self.local_events.items()
                             if key[0] != tool_id}

    def handled(self, code, exc):
        tool_id = qualification._QUALIFICATION_MONITORING_TOOL_ID
        callback = self.callbacks.get((tool_id, self.events.EXCEPTION_HANDLED))
        if self.global_events.get(tool_id, 0) & self.events.EXCEPTION_HANDLED and callback:
            callback(code, 0, exc)

    def returned(self, code):
        tool_id = qualification._QUALIFICATION_MONITORING_TOOL_ID
        callback = self.callbacks.get((tool_id, self.events.PY_RETURN))
        if (self.local_events.get((tool_id, code), 0) & self.events.PY_RETURN
                and callback):
            callback(code, 0, None)


_LAST_MONITORING = None
_NO_MONITORING_OVERRIDE = object()


def _run_cli(root_setup, monitoring=_NO_MONITORING_OVERRIDE, *, candidate_src=None):
    global _LAST_MONITORING
    previous = getattr(qualification.sys, "monitoring", _NO_MONITORING_OVERRIDE)
    if monitoring is _NO_MONITORING_OVERRIDE:
        monitoring = _FakeMonitoring()
    if monitoring is None:
        qualification.sys.monitoring = None
    else:
        qualification.sys.monitoring = monitoring
    _LAST_MONITORING = monitoring
    try:
        result = qualification._run_fixed_root_adapter_update(
            root_setup, (candidate_src or Path(__file__).resolve().parent),
            "a" * 40, "b" * 64)
        return result
    finally:
        if previous is _NO_MONITORING_OVERRIDE:
            if hasattr(qualification.sys, "monitoring"):
                del qualification.sys.monitoring
        else:
            qualification.sys.monitoring = previous


def _handled_main_exception(main, exc):
    if _LAST_MONITORING is not None:
        _LAST_MONITORING.handled(main.__code__, exc)


def _main_returned(main):
    if _LAST_MONITORING is not None:
        _LAST_MONITORING.returned(main.__code__)


def _stack_code_row(label, line_count=100000):
    for function, mapped_label in qualification._QUALIFICATION_STACK_FUNCTIONS.items():
        if mapped_label == label:
            return {"label": label,
                    "source_relative_path": qualification._QUALIFICATION_STACK_FUNCTION_PATHS[function],
                    "function": function, "line_count": line_count}
    raise AssertionError("test requested an unmapped stack label")


def _stack_frame_row(label, line=1):
    code = _stack_code_row(label)
    return {"source_relative_path": code["source_relative_path"],
            "function": code["function"], "line": line}


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
    real_flags = qualification.sys.flags

    class IsolatedFlags:
        def __getattr__(self, name):
            if name == "isolated":
                return True
            return getattr(real_flags, name)

    monkeypatch.setattr(qualification.sys, "flags", IsolatedFlags())
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


def test_fixed_cli_monitoring_retains_only_candidate_relative_exception_metadata():
    class RootSetup:
        @staticmethod
        def main(argv):
            assert argv == ["core-service", "adapter-update"]
            try:
                raise RuntimeError("PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE")
            except RuntimeError as exc:
                _handled_main_exception(RootSetup.main, exc)
                _main_returned(RootSetup.main)
                return 4

    cli_exit, origin = _run_cli(RootSetup)
    assert cli_exit == 4
    assert origin["exception_type"] == "RuntimeError"
    assert len(origin["frames"]) == 1
    frame = origin["frames"][0]
    assert frame["source_relative_path"] == Path(__file__).name
    assert frame["function"] == "main" and frame["line"] > 0
    assert "PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert qualification.sys.gettrace() is None
    assert _LAST_MONITORING.tools[qualification._QUALIFICATION_MONITORING_TOOL_ID] is None
    assert _LAST_MONITORING.callbacks == {}
    tool_id = qualification._QUALIFICATION_MONITORING_TOOL_ID
    assert ("global", tool_id, _LAST_MONITORING.events.EXCEPTION_HANDLED) \
        in _LAST_MONITORING.operations
    assert ("global", tool_id, 0) in _LAST_MONITORING.operations
    assert ("local", tool_id, RootSetup.main.__code__, _LAST_MONITORING.events.PY_RETURN) \
        in _LAST_MONITORING.operations
    assert ("local", tool_id, RootSetup.main.__code__, 0) \
        in _LAST_MONITORING.operations
    assert not any(op[0] == "global" and op[2] & _LAST_MONITORING.events.PY_RETURN
                   for op in _LAST_MONITORING.operations)
    assert _LAST_MONITORING.operations[-1] == ("free", tool_id)


def test_fixed_cli_monitoring_drops_caught_exception_when_cli_succeeds():
    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                raise RuntimeError("PRIVATE_EXCEPTION_TEXT_MUST_NOT_ESCAPE")
            except RuntimeError as exc:
                _handled_main_exception(RootSetup.main, exc)
                _main_returned(RootSetup.main)
                return 0

    cli_exit, origin = _run_cli(RootSetup)
    assert cli_exit == 0
    assert origin is None


def test_fixed_cli_monitoring_is_main_only_and_keeps_nested_origin():
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
            try:
                nested_failure()
            except LookupError as exc:
                # An event for a non-main code object must not capture it.
                _LAST_MONITORING.handled(nested_failure.__code__, exc)
                _handled_main_exception(RootSetup.main, exc)
                _main_returned(RootSetup.main)
                return 1

    cli_exit, origin = _run_cli(RootSetup)
    assert cli_exit == 1
    assert origin["exception_type"] == "LookupError"
    functions = [frame["function"] for frame in origin["frames"]]
    assert "main" in functions and "nested_failure" in functions
    assert "ordinary_calls" not in functions
    assert "PRIVATE_NESTED_EXCEPTION_TEXT_MUST_NOT_ESCAPE" not in repr(origin)
    assert _LAST_MONITORING.global_events == {}
    assert _LAST_MONITORING.local_events == {}
    assert _LAST_MONITORING.tools[qualification._QUALIFICATION_MONITORING_TOOL_ID] is None
    assert qualification.sys.gettrace() is None


def test_fixed_cli_monitoring_keeps_suppressed_context_frames_without_exception_text():
    def nested_failure():
        raise LookupError("PRIVATE_SUPPRESSED_CONTEXT_TEXT_MUST_NOT_ESCAPE")

    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                nested_failure()
            except LookupError as exc:
                _handled_main_exception(RootSetup.main, exc)
                raise RuntimeError("PRIVATE_OUTER_EXCEPTION_TEXT_MUST_NOT_ESCAPE") from None

    cli_exit, origin = _run_cli(RootSetup)
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


@pytest.mark.parametrize("mode", ["missing", "occupied", "partial"])
def test_fixed_cli_monitoring_refusal_keeps_cli_and_unknown_origin(mode):
    if mode == "missing":
        monitoring = None
    elif mode == "occupied":
        monitoring = _FakeMonitoring(occupied=True)
    else:
        monitoring = _FakeMonitoring(fail_local_setup=True)

    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                raise OSError("PRIVATE_MONITORING_REFUSAL_TEXT")
            except OSError as exc:
                _handled_main_exception(RootSetup.main, exc)
                _main_returned(RootSetup.main)
                return 9

    cli_exit, origin = _run_cli(RootSetup, monitoring)
    assert cli_exit == 9
    assert origin is None
    assert qualification.sys.gettrace() is None
    if mode == "occupied":
        assert monitoring.tools[qualification._QUALIFICATION_MONITORING_TOOL_ID] == "foreign-tool"
        assert monitoring.callbacks == {}
        assert monitoring.global_events == {}
    elif mode == "partial":
        assert monitoring.tools[qualification._QUALIFICATION_MONITORING_TOOL_ID] is None
        assert monitoring.callbacks == {}
        assert monitoring.global_events == {}


def test_fixed_cli_monitoring_captures_escaping_exception_from_outer_catch():
    def nested_failure():
        raise LookupError("PRIVATE_ESCAPING_EXCEPTION_TEXT")

    class RootSetup:
        @staticmethod
        def main(_argv):
            nested_failure()

    cli_exit, origin = _run_cli(RootSetup)
    assert cli_exit == 1
    assert origin["exception_type"] == "LookupError"
    assert any(frame["function"] == "nested_failure" for frame in origin["frames"])
    assert "PRIVATE_ESCAPING_EXCEPTION_TEXT" not in repr(origin)


def test_fixed_cli_uses_real_monitoring_api_for_caught_nested_exception():
    monitoring = getattr(qualification.sys, "monitoring", None)
    if monitoring is None:
        pytest.skip("runtime has no sys.monitoring API")
    tool_id = qualification._QUALIFICATION_MONITORING_TOOL_ID
    assert monitoring.get_tool(tool_id) is None
    original_trace = qualification.sys.gettrace()
    original_profile = qualification.sys.getprofile()

    def nested_failure():
        raise LookupError("PRIVATE_REAL_MONITORING_TEXT")

    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                nested_failure()
            except LookupError:
                return 23

    try:
        cli_exit, origin = qualification._run_fixed_root_adapter_update(
            RootSetup, Path(__file__).resolve().parent, "a" * 40, "b" * 64)
        assert cli_exit == 23
        assert origin["exception_type"] == "LookupError"
        assert {frame["function"] for frame in origin["frames"]} >= {
            "main", "nested_failure"}
        assert "PRIVATE_REAL_MONITORING_TEXT" not in repr(origin)
        assert qualification.sys.gettrace() is original_trace
        assert qualification.sys.getprofile() is original_profile
        assert monitoring.get_tool(tool_id) is None

        # Re-acquiring the released ID proves both callback registrations were
        # removed, while the disabled event mask proves no scope was retained.
        monitoring.use_tool_id(tool_id, "qualification-cleanup-contract")
        try:
            assert monitoring.get_events(tool_id) == 0
            events = monitoring.events
            for event in (events.EXCEPTION_HANDLED, events.PY_RETURN):
                assert monitoring.register_callback(tool_id, event, lambda *_args: None) is None
                monitoring.register_callback(tool_id, event, None)
        finally:
            monitoring.set_events(tool_id, 0)
            monitoring.free_tool_id(tool_id)
    finally:
        assert monitoring.get_tool(tool_id) is None


def test_monitoring_projector_failure_does_not_change_cli_result(monkeypatch):
    def refuse_projection(_exc, _candidate_src, **_kwargs):
        raise RuntimeError("PRIVATE_PROJECTOR_FAILURE")

    monkeypatch.setattr(qualification, "_root_setup_exception_origin", refuse_projection)

    class RootSetup:
        @staticmethod
        def main(_argv):
            try:
                raise LookupError("PRIVATE_PROJECTOR_INPUT")
            except LookupError as exc:
                _handled_main_exception(RootSetup.main, exc)
                _main_returned(RootSetup.main)
                return 19

    cli_exit, origin = _run_cli(RootSetup)
    assert cli_exit == 19
    assert origin is None
    assert _LAST_MONITORING.tools[qualification._QUALIFICATION_MONITORING_TOOL_ID] is None


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


def test_startup_denial_stage_and_type_fit_existing_origin_report(monkeypatch):
    class Socket:
        async def send_json(self, request):
            self.request_id = request["id"]

        async def receive(self):
            return SimpleNamespace(type=1, data=json.dumps({
                "jsonrpc": "2.0", "id": self.request_id, "error": {
                    "code": -32000, "message": "lifecycle startup probe refused",
                    "data": '{"exception_type":"RuntimeError","schema":1,"stage":"route"}',
                },
            }))

        async def close(self):
            pass

    class Session:
        async def close(self):
            pass

    client = CoreRpcClient(token_file=Path("/private/fake/token"))
    ws = Socket()
    ws_types = SimpleNamespace(TEXT=1, CLOSED=2, CLOSE=3, ERROR=4)

    async def connect(*, total_timeout=None):
        assert total_timeout == 120.0
        return Session(), ws, ws_types

    client._connect = connect
    handle = "P" * 43
    cohort = SimpleNamespace(phase="source-starting")
    pidfd, pidfd_writer = os.pipe()
    root_context = {"cohort": {"phase": "source-starting"}, "pid": 42,
                    "pidfd": pidfd, "new_read": object(), "identity": "identity",
                    "adapter": "a" * 64, "core": "b" * 64}
    context_token = core_runtime._ADAPTER_STARTUP_COHORT_CONTEXT.set(root_context)
    lock_token = core_runtime._ADAPTER_UPDATE_LOCK_HELD.set(True)
    monkeypatch.setattr(core_runtime.os, "geteuid", lambda: core_runtime.ROOT_UID)
    monkeypatch.setattr(core_runtime, "_validate_guarded_new_read", lambda _value: True)
    monkeypatch.setattr(core_runtime, "_adapter_process_identity",
                        lambda *_args: (42, "identity"))
    monkeypatch.setattr(core_runtime, "verify_starting_lifecycle_observer_custody",
                        lambda _custody: True)
    registry = SimpleNamespace(enroll_lifecycle_startup_probe=lambda **_kwargs: handle)
    observer_session = SimpleNamespace(
        custody=SimpleNamespace(cohort=cohort), registry=registry, rpc=client)
    monkeypatch.setattr(core_runtime, "_starting_lifecycle_observer",
                        lambda: contextlib.nullcontext(observer_session))

    # These ordinary fixture callers represent the update plus two nested
    # lock scopes. Their real test-module filenames stay inside the repo-root
    # projection so the existing 12-frame report cap must retain the startup
    # stage while traversing a deliberately conservative caller depth.
    def fixture_nested_lock():
        return core_runtime._prove_new_cohort_startup_chat()

    def fixture_lock():
        return fixture_nested_lock()

    def fixture_update():
        return fixture_lock()

    class RootSetup:
        @staticmethod
        def main(_argv):
            fixture_update()

    try:
        cli_exit, origin = _run_cli(
            RootSetup, candidate_src=Path(__file__).resolve().parents[2])
    finally:
        core_runtime._ADAPTER_STARTUP_COHORT_CONTEXT.reset(context_token)
        core_runtime._ADAPTER_UPDATE_LOCK_HELD.reset(lock_token)
        os.close(pidfd)
        os.close(pidfd_writer)

    assert cli_exit == 1
    assert origin is not None
    assert set(origin) == {"exception_type", "frames"}
    assert origin["exception_type"] == "_StartupNativeRuntimeErrorDenied"
    assert len(origin["frames"]) <= 12
    functions = {row["function"] for row in origin["frames"]}
    assert {"fixture_update", "fixture_lock", "fixture_nested_lock"} <= functions
    assert "_prove_new_cohort_startup_chat" in functions
    assert "_run_root_coro" in functions
    assert "lifecycle_startup_probe" in functions
    assert "_receive" in functions
    assert "_startup_refused_route" in functions
    assert "private" not in repr(origin)


def test_fixed_cli_trace_refuses_a_preexisting_trace():
    def prior_trace(_frame, _event, _arg):
        return prior_trace

    sys.settrace(prior_trace)
    try:
        with pytest.raises(RuntimeError, match="untraced root CLI context"):
            qualification._run_fixed_root_adapter_update(
                object(), Path(__file__).parent, "a" * 40, "b" * 64)
    finally:
        sys.settrace(None)
    assert sys.gettrace() is None


def test_stack_sample_is_innermost_bounded_and_unknown_when_mapping_incomplete():
    def descend(depth):
        if depth:
            return descend(depth - 1)
        return sys._getframe()

    frame = descend(36)
    expected_lines = []
    cursor = frame
    while cursor is not None and len(expected_lines) < 12:
        expected_lines.append(cursor.f_lineno)
        cursor = cursor.f_back
    listener_row = _stack_code_row("listener")
    record = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123,
        {id(descend.__code__): _stack_code_row("listener")}, True,
        frames_by_ident={123: frame})
    assert record == {
        "schema": 2, "candidate_commit": "a" * 40,
        "candidate_archive_sha256": "b" * 64, "elapsed_ms": 250_000,
        "labels": ["listener"] * 12,
        "frames": [{"source_relative_path": listener_row["source_relative_path"],
                    "function": listener_row["function"], "line": line}
                   for line in expected_lines],
        "examined_frames": 32,
        "unmatched_frames": 0, "truncated": True, "unknown": True,
    }

    unmapped = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123, {}, False,
        frames_by_ident={123: frame})
    assert unmapped["labels"] == []
    assert unmapped["unknown"] is True
    assert unmapped["examined_frames"] == 32

    foreign_thread_only = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123,
        {id(descend.__code__): _stack_code_row("listener")}, True,
        frames_by_ident={456: frame})
    assert foreign_thread_only["labels"] == []
    assert foreign_thread_only["examined_frames"] == 0
    assert foreign_thread_only["unknown"] is True

    class FrameWithoutPrivateReads:
        def __init__(self, code, parent=None, line=1):
            object.__setattr__(self, "f_code", code)
            object.__setattr__(self, "f_lineno", line)
            object.__setattr__(self, "f_back", parent)

        def __getattribute__(self, name):
            if name in {"f_locals", "f_globals", "f_lasti"}:
                raise AssertionError("stack sampler inspected private frame state")
            return object.__getattribute__(self, name)

    private_read_guard = FrameWithoutPrivateReads(descend.__code__)
    guarded = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123,
        {id(descend.__code__): _stack_code_row("listener")}, True,
        frames_by_ident={123: private_read_guard})
    assert guarded["labels"] == ["listener"]
    assert guarded["unknown"] is False
    stale = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123,
        {id(descend.__code__): _stack_code_row("listener")}, True,
        frames_by_ident={123: private_read_guard}, source_current=False)
    assert stale["labels"] == [] and stale["frames"] == []
    assert stale["unmatched_frames"] == 1 and stale["unknown"] is True
    line_two = FrameWithoutPrivateReads(descend.__code__, line=2)
    out_of_range = qualification._qualification_stack_sample(
        "a" * 40, "b" * 64, 250_000, 123,
        {id(descend.__code__): _stack_code_row("listener", line_count=1)}, True,
        frames_by_ident={123: line_two})
    assert out_of_range["labels"] == [] and out_of_range["frames"] == []
    assert out_of_range["unknown"] is True


def test_stack_sample_emitter_rejects_unclosed_record_before_output(capsys):
    class NoOutputAllowed:
        def fileno(self):
            raise AssertionError("unvalidated sample reached the output channel")

    previous = qualification._QUALIFICATION_STACK_SAMPLE_STREAM
    qualification._QUALIFICATION_STACK_SAMPLE_STREAM = NoOutputAllowed()
    try:
        qualification._emit_qualification_stack_sample({
            "schema": 2, "candidate_commit": "a" * 40,
            "candidate_archive_sha256": "b" * 64, "elapsed_ms": 1,
            "labels": [], "frames": [], "examined_frames": 0, "unmatched_frames": 0,
            "truncated": False, "unknown": True,
            "private": "PRIVATE sample field",
        }, qualification.threading.Event(), qualification.threading.Lock())
        qualification._emit_qualification_stack_sample({
            "schema": 2, "candidate_commit": "a" * 40,
            "candidate_archive_sha256": "b" * 64, "elapsed_ms": 1,
            "labels": ["updater"],
            "frames": [{"source_relative_path": "outside.py",
                        "function": "_update_owned_core_adapter_locked", "line": 1}],
            "examined_frames": 1, "unmatched_frames": 0,
            "truncated": False, "unknown": False,
        }, qualification.threading.Event(), qualification.threading.Lock())
    finally:
        qualification._QUALIFICATION_STACK_SAMPLE_STREAM = previous
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""


def test_stack_sample_emitter_drops_when_original_channel_is_not_a_pipe(monkeypatch):
    held = io.StringIO()
    monkeypatch.setattr(qualification, "_QUALIFICATION_STACK_SAMPLE_STREAM", held)
    record = {
        "schema": 2, "candidate_commit": "a" * 40,
        "candidate_archive_sha256": "b" * 64, "elapsed_ms": 1,
        "labels": ["updater"], "frames": [_stack_frame_row("updater")],
        "examined_frames": 1,
        "unmatched_frames": 0, "truncated": False, "unknown": False,
    }
    qualification._emit_qualification_stack_sample(
        record, qualification.threading.Event(), qualification.threading.Lock())
    assert held.getvalue() == ""


def test_stack_sample_emitter_drops_when_pipe_is_full_or_publication_gate_busy(monkeypatch):
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)
    os.set_blocking(write_fd, False)

    class HeldPipe:
        def fileno(self):
            return write_fd

    monkeypatch.setattr(qualification, "_QUALIFICATION_STACK_SAMPLE_STREAM", HeldPipe())
    record = {
        "schema": 2, "candidate_commit": "a" * 40,
        "candidate_archive_sha256": "b" * 64, "elapsed_ms": 1,
        "labels": ["updater"], "frames": [_stack_frame_row("updater")],
        "examined_frames": 1,
        "unmatched_frames": 0, "truncated": False, "unknown": False,
    }
    done = qualification.threading.Event()
    gate = qualification.threading.Lock()
    gate.acquire()
    try:
        qualification._emit_qualification_stack_sample(record, done, gate)
    finally:
        gate.release()
    with pytest.raises(BlockingIOError):
        os.read(read_fd, 4096)

    while True:
        try:
            os.write(write_fd, b"x" * 4096)
        except BlockingIOError:
            break
    flags_before = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    qualification._emit_qualification_stack_sample(record, done, gate)
    assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == flags_before
    os.close(read_fd)
    os.close(write_fd)


def test_stack_code_map_uses_only_already_loaded_candidate_modules(tmp_path, monkeypatch):
    source = tmp_path / "src"
    package = source / "hermes_installer"
    remote = package / "remote"
    remote.mkdir(parents=True)
    core_path = package / "core_runtime.py"
    inspector_path = remote / "core_gateway_inspector.py"
    core_names = {
        "_update_owned_core_adapter_locked": "updater",
        "_run_same_materialization_import": "importer",
        "_hash_generation_tree": "generation_tree",
        "_wait_for_listener": "listener",
        "_prove_new_cohort_startup_chat": "startup_chat",
        "_make_adapter_update_reconstruction": "reconstruction",
        "_root_runuser_proc_snapshot": "root_runuser",
    }
    inspector_names = {"_current_native_adapter_generation": "adapter_generation"}
    core_text = "\n".join(f"def {name}():\n    return None" for name in core_names) + "\n"
    inspector_text = "def _current_native_adapter_generation():\n    return None\n"
    core_path.write_text(core_text, encoding="utf-8")
    inspector_path.write_text(inspector_text, encoding="utf-8")

    def module_with_functions(module_name, path, names):
        module = ModuleType(module_name)
        module.__file__ = str(path)
        namespace = {}
        exec(compile("\n".join(f"def {name}():\n    return None" for name in names),
                      str(path), "exec"), namespace)
        for name in names:
            setattr(module, name, namespace[name])
        return module

    monkeypatch.setitem(sys.modules, "hermes_installer.core_runtime",
                        module_with_functions("hermes_installer.core_runtime",
                                              core_path, core_names))
    monkeypatch.setitem(
        sys.modules, "hermes_installer.remote.core_gateway_inspector",
        module_with_functions("hermes_installer.remote.core_gateway_inspector",
                              inspector_path, inspector_names))
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    code_labels, source_rows, complete = qualification._verified_qualification_stack_codes(
        source, source_fd)
    assert complete is True
    assert {row["label"] for row in code_labels.values()} == qualification._QUALIFICATION_STACK_LABELS
    assert all(row["source_relative_path"] in qualification._QUALIFICATION_STACK_SOURCE_FILES
               and qualification._QUALIFICATION_STACK_FUNCTIONS[row["function"]] == row["label"]
               and 1 <= row["line_count"]
               for row in code_labels.values())
    assert set(source_rows) == set(qualification._QUALIFICATION_STACK_SOURCE_FILES)
    assert qualification._qualification_stack_sources_current(source_fd, source_rows)
    core_path.write_text(core_path.read_text(encoding="utf-8") + "# changed\n",
                         encoding="utf-8")
    assert not qualification._qualification_stack_sources_current(source_fd, source_rows)
    core_path.write_text(core_text, encoding="utf-8")
    source_rows = {relative: qualification._stack_source_file_snapshot(source_fd, relative)
                   for relative in qualification._QUALIFICATION_STACK_SOURCE_FILES}
    assert qualification._qualification_stack_sources_current(source_fd, source_rows)
    saved_core_path = package / "core_runtime.saved"
    core_path.rename(saved_core_path)
    core_path.symlink_to(saved_core_path.name)
    assert not qualification._qualification_stack_sources_current(source_fd, source_rows)
    core_path.unlink()
    saved_core_path.rename(core_path)

    monkeypatch.delitem(sys.modules, "hermes_installer.remote.core_gateway_inspector")
    core_only, _sources, complete = qualification._verified_qualification_stack_codes(
        source, source_fd)
    assert complete is False
    assert {row["label"] for row in core_only.values()} == set(core_names.values())

    inspector = module_with_functions(
        "hermes_installer.remote.core_gateway_inspector", inspector_path,
        inspector_names)
    monkeypatch.setitem(sys.modules, "hermes_installer.remote.core_gateway_inspector", inspector)
    foreign = module_with_functions("hermes_installer.core_runtime", core_path, core_names)
    foreign.__file__ = str(tmp_path / "foreign" / "core_runtime.py")
    monkeypatch.setitem(sys.modules, "hermes_installer.core_runtime", foreign)
    _labels, _sources, complete = qualification._verified_qualification_stack_codes(
        source, source_fd)
    assert complete is False
    os.close(source_fd)


def test_stack_sample_is_one_shot_and_cancels_without_late_emission(monkeypatch):
    read_fd, write_fd = os.pipe()
    os.set_blocking(read_fd, False)

    class HeldPipe:
        def fileno(self):
            return write_fd

    held = HeldPipe()
    original_flags = fcntl.fcntl(write_fd, fcntl.F_GETFL)
    monkeypatch.setattr(qualification, "_QUALIFICATION_STACK_SAMPLE_STREAM", held)
    monkeypatch.setattr(qualification, "_QUALIFICATION_STACK_SAMPLE_SECONDS", 250.0)
    real_event = qualification.threading.Event

    class ImmediateDeadlineEvent:
        def __init__(self):
            self.event = real_event()

        def wait(self, timeout=None):
            assert timeout == 250.0
            return self.event.is_set()

        def set(self):
            self.event.set()

        def is_set(self):
            return self.event.is_set()

    monkeypatch.setattr(qualification.threading, "Event", ImmediateDeadlineEvent)
    threads = []

    class DeferredThread:
        def __init__(self, *, target, daemon, name):
            assert daemon is True
            assert name == "core-qualification-stack-sample"
            self.target = target
            self.join_timeouts = []
            threads.append(self)

        def start(self):
            return None

        def join(self, *, timeout):
            self.join_timeouts.append(timeout)

    monkeypatch.setattr(qualification.threading, "Thread", DeferredThread)

    class RootSetup:
        @staticmethod
        def main(_argv):
            # Execute the deferred observer while this verified CLI frame is
            # live, as if its fixed deadline had elapsed.
            threads[-1].target()
            _main_returned(RootSetup.main)
            return 0

    class MainOnlyFrame:
        f_code = RootSetup.main.__code__
        f_lineno = 6260
        f_back = None

    main_ident = qualification.threading.get_ident()
    monkeypatch.setattr(
        qualification.sys, "_current_frames",
        lambda: {main_ident: MainOnlyFrame()})
    monkeypatch.setattr(
        qualification, "_verified_qualification_stack_codes",
        lambda _src, _fd: ({id(RootSetup.main.__code__): _stack_code_row("updater")},
                           {}, True))
    monkeypatch.setattr(qualification, "_qualification_stack_sources_current",
                        lambda _fd, _sources: True)
    exit_code, origin = _run_cli(RootSetup)
    assert exit_code == 0 and origin is None
    assert len(threads) == 1 and threads[0].join_timeouts == [0.05]
    captured = os.read(read_fd, 4096)
    lines = captured.decode("ascii").splitlines()
    assert len(lines) == 1
    assert lines[0].startswith(qualification._QUALIFICATION_STACK_SAMPLE_PREFIX)
    encoded = lines[0][len(qualification._QUALIFICATION_STACK_SAMPLE_PREFIX):]
    sample = json.loads(encoded)
    assert encoded == json.dumps(sample, sort_keys=True, separators=(",", ":"))
    assert set(sample) == {
        "schema", "candidate_commit", "candidate_archive_sha256", "elapsed_ms",
        "labels", "frames", "examined_frames", "unmatched_frames", "truncated", "unknown",
    }
    assert sample["schema"] == 2
    assert sample["labels"] == ["updater"]
    assert sample["frames"] == [{
        "source_relative_path": "hermes_installer/core_runtime.py",
        "function": "_update_owned_core_adapter_locked",
        "line": 6260,
    }]
    assert sample["unknown"] is False
    assert "RootSetup" not in encoded
    assert fcntl.fcntl(write_fd, fcntl.F_GETFL) == original_flags

    # A cancelled observer invoked after the CLI frame has returned emits no
    # second record and cannot delay the completed CLI result.
    threads[-1].target()
    with pytest.raises(BlockingIOError):
        os.read(read_fd, 4096)

    class FastRootSetup:
        @staticmethod
        def main(_argv):
            return 0

    fast_exit, fast_origin = _run_cli(FastRootSetup)
    assert fast_exit == 0 and fast_origin is None
    assert threads[-1].join_timeouts == [0.05]
    threads[-1].target()
    with pytest.raises(BlockingIOError):
        os.read(read_fd, 4096)
    os.close(read_fd)
    os.close(write_fd)


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
