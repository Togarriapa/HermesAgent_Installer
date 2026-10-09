from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.authority.build_execution import ManagedBuildResult, managed_process_identity_digest
from hermes_installer.authority.build_probe import RootManagedCPython39Probe
from hermes_installer.authority.types import AuthorityDenied


def _selected_output(base: Path):
    root = base / "job-root"
    root.mkdir(mode=0o700)
    (root / "runtime" / "bin").mkdir(parents=True, mode=0o700)
    executable = root / "runtime" / "bin" / "python3.9"
    executable.write_bytes(b"fixed interpreter fixture")
    executable.chmod(0o700)
    root.chmod(0o700)
    return root, executable


def _build_result() -> ManagedBuildResult:
    return ManagedBuildResult(
        process_id="build-process-1", generation="build-generation-1", uid=os.getuid(),
        pid=421, start_ticks=1234, exit_code=0, timed_out=False, cancelled=False,
        cleanup_verified=True, started_monotonic=time.monotonic() - 1,
        finished_monotonic=time.monotonic(), kernel_limits={
            "PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
            "NoNewPrivileges": "yes", "ProtectSystem": "strict",
        }, terminal_success_record_id="build-terminal-1", process_identity_digest="a" * 64,
        cgroup_id="/system.slice/build-1.service", mount_namespace_inode=101,
        network_namespace_inode=102, bounded_log_digest="b" * 64, log_bytes=32,
    )


class ProbeLauncher:
    def __init__(self, root: Path, executable: Path, *, mutation=None, changes=None):
        self.root, self.executable = root, executable
        self.mutation, self.changes = mutation, changes or {}
        self.calls = 0

    def run_attested_cpython39_probe(self, inputs, build_result, *, timeout, cancelled):
        self.calls += 1
        assert timeout == 15.0
        assert build_result.terminal_success_record_id == "build-terminal-1"
        assert inputs.output_root == self.root
        assert not cancelled()
        if self.mutation == "replace-output":
            self.executable.write_bytes(b"changed after root hash")
        root_info = self.root.lstat()
        executable_info = self.executable.lstat()
        stdout = self.changes.get("stdout", json.dumps({
            "python_version": "3.9.25", "soabi": "cpython-39-aarch64-linux-gnu",
            "debug": False, "glibc_version": "2.35",
        }, sort_keys=True, separators=(",", ":")).encode())
        process_identity = managed_process_identity_digest(
            process_id="f" * 32, generation=build_result.generation, uid=os.getuid(), pid=422,
            start_ticks=1235, cgroup_id="/system.slice/probe-1.service",
            mount_namespace_inode=201, network_namespace_inode=202)
        return SimpleNamespace(
            terminal_success_record_id=self.changes.get("probe_id", "probe-terminal-1"),
            build_terminal_success_record_id=self.changes.get("build_id", "build-terminal-1"),
            build_process_identity_digest=self.changes.get("build_process_identity_digest", "a" * 64),
            process_identity_digest=self.changes.get("process_identity_digest", process_identity),
            process_id=self.changes.get("process_id", "f" * 32),
            generation=self.changes.get("generation", "build-generation-1"),
            uid=os.getuid(), gid=os.getgid(), pid=422, start_ticks=1235,
            exit_code=self.changes.get("exit_code", 0), cleanup_verified=self.changes.get("cleanup", True),
            startup_gate_verified=self.changes.get("startup_gate_verified", True),
            cgroup_id="/system.slice/probe-1.service", mount_namespace_inode=201,
            network_namespace_inode=202, output_root_id=inputs.output_root_id,
            output_root_device=root_info.st_dev, output_root_inode=root_info.st_ino,
            executable_sha256=hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            executable_size_bytes=self.executable.stat().st_size,
            bounded_log_digest=hashlib.sha256(stdout).hexdigest(), log_bytes=len(stdout), stdout=stdout,
        )


def _inputs(root: Path):
    return SimpleNamespace(
        target_id="coral-cpython-build:start", generation="build-generation-1",
        operation_id="coral-cpython39-source-build-v1", output_root=root,
        output_root_id="output-job-1", output_owner_uid=os.getuid(), output_owner_gid=os.getgid(),
    )


def test_probe_returns_runtime_facts_and_signed_receipt_material_only_after_verified_execution(tmp_path):
    root, executable = _selected_output(tmp_path)
    inputs, build = _inputs(root), _build_result()
    launcher = ProbeLauncher(root, executable)
    facts = RootManagedCPython39Probe(launcher).inspect_cpython39(
        SimpleNamespace(target_id=inputs.target_id, generation=inputs.generation), executable,
        build_result=build, build_inputs=inputs, cancelled=lambda: False,
    )

    assert facts["python_version"] == "3.9.25"
    assert facts["soabi"] == "cpython-39-aarch64-linux-gnu"
    assert facts["debug"] is False
    assert facts["glibc_version"] == "2.35"
    assert facts["probe_execution"]["build_terminal_success_record_id"] == build.terminal_success_record_id
    assert facts["probe_execution"]["cleanup_verified"] is True
    assert facts["probe_execution"]["output_root_inode"] == root.stat().st_ino
    assert launcher.calls == 1


@pytest.mark.parametrize("changes", [
    {"build_id": "another-build"},
    {"probe_id": "build-terminal-1"},
    {"build_process_identity_digest": "d" * 64},
    {"exit_code": 1},
    {"cleanup": False},
    {"startup_gate_verified": False},
    {"stdout": b"not-json"},
    {"stdout": b'{"python_version":"3.9.25","python_version":"3.9.25"}'},
])
def test_probe_rejects_unbound_or_invalid_terminal_receipt(tmp_path, changes):
    root, executable = _selected_output(tmp_path)
    launcher = ProbeLauncher(root, executable, changes=changes)
    probe = RootManagedCPython39Probe(launcher)
    with pytest.raises(AuthorityDenied):
        probe.inspect_cpython39(
            SimpleNamespace(target_id="coral-cpython-build:start", generation="build-generation-1"),
            executable, build_result=_build_result(), build_inputs=_inputs(root), cancelled=lambda: False,
        )


def test_probe_diagnostic_names_only_failed_proof_field(tmp_path):
    root, executable = _selected_output(tmp_path)
    probe = RootManagedCPython39Probe(
        ProbeLauncher(root, executable, changes={"startup_gate_verified": False}))
    with pytest.raises(AuthorityDenied) as denied:
        probe.inspect_cpython39(
            SimpleNamespace(target_id="coral-cpython-build:start", generation="build-generation-1"),
            executable, build_result=_build_result(), build_inputs=_inputs(root), cancelled=lambda: False,
        )
    assert "startup_gate_verified" in str(denied.value)
    assert "probe-terminal-1" not in str(denied.value)
    assert str(executable) not in str(denied.value)


def test_probe_rejects_caller_selected_path_before_launch(tmp_path):
    root, executable = _selected_output(tmp_path)
    launcher = ProbeLauncher(root, executable)
    with pytest.raises(AuthorityDenied):
        RootManagedCPython39Probe(launcher).inspect_cpython39(
            SimpleNamespace(target_id="coral-cpython-build:start", generation="build-generation-1"),
            root / "runtime/bin/another-python", build_result=_build_result(),
            build_inputs=_inputs(root), cancelled=lambda: False,
        )
    assert launcher.calls == 0


def test_probe_rejects_output_replacement_during_isolated_execution(tmp_path):
    root, executable = _selected_output(tmp_path)
    launcher = ProbeLauncher(root, executable, mutation="replace-output")
    with pytest.raises(AuthorityDenied, match="output changed"):
        RootManagedCPython39Probe(launcher).inspect_cpython39(
            SimpleNamespace(target_id="coral-cpython-build:start", generation="build-generation-1"),
            executable, build_result=_build_result(), build_inputs=_inputs(root), cancelled=lambda: False,
        )
