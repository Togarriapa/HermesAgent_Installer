"""Real Linux transient-unit proof for root-selected terminal build custody.

The context/grant objects are fixture claims because this test invokes the
already-authorized root adapter directly. Existing AuthorityService tests
exercise grant consumption; this module exercises the build unit's actual
UID, namespaces, mount flags, network denial and terminal cleanup in Ubuntu CI.
"""
from __future__ import annotations

import hashlib
import base64
import json
import os
import platform
import pwd
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.artifacts import TreeFile
from hermes_installer.authority.types import (
    AuthorityDenied, EffectAuthorization, HostContext, Sensitivity, canonical_digest,
)
from hermes_installer.managed_process_custodian import (
    ManagedProcessEffectHandler, ManagedProfileCustody, ManagedBuildJobRunner,
)


class BuildCustodyLinuxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        if platform.system() != "Linux" or os.geteuid() != 0 or not hasattr(os, "pidfd_open"):
            raise unittest.SkipTest("requires the isolated Linux root systemd CI job")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise unittest.SkipTest("requires cgroup v2")
        cls.systemctl = Path("/usr/bin/systemctl")
        cls.systemd_run = Path("/usr/bin/systemd-run")
        if not cls.systemctl.is_file() or not cls.systemd_run.is_file():
            raise unittest.SkipTest("system manager commands unavailable")
        check = subprocess.run([str(cls.systemctl), "--system", "show-environment"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False)
        if check.returncode:
            raise unittest.SkipTest("systemd system manager is unavailable")

    def setUp(self) -> None:
        self.token = uuid.uuid4().hex[:12]
        self.profile_id = "ci-build-" + self.token
        self.service_user = "hermes-" + hashlib.sha256(self.profile_id.encode()).hexdigest()[:16]
        created = subprocess.run(["/usr/sbin/useradd", "--system", "--no-create-home",
            "--home-dir=/nonexistent", "--shell=/usr/sbin/nologin", "--user-group", self.service_user],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=5, check=False)
        if created.returncode:
            self.fail("could not create the isolated build service identity")
        account = pwd.getpwnam(self.service_user)
        self.uid, self.gid = account.pw_uid, account.pw_gid
        if self.uid <= 0 or os.getgrouplist(self.service_user, self.gid) != [self.gid]:
            self.fail("build service account does not have an exclusive primary group")

        self.stage = Path(tempfile.mkdtemp(prefix="hermes-build-custody-", dir="/run"))
        os.chown(self.stage, 0, 0)
        os.chmod(self.stage, 0o700)
        self.source = self.stage / "source"
        self.toolchain = self.stage / "toolchain"
        self.source.mkdir(mode=0o555)
        self.toolchain.mkdir(mode=0o555)
        (self.toolchain / "bin").mkdir(mode=0o555)
        self._root_file(self.source / "input.txt", b"immutable source\n", 0o444)
        self._root_file(self.toolchain / "bin" / "tool.txt", b"immutable toolchain\n", 0o444)
        self.builder = Path(sys.executable).resolve(strict=True)
        self.builder_sha256 = hashlib.sha256(self.builder.read_bytes()).hexdigest()
        if self.builder.stat().st_uid != 0 or self.builder.stat().st_mode & 0o022:
            self.fail("CI builder interpreter is not root-owned and immutable")

        self.home = self._service_dir("home")
        self.work_root = self._service_dir("work-root")
        self.data = self._service_dir("data")
        (self.work_root / "ci").mkdir(mode=0o700)
        os.chown(self.work_root / "ci", self.uid, self.gid)
        self.output = self.stage / "output"
        self.output.mkdir(mode=0o700)
        os.chown(self.output, self.uid, self.gid)
        os.chmod(self.output, 0o700)
        self.loopback_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.loopback_listener.bind(("127.0.0.1", 0))
        self.loopback_listener.listen(1)
        self.loopback_port = self.loopback_listener.getsockname()[1]

        service_generation = "service-" + self.token
        self.target = "ci-build-" + self.token + ":start"
        self.profile = ManagedProfileCustody(
            profile_id=self.profile_id, owner_uid=self.uid, owner_gid=self.gid,
            service_user=self.service_user, executable=self.builder,
            artifact_sha256=self.builder_sha256, artifact_root=self.builder.parent,
            data_root=self.data, home_root=self.home, work_root=self.work_root,
            generation=service_generation, enrollment_id="service-enrollment-" + self.token,
            home_id="home-" + self.token, work_id="work-" + self.token,
            data_id="data-" + self.token,
            memory_max_bytes=512 * 1024 * 1024, cpu_quota_percent=100, io_weight=100,
            max_lifetime_seconds=30, argv_recipe=(),
            operation_targets={"process.start": self.target},
            operation_recipes={"ci-build-v1": {
                "executable_artifact_id": "ci-python-" + self.token,
                "executable_sha256": self.builder_sha256,
                "argv_recipe": [{"literal": "--version"}],
                "cwd_root_id": "work-" + self.token, "cwd_subpath": "ci",
                "environment": {"HOME": "/hermes", "HERMES_HOME": "/hermes",
                                "PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"},
                "child_artifact_refs": {}, "max_lifetime_seconds": 30,
                "max_output_bytes": 65536, "stdin_mode": "closed",
                "parameter_schema_id": "ci-empty-" + self.token,
            }},
            parameter_schemas={"ci-empty-" + self.token: {
                "id": "ci-empty-" + self.token, "fields": []}},
        )
        self.manager = ManagedProcessEffectHandler({self.profile_id: self.profile},
            systemd_run=self.systemd_run, systemctl=self.systemctl)
        self.runner = ManagedBuildJobRunner(self.manager,
            process_profile_resolver=lambda target, generation: self.profile
                if target == self.target and generation == "build-" + self.token else None,
            diagnostic_observer=lambda value: print("BUILD_CUSTODY_FIXTURE_DIAGNOSTIC", repr(value),
                                                    file=sys.stderr))
        self.inputs = self._inputs()
        self.context, self.authorization = self._claims()

    def tearDown(self) -> None:
        self.loopback_listener.close()
        shutil.rmtree(self.stage, ignore_errors=True)
        subprocess.run(["/usr/sbin/userdel", self.service_user], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)

    @staticmethod
    def _root_file(path: Path, value: bytes, mode: int) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        try:
            os.fchown(fd, 0, 0)
            os.write(fd, value)
            os.fchmod(fd, mode)
        finally:
            os.close(fd)

    def _service_dir(self, name: str) -> Path:
        path = self.stage / name
        path.mkdir(mode=0o700)
        os.chown(path, self.uid, self.gid)
        os.chmod(path, 0o700)
        return path

    @staticmethod
    def _tree(path: Path) -> tuple[tuple[TreeFile, ...], str]:
        rows = []
        for file in sorted(item for item in path.rglob("*") if item.is_file()):
            body = file.read_bytes()
            rows.append(TreeFile(file.relative_to(path).as_posix(), hashlib.sha256(body).hexdigest(),
                                 len(body), bool(file.stat().st_mode & 0o111)))
        canonical = [{"path": row.path, "sha256": row.sha256,
                      "size_bytes": row.size_bytes, "executable": row.executable} for row in rows]
        digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":"),
                                            ensure_ascii=False).encode()).hexdigest()
        return tuple(rows), digest

    def _inputs(self):
        source_rows, source_digest = self._tree(self.source)
        tool_rows, tool_digest = self._tree(self.toolchain)
        # The root-selected recipe carries only one no-newline literal token;
        # encoded fixture source is test data, never supplied by a worker.
        code = (
            "import json,pathlib,socket,time,os\n"
            "def denied_write(path):\n"
            " try:\n  open(path,'wb').write(b'x'); return False\n"
            " except OSError: return True\n"
            "def can_connect(address):\n"
            " try:\n  socket.create_connection(address,timeout=.3).close(); return True\n"
            " except OSError: return False\n"
            "result={'uid':os.geteuid(),"
            "'source_write_denied':denied_write('/run/hermes-installer/build/source/input.txt'),"
            "'toolchain_write_denied':denied_write('/run/hermes-installer/build/toolchain/bin/tool.txt'),"
            f"'loopback_reached':can_connect(('127.0.0.1',{self.loopback_port})),"
            "'external_reached':can_connect(('1.1.1.1',80))}\n"
            "pathlib.Path('/run/hermes-installer/build/output/effects.json').write_text(json.dumps(result))\n"
            "print('build-fixture-complete',flush=True)\n"
            "time.sleep(1.0)\n"
        )
        encoded = base64.b64encode(code.encode()).decode("ascii")
        code_arg = f"exec(__import__('base64').b64decode('{encoded}'))"
        return SimpleNamespace(
            target_id=self.target, generation="build-" + self.token,
            service_generation_digest="a" * 64,
            build_service_enrollment_id=self.profile.enrollment_id,
            build_service_generation=self.profile.generation,
            enrollment_id="build-enrollment-" + self.token,
            operation_id="ci-build-v1", selection_digest="b" * 64,
            source_artifact_id="ci-source-" + self.token, source_sha256="c" * 64,
            source_root=self.source, source_tree_files=source_rows,
            source_tree_manifest_sha256=source_digest,
            toolchain_artifact_id="ci-toolchain-" + self.token, toolchain_sha256="d" * 64,
            toolchain_root=self.toolchain, toolchain_tree_files=tool_rows,
            toolchain_tree_manifest_sha256=tool_digest,
            builder_artifact_id="ci-builder-" + self.token, builder_sha256=self.builder_sha256,
            builder_executable=self.builder,
            argv_recipe=({"build_path": {"mount_id": "builder", "relative_path": ""}},
                         {"literal": "-c"}, {"literal": code_arg}),
            environment={"LANG": "C", "LC_ALL": "C"}, output_specs={},
            output_root=self.output, output_root_id="output-" + self.token,
            output_owner_uid=self.uid, max_lifetime_seconds=30,
        )

    def _claims(self):
        now = time.monotonic()
        context = HostContext(
            principal_id="ci-controller-" + self.token, profile_id="ci-controller-" + self.token,
            namespace_id="ci-namespace-" + self.token, uid=65534,
            purpose="selected-process-operation", intent_id="ci-build-intent-" + self.token,
            trace_id="ci-build-trace-" + self.token, sensitivity=Sensitivity.UNKNOWN,
            lineage_hash="e" * 64, policy_revision="ci-build-v1",
            capabilities=frozenset({"hermes-profile-invoke"}),
            issued_at_monotonic=now, monotonic_expires_at=now + 15,
            nonce="ci-context-nonce-" + self.token, grant_id="ci-context-grant-" + self.token,
            signature="ci-context-signature", final_payload_digest="b" * 64,
            enrollment_id="build-enrollment-" + self.token, generation="build-" + self.token,
            operation="process.start",
        )
        authorization = EffectAuthorization(
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace_id=context.namespace_id, uid=context.uid, purpose=context.purpose,
            sensitivity=context.sensitivity, trace_id=context.trace_id,
            policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
            capability="hermes-profile-invoke", intent_id=context.intent_id,
            target=self.target, recipient=None, request_digest="b" * 64, retry_index=0,
            issued_at_monotonic=now, monotonic_expires_at=now + 15,
            grant_id="ci-effect-grant-" + self.token, nonce="ci-effect-nonce-" + self.token,
            context_digest=canonical_digest(context.claims()), signature="ci-effect-signature",
            final_payload_digest="b" * 64, enrollment_id=context.enrollment_id,
            generation=context.generation, operation="process.start",
        )
        return context, authorization

    def test_build_runs_under_real_isolation_and_emits_terminal_cleanup_proof(self) -> None:
        # A live host-loopback listener makes the network probe meaningful:
        # the isolated unit must not reach it.
        pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            result = self.runner.run_selected_build(self.inputs, context=self.context,
                authorization=self.authorization, peer_pid=os.getpid(), peer_pidfd=pidfd,
                timeout=20, cancelled=lambda: False)
        finally:
            os.close(pidfd)
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(result.timed_out)
        self.assertFalse(result.cancelled)
        self.assertTrue(result.cleanup_verified)
        self.assertEqual(result.uid, self.uid)
        self.assertGreater(result.pid, 1)
        self.assertGreater(result.start_ticks, 0)
        self.assertTrue(result.terminal_success_record_id)
        self.assertEqual(len(result.process_identity_digest), 64)
        self.assertEqual(len(result.bounded_log_digest), 64)
        # The root hash covers the bounded systemd-run transcript as well as
        # the child line; require that the child produced output without
        # assuming manager status chatter is absent.
        self.assertGreaterEqual(result.log_bytes, len(b"build-fixture-complete\n"))
        self.assertLess(result.log_bytes, 1024 * 1024)
        self.assertEqual(result.kernel_limits, {
            "PrivateNetwork": "yes", "IPAddressDeny": "0.0.0.0/0 ::/0",
            "NoNewPrivileges": "yes", "ProtectSystem": "strict",
        })
        self.assertFalse(self.manager._pids(result.cgroup_id), "build unit left cgroup members")
        observed = json.loads((self.output / "effects.json").read_text())
        self.assertEqual(observed, {
            "uid": self.uid, "source_write_denied": True,
            "toolchain_write_denied": True, "loopback_reached": False,
            "external_reached": False,
        })

    def test_prelaunch_cancel_has_no_unit_or_output_effect(self) -> None:
        pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            with self.assertRaises(AuthorityDenied):
                self.runner.run_selected_build(self.inputs, context=self.context,
                    authorization=self.authorization, peer_pid=os.getpid(), peer_pidfd=pidfd,
                    timeout=20, cancelled=lambda: True)
        finally:
            os.close(pidfd)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.runner._active, set())

    def test_expired_start_grant_is_rejected_before_systemd_unit_creation(self) -> None:
        import dataclasses
        now = time.monotonic()
        expired = dataclasses.replace(self.authorization,
            issued_at_monotonic=now - 2, monotonic_expires_at=now - 1)
        pidfd = os.pidfd_open(os.getpid(), 0)
        try:
            with self.assertRaises(AuthorityDenied):
                self.runner.run_selected_build(self.inputs, context=self.context,
                    authorization=expired, peer_pid=os.getpid(), peer_pidfd=pidfd,
                    timeout=20, cancelled=lambda: False)
        finally:
            os.close(pidfd)
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(self.runner._active, set())


if __name__ == "__main__":
    unittest.main()
