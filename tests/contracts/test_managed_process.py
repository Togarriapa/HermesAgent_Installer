from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import shutil
import uuid
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from hermes_installer.managed_process import (
    ManagedProcessError,
    ManagedProcessHandle,
    ManagedProcessSpec,
    ProcessIdentity,
    _manager_environment_keys,
    _observe_process,
    _proc_cgroup,
    _proc_stat,
    _validate_spec,
    ManagedProcessSupervisor,
    provision_service_identity,
)
from hermes_installer.managed_process_custodian import (
    ManagedProcessEffectHandler, ManagedProfileCustody, _argv_matches_recipe,
)
from hermes_installer.state import Journal, OwnedRoot
from hermes_installer.authority.client import AuthorityClient
from hermes_installer.authority.client import canonical_profile_target, profile_launch_envelope
from hermes_installer.authority.types import (
    EffectAuthorization, HostContext, Sensitivity, VerifiedEffectAuthorization,
    canonical_digest,
)


class _FixtureAuthorityVerifier(AuthorityClient):
    """Test-only stand-in; never evidence of the installed host authority service."""
    def __init__(self):
        # Keep the production client's bounded-call contract so tests exercise
        # the same timeout clamping without creating an authority connection.
        self.timeout = 5.0
        self.monotonic = time.monotonic

    def verify_effect(self, grant, context, *, capability, target, recipient=None,
                      request_digest=None, retry_index=None):
        if not isinstance(grant, EffectAuthorization) or not isinstance(context, HostContext):
            raise PermissionError("fixture grant denied")
        if (capability != grant.capability or capability != "hermes-profile-invoke"
                or target != grant.target or recipient is not None or grant.recipient is not None
                or request_digest != grant.request_digest or retry_index != grant.retry_index):
            raise PermissionError("fixture effect binding mismatch")
        return VerifiedEffectAuthorization(grant, "fixture", time.monotonic(), "fixture-receipt")


def _authorized_spec(spec: ManagedProcessSpec) -> ManagedProcessSpec:
    from dataclasses import replace
    import hashlib
    target = canonical_profile_target(spec.profile_id, spec.executable.resolve(), spec.data_root.resolve())
    envelope = profile_launch_envelope(
        target=target, profile_id=spec.profile_id, executable=spec.executable,
        artifact_sha256=spec.artifact_sha256, artifact_root=spec.artifact_root,
        cwd=spec.cwd, data_root=spec.data_root, argv=spec.argv,
        env_allowlist=spec.env_allowlist, child_artifact_refs=spec.child_artifact_refs,
        max_lifetime_seconds=int(spec.max_lifetime_seconds),
        max_output_bytes=spec.max_output_bytes, stdin_mode=spec.stdin_mode)
    now = time.monotonic()
    context = HostContext(
        principal_id="fixture-principal", profile_id=spec.profile_id,
        namespace_id="fixture-namespace", uid=os.getuid(), purpose="fixture",
        intent_id="fixture-intent", trace_id="fixture-trace", sensitivity=Sensitivity.PUBLIC,
        lineage_hash="a" * 64, policy_revision="fixture-policy", capabilities=frozenset({"hermes-profile-invoke"}),
        issued_at_monotonic=now, monotonic_expires_at=now + 30,
        nonce="fixture-context-nonce", grant_id="fixture-context-grant", signature="fixture-signature",
        final_payload_digest=canonical_digest(envelope),
        operation="process.start",
    )
    grant = EffectAuthorization(
        principal_id=context.principal_id, profile_id=context.profile_id,
        namespace_id=context.namespace_id, uid=context.uid, trace_id=context.trace_id,
        policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
        capability="hermes-profile-invoke", intent_id=context.intent_id, target=target,
        purpose=context.purpose, sensitivity=context.sensitivity,
        recipient=None, request_digest=canonical_digest(envelope), retry_index=0,
        issued_at_monotonic=now, monotonic_expires_at=now + 20, grant_id="fixture-effect-grant",
        nonce="fixture-effect-nonce", context_digest="b" * 64, signature="fixture-signature",
        final_payload_digest=canonical_digest(envelope),
        operation="process.start",
    )
    return replace(spec, authority_context=context, effect_authorization=grant)


class ManagedProcessArgvRecipeTests(unittest.TestCase):
    def test_code_interpreters_reject_inline_code_and_unenrolled_script_paths(self) -> None:
        executable = Path("/usr/bin/python3")
        child = "artifact:probe:" + "a" * 64
        profile = SimpleNamespace(executable=executable, argv_recipe=(str(executable), "{child_artifact}"))
        self.assertFalse(_argv_matches_recipe(profile, [str(executable), "-c", "print(1)"], {child: "a" * 64}))
        self.assertFalse(_argv_matches_recipe(profile, [str(executable), "/tmp/attacker.py"], {child: "a" * 64}))
        self.assertTrue(_argv_matches_recipe(profile, [str(executable), child], {child: "a" * 64}))
        shell = Path("/bin/bash")
        shell_profile = SimpleNamespace(executable=shell, argv_recipe=(str(shell), "{child_artifact}"))
        self.assertFalse(_argv_matches_recipe(shell_profile, [str(shell), "-c", "id"], {child: "a" * 64}))
        self.assertTrue(_argv_matches_recipe(shell_profile, [str(shell), child], {child: "a" * 64}))

    def test_desktop_launch_options_must_match_the_protected_recipe_exactly(self) -> None:
        executable = Path("/usr/bin/xpra")
        recipe = (str(executable), "start", "--bind-tcp=127.0.0.1:14500", "--html=on")
        profile = SimpleNamespace(executable=executable, argv_recipe=recipe)
        self.assertTrue(_argv_matches_recipe(profile, list(recipe), {}))
        for attempted in (
                [str(executable), "start", "--bind-tcp=0.0.0.0:14500", "--html=on"],
                [str(executable), "start", "--bind-tcp=127.0.0.1:14500", "--html=on", "--start=sh"],
                [str(executable), "start", "--profile=other", "--bind-tcp=127.0.0.1:14500"]):
            self.assertFalse(_argv_matches_recipe(profile, attempted, {}), attempted)


class ManagedProcessOperationRecipeTests(unittest.TestCase):
    def test_selection_resolves_only_root_recipe_and_typed_parameters(self) -> None:
        executable = Path("/protected/runtime/python")
        digest = "a" * 64
        child_ref = "artifact:installer-script:" + "b" * 64
        profile = ManagedProfileCustody(
            profile_id="installer", owner_uid=1001, owner_gid=1001,
            service_user="hermes-installer-test", executable=executable,
            artifact_sha256=digest, artifact_root=Path("/protected/artifacts"),
            data_root=Path("/var/tmp"), generation="generation:1",
            enrollment_id="enrollment:1", home_id="home:1", work_id="work:1", data_id="data:1",
            home_root=Path("/tmp"), work_root=Path.cwd(),
            operation_targets={"process.start": "installer:start"},
            operation_recipes={"install-stage": {
                "executable_artifact_id": "python-runtime", "executable_sha256": digest,
                "argv_recipe": (
                    {"literal": "installer-script"}, {"literal": "--stage"},
                    {"parameter": "stage"},
                ),
                "cwd_root_id": "work:1", "cwd_subpath": ".",
                "environment": {"HOME": "/hermes", "HERMES_HOME": "/hermes"},
                "child_artifact_refs": {"installer-script": "b" * 64},
                "max_lifetime_seconds": 60, "max_output_bytes": 4096,
                "stdin_mode": "closed", "parameter_schema_id": "stage-schema",
            }},
            parameter_schemas={"stage-schema": {"id": "stage-schema", "fields": [{
                "name": "stage", "type": "string", "required": True,
                "enum": ["manifest", "runtime"], "max_length": 16,
                "minimum": None, "maximum": None,
            }]}},
        )
        manager = object.__new__(ManagedProcessEffectHandler)
        manager.monotonic = time.monotonic
        manager.artifact_resolver = None
        manager._resolve_enrolled_artifact = lambda _ref, _digest, executable=False: Path(
            "/protected/runtime/python" if executable else "/protected/artifacts/installer-script"
        )
        captured: dict[str, object] = {}
        manager._start_reserved = lambda derived, _context, _authorization, payload, _timeout, _pid, _pidfd, _cancelled, **kwargs: (  # type: ignore[method-assign]
            captured.update(profile=derived, launch=json.loads(payload), canonical=kwargs["registered_profile"]) or {"ok": True}
        )
        now = time.monotonic()
        authorization = SimpleNamespace(monotonic_expires_at=now + 30)
        payload = json.dumps({
            "schema": 1, "enrollment_id": "enrollment:1", "generation": "generation:1",
            "operation_id": "install-stage", "parameters": {"stage": "runtime"},
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        result = manager.start_selected_operation(
            profile, SimpleNamespace(), authorization, payload, timeout=10,
            peer_pid=10, peer_pidfd=11, cancelled=lambda: False,
        )
        self.assertEqual(result, {"ok": True})
        self.assertEqual(captured["canonical"], profile)
        launch = captured["launch"]
        self.assertEqual(launch["target"], "installer:start")
        self.assertEqual(launch["cwd"], str(Path.cwd()))
        self.assertEqual(launch["argv"], [str(executable), child_ref, "--stage", "runtime"])
        self.assertEqual(launch["env_allowlist"], {"HOME": "/hermes", "HERMES_HOME": "/hermes"})

    def test_selection_rejects_path_parameters_and_unenrolled_operations(self) -> None:
        schema = {"id": "s", "fields": [{
            "name": "name", "type": "string", "required": True, "enum": None,
            "max_length": 64, "minimum": None, "maximum": None,
        }]}
        with self.assertRaisesRegex(Exception, "bounded scalar"):
            ManagedProcessEffectHandler._validate_operation_parameters({"name": "../secret"}, schema)


class ManagedProcessAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-managed-process-")
        self.owned = OwnedRoot(Path(self.temp.name))
        self.owned.ensure()
        # OwnedRoot canonicalizes the approved macOS /var alias to /private/var.
        # Build every fixture path from that same canonical root so tests exercise
        # the validator rather than failing on a lexical alias mismatch.
        self.root = self.owned.root
        self.artifact = self.root / "artifacts" / "test"
        self.data = self.root / "profiles" / "test"
        self.artifact.mkdir(parents=True)
        (self.data / "work").mkdir(parents=True)
        self.executable = self.artifact / "probe"
        self.executable.write_bytes(b"reviewed executable fixture")
        self.executable.chmod(0o700)
        self.journal = Journal(self.root / "journal.sqlite")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def spec(self, *, digest: str | None = None, lifetime: float = 30.0,
             executable: Path | None = None, data_root: Path | None = None,
             argv: tuple[str, ...] | None = None) -> ManagedProcessSpec:
        exe = executable or self.executable
        return ManagedProcessSpec(
            executable=exe,
            argv=argv or (str(exe), "--read-only"),
            artifact_sha256=digest or hashlib.sha256(exe.read_bytes()).hexdigest(),
            artifact_root=self.artifact,
            owned_root=self.owned,
            cwd=(data_root or self.data) / "work",
            data_root=data_root or self.data,
            env_allowlist={"HOME": "/hermes", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            journal_operation="test-operation",
            journal=self.journal,
            service_identity="contract-test",
            service_user="hermes-" + hashlib.sha256(b"fixture-profile").hexdigest()[:16],
            startup_deadline_monotonic=time.monotonic() + 5,
            max_lifetime_seconds=lifetime,
            profile_id="fixture-profile",
        )

    def test_admission_uses_private_owned_root_journal_and_pinned_artifact(self) -> None:
        spec = self.spec()
        owned, executable, artifact, cwd, data = _validate_spec(spec)
        self.assertIs(owned, self.owned)
        self.assertEqual(executable, self.executable.resolve())
        self.assertEqual(artifact, self.artifact.resolve())
        self.assertEqual(cwd, (self.data / "work").resolve())
        self.assertEqual(data, self.data.resolve())

    def test_changed_binary_hash_is_rejected(self) -> None:
        with self.assertRaisesRegex(ManagedProcessError, "artifact pin"):
            _validate_spec(self.spec(digest="0" * 64))

    def test_unowned_profile_or_substituted_argv_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaisesRegex(ManagedProcessError, "safe owned paths"):
                _validate_spec(self.spec(data_root=Path(outside)))
        spec = self.spec(argv=("/bin/sh", "-c", "true"))
        with self.assertRaisesRegex(ManagedProcessError, "argv must start"):
            _validate_spec(spec)

    def test_lifetime_is_mandatory_finite_and_bounded(self) -> None:
        for lifetime in (0, -1, float("inf"), 601):
            with self.subTest(lifetime=lifetime):
                with self.assertRaisesRegex(ManagedProcessError, "finite and at most"):
                    _validate_spec(self.spec(lifetime=lifetime))

    def test_environment_never_returns_manager_environment_values(self) -> None:
        keys = _manager_environment_keys("API_TOKEN=do-not-echo\nLANG=C\nDISPLAY=:0\n")
        self.assertIn("API_TOKEN", keys)
        self.assertIn("LANG", keys)
        self.assertNotIn("do-not-echo", repr(keys))

    def test_start_denies_without_trusted_authority_before_journaling(self) -> None:
        async def exercise() -> None:
            with self.assertRaisesRegex(ManagedProcessError, "trusted host context"):
                await ManagedProcessSupervisor().start(self.spec())
            self.assertIsNone(self.journal.operation("test-operation"))
        asyncio.run(exercise())


@unittest.skipUnless(sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                     "Linux pidfd and procfs are required")
class ManagedProcessKernelEvidenceTests(unittest.TestCase):
    def test_proc_executable_hash_and_pidfd_are_bound_to_live_child(self) -> None:
        child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(3)"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, close_fds=True,
        )
        pidfd = None
        try:
            cgroup = _proc_cgroup(child.pid)
            parent, ticks, digest, pidfd = _observe_process(child.pid, cgroup)
            self.assertGreater(parent, 1)
            self.assertGreater(ticks, 0)
            self.assertEqual(len(digest), 64)
            self.assertEqual(_proc_stat(child.pid)[1], ticks)
        finally:
            if pidfd is not None:
                os.close(pidfd)
            child.terminate()
            child.wait(timeout=2)

    def test_pipe_io_is_nonblocking_bounded_and_preserves_partial_progress(self) -> None:
        async def exercise() -> None:
            child = subprocess.Popen(
                [sys.executable, "-c",
                 "import sys; d=sys.stdin.buffer.read(131072); sys.stdout.buffer.write(d); sys.stdout.buffer.flush()"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                close_fds=True,
            )
            pidfd = None
            handle = None
            payload = b"x" * 131072
            try:
                cgroup = _proc_cgroup(child.pid)
                _, ticks, digest, pidfd = _observe_process(child.pid, cgroup)
                identity = ProcessIdentity("fixture.service", cgroup, child.pid, ticks, digest, pidfd)
                spec = _make_pipe_spec(self)
                started = time.monotonic()
                handle = ManagedProcessHandle(
                    spec, _FixtureAuthorityVerifier(), identity, "fixture-generation",
                    started, started + 30,
                )
                handle._check_live = AsyncMock()
                # This test is specifically about the handle's bounded partial
                # progress logic.  Simulate the root broker at the method
                # boundary while retaining real kernel pipes and a real child;
                # authority RPC and systemd admission have separate tests.
                cursors = {"stdout": 0, "stdin": 0}
                loop = asyncio.get_running_loop()

                async def wait_fd(fd: int, *, writable: bool) -> None:
                    ready = loop.create_future()
                    register = loop.add_writer if writable else loop.add_reader
                    unregister = loop.remove_writer if writable else loop.remove_reader
                    register(fd, lambda: not ready.done() and ready.set_result(None))
                    try:
                        await asyncio.wait_for(ready, timeout=2)
                    finally:
                        unregister(fd)

                async def broker_control(operation, fields, timeout=5.0):
                    if operation == "process.write":
                        chunk = base64.b64decode(fields["data"], validate=True)
                        while True:
                            try:
                                count = os.write(child.stdin.fileno(), chunk[:4096])
                                break
                            except BlockingIOError:
                                await wait_fd(child.stdin.fileno(), writable=True)
                        cursors["stdin"] += count
                        return {"schema": 1, "stdin_cursor": cursors["stdin"],
                                "bytes_written": count}
                    if operation == "process.read":
                        try:
                            data = os.read(child.stdout.fileno(), min(fields["max_bytes"], 4096))
                        except BlockingIOError:
                            await wait_fd(child.stdout.fileno(), writable=False)
                            data = os.read(child.stdout.fileno(), min(fields["max_bytes"], 4096))
                        cursors["stdout"] += len(data)
                        return {"schema": 1, "cursor": cursors["stdout"],
                                "data": base64.b64encode(data).decode("ascii"),
                                "eof": not data}
                    raise AssertionError(f"unexpected broker operation: {operation}")

                os.set_blocking(child.stdin.fileno(), False)
                os.set_blocking(child.stdout.fileno(), False)
                handle._control = broker_control
                self.assertEqual(await handle.write(payload[:65536], timeout=2), 65536)
                self.assertEqual(await handle.write(payload[65536:], timeout=2), 65536)
                result = bytearray()
                deadline = time.monotonic() + 3
                while len(result) < len(payload) and time.monotonic() < deadline:
                    try:
                        result.extend(await handle.read(min(65536, len(payload) - len(result)), timeout=.5))
                    except asyncio.TimeoutError:
                        continue
                self.assertEqual(bytes(result), payload)
                self.assertEqual(child.wait(timeout=2), 0)
            finally:
                if handle is not None:
                    handle._watchdog.cancel()
                if pidfd is not None:
                    os.close(pidfd)
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=2)
                for stream in (child.stdin, child.stdout):
                    if stream:
                        stream.close()

        asyncio.run(exercise())


def _make_pipe_spec(parent: unittest.TestCase) -> ManagedProcessSpec:
    # The handle exercises only its bounded pipe methods; admission itself is
    # covered independently and the test child is a real kernel subprocess.
    temp = tempfile.TemporaryDirectory(prefix="hermes-pipe-spec-")
    parent.addCleanup(temp.cleanup)
    root = Path(temp.name)
    owned = OwnedRoot(root)
    owned.ensure()
    artifacts = root / "artifacts"
    data = root / "profile"
    artifacts.mkdir()
    (data / "work").mkdir(parents=True)
    executable = artifacts / "fixture"
    executable.write_bytes(b"fixture")
    executable.chmod(0o700)
    journal = Journal(root / "journal.sqlite")
    return ManagedProcessSpec(
        executable=executable, argv=(str(executable),),
        artifact_sha256=hashlib.sha256(executable.read_bytes()).hexdigest(),
        artifact_root=artifacts, owned_root=owned, cwd=data / "work", data_root=data,
        env_allowlist={"HOME": "/hermes"}, journal_operation="pipe-test", journal=journal,
        service_identity="pipe-fixture", service_user="hermes-test", startup_deadline_monotonic=time.monotonic()+5,
        max_lifetime_seconds=30,
    )


@unittest.skip("superseded by tests/contracts/test_managed_process_custody_linux.py; this fixture used a fake authority route")
class ManagedProcessSystemdIntegrationTests(unittest.TestCase):
    """Exercise the real system manager when the Linux runner provides one."""
    @classmethod
    def setUpClass(cls) -> None:
        if not sys.platform.startswith("linux") or not shutil.which("sudo"):
            raise unittest.SkipTest("Linux systemd with noninteractive sudo is required")
        probe = subprocess.run(
            ["sudo", "-n", "/usr/bin/systemctl", "--system", "show-environment"],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=3, check=False,
        )
        if probe.returncode:
            raise unittest.SkipTest("system manager is not available in this CI runner")
        cls.profile_id = "ci-" + str(uuid.uuid4())
        cls.temp = tempfile.TemporaryDirectory(prefix="hermes-systemd-custody-")
        cls.root = Path(cls.temp.name)
        cls.owned = OwnedRoot(cls.root)
        cls.owned.ensure()
        cls.artifact = cls.root / "artifacts"
        cls.data = cls.root / "profile"
        self_path = Path(sys.executable).resolve()
        cls.artifact.mkdir(mode=0o755)
        cls.data.mkdir(mode=0o755)
        cls.work = cls.data / "work"
        cls.work.mkdir(mode=0o755)
        cls.executable = cls.artifact / "python"
        shutil.copyfile(self_path, cls.executable)
        cls.executable.chmod(0o755)
        cls.journal = Journal(cls.root / "journal.sqlite")
        cls.operation = "ci-custody-" + uuid.uuid4().hex[:12]
        cls.service_user, cls.service_uid, cls.service_gid = provision_service_identity(
            cls.owned, cls.journal, cls.profile_id, cls.operation)

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "temp"):
            cls.temp.cleanup()
        if hasattr(cls, "service_user"):
            subprocess.run(
                ["sudo", "-n", "/usr/sbin/userdel", cls.service_user],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=5, check=False,
            )

    def test_manager_applies_private_namespaces_and_kills_stubborn_descendant(self) -> None:
        with tempfile.NamedTemporaryFile(prefix="hermes-host-private-", dir=Path.home()) as host_secret:
            victim = subprocess.Popen(
                [sys.executable, "-c", "import time; time.sleep(30)"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True,
            )
            sentinel = str(Path(host_secret.name))
            code = (
                "import json,os,signal,socket,subprocess,sys,time; "
                "sentinel=sys.argv[1]; result={}; "
                "try_read=False; "
                "exec('try:\n open(sentinel, \'rb\').read(1); try_read=True\nexcept OSError: pass'); "
                "result['home_hidden']=not try_read; "
                "victim=int(sys.argv[2]); "
                "try: open('/proc/'+str(victim)+'/environ','rb').read(1); result['sibling_hidden']=False\n"
                "except OSError: result['sibling_hidden']=True; "
                "try: os.kill(victim,signal.SIGTERM); result['signal_denied']=False\n"
                "except PermissionError: result['signal_denied']=True; "
                "try:\n socket.socket(socket.AF_INET,socket.SOCK_STREAM); result['inet_denied']=False\n"
                "except OSError: result['inet_denied']=True; "
                "child=subprocess.Popen([sys.executable,'-c',"
                "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True); "
                "print(json.dumps(result),flush=True); time.sleep(25)"
            )
            spec = _authorized_spec(ManagedProcessSpec(
                executable=self.executable, argv=(str(self.executable), "-c", code, sentinel, str(victim.pid)),
                artifact_sha256=hashlib.sha256(self.executable.read_bytes()).hexdigest(),
                artifact_root=self.artifact, owned_root=self.owned, cwd=self.work, data_root=self.data,
                env_allowlist={"HOME": "/hermes", "PATH": "/usr/bin:/bin", "LANG": "C"},
                journal_operation=self.operation, journal=self.journal, service_identity="ci-isolation",
                service_user=self.service_user, startup_deadline_monotonic=time.monotonic()+10,
                max_lifetime_seconds=30,
                profile_id=self.profile_id,
            ))
            async def exercise() -> None:
                handle = await ManagedProcessSupervisor(_FixtureAuthorityVerifier()).start(spec)
                try:
                    self.assertEqual(handle.identity.uid, self.service_uid)
                    self.assertEqual(handle.identity.gid, self.service_gid)
                    self.assertNotEqual(handle.identity.network_namespace_inode,
                                        os.stat("/proc/self/ns/net").st_ino)
                    self.assertNotEqual(handle.identity.mount_namespace_inode,
                                        os.stat("/proc/self/ns/mnt").st_ino)
                    output = await handle.read(4096, timeout=5)
                    result = json.loads(output.decode())
                    self.assertEqual(result, {"home_hidden": True, "sibling_hidden": True,
                                              "signal_denied": True, "inet_denied": True})
                    deadline = time.monotonic() + 3
                    while len(handle._cgroup_pids()) < 2 and time.monotonic() < deadline:
                        await asyncio.sleep(.05)
                    self.assertGreaterEqual(len(handle._cgroup_pids()), 2)
                    await handle.stop("integration test", timeout=5)
                    self.assertFalse(handle._cgroup_pids())
                finally:
                    if not handle._closed:
                        await handle.stop("integration cleanup", timeout=5)
            try:
                asyncio.run(exercise())
            finally:
                if victim.poll() is None:
                    victim.terminate()
                    victim.wait(timeout=2)

    def test_managed_command_captures_separate_streams_and_proves_inode(self) -> None:
        from hermes_installer.managed_process import run_managed_process

        controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
        if not {"cpu", "memory", "io"}.issubset(controllers):
            self.skipTest("Linux cgroup v2 CPU, memory and I/O controllers are required")

        code = "import sys; print('out'); print('err', file=sys.stderr)"
        spec = _authorized_spec(ManagedProcessSpec(
            executable=self.executable, argv=(str(self.executable), "-c", code),
            artifact_sha256=hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            artifact_root=self.artifact, owned_root=self.owned, cwd=self.work, data_root=self.data,
            env_allowlist={"HOME": "/hermes", "PATH": "/usr/bin:/bin", "LANG": "C"},
            journal_operation=self.operation, journal=self.journal, service_identity="ci-capture",
            service_user=self.service_user, startup_deadline_monotonic=time.monotonic()+10,
            max_lifetime_seconds=20,
            profile_id=self.profile_id,
            memory_max_bytes=256 * 1024 * 1024, cpu_quota_percent=100, io_weight=100,
        ))
        async def exercise() -> None:
            result = await run_managed_process(spec, timeout=10, stdout_limit=128, stderr_limit=128,
                                               authority_verifier=_FixtureAuthorityVerifier())
            self.assertEqual(result.exit_code, 0)
            self.assertEqual(result.stdout, b"out\n")
            self.assertEqual(result.stderr, b"err\n")
            self.assertFalse(result.timed_out)
            self.assertFalse(result.cancelled)
            self.assertTrue(result.cleanup_verified)
            self.assertEqual(result.executable_device, self.executable.stat().st_dev)
            self.assertEqual(result.executable_inode, self.executable.stat().st_ino)
            self.assertGreater(result.start_ticks, 0)
            self.assertEqual(result.uid, self.service_uid)
            self.assertNotEqual(result.network_namespace_inode, os.stat("/proc/self/ns/net").st_ino)
            self.assertNotEqual(result.mount_namespace_inode, os.stat("/proc/self/ns/mnt").st_ino)
            self.assertEqual(result.memory_max_bytes, 256 * 1024 * 1024)
            self.assertEqual(result.cpu_quota_percent, 100)
            self.assertEqual(result.io_weight, 100)
            checkpoint = self.journal.operation(self.operation)
            self.assertEqual(checkpoint["status"], "stopped")
        asyncio.run(exercise())

    def test_managed_command_deadline_reaps_ignored_term_descendant(self) -> None:
        from hermes_installer.managed_process import run_managed_process

        code = (
            "import signal,subprocess,sys,time; "
            "subprocess.Popen([sys.executable,'-c',"
            "'import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True); "
            "print('ready',flush=True); time.sleep(30)"
        )
        spec = _authorized_spec(ManagedProcessSpec(
            executable=self.executable, argv=(str(self.executable), "-c", code),
            artifact_sha256=hashlib.sha256(self.executable.read_bytes()).hexdigest(),
            artifact_root=self.artifact, owned_root=self.owned, cwd=self.work, data_root=self.data,
            env_allowlist={"HOME": "/hermes", "PATH": "/usr/bin:/bin", "LANG": "C"},
            journal_operation=self.operation, journal=self.journal, service_identity="ci-deadline",
            service_user=self.service_user, startup_deadline_monotonic=time.monotonic()+10,
            max_lifetime_seconds=20,
            profile_id=self.profile_id,
        ))
        async def exercise() -> None:
            result = await run_managed_process(spec, timeout=3, stdout_limit=128, stderr_limit=128,
                                               authority_verifier=_FixtureAuthorityVerifier())
            self.assertTrue(result.timed_out)
            self.assertTrue(result.cleanup_verified)
            self.assertEqual(result.stdout, b"ready\n")
            self.assertFalse((Path("/sys/fs/cgroup") / result.cgroup.lstrip("/") / "cgroup.procs").exists())
            checkpoint = self.journal.operation(self.operation)
            self.assertEqual(checkpoint["status"], "stopped")
        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
