from __future__ import annotations

import asyncio
import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
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
)
from hermes_installer.state import Journal, OwnedRoot


class ManagedProcessAdmissionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-managed-process-")
        self.root = Path(self.temp.name)
        self.owned = OwnedRoot(self.root)
        self.owned.ensure()
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
            startup_deadline_monotonic=time.monotonic() + 5,
            max_lifetime_seconds=lifetime,
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
                handle = ManagedProcessHandle(spec, "fixture.service", cgroup, child, identity,
                                              time.monotonic(), {})
                handle._check_live = AsyncMock()
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
        service_identity="pipe-fixture", startup_deadline_monotonic=time.monotonic()+5,
        max_lifetime_seconds=30,
    )


if __name__ == "__main__":
    unittest.main()
