"""End-to-end kernel custody checks through a real root AuthorityService.

This module runs only in the disposable Ubuntu systemd CI job as root. Its
policy, principal and secrets are isolated test fixtures, not production
Authentik/host acceptance evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import pwd
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path

from hermes_installer.authority.client import canonical_bytes, canonical_digest
from hermes_installer.authority.daemon import DEFAULT_SOCKET_DIR
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import Sensitivity
from hermes_installer.managed_process_custodian import (
    ManagedProcessEffectHandler, ManagedProfileCustody,
    process_control_target, process_inspect_target, process_start_target,
)


class _ControlledCustodyPolicy:
    revision = "ci-controlled-custody-v1"

    def classify(self, *, purpose, intent, source_contexts, binding):
        if purpose == "custody-kernel-ci" and not source_contexts:
            return Sensitivity.UNKNOWN, canonical_digest({"fixture": intent, "uid": binding.uid})
        if (purpose == "managed-process-control" and len(source_contexts) == 1
                and source_contexts[0].purpose == "custody-kernel-ci"
                and source_contexts[0].profile_id == binding.profile_id
                and source_contexts[0].uid == binding.uid
                and source_contexts[0].namespace_id == binding.namespace_id):
            return Sensitivity.UNKNOWN, canonical_digest({
                "fixture-control": intent,
                "source_lineage_hash": source_contexts[0].lineage_hash,
            })
        return Sensitivity.UNKNOWN, canonical_digest({"rejected-fixture-context": intent})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return (context.purpose in {"custody-kernel-ci", "managed-process-control"}
                and context.profile_id.startswith("ci-custody-")
                and rule.capability in {"hermes-profile-invoke", "hermes-process-control"}
                and rule.operation in {"process.start", "process.status", "process.read", "process.write",
                                       "process.stop", "process.inspect"}
                and len(request_digest) == 64 and retry_index == 0)


def _drop_to(uid: int, gid: int):
    def drop() -> None:
        os.setgroups([])
        os.setgid(gid)
        os.setuid(uid)
    return drop


def _safe_runtime_dir(path: Path, *, create: bool) -> bool:
    """Check or create one root runtime directory; return whether test created it."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        if not create:
            raise
        path.mkdir(mode=0o711)
        os.chown(path, 0, 0)
        os.chmod(path, 0o711)
        return True
    if (not path.is_dir() or path.is_symlink() or info.st_uid != 0
            or info.st_mode & 0o022 or not info.st_mode & 0o001):
        raise RuntimeError(f"runtime fixture parent is not protected: {path}")
    return False


_RUN_PROBE_SOURCE = (
    "import json,os,signal,socket,subprocess,sys,time\n"
    "root_pid=__ROOT_PID__; home_secret=__HOME_SECRET__; credential=__CREDENTIAL__\n"
    "expected={'HOME':'/hermes','HERMES_HOME':'/hermes','PATH':'/usr/bin','LANG':'C'}\n"
    "def denied(path):\n"
    "    try:\n"
    "        with open(path,'rb') as source: source.read(1)\n"
    "        return False\n"
    "    except OSError: return True\n"
    "result={'environment_exact':dict(os.environ)==expected,\n"
    "        'root_home_hidden':denied(home_secret),'credential_directory_hidden':denied(credential),\n"
    "        'root_proc_hidden':denied('/proc/'+str(root_pid)+'/environ')}\n"
    "try: os.kill(root_pid,signal.SIGTERM); result['root_signal_denied']=False\n"
    "except OSError: result['root_signal_denied']=True\n"
    "for family,key in ((socket.AF_INET,'ipv4_denied'),(socket.AF_INET6,'ipv6_denied')):\n"
    "    try: socket.socket(family,socket.SOCK_STREAM); result[key]=False\n"
    "    except OSError: result[key]=True\n"
    "descendant=subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)\n"
    "result['descendant_pid']=descendant.pid\n"
    "print(json.dumps(result,sort_keys=True),flush=True)\n"
    "time.sleep(30)\n"
)
_PARENT_PROBE_SOURCE = (
    "import subprocess,sys,time\n"
    "subprocess.Popen([sys.executable,'-c','import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)\n"
    "print('parent-death-ready',flush=True)\n"
    "time.sleep(30)\n"
)


@unittest.skipUnless(platform.system() == "Linux" and hasattr(os, "pidfd_open"),
                     "requires Linux pidfd and systemd")
class ManagedProcessRootAuthorityIntegrationTests(unittest.TestCase):
    """Exercise actual authority RPC, systemd transient units, procfs and cgroups."""

    @classmethod
    def setUpClass(cls) -> None:
        if os.geteuid() != 0:
            raise unittest.SkipTest("dedicated UID kernel integration requires the isolated root CI job")
        if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
            raise unittest.SkipTest("cgroup v2 is unavailable")
        controllers = set(Path("/sys/fs/cgroup/cgroup.controllers").read_text().split())
        if not {"cpu", "memory", "io"}.issubset(controllers):
            raise unittest.SkipTest("cgroup v2 CPU, memory and I/O controllers are required")
        systemctl = Path("/usr/bin/systemctl")
        systemd_run = Path("/usr/bin/systemd-run")
        if not systemctl.is_file() or not systemd_run.is_file():
            raise unittest.SkipTest("system manager commands are unavailable")
        manager = subprocess.run([str(systemctl), "--system", "show-environment"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, timeout=3, check=False)
        if manager.returncode:
            raise unittest.SkipTest("systemd system manager is not active")
        cls.systemctl, cls.systemd_run = systemctl, systemd_run

    def setUp(self) -> None:
        self.token = uuid.uuid4().hex
        self.profile_id = "ci-custody-" + self.token[:12]
        self.service_user = "hermes-" + hashlib.sha256(self.profile_id.encode()).hexdigest()[:16]
        self.user_created = False
        self.runtime_dirs_created: list[Path] = []
        self.etc_dirs_created: list[Path] = []
        self.home_secret: Path | None = None
        self.credential_path: Path | None = None
        self.socket_path: Path | None = None
        self.socket_stop = threading.Event()
        self.server_errors: list[BaseException] = []
        self.server_thread: threading.Thread | None = None
        self.handler: ManagedProcessEffectHandler | None = None
        self.manager_diagnostics: list[bytes] = []
        self.clients: list[subprocess.Popen[str]] = []

        self._useradd(self.service_user)
        self.user_created = True
        account = pwd.getpwnam(self.service_user)
        self.uid, self.gid = account.pw_uid, account.pw_gid
        if self.uid <= 0 or self.gid <= 0 or os.getgrouplist(self.service_user, self.gid) != [self.gid]:
            self.fail("fixture account is not a unique, dedicated UID/GID")

        self.stage = Path(tempfile.mkdtemp(prefix="hermes-custody-ci-", dir="/run"))
        self.stage.chmod(0o755)
        self.runtime_dirs_created.append(self.stage)
        repository = Path(__file__).resolve().parents[2]
        self.client_source_root = self.stage / "client-source"
        shutil.copytree(repository / "src/hermes_installer", self.client_source_root / "hermes_installer")
        self.client_harness = self.stage / "managed_process_authority_harness.py"
        shutil.copyfile(repository / "tests/fixtures/managed_process_authority_harness.py", self.client_harness)
        self.client_harness.chmod(0o444)
        self.data_root = self.stage / "profile"
        self.data_root.mkdir(mode=0o700)
        os.chown(self.data_root, self.uid, self.gid)
        os.chmod(self.data_root, 0o700)

        self.executable = Path(sys.executable).resolve(strict=True)
        self.artifact_root = self.executable.parent.resolve(strict=True)
        for path in (self.executable, self.artifact_root):
            info = path.stat(follow_symlinks=False)
            if info.st_uid != 0 or info.st_mode & 0o022:
                self.skipTest("CI interpreter is not root-owned and immutable")
        self.digest = hashlib.sha256(self.executable.read_bytes()).hexdigest()

        installer_runtime = Path("/run/hermes-installer")
        authority_runtime = DEFAULT_SOCKET_DIR
        for directory in (installer_runtime, authority_runtime):
            if _safe_runtime_dir(directory, create=True):
                self.runtime_dirs_created.append(directory)

        self._prepare_host_secrets()
        self.script_root = self.stage / "immutable-scripts"
        self.script_root.mkdir(mode=0o755)
        os.chown(self.script_root, 0, 0)
        self.run_store_id, self.run_digest, self.run_script = self._enroll_script("run", self._run_probe_source())
        self.parent_store_id, self.parent_digest, self.parent_script = self._enroll_script("parent", self._parent_probe_source())
        self.child_refs = {self.run_store_id: self.run_digest, self.parent_store_id: self.parent_digest}
        self.profile = ManagedProfileCustody(
            profile_id=self.profile_id, owner_uid=self.uid, owner_gid=self.gid,
            service_user=self.service_user, executable=self.executable,
            artifact_sha256=self.digest, artifact_root=self.artifact_root,
            data_root=self.data_root, generation="ci-" + self.token[:16],
            max_lifetime_seconds=60,
            child_artifact_refs=self.child_refs,
            argv_recipe=(str(self.executable), "{child_artifact}"),
            authority_socket=DEFAULT_SOCKET_DIR / f"{self.uid}.sock",
        )
        self.socket_path = self.profile.authority_socket
        start_target = process_start_target(self.profile)
        effect_rules = [EffectRule("hermes-profile-invoke", "process.start", start_target)]
        for operation in ("process.status", "process.read", "process.write", "process.stop"):
            target = process_control_target(self.profile, operation)
            effect_rules.append(EffectRule("hermes-process-control", operation, target))
        effect_rules.append(EffectRule("hermes-process-control", "process.inspect",
                                       process_inspect_target(self.profile)))
        handlers = ManagedProcessEffectHandler({self.profile_id: self.profile},
                                                systemd_run=self.systemd_run,
                                                systemctl=self.systemctl,
                                                artifact_resolver=self._resolve_artifact)
        self.handler = handlers
        self.handler._diagnostic_sink = self.manager_diagnostics.append
        handler_map = handlers.handlers()
        service = AuthorityService(
            signing_key=os.urandom(32), key_id="ci-kernel-fixture",
            bindings_by_uid={self.uid: PrincipalBinding(
                uid=self.uid, principal_id="fixture-principal-" + self.token[:12],
                profile_id=self.profile_id, namespace_id="fixture-namespace-" + self.token[:12],
                capabilities=frozenset({"hermes-profile-invoke", "hermes-process-control"}),
            )},
            rules={(rule.capability, rule.operation, rule.target): rule for rule in effect_rules},
            handlers=handler_map, policy=_ControlledCustodyPolicy(),
            profile_generations={self.profile_id: self.profile.generation},
        )
        if self.socket_path.exists():
            self.fail("unique per-UID authority socket already exists")

        def serve() -> None:
            try:
                service.serve_unix(self.socket_path, socket_gid=self.gid,
                                   stop_event=self.socket_stop, expected_uid=0)
            except BaseException as exc:
                self.server_errors.append(exc)

        self.server_thread = threading.Thread(target=serve, name="ci-root-authority", daemon=True)
        self.server_thread.start()
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and not self.socket_path.exists():
            if self.server_errors:
                self.fail(f"root AuthorityService failed to bind: {type(self.server_errors[0]).__name__}")
            time.sleep(.025)
        self.assertTrue(self.socket_path.exists(), "root AuthorityService did not bind its per-UID socket")

    @staticmethod
    def _useradd(username: str) -> None:
        completed = subprocess.run(
            ["/usr/sbin/useradd", "--system", "--no-create-home", "--home-dir=/nonexistent",
             "--shell=/usr/sbin/nologin", "--user-group", username],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            timeout=5, check=False,
        )
        if completed.returncode:
            raise RuntimeError("could not create unique fixture-only process identity")

    def _prepare_host_secrets(self) -> None:
        root_home = Path(pwd.getpwuid(0).pw_dir)
        self.home_secret = root_home / f".hermes-custody-ci-{self.token}"
        fd = os.open(self.home_secret, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"fixture-only-secret")
        os.close(fd)

        base = Path("/etc/hermes-installer")
        credentials = base / "credentials"
        for directory in (base, credentials):
            try:
                info = directory.lstat()
            except FileNotFoundError:
                directory.mkdir(mode=0o755 if directory == base else 0o700)
                os.chown(directory, 0, 0)
                os.chmod(directory, 0o755 if directory == base else 0o700)
                self.etc_dirs_created.append(directory)
                continue
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != 0 or info.st_mode & 0o022):
                self.fail(f"credential fixture parent has unexpected custody: {directory}")
        fixture_dir = credentials / f"custody-ci-{self.token}"
        fixture_dir.mkdir(mode=0o700)
        self.credential_path = fixture_dir / "fixture-secret"
        fd = os.open(self.credential_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, b"fixture-only-credential")
        os.close(fd)

    def _enroll_script(self, label: str, source: str) -> tuple[str, str, Path]:
        path = self.script_root / f"{label}.py"
        data = source.encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o444)
        try:
            os.fchown(fd, 0, 0)
            os.write(fd, data)
            os.fchmod(fd, 0o444)
        finally:
            os.close(fd)
        return f"artifact:ci-{label}-{self.token[:16]}:{digest}", digest, path

    def _resolve_artifact(self, store_id: str, digest: str) -> Path:
        for enrolled_id, enrolled_digest, path in (
                (self.run_store_id, self.run_digest, self.run_script),
                (self.parent_store_id, self.parent_digest, self.parent_script)):
            if store_id == enrolled_id and digest == enrolled_digest:
                return path
        raise ValueError("test artifact is not enrolled")

    def _run_probe_source(self) -> str:
        return (_RUN_PROBE_SOURCE.replace("__ROOT_PID__", str(os.getpid()))
                .replace("__HOME_SECRET__", repr(str(self.home_secret)))
                .replace("__CREDENTIAL__", repr(str(self.credential_path))))

    @staticmethod
    def _parent_probe_source() -> str:
        return _PARENT_PROBE_SOURCE

    def _client(self, *, mode: str) -> subprocess.Popen[str]:
        config = {
            "profile_id": self.profile_id, "data_root": str(self.data_root),
            "executable": str(self.executable), "artifact_root": str(self.artifact_root),
            "artifact_sha256": self.digest, "service_user": self.service_user,
            "trace_id": "ci-trace-" + self.token[:12], "operation_id": "ci-op-" + self.token[:12],
            "environment": {"HOME": "/hermes", "HERMES_HOME": "/hermes",
                            "PATH": "/usr/bin", "LANG": "C"},
            "mode": mode, "artifact_ref": self.run_store_id if mode == "run" else self.parent_store_id,
            "child_artifact_refs": self.child_refs,
        }
        env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent",
               "PYTHONPATH": str(self.client_source_root), "PYTHONDONTWRITEBYTECODE": "1"}
        client = subprocess.Popen(
            [str(self.executable), str(self.client_harness)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd="/", env=env, close_fds=True,
            preexec_fn=_drop_to(self.uid, self.gid),
        )
        self.clients.append(client)
        return client

    def _start_client(self, *, mode: str, child_code: str = "", child_args: list[str] | None = None,
                      wait_ready: bool = True, argv_override: list[str] | None = None,
                      expect_denial: bool = False, startup_timeout: float = 12):
        client = self._client(mode=mode)
        config = {
            "profile_id": self.profile_id, "data_root": str(self.data_root),
            "executable": str(self.executable), "artifact_root": str(self.artifact_root),
            "artifact_sha256": self.digest, "service_user": self.service_user,
            "trace_id": "ci-trace-" + self.token[:12], "operation_id": "ci-op-" + self.token[:12],
            "environment": {"HOME": "/hermes", "HERMES_HOME": "/hermes",
                            "PATH": "/usr/bin", "LANG": "C"},
            "mode": mode, "artifact_ref": self.run_store_id if mode == "run" else self.parent_store_id,
            "child_artifact_refs": self.child_refs,
            "expect_denial": expect_denial,
            "startup_timeout": startup_timeout,
        }
        if argv_override is not None:
            config["argv_override"] = argv_override
        assert client.stdin is not None
        client.stdin.write(json.dumps(config) + "\n")
        client.stdin.close()
        if not wait_ready:
            return client, None
        import select
        ready, _, _ = select.select([client.stdout], [], [], 20)
        if not ready:
            client.kill()
            stdout, stderr = client.communicate()
            self.fail(f"unprivileged AuthorityClient did not start in time: {stderr[-1200:]} {stdout[-400:]}")
        line = client.stdout.readline()
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            stderr = client.stderr.read() if client.poll() is not None else ""
            diagnostics = b"\n".join(self.manager_diagnostics).decode("utf-8", "replace")
            self.fail(f"unprivileged AuthorityClient failed before readiness: {stderr[-1200:]} {line[-400:]} "
                      f"root-manager-diagnostic={diagnostics[-2048:]}")
        self.assertEqual(event.get("event"), "denied" if expect_denial else "started", event)
        return client, event

    def _root_wrapper(self, name: str, marker: Path, *, delay: float = 0.0) -> Path:
        wrapper = self.stage / name
        source = ("#!/usr/bin/python3\nimport os,sys,time\n"
                  f"open({str(marker)!r}, 'w').close()\n"
                  f"time.sleep({delay!r})\n"
                  f"os.execv('/usr/bin/{'systemctl' if name.startswith('systemctl') else 'systemd-run'}', "
                  f"['/usr/bin/{'systemctl' if name.startswith('systemctl') else 'systemd-run'}', *sys.argv[1:]])\n")
        fd = os.open(wrapper, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o755)
        try:
            os.fchown(fd, 0, 0)
            os.write(fd, source.encode())
            os.fchmod(fd, 0o755)
        finally:
            os.close(fd)
        return wrapper

    def test_authority_rpc_enforces_kernel_boundaries_and_stubborn_descendant_cleanup(self) -> None:
        child = r'''import json,os,signal,socket,subprocess,sys,time
root_pid=int(sys.argv[1]); home_secret=sys.argv[2]; credential=sys.argv[3]
expected=json.loads(sys.argv[4])
def denied(path):
    try:
        with open(path,'rb') as source: source.read(1)
        return False
    except OSError:
        return True
result={"environment_exact":dict(os.environ)==expected,
        "root_home_hidden":denied(home_secret),"credential_directory_hidden":denied(credential),
        "root_proc_hidden":denied('/proc/'+str(root_pid)+'/environ')}
try:
    os.kill(root_pid,signal.SIGTERM); result['root_signal_denied']=False
except OSError:
    result['root_signal_denied']=True
try:
    socket.socket(socket.AF_INET,socket.SOCK_STREAM); result['ipv4_denied']=False
except OSError:
    result['ipv4_denied']=True
try:
    socket.socket(socket.AF_INET6,socket.SOCK_STREAM); result['ipv6_denied']=False
except OSError:
    result['ipv6_denied']=True
descendant=subprocess.Popen([sys.executable,'-c',
    'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)'],
    stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True)
result['descendant_pid']=descendant.pid
print(json.dumps(result,sort_keys=True),flush=True)
time.sleep(30)
'''
        env_allowlist = {"HOME": "/hermes", "HERMES_HOME": "/hermes", "PATH": "/usr/bin", "LANG": "C"}
        args = [str(os.getpid()), str(self.home_secret), str(self.credential_path), json.dumps(env_allowlist)]
        client, started = self._start_client(mode="run", child_code=child, child_args=args)
        try:
            assert client.stdout is not None
            ready, _, _ = __import__("select").select([client.stdout], [], [], 20)
            self.assertTrue(ready, "client did not return its cleanup receipt")
            receipt_line = client.stdout.readline()
            if not receipt_line:
                client.wait(timeout=5)
                error_output = client.stderr.read(8192) if client.stderr is not None else ""
                diagnostics = b"\n".join(self.manager_diagnostics).decode("utf-8", "replace")
                self.fail(f"managed client exited before cleanup receipt (rc={client.returncode}); "
                          f"stderr={error_output[-4096:]!r}; root-manager-diagnostic={diagnostics[-2048:]}")
            result = json.loads(receipt_line)
            self.assertEqual(result.get("event"), "stopped", result)
            self.assertTrue(result.get("stdout_complete") and result.get("stdout", "").strip(),
                            f"child stdout lacked its bounded JSON line; stdout={result.get('stdout')!r}; "
                            f"stderr={result.get('stderr')!r}")
            try:
                child_effects = json.loads(result["stdout"])
            except json.JSONDecodeError as exc:
                self.fail(f"child stdout is not its bounded JSON probe; stdout={result.get('stdout')!r}; "
                          f"stderr={result.get('stderr')!r}; error={exc.msg} at {exc.pos}")
            self.assertEqual(child_effects["environment_exact"], True)
            for key in ("root_home_hidden", "credential_directory_hidden", "root_proc_hidden",
                        "root_signal_denied", "ipv4_denied", "ipv6_denied"):
                self.assertIs(child_effects[key], True, key)
            self.assertNotEqual(result["mount_namespace_inode"], os.stat("/proc/self/ns/mnt").st_ino)
            self.assertNotEqual(result["network_namespace_inode"], os.stat("/proc/self/ns/net").st_ino)
            self.assertEqual(result["uid"], self.uid)
            self.assertEqual(result["executable_device"], self.executable.stat().st_dev)
            self.assertEqual(result["executable_inode"], self.executable.stat().st_ino)
            self.assertTrue(result["cleanup_verified"])
            self.assertFalse(self.handler._pids(result["cgroup"]))
        finally:
            if client.poll() is None:
                client.kill()
            client.wait(timeout=5)
            if client.stderr is not None:
                error_output = client.stderr.read(2048)
                self.assertEqual(error_output, "")

    def test_parent_pidfd_death_stops_generation_and_reaps_descendant_cgroup(self) -> None:
        child = "import signal,subprocess,sys,time; subprocess.Popen([sys.executable,'-c'," \
                "'import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); time.sleep(30)']," \
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,close_fds=True); " \
                "print('parent-death-ready',flush=True); time.sleep(30)"
        client, started = self._start_client(mode="parent-death", child_code=child)
        process_id, cgroup = started["process_id"], started["cgroup"]
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(self.handler._pids(cgroup)) < 2:
                time.sleep(.025)
            self.assertGreaterEqual(len(self.handler._pids(cgroup)), 2)
            client.kill()
            client.wait(timeout=5)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and process_id in self.handler._handles:
                time.sleep(.025)
            self.assertNotIn(process_id, self.handler._handles)
            self.assertFalse(self.handler._pids(cgroup), "parent-death cleanup left a live cgroup member")
            self.assertIn(process_id, self.handler._finished)
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)

    def test_prelaunch_cancellation_after_slow_environment_probe_never_starts_unit(self) -> None:
        marker = self.stage / "environment-probe-entered"
        launch_marker = self.stage / "systemd-run-invoked"
        self.handler.systemctl = self._root_wrapper("systemctl-delayed", marker, delay=1.5)
        self.handler.systemd_run = self._root_wrapper("systemd-run-trap", launch_marker)
        client, _ = self._start_client(mode="run", wait_ready=False)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not marker.exists():
                time.sleep(.025)
            self.assertTrue(marker.exists(), "start did not enter the deliberately slow preparation probe")
            client.kill()
            client.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self.profile_id in self.handler._starting:
                time.sleep(.025)
            self.assertFalse(self.handler._starting, "cancelled start remained in preparation")
            self.assertFalse(self.handler._handles, "cancelled start created a managed process")
            self.assertFalse(launch_marker.exists(), "systemd-run was invoked after the caller disconnected")
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)

    def test_slow_preparation_cannot_outlive_launch_deadline_or_create_unit(self) -> None:
        marker = self.stage / "slow-environment-probe-entered"
        launch_marker = self.stage / "systemd-run-after-expiry"
        self.handler.systemctl = self._root_wrapper("systemctl-expiring", marker, delay=1.5)
        self.handler.systemd_run = self._root_wrapper("systemd-run-expiry-trap", launch_marker)
        client, _ = self._start_client(mode="run", wait_ready=False, startup_timeout=.7)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and not marker.exists():
                time.sleep(.025)
            self.assertTrue(marker.exists(), "start did not enter the slow preparation probe")
            client.wait(timeout=5)
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and self.profile_id in self.handler._starting:
                time.sleep(.025)
            self.assertFalse(self.handler._starting, "expired start remained in preparation")
            self.assertFalse(self.handler._handles, "expired start created a process handle")
            self.assertFalse(launch_marker.exists(), "expired start invoked systemd-run")
            assert client.stderr is not None
            self.assertNotIn("fixture-only", client.stderr.read(2048))
        finally:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)

    def test_signed_but_unenrolled_python_code_argv_is_denied_before_unit_creation(self) -> None:
        launch_marker = self.stage / "systemd-run-invoked-for-unenrolled-argv"
        self.handler.systemd_run = self._root_wrapper("systemd-run-argv-trap", launch_marker)
        for argv in (
                [str(self.executable), "-c", "open('/tmp/forbidden','w').close()"],
                [str(self.executable), "/tmp/untrusted-script.py"],
                [str(self.executable), "-m", "http.server"]):
            client, event = self._start_client(mode="reject", argv_override=argv, expect_denial=True)
            self.assertEqual(event["event"], "denied")
            self.assertEqual(client.wait(timeout=5), 0)
            self.assertFalse(self.handler._handles)
            self.assertFalse(self.handler._starting)
            self.assertFalse(launch_marker.exists(), "rejected argv reached systemd-run")
            assert client.stderr is not None
            self.assertEqual(client.stderr.read(2048), "")

    def tearDown(self) -> None:
        if self.handler is not None:
            for handle in tuple(self.handler._handles.values()):
                self.handler._stop(handle, timeout=5)
            if self.handler._handles:
                self.fail("fixture cleanup left active root-managed process handles")
        self.socket_stop.set()
        if self.server_thread is not None:
            self.server_thread.join(timeout=5)
            if self.server_thread.is_alive():
                self.fail("root AuthorityService listener did not stop")
        for client in self.clients:
            if client.poll() is None:
                client.kill()
                client.wait(timeout=5)
            for stream in (client.stdin, client.stdout, client.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        if self.socket_path is not None:
            try:
                self.socket_path.unlink()
            except FileNotFoundError:
                pass
        artifacts_uid = Path("/run/hermes-installer/process-artifacts") / str(getattr(self, "uid", ""))
        if artifacts_uid.exists() and artifacts_uid.is_dir() and not any(artifacts_uid.iterdir()):
            artifacts_uid.rmdir()
        artifacts_root = Path("/run/hermes-installer/process-artifacts")
        if artifacts_root.exists() and artifacts_root.is_dir() and not any(artifacts_root.iterdir()):
            artifacts_root.rmdir()
        if getattr(self, "credential_path", None) is not None:
            fixture_dir = self.credential_path.parent
            if fixture_dir.name == f"custody-ci-{self.token}":
                shutil.rmtree(fixture_dir)
        if self.home_secret is not None:
            self.home_secret.unlink(missing_ok=True)
        for directory in reversed(self.etc_dirs_created):
            try:
                directory.rmdir()
            except OSError:
                pass
        if self.user_created:
            subprocess.run(["/usr/sbin/userdel", self.service_user], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5, check=False)
        for directory in reversed(self.runtime_dirs_created):
            if directory == Path("/run/hermes-installer") or directory == DEFAULT_SOCKET_DIR:
                try:
                    directory.rmdir()
                except OSError:
                    pass
            elif directory.exists():
                shutil.rmtree(directory)
        if self.server_errors:
            self.fail(f"root AuthorityService failed: {type(self.server_errors[0]).__name__}")


if __name__ == "__main__":
    unittest.main()
