"""Pinned official Hermes installer stages, isolated in an installer-owned generation."""
from __future__ import annotations
import hashlib, json, os, signal, stat, subprocess, time, uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
import threading
from .network import BoundedNetwork, NetworkError
from .state import Journal, OwnedRoot, OwnershipError

HERMES_REPOSITORY = "https://github.com/NousResearch/hermes-agent.git"
HERMES_COMMIT = "7085fbf7753266fc4943c55ac04926186bc90005"
INSTALL_SCRIPT_BLOB = "055c725f114db694db751f34fd312e70f5ed90d8"
INSTALL_SCRIPT_URL = "https://raw.githubusercontent.com/NousResearch/hermes-agent/7085fbf7753266fc4943c55ac04926186bc90005/scripts/install.sh"
EXPECTED_STAGES = ("prerequisites", "repository", "venv", "python-deps", "config", "products", "setup", "gateway", "complete")

class BootstrapError(RuntimeError):
    """Safe bootstrap error that excludes downloaded content, env and command output."""

@dataclass(frozen=True)
class StageStatus:
    name: str
    state: str
    exit_code: int | None = None

@dataclass(frozen=True)
class BootstrapReport:
    commit: str
    generation: str
    hermes_home: str
    stages: tuple[StageStatus, ...]
    agent_ready: bool
    desktop_built: bool
    configuration_state: str
    resume_command: str

def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()

def _write_private(path: Path, data: bytes, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise OwnershipError("Installer staging file is a symlink")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass

def _child_state(proc: subprocess.Popen) -> str:
    """Inspect a direct child without reaping it, preserving its session ID as a safe group handle."""
    if proc.returncode is not None:
        return "reaped"
    if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
        return "unknown"
    try:
        result = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    except ChildProcessError:
        return "lost"
    except OSError:
        return "unknown"
    return "exited" if result is not None and result.si_pid == proc.pid else "running"


def _owned_process_group(proc: subprocess.Popen) -> bool:
    """Only signal the new session created for a still-unreaped Popen child."""
    try:
        return os.getpgid(proc.pid) == proc.pid and os.getsid(proc.pid) == proc.pid
    except (ProcessLookupError, PermissionError, OSError):
        return False


def _stop_group(proc: subprocess.Popen) -> bool:
    """Terminate only a process group whose unreaped leader proves our custody."""
    lock = getattr(proc, "_hermes_cleanup_lock", None)
    if lock is None:
        lock = threading.Lock()
        setattr(proc, "_hermes_cleanup_lock", lock)
    with lock:
        state = _child_state(proc)
        if state in {"lost", "unknown", "reaped"} or not _owned_process_group(proc):
            return False
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        deadline = time.monotonic() + 1.0
        while time.monotonic() < deadline:
            state = _child_state(proc)
            if state in {"lost", "unknown", "reaped"}:
                return False
            if state == "exited":
                break
            time.sleep(0.025)
        # WNOWAIT leaves the session leader unreaped here. Its PID/PGID cannot
        # be recycled while SIGKILL reaches any remaining descendants.
        if _child_state(proc) == "lost" or not _owned_process_group(proc):
            return False
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            return False
        return True

class HermesBootstrap:
    """Runs exact upstream script content and stage names; callers cannot inject commands."""
    def __init__(self, data_root: OwnedRoot, state: Journal, *, network: BoundedNetwork | None = None,
                 runner: Callable | None = None, desktop_builder: Callable | None = None, agent_probe: Callable | None = None, expected_script_blob: str = INSTALL_SCRIPT_BLOB):
        self.data_root = data_root
        self.state = state
        self.network = network or BoundedNetwork(deadline_seconds=20, socket_timeout=8, max_response_bytes=128 * 1024)
        self.runner = runner or self._run_process
        self.desktop_builder = desktop_builder or self._run_desktop_source_build
        self.agent_probe = agent_probe or self._verify_agent_runtime
        self.expected_script_blob = expected_script_blob
        self.install_dir = data_root.path("generations/hermes-agent-" + HERMES_COMMIT[:12])
        self.hermes_home = data_root.path("profiles/default")
        self.private_home = data_root.path("runtime/bootstrap-home")
        self.script_path = data_root.path("cache/hermes-install-" + HERMES_COMMIT[:12] + ".sh")
        self.operation = "hermes-agent:" + HERMES_COMMIT

    def _script_bytes(self) -> bytes:
        try:
            response = self.network.request(INSTALL_SCRIPT_URL, method="GET", headers={"Accept": "text/plain"})
        except NetworkError:
            raise BootstrapError("Pinned official Hermes installer download failed or exceeded its deadline") from None
        if response.status != 200 or git_blob_sha1(response.body) != self.expected_script_blob:
            raise BootstrapError("Pinned official Hermes installer content did not match its Git object identity")
        if not response.body.startswith(b"#!/usr/bin/env bash\n") or len(response.body) > 128 * 1024:
            raise BootstrapError("Pinned official Hermes installer format or size is invalid")
        return response.body

    def prepare(self) -> None:
        self.data_root.ensure()
        for relative in ("generations", "profiles", "runtime", "runtime/bootstrap-home", "runtime/bootstrap-home/share",
                         "runtime/bootstrap-home/config", "runtime/bootstrap-home/cache", "cache"):
            self.data_root.path(relative).mkdir(parents=True, exist_ok=True, mode=0o700)
        content = self._script_bytes()
        _write_private(self.script_path, content)
        self.hermes_home.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.hermes_home.is_symlink() or self.private_home.is_symlink():
            raise OwnershipError("Hermes profile or private bootstrap home cannot be a symlink")

    def _environment(self) -> dict[str, str]:
        home = str(self.private_home)
        return {
            "PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": home,
            "HERMES_HOME": str(self.hermes_home),
            "XDG_DATA_HOME": str(self.private_home / "share"),
            "XDG_CONFIG_HOME": str(self.private_home / "config"),
            "XDG_CACHE_HOME": str(self.private_home / "cache"),
            "XDG_STATE_HOME": str(self.private_home / "state"),
            "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
            "UV_NO_CONFIG": "1", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0", "GIT_LFS_SKIP_SMUDGE": "1",
        }

    def _base_args(self) -> list[str]:
        return ["--commit", HERMES_COMMIT, "--dir", str(self.install_dir), "--hermes-home", str(self.hermes_home)]

    def _run_process(self, args: list[str], *, timeout: float, capture: bool = False) -> tuple[int, bytes]:
        bash = Path("/bin/bash").resolve(strict=True)
        if bash != Path("/usr/bin/bash").resolve(strict=False) and not bash.is_file():
            raise BootstrapError("Reviewed system Bash was not found")
        cmd = [str(bash), str(self.script_path), *args]
        proc = subprocess.Popen(cmd, cwd=self.data_root.root, env=self._environment(), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, shell=False, close_fds=True, start_new_session=True)
        proc._hermes_cleanup_lock = threading.Lock()
        if not capture:
            try:
                return proc.wait(timeout=timeout), b""
            except subprocess.TimeoutExpired:
                if not _stop_group(proc):
                    raise BootstrapError("Installer timeout could not safely confirm process-group ownership") from None
                return 124, b""
            except BaseException:
                _stop_group(proc)
                raise

        assert proc.stdout is not None
        output = bytearray()
        overflow = threading.Event()
        eof = threading.Event()

        def drain() -> None:
            while True:
                block = proc.stdout.read(8192)
                if not block:
                    eof.set()
                    return
                if len(output) + len(block) > 64 * 1024:
                    overflow.set()
                elif not overflow.is_set():
                    output.extend(block)

        reader = threading.Thread(target=drain, name="hermes-manifest-reader", daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        try:
            while True:
                if overflow.is_set():
                    if not _stop_group(proc):
                        raise BootstrapError("Manifest output exceeded its bound and child ownership was unavailable") from None
                    reader.join(timeout=1)
                    raise BootstrapError("Official installer manifest exceeded its output bound")
                state = _child_state(proc)
                if state == "lost":
                    raise BootstrapError("Installer child custody was lost; refusing to signal a process group")
                if state == "unknown":
                    raise BootstrapError("Installer child state could not be verified safely")
                if state == "reaped":
                    raise BootstrapError("Installer child was reaped outside the bounded runner")
                if state == "exited":
                    reader.join(timeout=1)
                    if reader.is_alive() or not eof.is_set():
                        if not _stop_group(proc):
                            raise BootstrapError("Manifest child left an unowned output descendant") from None
                        reader.join(timeout=1)
                        raise BootstrapError("Manifest child left an output descendant")
                    code = proc.wait()
                    return code, bytes(output)
                if time.monotonic() >= deadline:
                    if not _stop_group(proc):
                        raise BootstrapError("Installer timeout could not safely confirm process-group ownership") from None
                    reader.join(timeout=1)
                    return 124, b""
                time.sleep(0.025)
        except BaseException:
            if proc.returncode is None:
                _stop_group(proc)
            reader.join(timeout=0.5)
            raise
        finally:
            proc.stdout.close()

    def _manifest(self) -> None:
        code, raw = self.runner(["--manifest", "--json", *self._base_args()], timeout=30, capture=True)
        if code != 0:
            raise BootstrapError("Pinned Hermes installer could not provide its stage manifest")
        try:
            value = json.loads(raw)
            stages = value["stages"]
            names = tuple(item["name"] for item in stages)
        except (ValueError, TypeError, KeyError):
            raise BootstrapError("Pinned Hermes installer returned an invalid stage manifest") from None
        if value.get("protocol_version") != 1 or names != EXPECTED_STAGES:
            raise BootstrapError("Pinned Hermes installer stage protocol changed; review the upstream pin before continuing")

    def _completed_stages(self) -> dict[str, str]:
        return {str(row["resource_id"]).split(":", 1)[1]: str(row["state"])
                for row in self.state.owned("hermes-stage")
                if str(row["resource_id"]).startswith(HERMES_COMMIT + ":")}

    def _generation_marker(self) -> bytes:
        return ("schema=1\ncommit=" + HERMES_COMMIT + "\n").encode("ascii")

    def _write_generation_marker(self) -> None:
        marker = self.install_dir.parent / ("." + self.install_dir.name + ".owned")
        if marker.exists() or marker.is_symlink():
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
            try:
                fd = os.open(marker, flags)
                try:
                    info = os.fstat(fd)
                    data = os.read(fd, 256)
                finally:
                    os.close(fd)
            except OSError:
                raise OwnershipError("Generation ownership marker cannot be safely verified") from None
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077 or data != self._generation_marker():
                raise OwnershipError("Generation ownership marker is invalid; existing source was preserved")
        else:
            _write_private(marker, self._generation_marker(), 0o600)

    def _source_head(self) -> str | None:
        git = self.install_dir / ".git"
        if git.is_symlink():
            return None
        if git.is_file():
            try:
                raw = git.read_text(encoding="utf-8").strip()
            except OSError:
                return None
            if not raw.startswith("gitdir: ") or "\\" in raw:
                return None
            git = (self.install_dir / raw[8:]).resolve(strict=False)
            if not git.is_relative_to(self.install_dir):
                return None
        if not git.is_dir():
            return None
        try:
            value = (git / "HEAD").read_text(encoding="ascii").strip()
        except OSError:
            return None
        if len(value) == 40 and all(ch in "0123456789abcdef" for ch in value):
            return value
        if value.startswith("ref: refs/heads/"):
            refname = value[5:]
            ref = git / refname
            try:
                resolved = ref.read_text(encoding="ascii").strip()
            except OSError:
                try:
                    lines = (git / "packed-refs").read_text(encoding="ascii").splitlines()
                except OSError:
                    return None
                resolved = next((fields[0] for line in lines if len(fields := line.split()) == 2 and fields[1] == refname), "")
            if len(resolved) == 40 and all(ch in "0123456789abcdef" for ch in resolved):
                return resolved
        return None

    def _existing_source_is_resumable(self, previous: dict[str, object] | None) -> bool:
        if self.install_dir.is_symlink():
            return False
        owned = any(row["resource_id"] == str(self.install_dir) and row["state"] == "active"
                    for row in self.state.owned("hermes-generation"))
        marker = self.install_dir.parent / ("." + self.install_dir.name + ".owned")
        if marker.exists() or marker.is_symlink():
            try:
                self._write_generation_marker()
            except OwnershipError:
                return False
        elif self.install_dir.exists():
            return False
        if self.install_dir.exists() and not self.install_dir.is_dir():
            return False
        if self.install_dir.exists() and not owned:
            return False
        if not self.install_dir.exists():
            if not marker.exists():
                return True
            return owned and bool(previous and previous.get("status") in {"running:repository", "failed:repository"})
        head = self._source_head()
        if head is None:
            return bool(owned and previous and previous.get("status") in {"running:repository", "failed:repository"})
        return head == HERMES_COMMIT


    def _run_desktop_source_build(self, *, timeout: float) -> tuple[int, bytes]:
        hermes = self.install_dir / ".hermes" / "bin" / "hermes"
        if not hermes.is_file() or hermes.is_symlink():
            raise BootstrapError("Pinned Hermes CLI entrypoint is unavailable for the source Desktop build")
        desktop_env = self._environment()
        desktop_env["HERMES_DESKTOP_HERMES_ROOT"] = str(self.install_dir)
        desktop_env["HERMES_DESKTOP_USER_DATA_DIR"] = str(self.data_root.path("runtime/desktop-user-data"))
        desktop_env["HERMES_DESKTOP_APP_NAME"] = "Hermes Installer Candidate"
        Path(desktop_env["HERMES_DESKTOP_USER_DATA_DIR"]).mkdir(parents=True,exist_ok=True,mode=0o700)
        proc = subprocess.Popen([str(hermes), "desktop", "--build-only", "--source"], cwd=self.install_dir,
            env=desktop_env, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, shell=False, close_fds=True, start_new_session=True)
        try:
            return proc.wait(timeout=timeout), b""
        except subprocess.TimeoutExpired:
            _stop_group(proc)
            return 124, b""

    def _verify_agent_runtime(self) -> bool:
        hermes = self.install_dir / ".hermes" / "bin" / "hermes"
        if hermes.is_symlink() or not hermes.is_file() or not os.access(hermes, os.X_OK):
            return False
        if self._source_head() != HERMES_COMMIT:
            return False
        proc = subprocess.Popen([str(hermes), "--version"], cwd=self.install_dir, env=self._environment(),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False,
            close_fds=True, start_new_session=True)
        proc._hermes_cleanup_lock = threading.Lock()
        chunks: list[bytes] = []
        seen = 0
        overflow = threading.Event()
        eof = threading.Event()

        def drain() -> None:
            nonlocal seen
            assert proc.stdout is not None
            while True:
                block = proc.stdout.read(1024)
                if not block:
                    eof.set()
                    return
                seen += len(block)
                if seen <= 8192 and not overflow.is_set():
                    chunks.append(block)
                else:
                    overflow.set()

        reader = threading.Thread(target=drain, name="hermes-version-reader", daemon=True)
        reader.start()
        deadline = time.monotonic() + 20
        try:
            while True:
                if overflow.is_set():
                    _stop_group(proc)
                    reader.join(timeout=1)
                    return False
                state = _child_state(proc)
                if state in {"lost", "unknown", "reaped"}:
                    return False
                if state == "exited":
                    reader.join(timeout=1)
                    if reader.is_alive() or not eof.is_set():
                        _stop_group(proc)
                        reader.join(timeout=1)
                        return False
                    code = proc.wait()
                    output = b"".join(chunks).strip()
                    return code == 0 and not overflow.is_set() and bool(output)
                if time.monotonic() >= deadline:
                    _stop_group(proc)
                    reader.join(timeout=1)
                    return False
                time.sleep(0.025)
        finally:
            if proc.stdout is not None:
                proc.stdout.close()

    def install(self, *, include_desktop: bool = True, timeout_per_stage: float = 7200) -> BootstrapReport:
        if not 60 <= timeout_per_stage <= 14_400:
            raise ValueError("Stage timeout is outside the supported bound")
        self.prepare()
        self._manifest()
        previous = self.state.operation(self.operation)
        if not self._existing_source_is_resumable(previous):
            raise OwnershipError("Pinned source generation already exists without a resumable installer checkpoint; it was preserved")
        done = self._completed_stages()
        self.install_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.state.record_owned("hermes-generation", str(self.install_dir), "active")
        self._write_generation_marker()
        statuses: list[StageStatus] = []
        skipped = {"setup", "gateway"}
        desktop_output = self.install_dir / "apps" / "desktop" / "dist" / "index.html"
        for stage in EXPECTED_STAGES:
            if done.get(stage) in {"complete", "skipped"}:
                if stage != "products" or not include_desktop or desktop_output.is_file():
                    statuses.append(StageStatus(stage, done[stage]))
                    continue
            extra: list[str] = []
            self.state.checkpoint(self.operation, "running:" + stage, {
                "commit": HERMES_COMMIT, "stage": stage, "generation": str(self.install_dir),
                "hermes_home": str(self.hermes_home), "desktop_requested": bool(include_desktop),
            })
            args = ["--stage", stage, "--json", "--non-interactive", *self._base_args(), *extra]
            # Skip optional integrations during base installation; their adapters
            # configure them only after explicit component selection.
            args += ["--skip-browser", "--skip-computer-use"]
            code, _ = self.runner(args, timeout=timeout_per_stage, capture=False)
            if code != 0:
                self.state.checkpoint(self.operation, "failed:" + stage, {
                    "commit": HERMES_COMMIT, "stage": stage, "exit_code": code,
                    "generation": str(self.install_dir), "resume": "hermes-installer resume",
                })
                raise BootstrapError(f"Hermes stage {stage} did not complete (exit {code}); use hermes-installer resume")
            state = "skipped" if stage in skipped else "complete"
            self.state.record_owned("hermes-stage", HERMES_COMMIT + ":" + stage, state)
            self.state.checkpoint(self.operation, "stage:" + stage, {
                "commit": HERMES_COMMIT, "stage": stage, "state": state,
                "generation": str(self.install_dir), "hermes_home": str(self.hermes_home),
            })
            statuses.append(StageStatus(stage, state, code))
        completion = self.install_dir / ".hermes-bootstrap-complete"
        try:
            complete = json.loads(completion.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            complete = {}
        if complete.get("pinnedCommit") != HERMES_COMMIT or not self.agent_probe():
            raise BootstrapError("Pinned Hermes source or executable runtime verification failed")
        desktop_dir = self.install_dir / "apps" / "desktop"
        desktop_built = False
        if include_desktop:
            code, _ = self.desktop_builder(timeout=timeout_per_stage)
            dist_index = desktop_dir / "dist" / "index.html"
            desktop_built = code == 0 and dist_index.is_file() and not dist_index.is_symlink() and dist_index.stat().st_size > 100
        self.state.checkpoint(self.operation, "complete", {
            "commit": HERMES_COMMIT, "generation": str(self.install_dir), "desktop_built": desktop_built,
            "configuration_state": "pending: provider and gateway setup were safely skipped",
        })
        return BootstrapReport(HERMES_COMMIT, str(self.install_dir), str(self.hermes_home), tuple(statuses),
            True, desktop_built, "pending: configure a supported provider and user-session services",
            "hermes-installer resume")

    def status(self) -> dict[str, object]:
        return {"commit": HERMES_COMMIT, "generation": str(self.install_dir),
                "hermes_home": str(self.hermes_home), "stages": self._completed_stages(),
                "source_present": self.install_dir.is_dir(),
                "complete": (self.install_dir / ".hermes-bootstrap-complete").is_file()}
