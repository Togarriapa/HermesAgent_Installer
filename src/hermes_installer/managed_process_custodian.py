"""Root-side fixed process verbs for the protected AuthorityService.

This adapter is injected into the root-owned authority daemon. It accepts no
shell command or arbitrary manager property and trusts only protected profile
registrations plus the already verified, consumed host effect grant.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import pwd
import re
import select
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext, canonical_digest


@dataclass(frozen=True, slots=True)
class ManagedProfileCustody:
    profile_id: str
    owner_uid: int
    owner_gid: int
    service_user: str
    executable: Path
    artifact_sha256: str
    artifact_root: Path
    data_root: Path
    generation: str
    memory_max_bytes: int | None = None
    cpu_quota_percent: int | None = None
    io_weight: int | None = None
    max_lifetime_seconds: float = 600.0
    child_artifact_refs: Mapping[str, str] | None = None
    argv_recipe: tuple[str, ...] | None = None
    authority_socket: Path | None = None


@dataclass(slots=True)
class _Handle:
    process_id: str
    profile: ManagedProfileCustody
    unit: str
    cgroup: str
    launcher: subprocess.Popen[bytes]
    parent_pidfd: int
    child_pidfd: int
    pid: int
    start_ticks: int
    kernel_namespace_id: str
    principal_id: str
    authority_namespace_id: str
    started: float
    expires: float
    output_cap: int
    artifact_mount_dir: Path
    stdin_cursor: int = 0
    stdout_cursor: int = 0
    stderr_cursor: int = 0
    stopped: bool = False
    lock: threading.RLock | None = None


_LAUNCH_FIELDS = {
    "schema", "target", "profile_id", "executable", "artifact_sha256", "artifact_root",
    "cwd", "data_root", "argv", "env_allowlist", "child_artifact_refs",
    "max_lifetime_seconds", "max_output_bytes", "stdin_mode",
}
_ALLOWED_ENV = {
    "HOME", "PATH", "LANG", "LC_ALL", "DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HERMES_HOME", "TMPDIR",
}


def process_start_target(profile: ManagedProfileCustody) -> str:
    return (f"hermes-profile-invoke:{profile.profile_id}:{profile.executable}:"
            f"{profile.artifact_sha256}:{profile.data_root}")


def process_control_target(profile: ManagedProfileCustody, operation: str) -> str:
    if operation not in {"process.status", "process.read", "process.write", "process.stop"}:
        raise ValueError("process control operation is not fixed")
    verb = operation.removeprefix("process.")
    return f"hermes-profile-control:{profile.profile_id}:{profile.data_root}:{verb}"


def _code_interpreter(name: str) -> bool:
    normalized = name.casefold()
    return (normalized in {"bash", "sh", "dash", "zsh", "node", "ruby", "perl"}
            or normalized.startswith("python"))


def _argv_matches_recipe(profile: ManagedProfileCustody, argv: list[str],
                         children: Mapping[str, str]) -> bool:
    """Only root-enrolled argv templates may execute; child code is catalog-bound."""
    recipe = profile.argv_recipe
    if not recipe or len(recipe) != len(argv) or recipe[0] != str(profile.executable):
        return False
    code_interpreter = _code_interpreter(profile.executable.name)
    if code_interpreter:
        # A profile may run only an immutable, catalog-enrolled script. Never accept
        # -c/-e, inline code, caller paths, or interpreter override flags.
        return (len(recipe) == 2 and recipe[1] == "{child_artifact}" and len(children) > 0
                and len(argv) == 2 and argv[1] in children)
    if any(arg.startswith("artifact:") for arg in argv[1:]):
        return False
    # Application-specific options may be present only when the protected root
    # enrollment pins them byte-for-byte in the recipe. Caller additions and
    # profile/config overrides therefore fail the exact comparison below.
    return all(expected == "{child_artifact}" and actual in children or expected == actual
               for expected, actual in zip(recipe, argv))


def _root_path(path: Path, *, directory: bool) -> Path:
    if not path.is_absolute():
        raise ValueError("protected executable paths must be absolute")
    cursor = Path(path.anchor)
    for index, part in enumerate(path.parts[1:], start=1):
        cursor /= part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("protected executable path traverses a symlink")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise ValueError("protected executable path has an untrusted writable ancestor")
    resolved = path.resolve(strict=True)
    info = resolved.stat(follow_symlinks=False)
    if (directory and not stat.S_ISDIR(info.st_mode)) or (not directory and not stat.S_ISREG(info.st_mode)):
        raise ValueError("protected executable path has the wrong type")
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("protected executable path is writable by an untrusted identity")
    return resolved


def _pidfd_exited(pidfd: int) -> bool:
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def _pid_identity(pid: int) -> tuple[int, str, int, int]:
    raw = Path(f"/proc/{pid}/stat").read_text()
    ticks = int(raw[raw.rfind(")") + 2:].split()[19])
    groups = [line.split(":", 2)[2] for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines()
              if line.startswith("0::")]
    if len(groups) != 1:
        raise AuthorityDenied("process.identity", "worker cgroup is unavailable")
    exe = Path(f"/proc/{pid}/exe")
    st = exe.stat()
    return ticks, groups[0], st.st_dev, st.st_ino


def _response(status: int, body: Mapping[str, Any]) -> Mapping[str, Any]:
    encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(encoded) > 262144:
        raise AuthorityDenied("process.response", "process receipt exceeds its bound")
    return {"status": status, "body": encoded, "headers": {"content-type": "application/json"},
            "receipt_id": uuid.uuid4().hex}


def _artifact_mount_slot(owner_uid: int, process_id: str) -> Path:
    """Create a root-only-to-modify, per-process mount target below fixed /run."""
    if type(owner_uid) is not int or owner_uid <= 0 or not re.fullmatch(r"[0-9a-f]{32}", process_id):
        raise AuthorityDenied("process.artifact", "artifact mount identity is invalid")
    base = Path("/run/hermes-installer")
    info = base.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_mode & 0o022):
        raise AuthorityDenied("process.artifact", "fixed runtime directory custody is invalid")
    parent = base / "process-artifacts"
    try:
        parent.mkdir(mode=0o711)
    except FileExistsError:
        pass
    else:
        os.chown(parent, 0, 0)
        os.chmod(parent, 0o711)
    info = parent.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "artifact runtime directory custody is invalid")
    user_dir = parent / str(owner_uid)
    try:
        user_dir.mkdir(mode=0o711)
    except FileExistsError:
        pass
    else:
        os.chown(user_dir, 0, 0)
        os.chmod(user_dir, 0o711)
    info = user_dir.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "profile artifact runtime directory custody is invalid")
    slot = user_dir / process_id
    slot.mkdir(mode=0o711)
    os.chown(slot, 0, 0)
    os.chmod(slot, 0o711)
    info = slot.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("process.artifact", "per-process artifact mount slot is not protected")
    return slot


def _remove_artifact_mount(slot: Path) -> None:
    """Remove only the exact root-created placeholder; never recurse through a path."""
    try:
        info = slot.lstat()
    except FileNotFoundError:
        return
    parent_info = slot.parent.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o711
            or slot.parent.parent != Path("/run/hermes-installer/process-artifacts")
            or not slot.parent.name.isdecimal() or parent_info.st_uid != 0
            or not stat.S_ISDIR(parent_info.st_mode) or stat.S_IMODE(parent_info.st_mode) != 0o711
            or not re.fullmatch(r"[0-9a-f]{32}", slot.name)):
        raise AuthorityDenied("process.artifact", "artifact mount slot changed custody")
    for child in slot.iterdir():
        child_info = child.lstat()
        if (child.name != "child-1" or not stat.S_ISREG(child_info.st_mode)
                or child_info.st_uid != 0 or stat.S_IMODE(child_info.st_mode) != 0o444):
            raise AuthorityDenied("process.artifact", "unexpected artifact mount slot content")
        child.unlink()
    slot.rmdir()


class ManagedProcessEffectHandler:
    """Root-only process.start/status/read/write/stop fixed-verb adapter."""

    def __init__(self, profiles: Mapping[str, ManagedProfileCustody], *,
                 systemd_run: Path = Path("/usr/bin/systemd-run"),
                 systemctl: Path = Path("/usr/bin/systemctl"),
                 artifact_resolver: Callable[[str, str], Any] | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if not profiles or any(key != item.profile_id for key, item in profiles.items()):
            raise ValueError("root process custody requires an explicit profile registry")
        self.profiles = dict(profiles)
        self.systemd_run = _root_path(systemd_run, directory=False)
        self.systemctl = _root_path(systemctl, directory=False)
        self.monotonic = monotonic
        self.artifact_resolver = artifact_resolver
        self._handles: dict[str, _Handle] = {}
        self._finished: dict[str, tuple[str, float]] = {}
        self._starting: set[str] = set()
        self._lock = threading.RLock()
        # Root-only test harness may capture bounded manager diagnostics. This
        # is never serialized to a worker or populated from caller text.
        self._diagnostic_sink: Callable[[bytes], None] | None = None
        for profile in self.profiles.values():
            self._validate_profile(profile)

    @staticmethod
    def _validate_profile(profile: ManagedProfileCustody) -> None:
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", profile.profile_id)
                or profile.owner_uid <= 0 or profile.owner_gid <= 0):
            raise ValueError("protected process profile identity is invalid")
        expected_user = "hermes-" + hashlib.sha256(profile.profile_id.encode()).hexdigest()[:16]
        account = pwd.getpwnam(profile.service_user)
        if (profile.service_user != expected_user or account.pw_uid != profile.owner_uid
                or account.pw_gid != profile.owner_gid or account.pw_shell != "/usr/sbin/nologin"
                or account.pw_dir != "/nonexistent" or os.getgrouplist(profile.service_user, account.pw_gid) != [account.pw_gid]):
            raise ValueError("profile does not use its dedicated non-login service identity")
        exe = _root_path(profile.executable, directory=False)
        artifacts = _root_path(profile.artifact_root, directory=True)
        if exe != profile.executable or artifacts != profile.artifact_root:
            raise ValueError("pinned executable or artifact root is not canonical")
        if hashlib.sha256(exe.read_bytes()).hexdigest() != profile.artifact_sha256:
            raise ValueError("pinned executable digest does not match protected profile registry")
        data = profile.data_root.resolve(strict=True)
        cursor = Path(data.anchor)
        for part in data.parts[1:]:
            cursor /= part
            if stat.S_ISLNK(cursor.lstat().st_mode):
                raise ValueError("profile data root traverses a symlink")
        data_info = data.stat(follow_symlinks=False)
        if data != profile.data_root or not data.is_dir() or data_info.st_uid != profile.owner_uid or data_info.st_mode & 0o077:
            raise ValueError("profile data root is not private to the service identity")
        children = profile.child_artifact_refs or {}
        if len(children) > 32 or any(
                not isinstance(store_id, str)
                or not re.fullmatch(r"artifact:[A-Za-z0-9_.-]{1,128}:[0-9a-f]{64}", store_id)
                or store_id.rsplit(":", 1)[-1] != digest
                for store_id, digest in children.items()):
            raise ValueError("child artifact references are invalid")
        recipe = profile.argv_recipe
        if (not isinstance(recipe, tuple) or not recipe or len(recipe) > 128
                or recipe[0] != str(exe)
                or any(not isinstance(arg, str) or "\x00" in arg or len(arg) > 4096
                       for arg in recipe)
                or recipe.count("{child_artifact}") > 1):
            raise ValueError("protected process argv recipe is invalid")
        if _code_interpreter(exe.name) and recipe != (str(exe), "{child_artifact}"):
            raise ValueError("code interpreters require one immutable child-artifact operand")
        sock = profile.authority_socket or Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock")
        if sock != Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock"):
            raise ValueError("profile authority socket path is not the per-UID endpoint")
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", profile.generation)
                or type(profile.max_lifetime_seconds) is not int
                or not 0 < profile.max_lifetime_seconds <= 600):
            raise ValueError("profile generation or maximum lifetime is invalid")
        for path in (profile.executable, profile.artifact_root, profile.data_root, sock):
            if any(char.isspace() for char in str(path)) or ":" in str(path):
                raise ValueError("protected process paths cannot contain systemd property delimiters")
        for value, lower, upper, label in (
            (profile.memory_max_bytes, 16 * 1024 * 1024, 64 * 1024**3, "memory"),
            (profile.cpu_quota_percent, 1, 10_000, "CPU"),
            (profile.io_weight, 1, 10_000, "I/O"),
        ):
            if value is not None and (type(value) is not int or not lower <= value <= upper):
                raise ValueError(f"profile {label} limit is invalid")

    def handlers(self) -> Mapping[tuple[str, str], Callable[..., Mapping[str, Any]]]:
        result = {}
        for profile in self.profiles.values():
            result[("process.start", process_start_target(profile))] = self._bound(profile, "process.start")
            for verb in ("process.status", "process.read", "process.write", "process.stop"):
                target = process_control_target(profile, verb)
                result[(verb, target)] = self._bound(profile, verb)
        return result

    def _bound(self, profile: ManagedProfileCustody, operation: str):
        def handler(*, context: HostContext, authorization: EffectAuthorization,
                    payload: bytes, timeout: float, peer_pid: int,
                    peer_pidfd: int | None,
                    cancelled: Callable[[], bool]) -> Mapping[str, Any]:
            return self.dispatch(profile, operation, context=context, authorization=authorization,
                                 payload=payload, timeout=timeout, peer_pid=peer_pid,
                                 peer_pidfd=peer_pidfd,
                                 cancelled=cancelled)
        return handler

    def dispatch(self, profile: ManagedProfileCustody, operation: str, *,
                 context: HostContext, authorization: EffectAuthorization, payload: bytes,
                 timeout: float, peer_pid: int, peer_pidfd: int | None,
                 cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        target = (process_start_target(profile) if operation == "process.start"
                  else process_control_target(profile, operation))
        expected_capability = "hermes-profile-invoke" if operation == "process.start" else "hermes-process-control"
        if (operation not in {"process.start", "process.status", "process.read", "process.write", "process.stop"}
                or context.profile_id != profile.profile_id or authorization.profile_id != profile.profile_id
                or authorization.uid != context.uid or authorization.target != target
                or authorization.capability != expected_capability
                or authorization.principal_id != context.principal_id
                or authorization.namespace_id != context.namespace_id
                or authorization.trace_id != context.trace_id
                or authorization.intent_id != context.intent_id
                or context.operation != operation or authorization.operation != operation
                or peer_pid <= 0 or canonical_digest(payload) != authorization.request_digest):
            raise AuthorityDenied("process.binding", "process grant does not match the enrolled profile effect")
        if operation == "process.start":
            return self._start(profile, context, authorization, payload, timeout, peer_pid,
                               peer_pidfd, cancelled)
        return self._control(profile, context, operation, payload, timeout, cancelled)

    @staticmethod
    def _json(payload: bytes) -> dict[str, Any]:
        if not isinstance(payload, bytes) or len(payload) > 131072:
            raise AuthorityDenied("process.bounds", "process request exceeds its bound")
        try:
            value = json.loads(payload.decode("ascii"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise AuthorityDenied("process.request", "process request is malformed") from None
        if not isinstance(value, dict):
            raise AuthorityDenied("process.request", "process request must be an object")
        return value

    def _start(self, profile: ManagedProfileCustody, context: HostContext,
               authorization: EffectAuthorization, payload: bytes, timeout: float,
               peer_pid: int, peer_pidfd: int | None,
               cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        with self._lock:
            if (profile.profile_id in self._starting
                    or any(item.profile.profile_id == profile.profile_id for item in self._handles.values())):
                raise AuthorityDenied("process.generation", "a managed process is already active for this profile")
            self._starting.add(profile.profile_id)
        try:
            return self._start_reserved(profile, context, authorization, payload, timeout,
                                        peer_pid, peer_pidfd, cancelled)
        finally:
            with self._lock:
                self._starting.discard(profile.profile_id)

    def _start_reserved(self, profile: ManagedProfileCustody, context: HostContext,
                        authorization: EffectAuthorization, payload: bytes, timeout: float,
                        peer_pid: int, peer_pidfd: int | None,
                        cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        launch_deadline = min(self.monotonic() + max(0.0, timeout),
                              authorization.monotonic_expires_at)

        def require_live_start(parent_fd: int | None = None) -> None:
            if (cancelled() or self.monotonic() >= launch_deadline
                    or self.profiles.get(profile.profile_id) is not profile
                    or (parent_fd is not None and _pidfd_exited(parent_fd))):
                raise AuthorityDenied("process.start_expired", "start grant, profile enrollment or caller expired before launch")

        if peer_pidfd is None:
            raise AuthorityDenied("process.parent", "authority did not retain the peer pidfd")
        require_live_start()
        request = self._json(payload)
        if set(request) != _LAUNCH_FIELDS or request.get("schema") != 1:
            raise AuthorityDenied("process.launch", "launch envelope fields are invalid")
        expected = {
            "target": process_start_target(profile), "profile_id": profile.profile_id,
            "executable": str(profile.executable), "artifact_sha256": profile.artifact_sha256,
            "artifact_root": str(profile.artifact_root), "data_root": str(profile.data_root),
        }
        if any(request.get(key) != value for key, value in expected.items()):
            raise AuthorityDenied("process.binding", "launch envelope differs from protected profile registration")
        registered_children = dict(profile.child_artifact_refs or {})
        supplied_children = request.get("child_artifact_refs")
        if not isinstance(supplied_children, dict) or supplied_children != registered_children:
            raise AuthorityDenied("process.child", "child artifacts do not match the protected catalog")
        resolved_children: dict[str, Path] = {}
        for store_id, child_digest in supplied_children.items():
            if not self.artifact_resolver:
                raise AuthorityDenied("process.child", "protected artifact resolver is not installed")
            try:
                resolved = self.artifact_resolver(store_id, child_digest)
                child_path = Path(getattr(resolved, "path", resolved))
                if (child_path != child_path.resolve(strict=True)
                        or _root_path(child_path, directory=False) != child_path
                        or hashlib.sha256(child_path.read_bytes()).hexdigest() != child_digest):
                    raise ValueError("artifact identity mismatch")
            except Exception:
                raise AuthorityDenied("process.child", "root catalog could not resolve the enrolled artifact") from None
            resolved_children[store_id] = child_path
        argv = list(request["argv"])
        env = request["env_allowlist"]
        if (not isinstance(argv, list) or not argv or len(argv) > 128 or argv[0] != str(profile.executable)
                or any(not isinstance(item, str) or "\x00" in item or len(item) > 4096 for item in argv)
                or sum(len(item.encode()) for item in argv) > 65536):
            raise AuthorityDenied("process.argv", "argv does not match pinned executable or is oversized")
        if not _argv_matches_recipe(profile, argv, registered_children):
            raise AuthorityDenied("process.argv", "argv differs from the protected profile recipe")
        artifact_args = [index for index, item in enumerate(argv) if item in registered_children]
        if artifact_args:
            argv[artifact_args[0]] = "__ROOT_ARTIFACT_MOUNT__"
        secrets = ("--token", "--secret", "--password", "--api-key", "--credential")
        if any(any(flag in item.casefold() for flag in secrets) for item in argv[1:]):
            raise AuthorityDenied("process.secret", "credential-bearing argv is forbidden")
        if (not isinstance(env, dict) or len(env) > 32
                or any(k not in _ALLOWED_ENV or not isinstance(v, str) or "\x00" in v or "\n" in v or "\r" in v
                       or len(v) > 1024 for k, v in env.items())
                or any(any(marker in k.casefold() for marker in ("token", "secret", "password", "credential", "api_key")) for k in env)
                or env.get("HOME") != "/hermes" or env.get("HERMES_HOME") != "/hermes"):
            raise AuthorityDenied("process.environment", "environment is not the sanitized profile allowlist")
        if "PATH" in env:
            for raw_path in env["PATH"].split(":"):
                try:
                    _root_path(Path(raw_path), directory=True)
                except (OSError, ValueError):
                    raise AuthorityDenied("process.environment", "PATH includes an unprotected directory") from None
        for key in ("HOME", "HERMES_HOME", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME"):
            value = env.get(key)
            if value is not None and not (value == "/hermes" or value.startswith("/hermes/")):
                raise AuthorityDenied("process.environment", "profile writable path escapes its private mount")
        cwd = Path(request["cwd"]).resolve(strict=True)
        root = profile.data_root.resolve(strict=True)
        if not cwd.is_relative_to(root):
            raise AuthorityDenied("process.cwd", "working directory is outside the private profile")
        lifetime, output_cap = request["max_lifetime_seconds"], request["max_output_bytes"]
        if (isinstance(lifetime, bool) or not isinstance(lifetime, (int, float))
                or not 0 < lifetime <= min(profile.max_lifetime_seconds, 600)
                or type(output_cap) is not int or not 1 <= output_cap <= 4 * 1024 * 1024
                or request["stdin_mode"] not in {"closed", "pipe"}):
            raise AuthorityDenied("process.bounds", "process lifetime or stream mode is invalid")
        require_live_start()
        try:
            parent_fd = os.dup(peer_pidfd)
        except OSError:
            raise AuthorityDenied("process.parent", "pidfd is required for parent-death custody") from None
        process_id = uuid.uuid4().hex
        artifact_mount_dir: Path | None = None
        artifact_target: Path | None = None
        artifact_path: Path | None = next(iter(resolved_children.values()), None)
        unit = "hermes-installer-" + uuid.uuid4().hex + ".service"
        mount = f"/hermes/profiles/{profile.profile_id}"
        rel = cwd.relative_to(root).as_posix()
        target_cwd = mount if rel == "." else f"{mount}/{rel}"
        properties = [
            "--property=Type=exec", f"--property=RuntimeMaxSec={float(lifetime)}s",
            "--property=KillMode=control-group", f"--property=Description=HermesInstaller {profile.profile_id} {profile.generation}",
            "--property=ProtectSystem=strict", "--property=ProtectHome=tmpfs",
            "--property=ProtectProc=invisible", "--property=ProcSubset=pid",
            "--property=PrivateTmp=yes", "--property=PrivateDevices=yes", "--property=NoNewPrivileges=yes",
            f"--property=User={profile.service_user}", "--property=SupplementaryGroups=",
            "--property=ProtectKernelTunables=yes", "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes", "--property=RestrictSUIDSGID=yes",
            "--property=RestrictNamespaces=user", "--property=RestrictAddressFamilies=AF_UNIX",
            "--property=PrivateNetwork=yes", "--property=IPAddressDeny=any",
            "--property=InaccessiblePaths=/etc/hermes-installer /var/lib/hermes-installer /etc/ssh /etc/ssl/private",
            f"--property=BindPaths={root}:{mount}",
        ]
        authority_socket = profile.authority_socket or Path(f"/run/hermes-installer/authority/{profile.owner_uid}.sock")
        try:
            parent = authority_socket.parent.lstat()
            socket_info = authority_socket.lstat()
        except OSError:
            os.close(parent_fd)
            raise AuthorityDenied("process.authority_socket", "protected per-UID authority socket is unavailable") from None
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022
                or not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != 0
                or socket_info.st_gid != profile.owner_gid or stat.S_IMODE(socket_info.st_mode) != 0o660):
            os.close(parent_fd)
            raise AuthorityDenied("process.authority_socket", "per-UID authority socket ACL is not protected")
        properties.append(f"--property=BindPaths={authority_socket}:{authority_socket}")
        if profile.memory_max_bytes is not None:
            properties.append(f"--property=MemoryMax={profile.memory_max_bytes}")
        if profile.cpu_quota_percent is not None:
            properties.append(f"--property=CPUQuota={profile.cpu_quota_percent}%")
        if profile.io_weight is not None:
            properties.append(f"--property=IOWeight={profile.io_weight}")
        env_args = ["--setenv=" + key + "=" + value for key, value in sorted(env.items())]
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        remaining = launch_deadline - self.monotonic()
        if remaining <= 0:
            os.close(parent_fd)
            raise AuthorityDenied("process.start_expired", "start lease ended during preparation")
        try:
            manager_env = subprocess.run([str(self.systemctl), "--system", "show-environment"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True,
                timeout=min(2.0, remaining), check=False)
        except (OSError, subprocess.TimeoutExpired):
            os.close(parent_fd)
            raise AuthorityDenied("process.environment", "system manager environment could not be bounded") from None
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            raise
        if manager_env.returncode != 0 or len(manager_env.stdout) > 65536:
            os.close(parent_fd)
            raise AuthorityDenied("process.environment", "system manager environment cannot be safely cleared")
        import re
        manager_keys = {line.split("=", 1)[0] for line in manager_env.stdout.decode("utf-8", "replace").splitlines()
                        if "=" in line and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", line.split("=", 1)[0])}
        manager_keys.update({"INVOCATION_ID", "JOURNAL_STREAM", "NOTIFY_SOCKET", "WATCHDOG_USEC",
                             "WATCHDOG_PID", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES",
                             "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "USER", "LOGNAME",
                             "SHELL", "PWD"})
        unset_keys = sorted(manager_keys - set(env))
        if sum(len(key) + 1 for key in unset_keys) > 60000:
            os.close(parent_fd)
            raise AuthorityDenied("process.environment", "system manager environment exceeds its safe bound")
        if unset_keys:
            properties.append("--property=UnsetEnvironment=" + " ".join(unset_keys))
        try:
            require_live_start(parent_fd)
            artifact_mount_dir = _artifact_mount_slot(profile.owner_uid, process_id)
            require_live_start(parent_fd)
            if resolved_children:
                artifact_target = artifact_mount_dir / "child-1"
                fd = os.open(artifact_target, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                             | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o444)
                try:
                    os.fchown(fd, 0, 0)
                    os.fchmod(fd, 0o444)
                finally:
                    os.close(fd)
                argv[artifact_args[0]] = str(artifact_target)
                properties.append(f"--property=BindReadOnlyPaths={artifact_path}:{artifact_target}")
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            raise
        command = [str(self.systemd_run), "--system", "--unit=" + unit, "--service-type=exec",
                   "--wait", "--collect", "--pipe", "--quiet", "--working-directory=" + target_cwd,
                   *properties, *env_args, str(profile.executable), *argv[1:]]
        try:
            require_live_start(parent_fd)
        except BaseException:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            raise
        try:
            launcher = subprocess.Popen(command,
                stdin=subprocess.PIPE if request["stdin_mode"] == "pipe" else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True, shell=False)
        except OSError:
            os.close(parent_fd)
            if artifact_mount_dir is not None:
                _remove_artifact_mount(artifact_mount_dir)
            raise AuthorityDenied("process.launcher_start", "root process manager could not start the enrolled service") from None
        started = self.monotonic()
        deadline = min(launch_deadline, started + 10.0)
        child_fd = None
        try:
            for stream in (launcher.stdin, launcher.stdout, launcher.stderr):
                if stream is not None:
                    os.set_blocking(stream.fileno(), False)
            identity = None
            cgroup = ""
            while self.monotonic() < deadline:
                if cancelled() or _pidfd_exited(parent_fd):
                    raise AuthorityDenied("process.parent", "process owner ended before admission")
                try:
                    cg = self._show(unit, "ControlGroup")
                except AuthorityDenied as exc:
                    # systemd-run returns after submitting the unit but before
                    # systemd necessarily publishes it to `show`. Retry only
                    # this initial fixed-property lookup while the bounded
                    # launcher is still alive; all later readback failures
                    # remain fail-closed.
                    if exc.code != "process.manager.readback" or launcher.poll() is not None:
                        raise
                    time.sleep(.025)
                    continue
                if cg.startswith("/") and Path("/sys/fs/cgroup", *cg.strip("/").split()).exists():
                    members = (Path("/sys/fs/cgroup") / cg.lstrip("/") / "cgroup.procs").read_text().split()
                    for raw_pid in members:
                        pid = int(raw_pid)
                        try:
                            ticks, observed_cgroup, dev, ino = _pid_identity(pid)
                            proc_exe = Path(f"/proc/{pid}/exe")
                            digest = hashlib.sha256(proc_exe.read_bytes()).hexdigest()
                            pinned = profile.executable.stat(follow_symlinks=False)
                            if (observed_cgroup == cg and digest == profile.artifact_sha256
                                    and (dev, ino) == (pinned.st_dev, pinned.st_ino)):
                                identity, cgroup = (pid, ticks, dev, ino), cg
                                break
                        except (OSError, ValueError, AuthorityDenied):
                            continue
                if identity:
                    break
                if launcher.poll() is not None:
                    sink = self._diagnostic_sink
                    if sink is not None and launcher.stderr is not None:
                        try:
                            diagnostic = launcher.stderr.read(2048)
                        except (OSError, ValueError):
                            diagnostic = b""
                        if diagnostic:
                            sink(diagnostic[:2048])
                    raise AuthorityDenied("process.launcher_early_exit", "service exited before admission")
                time.sleep(.025)
            if identity is None:
                raise AuthorityDenied("process.admission_deadline", "service did not become ready before its deadline")
            pid, ticks, dev, ino = identity
            if Path(cgroup).name != unit or ".." in Path(cgroup).parts:
                raise AuthorityDenied("process.cgroup", "service did not receive its exact cgroup")
            expected_props = {
                "KillMode": "control-group", "ProtectSystem": "strict", "PrivateTmp": "yes",
                "PrivateDevices": "yes", "NoNewPrivileges": "yes", "IPAddressDeny": "any",
                "PrivateNetwork": "yes", "RestrictAddressFamilies": "AF_UNIX", "ProtectHome": "tmpfs",
                "ProtectProc": "invisible", "ProcSubset": "pid", "User": profile.service_user,
            }
            for key, value in expected_props.items():
                if self._show(unit, key) != value:
                    raise AuthorityDenied("process.sandbox", "manager isolation readback failed")
            if self._show(unit, "Description") != f"HermesInstaller {profile.profile_id} {profile.generation}":
                raise AuthorityDenied("process.unit", "manager unit is not bound to the profile generation")
            if self._show(unit, "SupplementaryGroups") not in {"", "-"}:
                raise AuthorityDenied("process.groups", "worker has unexpected supplemental groups")
            actual_environment = self._read_environment(pid)
            if actual_environment != env:
                raise AuthorityDenied("process.environment", "actual child environment differs from the allowlist")
            child_fd = os.pidfd_open(pid, 0)
            actual_ticks, actual_cgroup, actual_dev, actual_ino = _pid_identity(pid)
            if ((actual_ticks, actual_cgroup, actual_dev, actual_ino) != (ticks, cgroup, dev, ino)
                    or _pidfd_exited(child_fd)):
                raise AuthorityDenied("process.identity", "kernel process identity changed during admission")
            status = Path(f"/proc/{pid}/status").read_text().splitlines()
            uids = next(line for line in status if line.startswith("Uid:")).split()[1:]
            if len(uids) != 4 or any(int(uid) != profile.owner_uid for uid in uids):
                raise AuthorityDenied("process.uid", "kernel worker UID does not match the profile")
            mnt, net = (os.stat(f"/proc/{pid}/ns/{name}").st_ino for name in ("mnt", "net"))
            if mnt == os.stat("/proc/self/ns/mnt").st_ino or net == os.stat("/proc/self/ns/net").st_ino:
                raise AuthorityDenied("process.namespace", "private mount or network namespace is missing")
            limits = self._limits(cgroup)
            if profile.memory_max_bytes is not None and limits["memory.max"] != str(profile.memory_max_bytes):
                raise AuthorityDenied("process.limits", "kernel memory.max does not match enrolled bound")
            if profile.cpu_quota_percent is not None:
                try:
                    quota, period = limits["cpu.max"].split()
                    if quota == "max" or int(quota) * 100 != profile.cpu_quota_percent * int(period):
                        raise AuthorityDenied("process.limits", "kernel cpu.max does not match enrolled bound")
                except ValueError:
                    raise AuthorityDenied("process.limits", "kernel cpu.max is unavailable") from None
            if profile.io_weight is not None:
                fields = limits["io.weight"].split()
                if not fields or int(fields[-1]) != profile.io_weight:
                    raise AuthorityDenied("process.limits", "kernel io.weight does not match enrolled bound")
            if artifact_mount_dir is None:
                raise AuthorityDenied("process.artifact", "artifact mount directory was not established")
            handle = _Handle(process_id, profile, unit, cgroup, launcher, parent_fd, child_fd, pid,
                ticks, f"mnt:{mnt};net:{net}", context.principal_id, context.namespace_id,
                started, started + float(lifetime), output_cap, artifact_mount_dir,
                lock=threading.RLock())
            child_fd = None
            with self._lock:
                self._handles[process_id] = handle
            threading.Thread(target=self._watch_parent, args=(handle,), daemon=True,
                             name="hermes-custody-watch").start()
            return _response(200, {"schema": 1, "process_id": process_id, "pid": pid,
            "uid": profile.owner_uid, "namespace_id": handle.kernel_namespace_id,
                "gid": profile.owner_gid, "unit": unit,
                "generation": profile.generation, "started_at_monotonic": started,
                "stdout_cursor": 0, "stderr_cursor": 0, "expires_at_monotonic": handle.expires,
                "cgroup": cgroup, "start_ticks": ticks, "executable_device": dev,
                "executable_inode": ino, "mount_namespace_inode": mnt,
                "network_namespace_inode": net, "kernel_limits": limits})
        except BaseException:
            try:
                self._stop_partial(unit, launcher)
            finally:
                try:
                    if artifact_mount_dir is not None:
                        _remove_artifact_mount(artifact_mount_dir)
                finally:
                    for fd in (parent_fd, child_fd):
                        if fd is not None:
                            try:
                                os.close(fd)
                            except OSError:
                                pass
            raise

    @staticmethod
    def _read_environment(pid: int) -> dict[str, str]:
        try:
            raw = Path(f"/proc/{pid}/environ").read_bytes()
        except OSError:
            raise AuthorityDenied("process.environment", "kernel child environment cannot be observed") from None
        if len(raw) > 65536:
            raise AuthorityDenied("process.environment", "kernel child environment exceeds its bound")
        values = {}
        for item in raw.split(b"\x00"):
            if item:
                key, sep, value = item.partition(b"=")
                if sep:
                    values[key.decode("utf-8", "strict")] = value.decode("utf-8", "strict")
        return values

    def _control(self, profile: ManagedProfileCustody, context: HostContext, operation: str,
                 payload: bytes, timeout: float, cancelled: Callable[[], bool]) -> Mapping[str, Any]:
        item = self._json(payload)
        common = {"schema", "process_id", "generation"}
        extras = {"process.status": set(), "process.stop": set(),
                  "process.read": {"stream", "after_cursor", "max_bytes"},
                  "process.write": {"data", "stdin_cursor"}}[operation]
        if set(item) != common | extras or item.get("schema") != 1 or not isinstance(item.get("process_id"), str):
            raise AuthorityDenied("process.control", "control envelope is malformed")
        with self._lock:
            handle = self._handles.get(item["process_id"])
            finished = self._finished.get(item["process_id"])
        if handle is None and operation == "process.stop" and finished and finished[0] == profile.generation:
            return _response(200, {"schema": 1, "stopped": True, "cleanup_verified": True})
        if (handle is None or handle.profile.profile_id != profile.profile_id
                or item["generation"] != profile.generation
                or context.principal_id != handle.principal_id
                or context.namespace_id != handle.authority_namespace_id):
            raise AuthorityDenied("process.handle", "process handle is stale or belongs to another principal")
        if operation != "process.stop" and (cancelled() or _pidfd_exited(handle.parent_pidfd)
                                               or self.monotonic() >= handle.expires):
            self._stop(handle, timeout=min(timeout, 5.0))
            raise AuthorityDenied("process.expired", "parent, lease or service lifetime ended")
        if operation == "process.status":
            code = handle.launcher.poll()
            if item.get("include_children", False):
                raise AuthorityDenied("process.status", "child snapshots are not available through this fixed status schema")
            return _response(200, {"schema": 1, "state": "running" if code is None else "exited",
                "pid": handle.pid, "uid": profile.owner_uid, "namespace_id": handle.kernel_namespace_id,
                "generation": profile.generation, "stdout_cursor": handle.stdout_cursor,
                "stderr_cursor": handle.stderr_cursor, "expires_at_monotonic": handle.expires,
                "exit_code": code, "cgroup": handle.cgroup, "kernel_limits": self._limits(handle.cgroup)})
        if operation == "process.read":
            stream_name, cursor, maximum = item["stream"], item["after_cursor"], item["max_bytes"]
            if (stream_name not in {"stdout", "stderr"} or type(cursor) is not int
                    or type(maximum) is not int or not 1 <= maximum <= 65536):
                raise AuthorityDenied("process.read", "stream or read bounds are invalid")
            current = handle.stdout_cursor if stream_name == "stdout" else handle.stderr_cursor
            if cursor != current:
                raise AuthorityDenied("process.cursor", "read cursor is stale")
            remaining_output = handle.output_cap - handle.stdout_cursor - handle.stderr_cursor
            if remaining_output <= 0:
                self._stop(handle, timeout=min(timeout, 5.0))
                raise AuthorityDenied("process.output", "managed process exceeded its output cap")
            maximum = min(maximum, remaining_output)
            stream = getattr(handle.launcher, stream_name)
            ready, _, _ = select.select([stream.fileno()], [], [], min(max(timeout, 0), .75))
            data = os.read(stream.fileno(), maximum) if ready else b""
            eof = bool(ready and not data)
            if stream_name == "stdout":
                handle.stdout_cursor += len(data)
                current = handle.stdout_cursor
            else:
                handle.stderr_cursor += len(data)
                current = handle.stderr_cursor
            return _response(200, {"schema": 1, "stream": stream_name, "cursor": current,
                "data": base64.b64encode(data).decode("ascii"), "eof": eof})
        if operation == "process.write":
            cursor = item["stdin_cursor"]
            try:
                data = base64.b64decode(item["data"], validate=True)
            except Exception:
                raise AuthorityDenied("process.write", "stdin data is malformed") from None
            if (type(cursor) is not int or cursor != handle.stdin_cursor or len(data) > 65536
                    or handle.launcher.stdin is None):
                raise AuthorityDenied("process.cursor", "stdin cursor or data length is invalid")
            fd = handle.launcher.stdin.fileno()
            _, writable, _ = select.select([], [fd], [], min(max(timeout, 0), .75))
            try:
                written = os.write(fd, data) if writable else 0
            except BlockingIOError:
                written = 0
            handle.stdin_cursor += written
            return _response(200, {"schema": 1, "stdin_cursor": handle.stdin_cursor, "bytes_written": written})
        self._stop(handle, timeout=min(timeout, 5.0))
        return _response(200, {"schema": 1, "stopped": True, "cleanup_verified": True})

    def _watch_parent(self, handle: _Handle) -> None:
        poller = select.poll()
        poller.register(handle.parent_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while not handle.stopped:
            remaining = handle.expires - self.monotonic()
            if remaining <= 0 or poller.poll(min(250, max(1, int(remaining * 1000)))):
                self._stop(handle, timeout=5.0)
                return

    def _show(self, unit: str, prop: str) -> str:
        allowed = {"ControlGroup", "Description", "KillMode", "ProtectSystem", "PrivateTmp", "PrivateDevices",
            "NoNewPrivileges", "IPAddressDeny", "PrivateNetwork", "RestrictAddressFamilies", "ProtectHome",
            "ProtectProc", "ProcSubset", "User", "SupplementaryGroups", "RuntimeMaxUSec", "MemoryMax",
            "CPUQuotaPerSecUSec", "IOWeight"}
        if prop not in allowed or not unit.startswith("hermes-installer-") or not unit.endswith(".service"):
            raise AuthorityDenied("process.manager", "manager property or unit is outside the fixed set")
        result = subprocess.run([str(self.systemctl), "--system", "show", "--property=" + prop, "--value", unit],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            env={"PATH": "/usr/bin:/bin", "LANG": "C"}, close_fds=True, timeout=1.5, check=False)
        if result.returncode or len(result.stdout) > 4096:
            raise AuthorityDenied("process.manager.readback", "manager readback failed")
        return result.stdout.decode("utf-8", "strict").strip()

    def _ctl(self, args: list[str], timeout: float) -> None:
        if not args or args[0] not in {"kill", "stop"} or not args[-1].startswith("hermes-installer-"):
            raise AuthorityDenied("process.manager", "manager control verb or unit is invalid")
        result = subprocess.run([str(self.systemctl), "--system", *args], stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C"},
            close_fds=True, timeout=timeout, check=False)
        if result.returncode:
            raise AuthorityDenied("process.manager", "manager control failed")

    @staticmethod
    def _pids(cgroup: str) -> tuple[int, ...]:
        if not cgroup.startswith("/") or ".." in Path(cgroup).parts:
            raise AuthorityDenied("process.cgroup", "invalid cgroup identity")
        try:
            return tuple(int(value) for value in (Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.procs").read_text().split())
        except FileNotFoundError:
            return ()
        except (OSError, ValueError):
            raise AuthorityDenied("process.cgroup", "cgroup membership is unavailable") from None

    @staticmethod
    def _limits(cgroup: str) -> dict[str, str]:
        root = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
        out = {}
        for name in ("memory.max", "cpu.max", "io.weight"):
            try:
                out[name] = (root / name).read_text().strip()
            except OSError:
                out[name] = "unavailable"
        return out

    def _stop(self, handle: _Handle, *, timeout: float) -> None:
        with handle.lock:
            if handle.stopped:
                return
            deadline = time.monotonic() + min(max(timeout, .1), 10)
            try:
                try:
                    owned = self._show(handle.unit, "ControlGroup") == handle.cgroup
                except AuthorityDenied:
                    owned = False
                if owned:
                    self._ctl(["kill", "--kill-whom=all", "--signal=SIGTERM", handle.unit], 1)
                    time.sleep(min(.25, max(0, deadline - time.monotonic())))
                    if self._pids(handle.cgroup):
                        self._ctl(["kill", "--kill-whom=all", "--signal=SIGKILL", handle.unit], 1)
                    self._ctl(["stop", handle.unit], min(1, max(.1, deadline - time.monotonic())))
                while self._pids(handle.cgroup) and time.monotonic() < deadline:
                    time.sleep(.02)
                if self._pids(handle.cgroup):
                    raise AuthorityDenied("process.cleanup", "manager failed to empty the owned cgroup")
                handle.stopped = True
            finally:
                if handle.stopped:
                    with self._lock:
                        self._handles.pop(handle.process_id, None)
                        self._finished[handle.process_id] = (handle.profile.generation, self.monotonic() + 600)
                        now = self.monotonic()
                        self._finished = {key: item for key, item in self._finished.items() if item[1] > now}
                    for fd in (handle.parent_pidfd, handle.child_pidfd):
                        try:
                            os.close(fd)
                        except OSError:
                            pass
                    for stream in (handle.launcher.stdin, handle.launcher.stdout, handle.launcher.stderr):
                        if stream:
                            stream.close()
                    if handle.launcher.poll() is None:
                        handle.launcher.kill()
                    try:
                        handle.launcher.wait(timeout=1.0)
                    except subprocess.TimeoutExpired:
                        raise AuthorityDenied("process.cleanup", "root service launcher did not reap")
                    finally:
                        _remove_artifact_mount(handle.artifact_mount_dir)

    def _stop_partial(self, unit: str, launcher: subprocess.Popen[bytes]) -> None:
        if unit.startswith("hermes-installer-"):
            cgroup = f"/system.slice/{unit}"
            for command in (["kill", "--kill-whom=all", "--signal=SIGKILL", unit],
                            ["stop", unit]):
                try:
                    self._ctl(command, 1)
                except AuthorityDenied:
                    # systemd returns failure when --collect already removed
                    # a transient unit. Treat that as clean only when the
                    # exact registered system.slice cgroup is absent/empty.
                    if self._pids(cgroup):
                        raise AuthorityDenied("process.cleanup", "partial unit cgroup could not be stopped") from None
        if launcher.poll() is None:
            launcher.kill()
        try:
            launcher.wait(timeout=1.0)
        except subprocess.TimeoutExpired:
            raise AuthorityDenied("process.cleanup", "partial root service launcher did not reap") from None
        if unit.startswith("hermes-installer-") and self._pids(f"/system.slice/{unit}"):
            raise AuthorityDenied("process.cleanup", "partial unit cgroup remains populated")


def build_managed_process_handlers(profiles: Mapping[str, ManagedProfileCustody], **kwargs: Any):
    """Build the fixed root process handler map for AuthorityService."""
    return ManagedProcessEffectHandler(profiles, **kwargs).handlers()
