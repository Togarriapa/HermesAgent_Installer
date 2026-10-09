"""Launch Xpra through the host-issued, kernel-custodied profile process service."""
from __future__ import annotations

import inspect
import os
import shlex
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping, Protocol

from ..authority.client import (
    AuthorityClient,
    canonical_profile_target,
    profile_launch_envelope,
)
from ..authority.types import HostContext, canonical_digest
from ..managed_process import ManagedProcessHandle, ManagedProcessSpec, ManagedProcessSupervisor
from .session import SessionSpec, SessionUnavailable, require_sandbox_evidence


def build_xpra_command(session: SessionSpec, xpra: str | Path, runtime_dir: Path) -> list[str]:
    """Build argv using only options accepted by the pinned Xpra parser."""
    executable = str(Path(xpra).resolve(strict=False))
    child = shlex.join([session.hermes_executable, *session.hermes_arguments])
    return [
        executable, "seamless", session.display,
        "--daemon=no", "--systemd-run=no", "--attach=no", "--exit-with-children=yes",
        "--socket-dirs=" + str(runtime_dir), "--bind-tcp=127.0.0.1:14500",
        "--html=on", "--start-child=" + child,
        "--commands=no", "--shell=no", "--start-new-commands=no",
        "--start-via-proxy=no", "--proxy-start-sessions=no", "--control=no",
        "--dbus=no", "--dbus-control=no", "--clipboard=no", "--file-transfer=no",
        "--open-files=no", "--open-url=no", "--printing=no", "--webcam=no",
        "--audio=no", "--speaker=off", "--microphone=off", "--remote-logging=off",
        "--http-scripts=no", "--ssh-upgrade=no", "--rfb-upgrade=0", "--rdp-upgrade=no",
        "--socket-permissions=600",
    ]


class XpraSessionInspector(Protocol):
    """Root-backed process inspector; a caller-supplied PID probe is not evidence."""

    async def inspect(self, handle: ManagedProcessHandle) -> Mapping[str, Any]: ...


class XpraLauncher:
    def __init__(
        self,
        session: SessionSpec,
        *,
        authority: AuthorityClient,
        host_context: HostContext,
        process_template: ManagedProcessSpec,
        supervisor: ManagedProcessSupervisor,
        runtime_dir: Path,
        inspector: XpraSessionInspector | None = None,
    ) -> None:
        if not isinstance(authority, AuthorityClient):
            raise SessionUnavailable("host AuthorityClient is required for Xpra launch")
        if not isinstance(host_context, HostContext):
            raise SessionUnavailable("installer-issued profile context is required for Xpra launch")
        if not isinstance(process_template, ManagedProcessSpec):
            raise SessionUnavailable("typed managed process specification is required")
        if not isinstance(supervisor, ManagedProcessSupervisor) or supervisor.authority_verifier is not authority:
            raise SessionUnavailable("Xpra must use the authority-bound managed process supervisor")
        profile_mount = Path("/hermes/profiles") / process_template.profile_id
        try:
            runtime_dir.resolve(strict=False).relative_to(profile_mount)
        except (ValueError, OSError):
            raise SessionUnavailable("Xpra runtime path must stay inside its enrolled private profile")
        if process_template.profile_id != "hermes-desktop" or host_context.profile_id != process_template.profile_id:
            raise SessionUnavailable("host-issued context is not bound to the exact Hermes Desktop profile")
        if host_context.uid != os.geteuid() or host_context.uid <= 0:
            raise SessionUnavailable("host-issued context does not belong to this installer process")
        if "hermes-profile-invoke" not in host_context.capabilities:
            raise SessionUnavailable("Desktop profile is not authorized for managed process launch")
        if str(process_template.executable.resolve(strict=False)) != str(process_template.argv[0]):
            raise SessionUnavailable("managed Xpra executable differs from its protected process registration")
        if process_template.artifact_sha256 != _sha256_file(process_template.executable):
            raise SessionUnavailable("managed Xpra executable does not match its registered artifact pin")
        hermes_path = Path(session.hermes_executable)
        try:
            hermes_path.resolve(strict=False).relative_to(profile_mount)
        except (ValueError, OSError):
            raise SessionUnavailable("Hermes Desktop executable must be inside its enrolled profile mount")
        child_hashes = {str(Path(path).resolve(strict=False)): digest
                        for path, digest in (process_template.child_artifact_hashes or {}).items()}
        if child_hashes.get(str(hermes_path.resolve(strict=False))) is None:
            raise SessionUnavailable("Hermes Desktop executable is absent from the protected child artifact pins")
        if type(process_template.max_lifetime_seconds) is not int or not 1 <= process_template.max_lifetime_seconds <= 600:
            raise SessionUnavailable("managed Xpra lifetime must be an integer bounded to ten minutes")
        self.session = session
        self.authority = authority
        self.host_context = host_context
        self.process_template = process_template
        self.supervisor = supervisor
        self.xpra = str(process_template.executable)
        self.runtime_dir = runtime_dir
        self.inspector = inspector
        self.handle: ManagedProcessHandle | None = None

    def command(self) -> list[str]:
        return build_xpra_command(self.session, self.xpra, self.runtime_dir)

    def _bound_process_spec(self) -> ManagedProcessSpec:
        template = self.process_template
        env = {
            "HOME": "/hermes",
            "HERMES_HOME": "/hermes",
            "PATH": template.env_allowlist.get("PATH", "/usr/bin:/bin"),
            "DISPLAY": self.session.display,
            "XDG_RUNTIME_DIR": str(self.runtime_dir),
        }
        for key, value in self.session.hermes_environment.items():
            if key not in {"PATH", "HERMES_HOME"}:
                raise SessionUnavailable("Desktop environment is outside the host-managed allowlist")
            if key == "HERMES_HOME" and value != "/hermes":
                raise SessionUnavailable("Hermes home must use the isolated profile mount")
            env[key] = value
        argv = tuple(self.command())
        target = canonical_profile_target(template.profile_id, template.executable, template.data_root)
        envelope = profile_launch_envelope(
            target=target,
            profile_id=template.profile_id,
            executable=template.executable,
            artifact_sha256=template.artifact_sha256,
            artifact_root=template.artifact_root,
            cwd=template.cwd,
            data_root=template.data_root,
            argv=argv,
            env_allowlist=env,
            child_artifact_hashes=template.child_artifact_hashes,
            max_lifetime_seconds=template.max_lifetime_seconds,
            max_output_bytes=4096,
            stdin_mode="closed",
        )
        grant = self.authority.authorize_effect(
            self.host_context,
            capability="hermes-profile-invoke",
            target=target,
            request_digest=canonical_digest(envelope),
            retry_index=0,
        )
        return replace(
            template,
            argv=argv,
            env_allowlist=env,
            authority_context=self.host_context,
            effect_authorization=grant,
            max_output_bytes=4096,
            stdin_mode="closed",
        )

    async def start(self) -> Mapping[str, Any]:
        if self.inspector is None:
            raise SessionUnavailable("root-backed Xpra/Electron process inspection is unavailable")
        if self.handle is not None:
            raise SessionUnavailable("this Desktop profile already has an active Xpra generation")
        process_spec = self._bound_process_spec()
        handle = await self.supervisor.start(process_spec)
        self.handle = handle
        try:
            evidence = self.inspector.inspect(handle)
            if inspect.isawaitable(evidence):
                evidence = await evidence
            identity = handle.identity
            required = {
                "process_id": identity.process_id,
                "generation": identity.generation,
                "pid": identity.pid,
                "start_ticks": identity.start_ticks,
                "cgroup": identity.cgroup,
                "executable_sha256": identity.executable_sha256,
                "executable_device": identity.executable_device,
                "executable_inode": identity.executable_inode,
            }
            if not isinstance(evidence, Mapping) or any(evidence.get(k) != v for k, v in required.items()):
                raise SessionUnavailable("root-backed Xpra identity does not match managed process custody")
            if (evidence.get("display") != self.session.display
                    or evidence.get("foreign_children") != 0
                    or evidence.get("foreign_windows") != 0
                    or evidence.get("hermes_build_sha") != self.session.hermes_build_sha):
                raise SessionUnavailable("dedicated session/window/build check failed")
            renderer_pid = evidence.get("renderer_pid")
            if (type(renderer_pid) is not int or renderer_pid <= 0
                    or evidence.get("renderer_cgroup") != identity.cgroup
                    or evidence.get("renderer_parent_chain_verified") is not True):
                raise SessionUnavailable("pinned Hermes Electron renderer is not proven inside the managed cgroup")
            sandboxed = evidence.get("renderer_sandboxed") is True
            no_sandbox_marker = evidence.get("no_sandbox_marker") is True
            require_sandbox_evidence(renderer_sandboxed=sandboxed, no_sandbox_marker=no_sandbox_marker)
            if evidence.get("renderer_relaunch_monitor") is not True:
                raise SessionUnavailable("renderer relaunch monitor is not active")
            return {
                "process_id": identity.process_id,
                "generation": identity.generation,
                "pid": identity.pid,
                "renderer_pid": renderer_pid,
                "display": self.session.display,
                "cgroup": identity.cgroup,
                "sandboxed": sandboxed,
                "no_sandbox_marker": no_sandbox_marker,
            }
        except BaseException:
            await self.stop()
            raise

    async def stop(self) -> None:
        handle, self.handle = self.handle, None
        if handle is None:
            return
        try:
            await handle.stop("remote Desktop session ended", timeout=5.0)
        except Exception as exc:
            raise SessionUnavailable("root managed Xpra cgroup did not prove cleanup") from exc


def _sha256_file(path: Path) -> str:
    import hashlib

    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
    except OSError:
        raise SessionUnavailable("managed Xpra executable cannot be read for pin validation") from None
    return digest.hexdigest()
