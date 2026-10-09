"""Launch Xpra through the host-issued, kernel-custodied profile process service."""
from __future__ import annotations

import os
import shlex
from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from ..authority.client import (
    AuthorityClient,
    canonical_profile_target,
    profile_launch_envelope,
)
from ..authority.types import HostContext, canonical_digest
from ..managed_process import ManagedProcessHandle, ManagedProcessSpec, ManagedProcessSupervisor
from .host_process import InspectedProcess, inspect_managed_process
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


class XpraLauncher:
    def __init__(
        self,
        session: SessionSpec,
        *,
        authority: AuthorityClient,
        process_template: ManagedProcessSpec,
        supervisor: ManagedProcessSupervisor,
        runtime_dir: Path,
    ) -> None:
        if type(authority) is not AuthorityClient:
            raise SessionUnavailable("host AuthorityClient is required for Xpra launch")
        if not callable(getattr(authority, "inspect_profile_process", None)):
            raise SessionUnavailable("root process inspection is not installed; Desktop session launch remains pending")
        if not isinstance(process_template, ManagedProcessSpec):
            raise SessionUnavailable("typed managed process specification is required")
        if not isinstance(supervisor, ManagedProcessSupervisor) or supervisor.authority_verifier is not authority:
            raise SessionUnavailable("Xpra must use the authority-bound managed process supervisor")
        profile_mount = Path("/hermes/profiles") / process_template.profile_id
        try:
            runtime_dir.resolve(strict=False).relative_to(profile_mount)
        except (ValueError, OSError):
            raise SessionUnavailable("Xpra runtime path must stay inside its enrolled private profile")
        if process_template.profile_id != "hermes-desktop":
            raise SessionUnavailable("only the enrolled Hermes Desktop profile may start Xpra")
        if str(process_template.executable.resolve(strict=False)) != str(process_template.argv[0]):
            raise SessionUnavailable("managed Xpra executable differs from its protected process registration")
        if process_template.artifact_sha256 != _sha256_file(process_template.executable):
            raise SessionUnavailable("managed Xpra executable does not match its registered artifact pin")
        hermes_path = Path(session.hermes_executable)
        try:
            hermes_path.resolve(strict=False).relative_to(profile_mount)
        except (ValueError, OSError):
            raise SessionUnavailable("Hermes Desktop executable must be inside its enrolled profile mount")
        hermes_digest = _sha256_file(hermes_path)
        child_refs = process_template.child_artifact_refs or {}
        if not any(ref.rsplit(":", 1)[-1] == digest == hermes_digest
                   for ref, digest in child_refs.items()):
            raise SessionUnavailable("Hermes Desktop executable is absent from the protected child artifact pins")
        if type(process_template.max_lifetime_seconds) is not int or not 1 <= process_template.max_lifetime_seconds <= 600:
            raise SessionUnavailable("managed Xpra lifetime must be an integer bounded to ten minutes")
        self.session = session
        self.authority = authority
        self.process_template = process_template
        self.supervisor = supervisor
        self.xpra = str(process_template.executable)
        self.runtime_dir = runtime_dir
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
            child_artifact_refs=template.child_artifact_refs,
            max_lifetime_seconds=template.max_lifetime_seconds,
            max_output_bytes=4096,
            stdin_mode="closed",
        )
        payload_digest = canonical_digest(envelope)
        context = self.authority.context(
            purpose="hermes-profile-invoke",
            intent="start-pinned-hermes-desktop-xpra",
            operation="process.start",
            final_payload_digest=payload_digest,
            lease_seconds=30.0,
        )
        if (not isinstance(context, HostContext)
                or context.profile_id != template.profile_id or context.uid != os.geteuid()
                or context.operation != "process.start"
                or "hermes-profile-invoke" not in context.capabilities
                or context.final_payload_digest != payload_digest):
            raise SessionUnavailable("host context is not bound to this caller, profile and exact Xpra launch")
        grant = self.authority.authorize_effect(
            context,
            capability="hermes-profile-invoke",
            target=target,
            request_digest=canonical_digest(envelope),
            retry_index=0,
        )
        return replace(
            template,
            argv=argv,
            env_allowlist=env,
            authority_context=context,
            effect_authorization=grant,
            max_output_bytes=4096,
            stdin_mode="closed",
        )

    async def start(self) -> Mapping[str, Any]:
        if self.handle is not None:
            raise SessionUnavailable("this Desktop profile already has an active Xpra generation")
        import asyncio

        process_spec = await asyncio.to_thread(self._bound_process_spec)
        handle = await self.supervisor.start(process_spec)
        self.handle = handle
        try:
            identity = handle.identity
            receipt = await asyncio.to_thread(
                inspect_managed_process, self.authority,
                process_id=identity.process_id,
                generation=identity.generation,
                profile_id=self.process_template.profile_id,
            )
            if receipt.cgroup_identity != identity.cgroup:
                raise SessionUnavailable("root inspection cgroup does not match the managed Xpra generation")
            main = [item for item in receipt.processes if item.role == "xpra-server"]
            if len(main) != 1 or not self._matches_identity(main[0], identity):
                raise SessionUnavailable("root inspection does not identify the pinned Xpra server process")
            child_pins = self.process_template.child_artifact_refs or {}
            renderers = [item for item in receipt.processes
                         if item.role == "electron-renderer"
                         and item.exe_sha256 in child_pins.values()
                         and any(ref.rsplit(":", 1)[-1] == item.exe_sha256
                                 for ref, digest in child_pins.items() if digest == item.exe_sha256)
                         and item.cgroup_identity == identity.cgroup
                         and item.kernel_uid == identity.uid]
            renderer = next((item for item in renderers if self._descends_from(item, main[0], receipt.processes)), None)
            if renderer is None:
                raise SessionUnavailable("pinned Hermes Electron renderer lineage is absent from the root cgroup receipt")
            attestation = renderer.sandbox_attestation
            sandboxed = (attestation.get("verified") is True
                         and attestation.get("role") == "electron-renderer"
                         and attestation.get("artifact_verified") is True
                         and attestation.get("parent_chain_verified") is True
                         and attestation.get("kernel_uid") == renderer.kernel_uid
                         and attestation.get("cgroup_identity") == identity.cgroup
                         and attestation.get("seccomp_mode") == 2
                         and attestation.get("no_new_privs") is True
                         and attestation.get("forbidden_flags_present") is False)
            no_sandbox_marker = attestation.get("forbidden_flags_present") is True
            require_sandbox_evidence(renderer_sandboxed=sandboxed, no_sandbox_marker=no_sandbox_marker)
            if (attestation.get("relaunch_monitor_verified") is not True
                    or attestation.get("window_denial_verified") is not True
                    or attestation.get("native_generation") != receipt.generation):
                raise SessionUnavailable("root-protected renderer, relaunch, or window-denial enrollment is incomplete")
            return {
                "process_id": identity.process_id,
                "generation": identity.generation,
                "pid": identity.pid,
                "renderer_member_id": renderer.member_id,
                "display": self.session.display,
                "cgroup": identity.cgroup,
                "sandboxed": sandboxed,
                "no_sandbox_marker": no_sandbox_marker,
            }
        except BaseException:
            await self.stop()
            raise

    @staticmethod
    def _matches_identity(process: InspectedProcess, identity: Any) -> bool:
        return (process.cgroup_identity == identity.cgroup
                and process.exe_sha256 == identity.executable_sha256
                and process.exe_device == identity.executable_device
                and process.exe_inode == identity.executable_inode
                and process.starttime == identity.start_ticks
                and process.kernel_uid == identity.uid)

    @staticmethod
    def _descends_from(process: InspectedProcess, ancestor: InspectedProcess,
                       processes: tuple[InspectedProcess, ...]) -> bool:
        by_id = {item.member_id: item for item in processes}
        seen: set[str] = set()
        current = process
        while current.parent_member_id is not None:
            if current.parent_member_id == ancestor.member_id:
                return True
            if current.parent_member_id in seen:
                return False
            seen.add(current.parent_member_id)
            current = by_id.get(current.parent_member_id)  # type: ignore[assignment]
            if current is None:
                return False
        return False

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
