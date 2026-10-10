"""Human and JSON command line for the installer orchestration layer."""

from __future__ import annotations

import argparse
import json
import os
import sys
import sqlite3
import stat
import contextlib
import fcntl
import math
import shlex
import tarfile
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from . import __version__
from .state import Journal, OwnedRoot, OwnershipError, process_lock
from .lifecycle import GenerationStore, LifecycleBlocked, LifecycleError, LifecycleRecovery
from .config import ConfigError, InstallerConfig, load_config, validate_config, write_example
from .preflight import discover_host
from .results import CommandResult, Finding, OutcomeState
from .registry.native import NativeRegistry
from .registry.source import load_bundled_source


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="hermes-installer", description="Install and maintain Hermes Agent on supported Linux ARM64 systems")
    parser.add_argument("--version", action="version", version=f"hermes-installer {__version__}")
    parser.add_argument("--json", action="store_true", help="Write machine-readable output")
    parser.add_argument("--config", type=Path, help="Validated JSON configuration path")
    sub = parser.add_subparsers(dest="command", required=True)
    def command(name: str, help_text: str) -> argparse.ArgumentParser:
        child = sub.add_parser(name, help=help_text)
        child.add_argument("--json", action="store_true", default=argparse.SUPPRESS, help="Write machine-readable output")
        child.add_argument("--config", type=Path, default=argparse.SUPPRESS, help="Validated JSON configuration path")
        return child
    plan = command("plan", "Read-only compatibility and installation plan")
    plan.add_argument("--dry-run", action="store_true", help="Explicitly request no changes")
    install = command("install", "Apply the supported installation plan")
    install.add_argument("--dry-run", action="store_true", help="Print the plan without changes")
    install.add_argument("--non-interactive", action="store_true", help="Require complete validated configuration")
    setup = command("setup", "Choose components and configure accounts")
    setup.add_argument("--non-interactive", action="store_true", help="Use only explicit config and secure credential references")
    setup.add_argument("--save-config", type=Path, help="Write the secret-reference-only result to a new private config file")
    command("resume", "Resume the last checkpointed operation")
    status = command("status", "Show discovered and recorded component states")
    status.add_argument("component", nargs="?", help="Limit status to a component")
    command("doctor", "Run read-only host diagnostics")
    verify = command("verify", "Run executable acceptance probes on an identified target")
    verify.add_argument("--target", type=Path, help="Authorized target manifest")
    verify.add_argument("--output", type=Path, help="Evidence output directory")
    resources = command("resources", "Inspect the packaged offline resource registry")
    resources.add_argument("action", choices=("plan", "status"), help="Show the verified source crosswalk and pending native adapters")
    configure = command("configure", "Configure an external provider or MCP")
    configure.add_argument("target", choices=("provider", "mcp", "remote-desktop"))
    configure.add_argument("name", nargs="?", help="Adapter or connection name")
    configure.add_argument("--save-config", type=Path, help="Write the secret-reference-only result to a new private config file")
    connection = command("test-connection", "Test a configured provider or MCP")
    connection.add_argument("target", choices=("provider", "mcp", "remote-desktop"))
    connection.add_argument("name", nargs="?", help="Adapter or connection name")
    connection.add_argument("--save-config", type=Path, help="Write the secret-reference-only result to a new private config file")
    memory = command("select-memory", "Select the single long-term memory backend")
    memory.add_argument("choice", choices=("openviking", "claude-mem", "agent-memory"))
    memory.add_argument("--save-config", type=Path, help="Write the secret-reference-only result to a new private config file")
    source = command("resolve-source", "Resolve a source URL to an immutable revision")
    source.add_argument("url")
    component = sub.add_parser("component", help="Manage an installed component")
    component.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    component.add_argument("--config", type=Path, default=argparse.SUPPRESS)
    component.add_argument("action", choices=("enable", "disable", "start", "stop", "logs"))
    component.add_argument("name")
    updates = sub.add_parser("update", help="Check, apply, or roll back an update")
    updates.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    updates.add_argument("--config", type=Path, default=argparse.SUPPRESS)
    updates.add_argument("action", choices=("check", "apply", "rollback"))
    data = sub.add_parser("data", help="Back up, restore, or uninstall while retaining user data")
    data.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
    data.add_argument("--config", type=Path, default=argparse.SUPPRESS)
    data.add_argument("action", choices=("backup", "restore", "uninstall"))
    data.add_argument("--backup", type=Path, help="Installer-owned backup directory for restore")
    data.add_argument("--overwrite", action="store_true", help="Replace conflicting user files during restore")
    data.add_argument("--include-database", action="store_true", help="Include a consistent installer-state database snapshot")
    data.add_argument("--restore-database", action="store_true", help="Explicitly restore the installer-state database snapshot")
    sub.add_parser("init-config", help="Write a secret-free example JSON configuration")
    return parser


def _configuration(path: Path | None) -> InstallerConfig:
    return load_config(path) if path else validate_config({"schema_version": 1})


def _root_launcher_status() -> tuple[str, str | None, str, str]:
    """Read the root entrypoint's pathless status without escalating or launching it."""
    try:
        from .root_setup import LauncherStatus, launcher_status
        status = launcher_status()
        if type(status) is not LauncherStatus or status.authority is not False:
            raise ValueError("launcher status is not the read-only typed schema")
        return status.state, status.blocker_code, status.message, status.resume_command
    except (ImportError, OSError, RuntimeError, ValueError):
        return ("root-setup-required", "ROOT_ATTESTATION_REQUIRED",
                "The installed launcher has not been verified by its root actor.", "")


def _run_setup(args: argparse.Namespace) -> CommandResult:
    from .setup_wizard import PrivateFileCredentialStore, run_setup_wizard

    if not args.non_interactive and not sys.stdin.isatty():
        return CommandResult("setup", OutcomeState.FAILED,
            "Interactive setup requires a terminal. Use --non-interactive with a validated config and secure credential references.",
            exit_code=2)
    try:
        if args.config:
            raw_config = json.loads(args.config.read_text(encoding="utf-8"))
            if not isinstance(raw_config, dict):
                raise ValueError("Configuration root must be an object")
        else:
            raw_config = {"schema_version": 1}
        paths_value = raw_config.get("paths", {})
        if not isinstance(paths_value, dict):
            raise ValueError("paths must be an object")
        state_value = paths_value.get("state_root", "~/HermesInstaller/state")
        if not isinstance(state_value, str) or not state_value:
            raise ValueError("paths.state_root must be a non-empty path string")
        state_root = OwnedRoot(Path(state_value).expanduser())
        state_root.ensure()
        resume = "hermes-installer setup" + (" --non-interactive" if args.non_interactive else "")
        if args.config:
            resume += " --config " + shlex.quote(str(args.config))
        if args.save_config:
            resume += " --save-config " + shlex.quote(str(args.save_config))
        with process_lock(state_root.path("installer.lock")):
            journal = Journal(state_root.path("journal.sqlite3"))
            journal.checkpoint("installer:setup-command", "running", {
                "config_path": str(args.config) if args.config else None,
                "non_interactive": bool(args.non_interactive)})
            try:
                result = run_setup_wizard(raw_config, credential_store=PrivateFileCredentialStore(state_root.root),
                    journal=journal, interactive=not args.non_interactive, resume_command=resume)
            except KeyboardInterrupt:
                journal.checkpoint("installer:setup-command", "cancelled", {"resume": resume})
                journal.event("installer:setup-command", "wizard", "cancelled", {"resume": resume})
                return CommandResult("setup", OutcomeState.PENDING,
                    "Setup was cancelled; completed private credential writes and user data were preserved.",
                    resume_command=resume, exit_code=4)
            except Exception as exc:
                journal.checkpoint("installer:setup-command", "failed", {
                    "error_type": type(exc).__name__, "resume": resume})
                journal.event("installer:setup-command", "wizard", "failed", {
                    "error_type": type(exc).__name__})
                raise
            state_name = result.state
            message = result.message
            account_states = dict(result.account_states)
            next_steps = list(result.next_steps)
            config_output = dict(result.config)
            remote_config = config_output.get("remote_desktop", {})
            if (result.selected_components.get("remote_desktop") is True
                    and isinstance(remote_config, dict)
                    and isinstance(remote_config.get("hostname"), str) and remote_config["hostname"]
                    and isinstance(remote_config.get("management_token_ref"), str)
                    and remote_config["management_token_ref"]):
                try:
                    from .remote.enrollment import run_remote_desktop_enrollment
                    enrollment = run_remote_desktop_enrollment(
                        config_output, journal, activate_route=False,
                        resume_command=result.resume_command or resume)
                    account_states["remote_desktop_access"] = enrollment.access_state
                    account_states["remote_desktop_policy_read"] = enrollment.policy_read_state
                    account_states["remote_desktop_route"] = enrollment.route_state
                    if enrollment.component_installable is True:
                        installable_config = dict(config_output)
                        installable_components = dict(installable_config.get("components", {}))
                        installable_components["remote_desktop"] = True
                        installable_config["components"] = installable_components
                        config_output = asdict(validate_config(installable_config))
                    if enrollment.state == "failed":
                        state_name = "failed"
                    elif enrollment.state != "ready" and state_name == "ready":
                        state_name = "pending"
                    next_steps.extend(enrollment.next_steps)
                    message = enrollment.message
                    journal.checkpoint("installer:setup-command", state_name, {
                        "selected_components": dict(result.selected_components),
                        "account_states": account_states, "resume": result.resume_command or resume,
                        "remote_phase": enrollment.phase,
                        "remote_resource_ids": dict(enrollment.resource_ids),
                    })
                    journal.event("installer:setup-command", "remote-enrollment", enrollment.state, {
                        "phase": enrollment.phase, "access_state": enrollment.access_state,
                        "policy_read_state": enrollment.policy_read_state,
                        "route_state": enrollment.route_state,
                        "resource_ids": dict(enrollment.resource_ids),
                    })
                except Exception as exc:
                    # Preserve the setup checkpoint for retry. Never expose
                    # token values or raw provider bodies in the CLI result.
                    state_name = "pending" if state_name != "failed" else state_name
                    account_states["remote_desktop_access"] = "pending"
                    next_steps.append(
                        "Owned Access enrollment could not be completed; preserve the saved secure references and rerun setup."
                    )
                    message = "Remote Desktop setup remains pending; owned resource checkpoints and secure references were preserved."
                    journal.checkpoint("installer:setup-command", state_name, {
                        "selected_components": dict(result.selected_components),
                        "account_states": account_states, "resume": result.resume_command or resume,
                        "remote_error_type": type(exc).__name__,
                    })
                    journal.event("installer:setup-command", "remote-enrollment", "pending", {
                        "error_type": type(exc).__name__,
                    })
            state = {"ready": OutcomeState.READY, "pending": OutcomeState.PENDING,
                     "failed": OutcomeState.FAILED}[state_name]
            saved_path = None
            if args.save_config and result.state != "failed":
                try:
                    saved_path = _write_private_config(args.save_config, config_output)
                except OSError as exc:
                    journal.checkpoint("installer:setup-command", "failed", {
                        "error_type": type(exc).__name__, "resume": resume})
                    journal.event("installer:setup-command", "config-write", "failed", {
                        "error_type": type(exc).__name__})
                    raise
            journal.checkpoint("installer:setup-command", state_name, {
                "selected_components": dict(result.selected_components),
                "account_states": account_states, "resume": result.resume_command,
                "saved_config": str(saved_path) if saved_path else None})
            details = {"selected_components": dict(result.selected_components),
                "account_states": account_states, "next_steps": next_steps,
                "config": config_output, "saved_config": str(saved_path) if saved_path else None}
            if state_name == "failed":
                # Retain a wizard validation code, but do not return the
                # resumable-pending code for an owned-resource conflict.
                exit_code = result.exit_code if result.state == "failed" and result.exit_code else 1
            elif state_name == "pending":
                exit_code = 4
            else:
                exit_code = 0
            return CommandResult("setup", state, message,
                (Finding("setup.wizard", message, state, details),),
                result.resume_command or resume, exit_code)
    except (OSError, OwnershipError, RuntimeError, ValueError, ConfigError) as exc:
        return CommandResult("setup", OutcomeState.FAILED, str(exc), exit_code=2)


def _run_configuration_command(args: argparse.Namespace, config: InstallerConfig) -> CommandResult:
    from .configuration_cli import run_configuration_command
    from .setup_wizard import PrivateFileCredentialStore

    action = args.command
    if action == "configure" and not sys.stdin.isatty():
        return CommandResult(action, OutcomeState.FAILED,
            "Interactive configuration requires a terminal; no credential was collected.", exit_code=2)
    state_path = Path(config.paths.get("state_root", "~/HermesInstaller/state")).expanduser()
    resume = f"hermes-installer {action}"
    target = getattr(args, "target", None)
    if action == "select-memory":
        target = "memory"
    name = getattr(args, "name", None)
    if target:
        resume += " " + shlex.quote(target)
    if name:
        resume += " " + shlex.quote(name)
    if getattr(args, "choice", None):
        resume += " " + shlex.quote(args.choice)
    if getattr(args, "url", None):
        resume += " " + shlex.quote(args.url)
    if args.config:
        resume += " --config " + shlex.quote(str(args.config))
    save_config = getattr(args, "save_config", None)
    if save_config:
        resume += " --save-config " + shlex.quote(str(save_config))
    journal = None
    try:
        state_root = OwnedRoot(state_path)
        state_root.ensure()
        with process_lock(state_root.path("installer.lock")):
            journal = Journal(state_root.path("journal.sqlite3"))
            journal.checkpoint("installer:configuration:" + action, "running", {
                "target": target, "name": name, "config_path": str(args.config) if args.config else None,
                "resume": resume})
            result = run_configuration_command(
                action, config_data={"schema_version": config.schema_version,
                    "timezone": config.timezone, "paths": config.paths,
                    "components": config.components, "privacy": config.privacy,
                    "remote_desktop": config.remote_desktop},
                journal=journal, credential_store=PrivateFileCredentialStore(state_root.root),
                interactive=action == "configure", resume_command=resume,
                target=target, name=name, choice=getattr(args, "choice", None),
                url=getattr(args, "url", None))
            saved_path = None
            if result.state != OutcomeState.FAILED and save_config:
                config_value = next((finding.details.get("config") for finding in result.findings
                                     if isinstance(finding.details.get("config"), dict)), None)
                if config_value is None:
                    raise ValueError("Configuration adapter did not return a validated config")
                saved_path = _write_private_config(save_config, config_value)
                findings = tuple(Finding(item.code, item.message, item.state,
                    {**item.details, "saved_config": str(saved_path)}) for item in result.findings)
                result = CommandResult(result.command, result.state, result.message, findings,
                    result.resume_command, result.exit_code)
            journal.checkpoint("installer:configuration:" + action, result.state.value, {
                "exit_code": result.exit_code, "resume": result.resume_command or resume})
            journal.event("installer:configuration:" + action, "command", result.state.value, {
                "exit_code": result.exit_code, "target": target, "name": name})
            return result
    except (OSError, OwnershipError, RuntimeError, ValueError, ConfigError, sqlite3.Error) as exc:
        if journal is not None:
            try:
                journal.checkpoint("installer:configuration:" + action, "failed", {
                    "error_type": type(exc).__name__, "resume": resume})
                journal.event("installer:configuration:" + action, "command", "failed", {
                    "error_type": type(exc).__name__})
            except (OSError, RuntimeError, sqlite3.Error):
                pass
        return CommandResult(action, OutcomeState.FAILED,
            f"Configuration state could not be safely accessed: {type(exc).__name__}.",
            resume_command=resume, exit_code=1)


def _write_private_config(path: Path, config: dict[str, object]) -> Path:
    """Create a new mode-0600 config file without following links or replacing data."""
    target = path.expanduser().absolute()
    parent = target.parent
    if parent.is_symlink() or not parent.is_dir():
        raise OwnershipError("Config output parent must be an existing non-symlink directory")
    payload = (json.dumps(config, indent=2, sort_keys=True) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(target, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        directory_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    return target


def _render(result: CommandResult, as_json: bool) -> None:
    if as_json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return
    print(f"{result.command}: {result.state.value} — {result.message}")
    for finding in result.findings:
        print(f"  [{finding.state.value}] {finding.code}: {finding.message}")
    if result.resume_command:
        print(f"Resume: {result.resume_command}")


def _host_findings(config: InstallerConfig | None = None) -> tuple[Finding, ...]:
    configured_paths = tuple(Path(value).expanduser() for value in (config.paths.values() if config else ()))
    facts = discover_host(selected_paths=configured_paths or None)
    state = OutcomeState.READY if facts.supported_arm64_linux else OutcomeState.PENDING
    items = [Finding("host.support", "Supported 64-bit Linux ARM64" if facts.supported_arm64_linux else "Host is not an enrolled supported Linux ARM64 target", state, {"os": facts.os_name, "architecture": facts.architecture})]
    if facts.graphical_session:
        items.append(Finding("desktop.session", "A graphical user session is present", OutcomeState.READY))
    else:
        items.append(Finding("desktop.session", "No graphical user session is present", OutcomeState.PENDING))
    for lock in facts.package_locks:
        items.append(Finding("package.lock", f"Package manager state requires review: {lock}", OutcomeState.PENDING))
    for service in facts.service_conflicts:
        items.append(Finding("service.conflict", f"Existing service detected; adoption must be explicit: {service}", OutcomeState.PENDING))
    for lock in facts.package_locks:
        items.append(Finding("package.lock.held", f"Package manager lock is currently held: {lock}", OutcomeState.PENDING))
    for problem in facts.package_lock_probe_errors:
        items.append(Finding("package.lock.unknown", f"Could not determine whether package manager is active: {problem}", OutcomeState.PENDING))
    items.append(Finding("network.dns", "DNS lookup succeeded" if facts.network_dns else "DNS lookup failed or timed out" if facts.network_dns is False else "DNS probe was unavailable", OutcomeState.READY if facts.network_dns else OutcomeState.PENDING))
    items.append(Finding("network.tls", "TLS certificate validation succeeded" if facts.network_tls else "TLS validation failed" if facts.network_tls is False else "TLS probe was unavailable", OutcomeState.READY if facts.network_tls else OutcomeState.PENDING))
    for disk in facts.disks:
        presence = "exists" if disk.path_exists else "does not exist yet; parent filesystem measured"
        items.append(Finding("storage.mount", f"{disk.path} {presence}; {disk.mount} uses {disk.filesystem or 'filesystem unknown'}, {disk.available_bytes} bytes free", OutcomeState.READY if disk.path_exists and disk.filesystem and disk.available_bytes > 0 else OutcomeState.PENDING, {"device": disk.device, "connection_type": disk.connection_type, "total_bytes": disk.total_bytes}))
    if facts.coral_devices:
        for coral in facts.coral_devices:
            items.append(Finding("coral.detected", f"Coral-compatible device evidence found on {coral.bus}: {coral.path}", OutcomeState.READY, coral.details))
    else:
        items.append(Finding("coral.pending", "No supported Coral identifier was detected; no driver was selected", OutcomeState.PENDING))
    if facts.occupied_ports:
        items.append(Finding("ports.bound", "Listening ports were detected; component port conflicts require review", OutcomeState.PENDING, {"ports": facts.occupied_ports}))
    return tuple(items)



@contextlib.contextmanager
def _quiescent_journal(state_path: Path):
    """Yield an immutable SQLite reader only while a pre-existing writer lock is quiescent.

    Status must never create lock/database/WAL files or update WAL read marks.
    Writers cooperate through installer.lock; a live lock holder or nonempty WAL
    makes the answer indeterminate instead of returning a stale checkpoint.
    """
    path = state_path.expanduser().absolute()
    if path.is_symlink() or not path.is_dir():
        raise OSError("state root unavailable")
    root_info = path.lstat()
    if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid()
            or stat.S_IMODE(root_info.st_mode) & 0o077):
        raise OSError("state root ownership is not verified")
    marker = path / ".hermes-installer-owned"
    marker_fd = os.open(marker, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        marker_info = os.fstat(marker_fd)
        if (not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid()
                or stat.S_IMODE(marker_info.st_mode) & 0o077
                or os.read(marker_fd, 65) != b"schema=1\n"):
            raise OSError("ownership marker is invalid")
    finally:
        os.close(marker_fd)

    lock_path = path / "installer.lock"
    lock_fd = os.open(lock_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        lock_info = os.fstat(lock_fd)
        if (not stat.S_ISREG(lock_info.st_mode) or lock_info.st_uid != os.getuid()
                or stat.S_IMODE(lock_info.st_mode) & 0o077):
            raise OSError("lock ownership is not verified")
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("installer operation is active") from None

        database = path / "journal.sqlite3"
        db_info = database.lstat()
        if (database.is_symlink() or not stat.S_ISREG(db_info.st_mode)
                or db_info.st_uid != os.getuid() or stat.S_IMODE(db_info.st_mode) & 0o077):
            raise OSError("journal ownership is not verified")
        wal = path / "journal.sqlite3-wal"
        try:
            wal_info = wal.lstat()
        except FileNotFoundError:
            wal_info = None
        if wal_info is not None:
            if wal.is_symlink() or not stat.S_ISREG(wal_info.st_mode) or wal_info.st_uid != os.getuid():
                raise OSError("journal WAL ownership is not verified")
            if wal_info.st_size:
                raise RuntimeError("journal has an active or uncheckpointed WAL")
        before = (db_info.st_dev, db_info.st_ino, db_info.st_size, db_info.st_mtime_ns, db_info.st_ctime_ns,
                  None if wal_info is None else (wal_info.st_dev, wal_info.st_ino, wal_info.st_size, wal_info.st_mtime_ns, wal_info.st_ctime_ns))
        uri = database.as_uri() + "?mode=ro&immutable=1"
        with contextlib.closing(sqlite3.connect(uri, uri=True, timeout=2)) as db:
            db.row_factory = sqlite3.Row
            yield db
        db_after = database.lstat()
        try:
            wal_after_info = wal.lstat()
        except FileNotFoundError:
            wal_after_info = None
        after = (db_after.st_dev, db_after.st_ino, db_after.st_size, db_after.st_mtime_ns, db_after.st_ctime_ns,
                 None if wal_after_info is None else (wal_after_info.st_dev, wal_after_info.st_ino, wal_after_info.st_size, wal_after_info.st_mtime_ns, wal_after_info.st_ctime_ns))
        if before != after:
            raise RuntimeError("journal changed during immutable read")
    finally:
        with contextlib.suppress(OSError):
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)


def _run_data_command(args: argparse.Namespace, config: InstallerConfig) -> CommandResult:
    data_path = Path(config.paths.get("data_root", "~/HermesInstaller/data")).expanduser()
    state_path = Path(config.paths.get("state_root", "~/HermesInstaller/state")).expanduser()
    config_path = getattr(args, "config", None)
    resume = f"hermes-installer data {args.action}" + (f" --config {shlex.quote(str(config_path))}" if config_path else "")
    if args.action == "restore" and getattr(args, "backup", None) is not None:
        resume += " --backup " + shlex.quote(str(args.backup))
        if getattr(args, "overwrite", False):
            resume += " --overwrite"
        if getattr(args, "restore_database", False):
            resume += " --restore-database"
    if args.action == "restore" and getattr(args, "backup", None) is None:
        return CommandResult("data", OutcomeState.FAILED,
            "Restore requires an explicit installer-owned backup path; no data was changed.",
            resume_command=resume + " --backup <backup-directory>", exit_code=2)
    if args.action == "backup" and getattr(args, "restore_database", False):
        return CommandResult("data", OutcomeState.FAILED,
            "--restore-database applies only to restore; no data was changed.", exit_code=2)
    if args.action != "backup" and getattr(args, "include_database", False):
        return CommandResult("data", OutcomeState.FAILED,
            "--include-database applies only to backup; no data was changed.", exit_code=2)
    if (args.action == "uninstall" and not data_path.exists() and not data_path.is_symlink()
            and not state_path.exists() and not state_path.is_symlink()):
        return CommandResult("data", OutcomeState.READY,
            "No installer-owned data or state roots exist; uninstall was a no-op.",
            (Finding("lifecycle.uninstall", "No owned installation was found", OutcomeState.READY,
                {"removed_generations": [], "data_retained": True}),))
    if args.action != "restore" and (getattr(args, "overwrite", False) or getattr(args, "restore_database", False)):
        return CommandResult("data", OutcomeState.FAILED,
            "--overwrite and --restore-database apply only to restore; no data was changed.", exit_code=2)
    try:
        data_root = OwnedRoot(data_path)
        state_root = OwnedRoot(state_path)
        state_root.ensure()
        lock = state_root.path("installer.lock")
        with process_lock(lock):
            data_root.ensure()
            journal = Journal(state_root.path("journal.sqlite3"))
            recovery = LifecycleRecovery(data_root, state_root, journal)
            if args.action == "backup":
                database = state_root.path("journal.sqlite3")
                backup = recovery.backup(database=database if getattr(args, "include_database", False) else None)
                return CommandResult("data", OutcomeState.READY,
                    "Owned user data backup completed; credential values remain in their configured secure stores.",
                    (Finding("lifecycle.backup", "Versioned backup verified and committed", OutcomeState.READY,
                        {"backup": str(backup), "database_included": bool(getattr(args, "include_database", False))}),))
            if args.action == "restore":
                database = state_root.path("journal.sqlite3") if getattr(args, "restore_database", False) else None
                result = recovery.restore(args.backup, overwrite=bool(getattr(args, "overwrite", False)),
                    database_destination=database)
                state = OutcomeState.PENDING if result["conflicts_preserved"] else OutcomeState.READY
                return CommandResult("data", state,
                    "Backup restore completed; existing conflicting user files were preserved." if result["conflicts_preserved"]
                    else "Backup restore completed with per-file integrity verification.",
                    (Finding("lifecycle.restore", "Restore results are journaled", state, result),))
            if args.action == "uninstall":
                active_services = [row for row in journal.owned()
                    if row["kind"] in {"service", "process", "daemon"}
                    and row["state"] in {"active", "running", "enabled"}]
                active_generations = [row for row in journal.owned()
                    if row["kind"] in {"generation", "hermes-generation"}
                    and row["state"] == "active"]
                pointer_generation = GenerationStore.inspect_active_readonly(data_root)
                if active_services or active_generations or pointer_generation is not None:
                    return CommandResult("data", OutcomeState.PENDING,
                        "Uninstall is blocked until host custody verifies shutdown and deactivation of active generations; user data was retained.",
                        (Finding("lifecycle.uninstall", "Active managed effects require verified shutdown", OutcomeState.PENDING,
                            {"services": [row["resource_id"] for row in active_services],
                             "generations": [row["resource_id"] for row in active_generations],
                             "active_generation": pointer_generation.identity if pointer_generation else None}),),
                        resume_command=resume)
                result = recovery.uninstall()
                return CommandResult("data", OutcomeState.READY,
                    "Installer-owned generations were removed and profiles, overlays, memories, models, and backups were retained.",
                    (Finding("lifecycle.uninstall", "Data-preserving uninstall completed", OutcomeState.READY, result),))
    except LifecycleBlocked as exc:
        return CommandResult("data", OutcomeState.PENDING, str(exc), resume_command=resume)
    except LifecycleError as exc:
        return CommandResult("data", OutcomeState.FAILED, str(exc), resume_command=resume, exit_code=1)
    except RuntimeError:
        return CommandResult("data", OutcomeState.PENDING,
            "Another installer operation holds the lifecycle lease; no concurrent lifecycle action was started.",
            resume_command=resume)
    except (OwnershipError, OSError, sqlite3.Error, ValueError, tarfile.TarError) as exc:
        return CommandResult("data", OutcomeState.FAILED, str(exc), resume_command=resume, exit_code=1)
    return CommandResult("data", OutcomeState.FAILED, "Unsupported data lifecycle action.", exit_code=2)


def _recorded_component_findings(state_path: Path, component: str | None = None) -> tuple[Finding, ...]:
    """Report historical checkpoints without mutating SQLite or implying current health."""
    path = state_path.expanduser().absolute()
    try:
        with _quiescent_journal(path) as db:
            row = db.execute(
                "SELECT status,updated_at,payload FROM operations WHERE id='installer:selection'"
            ).fetchone()
            resources = db.execute(
                "SELECT kind,state,COUNT(*) AS count FROM owned_resources GROUP BY kind,state ORDER BY kind,state"
            ).fetchall()
    except RuntimeError as exc:
        detail = ("Installer operation is active" if str(exc) == "installer operation is active"
                  else "Installer journal has uncheckpointed changes")
        return (Finding("installer.state", detail + "; status is indeterminate until it is quiescent", OutcomeState.PENDING),)
    except (OSError, sqlite3.Error, ValueError):
        return (Finding("installer.state", "No safely readable, quiescent installer checkpoint is available", OutcomeState.PENDING),)
    if row is None:
        findings = (Finding("installer.state", "No installation operation has been recorded", OutcomeState.PENDING),)
        if component:
            selected = component.lower().replace(".", "_").replace("-", "_")
            return (Finding("component." + selected, f"No durable status is recorded for component {selected}", OutcomeState.PENDING),)
        return findings
    try:
        payload = json.loads(row["payload"])
        if not isinstance(payload, dict):
            raise ValueError("invalid journal payload")
        report = payload.get("report", payload)
        if not isinstance(report, dict):
            report = {}
    except (ValueError, TypeError):
        return (Finding("installer.state", "Recorded installer checkpoint is malformed", OutcomeState.PENDING),)
    try:
        timestamp = float(row["updated_at"])
        if not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("invalid checkpoint timestamp")
    except (ValueError, TypeError, OverflowError):
        return (Finding("installer.state", "Recorded installer checkpoint is malformed", OutcomeState.PENDING),)
    findings = [
        Finding("installer.operation", f"Recorded installer operation: {row['status']} (updated_at={timestamp:.3f})",
                OutcomeState.PENDING, {"recorded_at": timestamp, "historical": True}),
        Finding("hermes.agent.bootstrap", "A historical Agent runtime verification passed" if report.get("agent_ready") is True
                else "Agent runtime verification is not recorded as passed",
                OutcomeState.PENDING, {"historical": True}),
        Finding("hermes.desktop.build", "A historical official Desktop build was recorded" if report.get("desktop_built") is True
                else "Official Desktop build is not recorded",
                OutcomeState.PENDING, {"historical": True}),
    ]
    for item in resources:
        findings.append(Finding(
            "resource." + str(item["kind"]),
            f"Recorded owned {item['kind']} resources in state {item['state']}: {int(item['count'])}",
            OutcomeState.PENDING,
            {"count": int(item["count"]), "historical": True},
        ))
    if component:
        selected = component.lower().replace(".", "_").replace("-", "_")
        aliases = {
            "agent": "hermes_agent", "hermes_agent": "hermes_agent",
            "desktop": "hermes_desktop", "hermes_desktop": "hermes_desktop",
            "provider": "provider", "gateway": "provider_gateway",
            "remote": "remote_desktop", "remote_desktop": "remote_desktop",
        }
        selected = aliases.get(selected, selected)
        matching = tuple(item for item in findings
                         if item.code.lower().replace(".", "_").replace("-", "_").startswith(selected)
                         or item.code.lower().replace(".", "_").replace("-", "_").startswith("resource_" + selected))
        return matching or (Finding("component." + selected,
            f"No durable status is recorded for component {selected}",
            OutcomeState.PENDING),)
    return tuple(findings)


def run(args: argparse.Namespace) -> CommandResult:
    if args.command == "init-config":
        path = args.config or Path("installer.example.json")
        try:
            write_example(path)
        except FileExistsError:
            return CommandResult("init-config", OutcomeState.FAILED, f"Refusing to overwrite {path}", exit_code=2)
        return CommandResult("init-config", OutcomeState.READY, f"Wrote secret-free example configuration to {path}")
    if args.command == "setup":
        return _run_setup(args)
    try:
        config = _configuration(args.config)
    except ConfigError as exc:
        return CommandResult(args.command, OutcomeState.FAILED, str(exc), exit_code=2)

    if args.command in {"plan", "doctor"}:
        findings = _host_findings(config)
        state = OutcomeState.READY if all(f.state == OutcomeState.READY for f in findings) else OutcomeState.PENDING
        suffix = "No files, services, packages, or accounts were changed."
        return CommandResult(args.command, state, suffix, findings, exit_code=0 if state != OutcomeState.FAILED else 1)
    if args.command == "status":
        state_path = Path(config.paths.get("state_root", "~/HermesInstaller/state")).expanduser()
        host = _host_findings(config)
        recorded = _recorded_component_findings(state_path, getattr(args, "component", None))
        findings = tuple(recorded) if getattr(args, "component", None) else tuple(host) + tuple(recorded)
        state = OutcomeState.READY if findings and all(f.state == OutcomeState.READY for f in findings) else OutcomeState.PENDING
        return CommandResult("status", state, "Read-only host and durable component status; no state was changed.", findings)
    if args.command == "resources":
        try:
            registry = NativeRegistry.from_verified_source(load_bundled_source())
            bindings = registry.crosswalk()
        except (OSError, RuntimeError, ValueError) as exc:
            return CommandResult("resources", OutcomeState.FAILED, f"Packaged resource verification failed: {exc}", exit_code=1)
        by_kind: dict[str, dict[str, int]] = {}
        for item in bindings:
            counts = by_kind.setdefault(item.kind, {"total": 0, "native": 0, "blocked": 0})
            counts["total"] += 1
            counts["native"] += int(item.kind in {"profiles", "skills"})
            counts["blocked"] += int(bool(item.blockers))
        blocked = [item for item in bindings if item.blockers]
        finding = Finding("resources.native-crosswalk", "Verified catalog and native materialization bindings; selected-target discovery, invocation, remaining adapters, and runtime acceptance are pending", OutcomeState.PENDING, {
            "catalog_version": registry.source.catalog_version,
            "source_revision": registry.source.revision,
            "root_counts": dict(registry.root_counts),
            "native_profile_root": "HERMES_HOME/profiles/<profile_id>/",
            "native_skill_root": "HERMES_HOME/skills/<skill_id>/SKILL.md",
            "target_discovery": "not-probed-by-this-read-only-command",
            "target_verified": False,
            "kinds": by_kind,
            "blocked_items": len(blocked),
            "sample_blockers": [{"kind": item.kind, "id": item.resource_id, "reason": item.blockers[0]} for item in blocked[:8]],
        })
        action = args.action
        return CommandResult("resources", OutcomeState.PENDING,
            f"Read-only {action}: verified {len(bindings)} declarations from the packaged bundle; materialization is planned, selected-target discovery and native operation remain pending.",
            (finding,), resume_command="hermes-installer resources status")
    if args.command == "verify":
        if args.target is None or args.output is None:
            return CommandResult("verify", OutcomeState.FAILED, "An authorized target manifest and evidence directory are required.", resume_command="hermes-installer verify --target <authorized-target.json> --output <evidence-dir>", exit_code=2)
        return CommandResult("verify", OutcomeState.PENDING, "Target verification adapter is not implemented yet; no target was contacted.", resume_command=f"hermes-installer verify --target {args.target} --output {args.output}")
    if args.command in {"install", "resume"}:
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult(args.command, OutcomeState.FAILED, "Installation is restricted to supported Linux ARM64 targets; this host was not changed.", findings=_host_findings(config), exit_code=3)
        if facts.package_locks or facts.package_lock_probe_errors:
            details = facts.package_locks or facts.package_lock_probe_errors
            return CommandResult(args.command, OutcomeState.PENDING,
                "Package manager activity could not be ruled out safely; no installation stage was started.",
                tuple(Finding("package.lock", str(item), OutcomeState.PENDING) for item in details),
                resume_command=f"hermes-installer {args.command}" + (f" --config {args.config}" if args.config else ""))
        if args.command == "install" and getattr(args, "dry_run", False):
            return CommandResult("install", OutcomeState.READY, "Dry run completed; no installer files, packages, services, or accounts were changed.", _host_findings(config))
        if config.components.get("hermes_agent") is False:
            return CommandResult(args.command, OutcomeState.FAILED, "Hermes Agent is explicitly disabled in configuration; no Agent stages were run.", exit_code=2)
        launcher_state, blocker_code, launcher_message, root_resume = _root_launcher_status()
        # Install/update execution belongs to the separately installed root-local
        # setup entrypoint. The pathless launcher-status check is informational
        # only; an unverified caller must not create state roots or fall back to worker-side
        # downloads/process execution. Root setup revalidates the durable selection
        # and owns the transaction, enrollment, and managed effects.
        expected_root_command = f"sudo -- hermes-installer-root-setup {args.command}"
        resume_command = (root_resume if root_resume == expected_root_command
                          else "hermes-installer status")
        return CommandResult(args.command, OutcomeState.PENDING,
            f"{launcher_message} No installer state, data root, package, service, or account was changed.",
            (Finding("lifecycle.root-setup", "Root-local launcher status gates privileged setup effects.", OutcomeState.PENDING,
                     {"launcher_status": launcher_state, "blocker_code": blocker_code,
                      "effects_started": False}),),
            resume_command=resume_command)
    if args.command == "data":
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult("data", OutcomeState.FAILED,
                "Data lifecycle commands are restricted to supported Linux ARM64 targets; this host was not changed.",
                findings=_host_findings(config), exit_code=3)
        return _run_data_command(args, config)
    if args.command == "update":
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult("update", OutcomeState.FAILED,
                "Updates are restricted to supported Linux ARM64 targets; this host was not changed.",
                findings=_host_findings(config), exit_code=3)
        action = args.action
        if action == "check":
            try:
                data_root = OwnedRoot(Path(config.paths.get("data_root", "~/HermesInstaller/data")).expanduser())
                active = GenerationStore.inspect_active_readonly(data_root)
            except (LifecycleError, OwnershipError, OSError, ValueError) as exc:
                return CommandResult("update", OutcomeState.FAILED,
                    f"Managed generation state could not be verified: {exc}", exit_code=1)
            identity = active.identity if active else None
            message = ("No pinned update candidate is enrolled in the protected artifact catalog; active generation was not changed."
                       if active else "No installer-managed active generation exists; no update candidate was applied.")
            return CommandResult("update", OutcomeState.PENDING, message,
                (Finding("lifecycle.update", message, OutcomeState.PENDING,
                    {"active_generation": identity, "active_digest": active.digest if active else None,
                     "candidate_generation": None, "candidate_available": False}),),
                resume_command=f"hermes-installer update check" + (f" --config {shlex.quote(str(args.config))}" if args.config else ""))
        launcher_state, blocker_code, launcher_message, root_resume = _root_launcher_status()
        root_action = "update" if action == "apply" else None
        expected_root_command = (f"sudo -- hermes-installer-root-setup {root_action}"
                                 if root_action is not None else "")
        message = f"{launcher_message} No update or rollback effect was started; managed generation activation requires the root-owned transaction and live health observer."
        return CommandResult("update", OutcomeState.PENDING, message,
            (Finding("lifecycle.update", message, OutcomeState.PENDING,
                {"candidate_generation": None, "health_probe": "protected-managed-process-not-enrolled",
                 "launcher_status": launcher_state, "blocker_code": blocker_code,
                 "effects_started": False}),),
            resume_command=(root_resume if root_resume == expected_root_command and expected_root_command
                            else "hermes-installer status"))
    if args.command in {"configure", "test-connection", "select-memory", "resolve-source"}:
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult(args.command, OutcomeState.FAILED, "This operation is restricted to supported Linux ARM64 targets; this host was not changed.", findings=_host_findings(config), exit_code=3)
        return _run_configuration_command(args, config)
    if args.command == "component":
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult("component", OutcomeState.FAILED, "Component lifecycle operations are restricted to supported Linux ARM64 targets; this host was not changed.", findings=_host_findings(config), exit_code=3)
        return CommandResult("component", OutcomeState.PENDING,
            "Component lifecycle remains unavailable until its protected service selector and verified runtime binding are enrolled.",
            resume_command=f"hermes-installer component {shlex.quote(args.action)} {shlex.quote(args.name)}" + (f" --config {shlex.quote(str(args.config))}" if args.config else ""))
    raise AssertionError(f"Unhandled CLI command: {args.command}")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_args = list(sys.argv[1:] if argv is None else argv)
    if not raw_args:
        print("Hermes Agent Installer — guided setup")
        if not sys.stdin.isatty():
            print("Run this command in a terminal to choose an action, or use `./install.sh plan` for a read-only preflight.")
            parser.print_help()
            return 0
        choices = {"1": ["plan"], "2": ["setup"], "3": ["doctor"], "4": ["verify"], "5": ["resources", "status"], "0": []}
        print("1) Review a read-only plan\n2) Guided setup\n3) Diagnose this machine\n4) Verify an authorized target\n5) Inspect bundled Resources\n0) Exit")
        selected = input("Choose an action [0-5]: ").strip()
        if selected not in choices:
            print("Choose one of the listed actions.", file=sys.stderr)
            return 2
        if not choices[selected]:
            return 0
        raw_args = choices[selected]
    args = parser.parse_args(raw_args)
    try:
        result = run(args)
    except (OSError, RuntimeError, ValueError) as exc:
        result = CommandResult(args.command, OutcomeState.FAILED, str(exc), exit_code=1)
    _render(result, args.json)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
