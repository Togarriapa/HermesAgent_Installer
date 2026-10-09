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
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from . import __version__
from .bootstrap import BootstrapError, HermesBootstrap
from .state import Journal, OwnedRoot, OwnershipError, process_lock
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
    connection = command("test-connection", "Test a configured provider or MCP")
    connection.add_argument("target", choices=("provider", "mcp", "remote-desktop"))
    connection.add_argument("name", nargs="?", help="Adapter or connection name")
    memory = command("select-memory", "Select the single long-term memory backend")
    memory.add_argument("choice", choices=("openviking", "claude-mem", "agent-memory"))
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
    sub.add_parser("init-config", help="Write a secret-free example JSON configuration")
    return parser


def _configuration(path: Path | None) -> InstallerConfig:
    return load_config(path) if path else validate_config({"schema_version": 1})


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


def _resume_checkpoint_exists(state_path: Path) -> bool:
    """Read-only gate so a fresh resume cannot create a root, marker, database, or WAL."""
    try:
        with _quiescent_journal(state_path) as db:
            row = db.execute("SELECT 1 FROM operations WHERE id='installer:selection'").fetchone()
        return row is not None
    except RuntimeError as exc:
        # A committed WAL needs SQLite recovery under the exclusive installer lock.
        # Active writers are also allowed through this structural gate; process_lock
        # below will reject them without opening the journal.
        return "journal has an active or uncheckpointed WAL" in str(exc) or "installer operation is active" in str(exc)
    except (OSError, sqlite3.Error, ValueError):
        return False


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
        finding = Finding("resources.native-crosswalk", "Verified offline catalog; profile and skill artifacts map to Hermes discovery, remaining adapters and runtime acceptance are pending", OutcomeState.PENDING, {
            "catalog_version": registry.source.catalog_version,
            "source_revision": registry.source.revision,
            "root_counts": dict(registry.root_counts),
            "kinds": by_kind,
            "blocked_items": len(blocked),
            "sample_blockers": [{"kind": item.kind, "id": item.resource_id, "reason": item.blockers[0]} for item in blocked[:8]],
        })
        action = args.action
        return CommandResult("resources", OutcomeState.PENDING,
            f"Read-only {action}: verified {len(bindings)} declarations from the packaged bundle; native operation and target verification remain pending.",
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
        data_path = Path(config.paths.get("data_root", "~/HermesInstaller/data")).expanduser()
        state_path = Path(config.paths.get("state_root", "~/HermesInstaller/state")).expanduser()
        resume_command = "./install.sh resume" + (f" --config {shlex.quote(str(args.config))}" if args.config else "")
        try:
            if args.command == "resume" and not _resume_checkpoint_exists(state_path):
                return CommandResult("resume", OutcomeState.FAILED, "There is no readable installer checkpoint to resume; the state directory was not created.", exit_code=2)
            data_root = OwnedRoot(data_path); data_root.ensure()
            state_root = OwnedRoot(state_path); state_root.ensure()
            selection = {"schema_version": config.schema_version, "timezone": config.timezone,
                "paths": config.paths, "components": config.components, "privacy": config.privacy,
                "remote_desktop": config.remote_desktop}
            with process_lock(state_root.path("installer.lock")):
                # Journal initialization can create/recover WAL state; keep it under
                # the exclusive lock shared by status's immutable-reader gate.
                journal = Journal(state_root.path("journal.sqlite3"))
                prior = journal.operation("installer:selection")
                if args.command == "resume" and prior is None:
                    return CommandResult("resume", OutcomeState.FAILED, "There is no installer operation to resume; no stages were started.", exit_code=2)
                if prior is not None and prior["payload"].get("config") != selection:
                    return CommandResult(args.command, OutcomeState.FAILED, "Configuration differs from the durable installer selection; restore the original validated config before resuming.", resume_command=resume_command, exit_code=2)
                if prior is None:
                    journal.checkpoint("installer:selection", "active", {"config": selection,
                        "config_path": str(args.config) if args.config else None})
                report = HermesBootstrap(data_root, journal).install(include_desktop=config.components.get("hermes_desktop", True))
                journal.checkpoint("installer:selection", "bootstrap-complete", {"config": selection,
                    "config_path": str(args.config) if args.config else None, "commit": report.commit,
                    "generation": report.generation, "agent_ready": report.agent_ready,
                    "desktop_built": report.desktop_built})
        except (BootstrapError, OwnershipError, OSError, RuntimeError, ValueError, sqlite3.Error) as exc:
            return CommandResult(args.command, OutcomeState.FAILED, str(exc),
                resume_command=resume_command, exit_code=1)
        findings = (
            Finding("hermes.agent.bootstrap", "Pinned Hermes source and runtime stages completed", OutcomeState.READY if report.agent_ready else OutcomeState.PENDING, {"commit": report.commit, "generation": report.generation}),
            Finding("hermes.desktop.build", "Official ARM64 Desktop artifact was produced" if report.desktop_built else "Official Desktop artifact remains unavailable", OutcomeState.READY if report.desktop_built else OutcomeState.PENDING),
            Finding("hermes.configuration", report.configuration_state, OutcomeState.PENDING),
        )
        state = OutcomeState.PENDING
        if report.agent_ready and (not config.components.get("hermes_desktop", True) or report.desktop_built):
            message = "Pinned Hermes Agent and selected Desktop build verified; provider, user-session service, and remaining configuration steps are pending."
        else:
            message = "Pinned bootstrap finished with runtime verification pending; no public service was activated."
        return CommandResult(args.command, state, message, findings, resume_command)
    if args.command in {"configure", "test-connection", "select-memory", "resolve-source", "component", "update", "data"}:
        facts = discover_host()
        if not facts.supported_arm64_linux:
            return CommandResult(args.command, OutcomeState.FAILED, "This operation is restricted to supported Linux ARM64 targets; this host was not changed.", findings=_host_findings(config), exit_code=3)
        return CommandResult(args.command, OutcomeState.PENDING, "The selected component adapter is not available yet; no external account or service was changed.", resume_command=f"hermes-installer {args.command}" + (f" --config {args.config}" if args.config else ""))
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
        choices = {"1": ["plan"], "2": ["install"], "3": ["doctor"], "4": ["verify"], "5": ["resources", "status"], "0": []}
        print("1) Review a read-only plan\n2) Install or resume setup\n3) Diagnose this machine\n4) Verify an authorized target\n5) Inspect bundled Resources\n0) Exit")
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
