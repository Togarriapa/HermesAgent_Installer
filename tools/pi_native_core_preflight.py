#!/usr/bin/env python3
"""Read-only, secret-safe inventory for the fixed Hermes Pi core migration.

Run as root from the Pi's local browser terminal. This does not read token
contents, process environments, or Hermes config fields; the config file is
streamed only to compute its digest. It never requests systemd ExecStart.
It makes no service or filesystem changes and creates no evidence receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
import sys
from pathlib import Path

CORE = "hermes-jarvis-core.service"
GATEWAY = "hermes-jarvis-core-gateway.service"
INSPECTOR = "hermes-jarvis-core-inspector.service"
TUNNEL = "hermes-jarvis-mvp-tunnel.service"
SOURCE = Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
PYTHON = Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
PYTHON_REAL = Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")
HERMES_HOME = Path("/home/admin/.hermes")
JOURNAL = Path("/var/lib/hermes-installer/core-runtime/ownership.json")
UNIT = Path("/etc/systemd/system/hermes-jarvis-core.service")
LAUNCHER = Path("/usr/local/libexec/hermes-jarvis-core-launcher")
TOKEN = Path("/etc/hermes-installer/jarvis-core/session-token")
GATEWAY_CONFIG = Path("/etc/hermes-installer/jarvis-core-gateway.json")
CHAT_DATABASE = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
SOCKETS = {
    "gateway_ingress": Path("/run/hermes-jarvis-mvp-gateway/origin.sock"),
    "core_inspector": Path("/run/hermes-jarvis-mvp-core/inspection.sock"),
    "native_observer": Path("/run/hermes-jarvis-native-observer/native-observer.sock"),
}
PLUGIN = HERMES_HOME / "plugins/hermes-installer-resources-delegation"
OBSIDIAN_REGISTRATION = Path("/var/lib/hermes-installer/core-runtime/obsidian-registration.json")
OBSIDIAN_DATA_ROOT = HERMES_HOME / "jarvis-second-brain"
OBSIDIAN_VAULT = OBSIDIAN_DATA_ROOT / "obsidian-vault"
JOURNAL_FIELDS = (
    "schema", "state", "service", "source_commit", "lock_sha256",
    "python_sha256", "python_link", "python_uid", "python_gid", "python_mode",
    "admin_uid", "admin_gid", "host", "port", "unit_sha256", "launcher_sha256",
    "adapter_source", "adapter_generation", "adapter_migration_state",
    "core_source_generation", "plugin_selection_sha256",
)
EXPECTED_OLD_ARGV = [str(PYTHON), "-m", "hermes_cli.main", "serve", "--isolated",
                     "--host", "127.0.0.1", "--port", "8766"]
EXPECTED_ADOPTED_ARGV = [str(PYTHON), "-P", "-m", "hermes_cli.main", "serve",
                         "--isolated", "--host", "127.0.0.1", "--port", "8766"]


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _safe_file(path: Path, *, digest: bool = False, max_bytes: int = 1_048_576):
    try:
        info = path.lstat()
        row = {"path": str(path), "type": "regular" if stat.S_ISREG(info.st_mode) else
               "directory" if stat.S_ISDIR(info.st_mode) else "socket" if stat.S_ISSOCK(info.st_mode)
               else "symlink" if stat.S_ISLNK(info.st_mode) else "other",
               "uid": info.st_uid, "gid": info.st_gid,
               "mode": format(stat.S_IMODE(info.st_mode), "04o"),
               "nlink": info.st_nlink, "size": info.st_size}
        if digest and stat.S_ISREG(info.st_mode) and info.st_size <= max_bytes:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if (opened.st_dev, opened.st_ino, opened.st_size) != (info.st_dev, info.st_ino, info.st_size):
                    raise OSError("file changed during safe digest")
                hasher = hashlib.sha256()
                total = 0
                while True:
                    block = os.read(fd, min(65536, max_bytes + 1 - total))
                    if not block:
                        break
                    total += len(block)
                    if total > max_bytes:
                        raise OSError("file grew beyond safe digest limit")
                    hasher.update(block)
                after = os.fstat(fd)
                if (total != info.st_size or (after.st_dev, after.st_ino, after.st_size)
                        != (info.st_dev, info.st_ino, info.st_size)):
                    raise OSError("file changed during safe digest")
                row["sha256"] = hasher.hexdigest()
            finally:
                os.close(fd)
        return row
    except FileNotFoundError:
        return {"path": str(path), "state": "missing"}
    except OSError as error:
        return {"path": str(path), "state": "unavailable", "error": type(error).__name__}


def _journal_projection():
    try:
        fd = os.open(JOURNAL, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 1 <= info.st_size <= 65536):
                return {"state": "custody-mismatch", "metadata": _safe_file(JOURNAL)}
            chunks = []
            remaining = 65537
            while remaining:
                block = os.read(fd, min(8192, remaining))
                if not block:
                    break
                chunks.append(block)
                remaining -= len(block)
            raw = b"".join(chunks)
            after = os.fstat(fd)
            named = os.stat(JOURNAL, follow_symlinks=False)
            if (len(raw) != info.st_size or len(raw) > 65536
                    or (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
                       != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                    or (after.st_dev, after.st_ino) != (named.st_dev, named.st_ino)):
                return {"state": "changed-during-read", "metadata": _safe_file(JOURNAL)}
            value = json.loads(raw, object_pairs_hook=_unique_pairs)
            if type(value) is not dict:
                raise ValueError("journal is not an object")
            # Deliberately omit token_sha256 and all unknown/future fields.
            return {"state": "read", "metadata": _safe_file(JOURNAL),
                    "fields": {key: value[key] for key in JOURNAL_FIELDS if key in value}}
        finally:
            os.close(fd)
    except FileNotFoundError:
        return {"state": "missing", "metadata": _safe_file(JOURNAL)}
    except (OSError, ValueError, TypeError, UnicodeError):
        return {"state": "invalid-or-unavailable", "metadata": _safe_file(JOURNAL)}


def _command(args):
    try:
        result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, timeout=5,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
        return result.stdout.strip() if result.returncode == 0 else "unavailable"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def _unit(name):
    # Never request ExecStart, Environment, or status logs.
    fields = {}
    for key in ("FragmentPath", "DropInPaths", "ActiveState", "SubState", "MainPID",
                "User", "Group", "ControlGroup"):
        fields[key] = _command(["systemctl", "show", "--property=" + key, "--value", name])
    return fields


def _ingress_source(path: Path, module: str):
    """Project only the fixed import generation and unit digest for review."""
    result = {"unit": _safe_file(path, digest=True, max_bytes=65536)}
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o644):
            raise OSError("fixed unit custody differs")
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            raw = os.read(fd, 65537)
            if len(raw) != info.st_size or len(raw) > 65536:
                raise OSError("fixed unit changed during read")
        finally:
            os.close(fd)
        prefix = b"Environment=PYTHONPATH="
        values = [line[len(prefix):] for line in raw.splitlines() if line.startswith(prefix)]
        if (len(values) == 1
                and re.fullmatch(rb"/opt/hermes-installer-core-[0-9a-f]{9,64}/src", values[0])
                and b"-m hermes_installer.remote." + module.encode("ascii") in raw):
            result["source_generation"] = values[0].decode("ascii", "strict")
        else:
            result["source_generation"] = "unexpected-redacted"
    except (OSError, UnicodeError):
        result["source_generation"] = "unavailable"
    return result


def _proc(pid_text):
    if not pid_text.isdecimal() or int(pid_text) <= 1:
        return {"state": "no-current-pid"}
    pid = int(pid_text)
    proc = Path("/proc") / str(pid)
    try:
        status = {}
        for line in (proc / "status").read_text(encoding="ascii").splitlines():
            key, sep, value = line.partition(":")
            if sep and key in {"Uid", "Gid"}:
                status[key] = value.split()
        argv = (proc / "cmdline").read_bytes().decode("ascii").rstrip("\0").split("\0")
        if argv not in (EXPECTED_OLD_ARGV, EXPECTED_ADOPTED_ARGV):
            argv_state = "unexpected-redacted"
            safe_argv = None
        else:
            argv_state = "legacy-exact" if argv == EXPECTED_OLD_ARGV else "adopted-exact"
            safe_argv = argv
        cgroup_lines = (proc / "cgroup").read_text(encoding="ascii").splitlines()
        return {"pid": pid, "uid_vector": status.get("Uid"), "gid_vector": status.get("Gid"),
                "exe": os.readlink(proc / "exe"), "cwd": os.readlink(proc / "cwd"),
                "argv_state": argv_state, "argv": safe_argv,
                "service_cgroup_present": any(CORE in row for row in cgroup_lines),
                "listener_127001_8766": _listener_for_process(proc)}
    except (OSError, UnicodeError, ValueError):
        return {"pid": pid, "state": "process-changed-or-unavailable"}


def _listener_for_process(proc: Path):
    try:
        owned = set()
        for fd in (proc / "fd").iterdir():
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if target.startswith("socket:[") and target.endswith("]"):
                owned.add(target[8:-1])
        for table in (Path("/proc/net/tcp"), Path("/proc/net/tcp6")):
            if not table.is_file():
                continue
            for row in table.read_text(encoding="ascii").splitlines()[1:]:
                cols = row.split()
                if len(cols) <= 9 or cols[3] != "0A" or cols[9] not in owned:
                    continue
                address, port = cols[1].split(":")
                if int(port, 16) == 8766 and address in {
                        "0100007F", "00000000000000000000000001000000"}:
                    return True
        return False
    except (OSError, ValueError, UnicodeError):
        return False


def _plugin_files():
    rows = {"directory": _safe_file(PLUGIN)}
    for name in ("plugin.yaml", "__init__.py"):
        rows[name] = _safe_file(PLUGIN / name, digest=True, max_bytes=65536)
    return rows


def main():
    if os.geteuid() != 0:
        print("Run this read-only preflight as root from the Pi browser terminal.", file=sys.stderr)
        return 2
    try:
        admin = pwd.getpwnam("admin")
        admin_identity = {"uid": admin.pw_uid, "gid": admin.pw_gid, "home": admin.pw_dir}
    except KeyError:
        admin_identity = {"state": "missing"}
    core_unit = _unit(CORE)
    report = {
        "schema": 1,
        "purpose": "read-only legacy core adoption preflight; no acceptance witness",
        "admin": admin_identity,
        "paths": {"core_source": _safe_file(SOURCE), "core_python_link": _safe_file(PYTHON),
                  "core_python_real": _safe_file(PYTHON_REAL, digest=True),
                  "workspace": _safe_file(HERMES_HOME / "workspaces/jarvis-core"),
                  "ownership_journal": _journal_projection(),
                  "core_unit": _safe_file(UNIT, digest=True),
                  "core_launcher": _safe_file(LAUNCHER, digest=True),
                  "session_token_metadata_only": _safe_file(TOKEN),
                  "gateway_config_metadata_and_digest_only": _safe_file(GATEWAY_CONFIG, digest=True),
                  "chat_database_metadata_only": _safe_file(CHAT_DATABASE),
                  "obsidian_owner_registration_metadata_only": _safe_file(OBSIDIAN_REGISTRATION),
                  "obsidian_owner_data_root": _safe_file(OBSIDIAN_DATA_ROOT),
                  "obsidian_vault_root": _safe_file(OBSIDIAN_VAULT),
                  "native_plugin_files": _plugin_files(),
                  "sockets": {key: _safe_file(path) for key, path in SOCKETS.items()}},
        "units": {name: _unit(name) for name in (CORE, INSPECTOR, GATEWAY, TUNNEL)},
        "ingress_unit_files": {
            "inspector": _ingress_source(Path("/etc/systemd/system/hermes-jarvis-core-inspector.service"),
                                         "core_gateway_inspector"),
            "gateway": _ingress_source(Path("/etc/systemd/system/hermes-jarvis-core-gateway.service"),
                                       "core_gateway"),
        },
        "core_process": _proc(core_unit.get("MainPID", "unavailable")),
        "limits": ["No credential bytes, environment, config fields, ExecStart, logs, or socket protocol are emitted; config is streamed only for its digest.",
                   "Plugin file digests prove staged bytes only; native selection/load/effect remain separate witnesses.",
                   "Root observer socket metadata does not prove peer authentication or UID-bound protocol."],
    }
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
