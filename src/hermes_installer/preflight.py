"""Read-only host and hardware discovery with provenance and explicit limits."""

from __future__ import annotations

import json
import os
import platform
import queue
import shutil
import socket
import ssl
import subprocess
import threading
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class DiskFact:
    path: str
    mount: str
    filesystem: str | None
    total_bytes: int
    available_bytes: int
    path_exists: bool
    device: str | None = None
    connection_type: str | None = None


@dataclass(frozen=True, slots=True)
class DeviceFact:
    kind: str
    path: str
    bus: str | None
    details: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class HostFacts:
    os_name: str
    os_version: str | None
    architecture: str
    supported_arm64_linux: bool
    ram_bytes: int | None
    disks: tuple[DiskFact, ...]
    coral_devices: tuple[DeviceFact, ...]
    graphical_session: bool
    current_user: str
    package_locks: tuple[str, ...]
    package_lock_probe_errors: tuple[str, ...]
    service_conflicts: tuple[str, ...]
    occupied_ports: tuple[int, ...]
    network_dns: bool | None
    network_tls: bool | None
    provenance: tuple[str, ...]
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def discover_host(*, sys_root: Path = Path("/sys"), proc_root: Path = Path("/proc"), etc_root: Path = Path("/etc"), environ: dict[str, str] | None = None, run_subprocess: bool = True, selected_paths: tuple[Path, ...] | None = None) -> HostFacts:
    env = os.environ if environ is None else environ
    os_name = platform.system()
    architecture = platform.machine().lower()
    version = None
    provenance = ["platform.system", "platform.machine", "os.statvfs", "process environment"]
    limitations: list[str] = []
    if os_name == "Linux":
        try:
            fields = _read_os_release(etc_root / "os-release")
            version = " ".join(filter(None, (fields.get("PRETTY_NAME"), fields.get("VERSION_ID")))) or None
            provenance.append("/etc/os-release")
        except OSError:
            limitations.append("/etc/os-release unavailable")
    ram = _memory_bytes(proc_root / "meminfo")
    disks = _disk_facts(run_subprocess, proc_root / "self/mountinfo", selected_paths)
    coral = _coral_facts(sys_root)
    if not coral:
        limitations.append("No Coral device found; device access was not exercised")
    lock_errors: list[str] = []
    locks = _held_package_locks(errors=lock_errors) if os_name == "Linux" else ()
    services = _service_conflicts(run_subprocess)
    ports = _ports(proc_root)
    addresses = _resolve_dns() if run_subprocess else None
    dns = bool(addresses) if addresses is not None else None
    tls = _tls_probe() if run_subprocess and addresses else (False if run_subprocess and addresses == [] else None)
    if os_name != "Linux" or architecture not in {"aarch64", "arm64"}:
        limitations.append("This host is not supported 64-bit Linux ARM64; no installation is permitted from this preflight")
    if os_name == "Linux" and architecture in {"aarch64", "arm64"}:
        supported = _linux_release_supported(etc_root / "os-release") and _runtime_platform_ready()
        if not supported:
            limitations.append("Linux ARM64 was detected, but the distribution/version/runtime prerequisite matrix did not pass")
    else:
        supported = False
    if not run_subprocess:
        limitations.append("Subprocess-based disk, service, and DNS probes were disabled by the fixture")
    graphical = _graphical_session(env, run_subprocess)
    if os_name == "Linux" and run_subprocess:
        provenance.append("loginctl show-session")
    return HostFacts(os_name, version, architecture, supported, ram, disks, coral, graphical, env.get("USER") or env.get("LOGNAME") or "unknown", locks, tuple(lock_errors), services, ports, dns, tls, tuple(provenance), tuple(limitations))


def _graphical_session(env: dict[str, str], use_subprocess: bool) -> bool:
    if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"):
        return True
    if not use_subprocess:
        return False
    try:
        from .runner import CommandRunner

        runner = CommandRunner(allowed_programs={"loginctl"}, timeout=2)
        sessions = runner.run(["loginctl", "list-sessions", "--no-legend", "--no-pager"], cwd=Path("/"))
        if sessions.returncode != 0:
            return False
        for line in sessions.stdout.splitlines():
            fields = line.split()
            if not fields or not fields[0].isdigit():
                continue
            detail = runner.run(["loginctl", "show-session", fields[0]], cwd=Path("/"))
            if detail.returncode != 0:
                continue
            properties = dict(item.split("=", 1) for item in detail.stdout.splitlines() if "=" in item)
            if properties.get("Type") in {"wayland", "x11"} and properties.get("Class") == "user" and properties.get("State") == "active":
                return True
    except (OSError, RuntimeError, ValueError):
        return False
    return False


def _read_os_release(path: Path) -> dict[str, str]:
    fields = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            key, value = line.split("=", 1)
            fields[key] = value.strip().strip('"')
    return fields


def _memory_bytes(path: Path) -> int | None:
    try:
        for line in path.read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        pass
    return None


def _disk_facts(use_subprocess: bool, mountinfo: Path = Path("/proc/self/mountinfo"), selected_paths: tuple[Path, ...] | None = None, block_devices: dict[str, Any] | None = None) -> tuple[DiskFact, ...]:
    paths = selected_paths or (Path("/"), Path.home())
    mounts = _read_mountinfo(mountinfo)
    devices = block_devices if block_devices is not None else (_lsblk_inventory() if use_subprocess else {})
    by_mount: dict[str, dict[str, Any]] = {}
    _map_devices_to_mounts(devices.get("blockdevices", []), by_mount)
    result: list[DiskFact] = []
    seen_mounts: set[str] = set()
    for path in paths:
        try:
            probe_path = path
            while not probe_path.exists() and probe_path.parent != probe_path:
                probe_path = probe_path.parent
            stats = os.statvfs(probe_path)
            mount = _mount_entry(probe_path, mounts)
            mountpoint = mount.get("mountpoint") or _mount_for(probe_path)
            if mountpoint in seen_mounts:
                continue
            seen_mounts.add(mountpoint)
            source = mount.get("source")
            selected_device = by_mount.get(mountpoint)
            if selected_device is None and source:
                selected_device = _find_device(devices.get("blockdevices", []), source)
            result.append(DiskFact(str(path), mountpoint, mount.get("filesystem"), stats.f_blocks * stats.f_frsize, stats.f_bavail * stats.f_frsize, path.exists(), source, (selected_device or {}).get("tran")))
        except OSError:
            continue
    return tuple(result)


def _map_devices_to_mounts(devices: list[dict[str, Any]], result: dict[str, dict[str, Any]], inherited_transport: str | None = None) -> None:
    for device in devices:
        if not isinstance(device, dict):
            continue
        transport = device.get("tran") or inherited_transport
        mountpoints = device.get("mountpoints") or ([device["mountpoint"]] if device.get("mountpoint") else [])
        for mountpoint in mountpoints:
            if mountpoint:
                result[str(mountpoint)] = {**device, "tran": transport}
        _map_devices_to_mounts(device.get("children", []), result, transport)


def _read_mountinfo(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            left, right = line.split(" - ", 1)
            a, b = left.split(), right.split()
            rows.append({"mountpoint": _unescape_mount(a[4]), "filesystem": b[0], "source": _unescape_mount(b[1])})
        except (ValueError, IndexError):
            continue
    return rows


def _unescape_mount(value: str) -> str:
    return value.replace("\\040", " ").replace("\\011", "\t").replace("\\134", "\\")


def _mount_entry(path: Path, mounts: list[dict[str, str]]) -> dict[str, str]:
    target = str(path.resolve())
    matches = [row for row in mounts if target == row["mountpoint"] or target.startswith(row["mountpoint"].rstrip("/") + "/")]
    return max(matches, key=lambda row: len(row["mountpoint"])) if matches else {}


def _lsblk_inventory() -> dict[str, Any]:
    try:
        from .runner import CommandRunner

        result = CommandRunner(allowed_programs={"lsblk"}, timeout=3).run(["lsblk", "--json", "--bytes", "--output", "PATH,TYPE,TRAN,SIZE,FSTYPE,PKNAME,MODEL,MOUNTPOINTS"], cwd=Path("/"))
        if result.returncode == 0:
            parsed = json.loads(result.stdout)
            if isinstance(parsed, dict) and isinstance(parsed.get("blockdevices"), list):
                return parsed
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError, RuntimeError, ValueError):
        pass
    return {}


def _find_device(devices: list[dict[str, Any]], source: str) -> dict[str, Any] | None:
    for device in devices:
        if device.get("path") == source or device.get("name") == Path(source).name:
            return device
        nested = _find_device(device.get("children", []), source)
        if nested:
            return {**device, **{key: value for key, value in nested.items() if not device.get(key)}}
    return None


def _mount_for(path: Path) -> str:
    current = path.resolve()
    while not current.is_mount() and current.parent != current:
        current = current.parent
    return str(current)


def _coral_facts(sys_root: Path) -> tuple[DeviceFact, ...]:
    found: list[DeviceFact] = []
    for bus in ("bus/usb/devices", "bus/pci/devices"):
        root = sys_root / bus
        if not root.exists():
            continue
        for device in root.iterdir():
            try:
                info: dict[str, str] = {}
                for key in ("idVendor", "idProduct", "vendor", "device", "uevent"):
                    p = device / key
                    if p.is_file():
                        info[key] = p.read_text(errors="replace")[:512].strip()
                vendor, product = info.get("idVendor", "").lower(), info.get("idProduct", "").lower()
                pci_vendor, pci_product = info.get("vendor", "").lower().removeprefix("0x"), info.get("device", "").lower().removeprefix("0x")
                exact_usb = (vendor, product) in {("1a6e", "089a"), ("18d1", "9302")}
                exact_pci = (pci_vendor, pci_product) == ("1ac1", "089a")
                if exact_usb or exact_pci:
                    found.append(DeviceFact("coral", str(device), "usb" if bus.endswith("usb/devices") else "pci", info))
            except OSError:
                continue
    apex = sys_root / "class/apex"
    if apex.exists():
        if not any(device.bus == "pci" for device in found):
            for device in apex.iterdir():
                found.append(DeviceFact("coral", str(device), "pci-driver-node", {"evidence": "kernel apex class entry; PCI vendor/product must be verified before driver selection"}))
    return tuple(found)


def _service_conflicts(use_subprocess: bool) -> tuple[str, ...]:
    if not use_subprocess or not shutil.which("systemctl", path="/usr/bin:/bin:/usr/sbin:/sbin"):
        return ()
    try:
        from .runner import CommandRunner

        p = CommandRunner(allowed_programs={"systemctl"}, timeout=3).run(["systemctl", "list-units", "--all", "--type", "service", "--no-legend", "--no-pager"], cwd=Path("/"))
        return _matching_service_units(p.stdout) if p.returncode == 0 else ()
    except (OSError, subprocess.TimeoutExpired, RuntimeError, ValueError):
        return ()


def _matching_service_units(output: str) -> tuple[str, ...]:
    markers = ("home-assistant", "homeassistant", "hassio", "hermes", "ollama", "vllm", "llama", "piper", "wyoming", "whisper", "openviking", "cloudflared")
    units: set[str] = set()
    for line in output.splitlines():
        fields = line.split()
        if fields and fields[0].lower().endswith(".service") and any(marker in fields[0].lower() for marker in markers):
            units.add(fields[0])
    return tuple(sorted(units))


def _ports(proc_root: Path = Path("/proc")) -> tuple[int, ...]:
    ports: set[int] = set()
    for filename in ("tcp", "tcp6", "udp", "udp6"):
        path = proc_root / "net" / filename
        try:
            for line in path.read_text().splitlines()[1:]:
                columns = line.split()
                state = columns[3]
                if (filename.startswith("tcp") and state != "0A") or (filename.startswith("udp") and state != "07"):
                    continue
                ports.add(int(columns[1].rsplit(":", 1)[1], 16))
        except (OSError, ValueError, IndexError):
            continue
    return tuple(sorted(ports))


def _resolve_dns(host: str = "github.com", timeout: float = 3.0) -> list[tuple] | None:
    result: queue.Queue[list[tuple] | OSError] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            result.put(socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM))
        except OSError as exc:
            result.put(exc)

    worker = threading.Thread(target=resolve, name="hermes-dns-probe", daemon=True)
    worker.start()
    try:
        value = result.get(timeout=timeout)
    except queue.Empty:
        return None
    return value if isinstance(value, list) else []


def _tls_probe(timeout: float = 3.0) -> bool | None:
    # urllib honors explicitly configured system proxies and still uses the
    # platform's certificate-verifying TLS context. The response body is never read.
    request = urllib.request.Request("https://github.com/", method="HEAD", headers={"User-Agent": "hermes-installer-preflight/1"})
    try:
        response = urllib.request.urlopen(request, timeout=timeout, context=ssl.create_default_context())
        response.close()
        return True
    except urllib.error.HTTPError:
        # An HTTP status still proves the TLS handshake and certificate check succeeded.
        return True
    except (urllib.error.URLError, TimeoutError, OSError, ssl.SSLError):
        return False


def _held_package_locks(lock_paths: tuple[Path, ...] = (Path("/var/lib/dpkg/lock-frontend"), Path("/var/lib/dpkg/lock"), Path("/var/lib/apt/lists/lock"), Path("/var/lib/rpm/.rpm.lock")), errors: list[str] | None = None) -> tuple[str, ...]:
    import fcntl

    held: list[str] = []
    for path in lock_paths:
        if not path.exists():
            continue
        try:
            fd = os.open(path, os.O_RDWR | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            # Existence is not evidence of contention; inability to inspect is a separate unknown.
            if errors is not None:
                errors.append(f"{path}: {exc.strerror or type(exc).__name__}")
            continue
        try:
            try:
                fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.lockf(fd, fcntl.LOCK_UN)
            except BlockingIOError:
                held.append(str(path))
        finally:
            os.close(fd)
    return tuple(held)


def _linux_release_supported(path: Path) -> bool:
    try:
        fields = _read_os_release(path)
    except OSError:
        return False
    distro = fields.get("ID", "").lower()
    version = fields.get("VERSION_ID", "")
    supported = {"debian": {"11", "12", "13"}, "raspbian": {"11", "12", "13"}, "ubuntu": {"20.04", "22.04", "24.04", "26.04"}}
    return version in supported.get(distro, set())


def _runtime_platform_ready(libc: tuple[str, str] | None = None, systemd_active: bool | None = None, fhs_paths: tuple[Path, ...] = (Path("/etc"), Path("/usr"), Path("/var"))) -> bool:
    libc = libc or platform.libc_ver()
    try:
        glibc = libc[0].lower() == "glibc" and tuple(int(piece) for piece in libc[1].split(".")[:2]) >= (2, 28)
    except (ValueError, IndexError):
        glibc = False
    if systemd_active is None:
        systemd_active = Path("/run/systemd/system").is_dir() and shutil.which("systemctl", path="/usr/bin:/bin:/usr/sbin:/sbin") is not None
    return glibc and systemd_active and all(path.is_dir() for path in fhs_paths)
