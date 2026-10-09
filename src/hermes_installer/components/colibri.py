"""Pinned ARM64 Colibri build and experimental GLM-5.2 runtime planning."""
from __future__ import annotations

import ctypes.util
import hashlib
import json
import os
import platform
import shutil
import stat
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Protocol, Sequence

from hermes_installer.models.artifacts import ArtifactManifest, MODEL_ID, MODEL_REVISION
from hermes_installer.models.downloads import DownloadCancelled, StoragePlan, StorageReserve, estimate_storage

COLIBRI_REVISION = "bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850"
COLIBRI_URL = "https://github.com/JustVugg/colibri.git"
BUILD_PACKAGES = ("build-essential", "git", "python3", "libgomp1")


class ColibriError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BuildEvidence:
    source_revision: str
    architecture: str
    binary_sha256: str
    elf_machine: str
    openmp_verified: bool
    libgomp_runtime: str
    self_test_output: str


@dataclass(frozen=True, slots=True)
class HostReadiness:
    architecture: str
    cpu_features: tuple[str, ...]
    memory_total_bytes: int | None
    memory_available_bytes: int | None
    temperature_millidegrees: int | None
    throttling: str | None
    storage_free_bytes: int | None
    storage_health: str
    device_access: str
    warnings: tuple[str, ...]


def _run(argv: Sequence[str], *, cwd: Path | None = None, env: Mapping[str, str] | None = None,
         timeout: float = 60, runner: Callable[..., object] = subprocess.run) -> subprocess.CompletedProcess[str]:
    result = runner(list(argv), cwd=cwd, env=dict(env) if env is not None else None,
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    check=False, timeout=timeout)
    code = getattr(result, "returncode", getattr(result, "exit_code", None))
    output = getattr(result, "stdout", "") or ""
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    return subprocess.CompletedProcess(list(argv), int(code if code is not None else 255), str(output))


def _adapt_managed_runner(run_command: Callable[..., object]) -> Callable[..., subprocess.CompletedProcess[str]]:
    def invoke(argv, *, cwd=None, env=None, timeout=60, **_ignored):
        result = run_command(tuple(argv), cwd=cwd, env=env, timeout=timeout)
        code = getattr(result, "returncode", getattr(result, "exit_code", None))
        output = getattr(result, "stdout", "") or ""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(list(argv), int(code if code is not None else 255), str(output))
    return invoke


def _elf_machine(path: Path) -> tuple[str, str]:
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF" or header[5] not in (1, 2):
        raise ColibriError("Colibri build output is not a valid ELF executable")
    byteorder = "little" if header[5] == 1 else "big"
    machine = int.from_bytes(header[18:20], byteorder)
    return {183: "aarch64", 62: "x86_64", 40: "arm"}.get(machine, f"unknown-{machine}"), byteorder


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch_pinned_colibri_source(component_root: Path, *, run_command: Callable[..., object]) -> Path:
    """Fetch only the reviewed Colibri commit through a caller-supplied managed runner."""
    destination = component_root / "sources" / ("colibri-" + COLIBRI_REVISION)
    managed_runner = _adapt_managed_runner(run_command)
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir():
            raise ColibriError("pinned Colibri source path is not a managed real directory")
        revision = _run(("git", "rev-parse", "HEAD"), cwd=destination, timeout=15,
                        runner=managed_runner)
        remote = _run(("git", "remote", "get-url", "origin"), cwd=destination, timeout=15,
                      runner=managed_runner)
        if revision.returncode or revision.stdout.strip() != COLIBRI_REVISION or remote.stdout.strip() != COLIBRI_URL:
            raise ColibriError("existing Colibri source does not match the reviewed immutable commit and origin")
        return destination
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(".colibri-fetch-" + hashlib.sha256(os.urandom(32)).hexdigest()[:12])
    temporary.mkdir(mode=0o700)
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
           "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_GLOBAL": "/dev/null"}
    try:
        initialized = _run(("git", "init", str(temporary)), cwd=component_root, env=env, timeout=30,
             runner=managed_runner)
        if initialized.returncode:
            raise ColibriError("managed git init failed for the isolated Colibri source path")
        added = _run(("git", "-C", str(temporary), "remote", "add", "origin", COLIBRI_URL),
             cwd=component_root, env=env, timeout=30,
             runner=managed_runner)
        if added.returncode:
            raise ColibriError("managed git remote setup failed for the pinned Colibri source")
        fetched = _run(("git", "-C", str(temporary), "fetch", "--depth=1", "--no-tags", "origin", COLIBRI_REVISION),
             cwd=component_root, env=env, timeout=300,
             runner=managed_runner)
        if fetched.returncode:
            raise ColibriError("managed source fetch could not retrieve the pinned Colibri commit")
        checked = _run(("git", "-C", str(temporary), "checkout", "--detach", "FETCH_HEAD"),
             cwd=component_root, env=env, timeout=60,
             runner=managed_runner)
        if checked.returncode:
            raise ColibriError("managed source checkout failed for the pinned Colibri commit")
        revision = _run(("git", "-C", str(temporary), "rev-parse", "HEAD"), cwd=component_root,
             env=env, timeout=15, runner=managed_runner)
        if revision.returncode or revision.stdout.strip() != COLIBRI_REVISION:
            raise ColibriError("fetched Colibri source did not match the exact reviewed commit")
        os.replace(temporary, destination)
        return destination
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def build_colibri_arm64(source: Path, *, expected_revision: str = COLIBRI_REVISION,
                        system: str | None = None, machine: str | None = None,
                        runner: Callable[..., subprocess.CompletedProcess[str]],
                        timeout: float = 600) -> BuildEvidence:
    """Build only the pinned upstream C engine on an actual Linux ARM64 target."""
    system = system or platform.system()
    machine = machine or platform.machine()
    if system != "Linux" or machine.casefold() not in {"aarch64", "arm64"}:
        raise ColibriError(f"Colibri engine must be built on Linux ARM64; found {system}/{machine}")
    source = source.resolve(strict=True)
    runner = _adapt_managed_runner(runner)
    revision = _run(("git", "rev-parse", "HEAD"), cwd=source, timeout=15, runner=runner)
    if revision.returncode or revision.stdout.strip() != expected_revision:
        raise ColibriError("Colibri source checkout does not match the reviewed revision pin")
    setup = source / "c" / "setup.sh"
    if setup.is_symlink() or not setup.is_file():
        raise ColibriError("pinned Colibri source is missing its reviewed c/setup.sh build entry point")
    for tool in ("gcc", "make", "python3"):
        if shutil.which(tool) is None:
            raise ColibriError(f"Colibri build dependency {tool} is unavailable; install {', '.join(BUILD_PACKAGES)} through the managed host")
    # Match the upstream setup check and ensure it links and runs against ARM64 libgomp.
    with tempfile.TemporaryDirectory(prefix="hermes-colibri-omp-") as td:
        probe_c, probe_bin = Path(td) / "probe.c", Path(td) / "probe"
        probe_c.write_text("#include <omp.h>\nint main(void){int n=0;\n#pragma omp parallel reduction(+:n)\n n += 1; return n < 1;}\n", encoding="ascii")
        compile_result = _run(("gcc", "-fopenmp", str(probe_c), "-o", str(probe_bin)), timeout=60, runner=runner)
        if compile_result.returncode:
            raise ColibriError("OpenMP/libgomp compile probe failed; install the ARM64 libgomp runtime and compiler package")
        execute_result = _run((str(probe_bin),), timeout=15, runner=runner)
        if execute_result.returncode:
            raise ColibriError("OpenMP/libgomp runtime probe failed on the target")
    if not ctypes.util.find_library("gomp"):
        raise ColibriError("libgomp runtime is absent; install the managed ARM64 libgomp1 dependency")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "ARCH": "native", "LC_ALL": "C"}
    if timeout <= 0 or timeout > 600:
        raise ValueError("managed Colibri build command must be bounded to 600 seconds")
    build_result = _run(("bash", str(setup)), cwd=source / "c", env=env, timeout=timeout, runner=runner)
    if build_result.returncode:
        tail = build_result.stdout[-2400:].strip()
        raise ColibriError(f"pinned Colibri ARM64 build/self-test failed: {tail}")
    binary = source / "c" / "colibri"
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ColibriError("pinned build completed without an executable c/colibri binary")
    elf, _ = _elf_machine(binary)
    if elf != "aarch64":
        raise ColibriError(f"Colibri binary is {elf}, expected aarch64")
    linked = _run(("ldd", str(binary)), timeout=15, runner=runner)
    if linked.returncode or "libgomp.so" not in linked.stdout:
        raise ColibriError("Colibri binary is not linked to the required libgomp.so runtime")
    if "engine self-test:" not in build_result.stdout:
        raise ColibriError("pinned Colibri setup did not report its engine self-test evidence")
    return BuildEvidence(expected_revision, "aarch64", _sha256(binary), elf, True,
                         next((line.strip() for line in linked.stdout.splitlines() if "libgomp.so" in line), "libgomp.so"),
                         next((line.strip() for line in build_result.stdout.splitlines() if "engine self-test:" in line), ""))


def _read_meminfo(path: Path) -> tuple[int | None, int | None]:
    if path.is_symlink() or not path.is_file():
        return None, None
    values: dict[str, int] = {}
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].rstrip(":") in {"MemTotal", "MemAvailable"}:
            try:
                values[parts[0].rstrip(":")] = int(parts[1]) * 1024
            except ValueError:
                pass
    return values.get("MemTotal"), values.get("MemAvailable")


def _cpu_features(path: Path) -> tuple[str, ...]:
    if path.is_symlink() or not path.is_file():
        return ()
    for line in path.read_text(encoding="ascii", errors="replace").splitlines():
        if line.lower().startswith(("features", "flags")) and ":" in line:
            return tuple(sorted(set(line.split(":", 1)[1].lower().split())))
    return ()


def probe_host_readiness(model_path: Path, *, proc_root: Path = Path("/proc"), sys_root: Path = Path("/sys"),
                         system: str | None = None, machine: str | None = None,
                         block_device: Path | None = None,
                         runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run) -> HostReadiness:
    """Collect measured target facts. Nominal RAM and TPU presence never imply readiness."""
    system, machine = system or platform.system(), machine or platform.machine()
    warnings: list[str] = []
    total, available = _read_meminfo(proc_root / "meminfo")
    if total is None or available is None:
        warnings.append("physical-memory facts unavailable")
    features = _cpu_features(proc_root / "cpuinfo")
    if system != "Linux" or machine.casefold() not in {"aarch64", "arm64"}:
        warnings.append("native GLM runtime requires Linux ARM64")
    temp = None
    for zone in sorted((sys_root / "class" / "thermal").glob("thermal_zone*/temp")):
        if zone.is_symlink():
            continue
        try:
            raw = int(zone.read_text(encoding="ascii").strip())
            temp = raw * 1000 if abs(raw) < 1000 else raw
            break
        except (OSError, ValueError):
            continue
    throttling = None
    vcgencmd = shutil.which("vcgencmd")
    if vcgencmd:
        result = _run((vcgencmd, "get_throttled"), timeout=3, runner=runner)
        if result.returncode == 0:
            throttling = result.stdout.strip()
    try:
        free = shutil.disk_usage(model_path).free
    except OSError:
        free = None
        warnings.append("target model storage free space unavailable")
    health = "not_checked"
    smartctl = shutil.which("smartctl")
    if block_device is None:
        health = "requires_block_device_identity"
    else:
        try:
            device_valid = not block_device.is_symlink() and stat.S_ISBLK(block_device.stat().st_mode)
        except OSError:
            device_valid = False
        if not device_valid:
            health = "invalid_block_device_identity"
        elif smartctl is None:
            health = "smartctl_unavailable"
        else:
            result = _run((smartctl, "-j", "-H", str(block_device)), timeout=10, runner=runner)
            if result.returncode == 0:
                try:
                    smart = json.loads(result.stdout)
                    health = "healthy" if smart.get("smart_status", {}).get("passed") is True else "failed_or_unknown"
                except (ValueError, AttributeError):
                    health = "unparseable_smart_status"
            else:
                health = "smartctl_failed"
    device_access = "pending_device_probe"
    try:
        from .coral import probe_coral_devices
        devices = probe_coral_devices(sys_root=sys_root)
        accessible = [d for d in devices if d.access_status == "accessible"]
        device_access = "coral_device_accessible" if accessible else (
            "coral_present_permission_pending" if devices else "no_coral_device")
    except OSError:
        device_access = "device_bus_unavailable"
    return HostReadiness(machine, features, total, available, temp, throttling, free, health,
                         device_access, tuple(warnings))


@dataclass(frozen=True, slots=True)
class ServiceBounds:
    memory_max_bytes: int
    cpu_quota_percent: int
    io_weight: int
    request_timeout_seconds: int = 600
    max_request_bytes: int = 8 * 1024 * 1024
    max_output_tokens: int = 2048
    max_concurrent_requests: int = 1

    def __post_init__(self) -> None:
        if min(self.memory_max_bytes, self.cpu_quota_percent, self.io_weight) <= 0:
            raise ValueError("Colibri service resource bounds must be positive")
        if self.cpu_quota_percent > 1000 or self.io_weight > 10000:
            raise ValueError("Colibri CPU quota or I/O weight exceeds the host manager's supported range")
        if self.request_timeout_seconds < 1 or self.request_timeout_seconds > 600:
            raise ValueError("Colibri request timeout must not exceed 600 seconds")
        if self.max_request_bytes < 1024 or self.max_output_tokens < 1 or self.max_output_tokens > 8192:
            raise ValueError("invalid Colibri request/output bounds")
        if self.max_concurrent_requests != 1:
            raise ValueError("the experimental Colibri route permits exactly one concurrent generation")


@dataclass(frozen=True, slots=True)
class ColibriServicePlan:
    executable: Path
    working_directory: Path
    model_directory: Path
    bind_host: str
    bind_port: int
    model_id: str
    model_revision: str
    api_key_reference: str
    bounds: ServiceBounds
    environment: tuple[tuple[str, str], ...]

    @classmethod
    def create(cls, executable: Path, working_directory: Path, model_directory: Path,
               api_key_reference: str, bounds: ServiceBounds, *, port: int = 8000) -> "ColibriServicePlan":
        if not api_key_reference or "\n" in api_key_reference or "\x00" in api_key_reference:
            raise ValueError("Colibri API key must be supplied by a protected credential reference")
        if not 1 <= port <= 65535:
            raise ValueError("invalid Colibri loopback port")
        return cls(executable.resolve(strict=True), working_directory.resolve(strict=True),
                   model_directory.resolve(strict=True), "127.0.0.1", port, MODEL_ID,
                   MODEL_REVISION, api_key_reference, bounds,
                   (("COLI_MODEL", str(model_directory.resolve(strict=True))),))

    @property
    def argv(self) -> tuple[str, ...]:
        # Upstream API docs confirm these exact serve flags; the key is injected from vault ref.
        return (str(self.executable), "serve", "--host", self.bind_host, "--port", str(self.bind_port),
                "--model-id", "glm-5.2-colibri")


@dataclass(frozen=True, slots=True)
class CgroupLimitSnapshot:
    """Literal values read back from the admitted unit's actual cgroup files."""
    unit: str
    cgroup_path: str
    memory_max: str
    cpu_max: str
    io_weight: str
    kill_mode: str
    network_policy: str
    namespace_id: str
    lifetime_limit_seconds: int


@dataclass(frozen=True, slots=True)
class CgroupStopEvidence:
    unit: str
    cgroup_path: str
    cgroup_procs_after: tuple[int, ...]


class ManagedServiceHandle(Protocol):
    """Host manager must return measured cgroup values for the actual admitted unit."""
    @property
    def cgroup_limits(self) -> CgroupLimitSnapshot: ...
    def wait_healthy(self, timeout: float) -> bool: ...
    def stop(self, reason: str) -> CgroupStopEvidence: ...


class ManagedServiceLauncher(Protocol):
    def start_colibri(self, plan: ColibriServicePlan) -> ManagedServiceHandle: ...


class ColibriService:
    def __init__(self, plan: ColibriServicePlan, launcher: ManagedServiceLauncher):
        self.plan, self.launcher = plan, launcher
        self._handle: ManagedServiceHandle | None = None

    def start(self) -> None:
        if self._handle is not None:
            return
        handle = self.launcher.start_colibri(self.plan)
        snapshot = handle.cgroup_limits
        try:
            memory = int(snapshot.memory_max)
            cpu_quota, cpu_period = (int(v) for v in snapshot.cpu_max.split())
            io_values = snapshot.io_weight.split()
            if len(io_values) != 2 or io_values[0] != "default":
                raise ValueError("cgroup I/O weight lacks a default value")
            io_weight = int(io_values[1])
        except (AttributeError, TypeError, ValueError):
            self._stop_managed(handle, "host manager returned no parseable cgroup limits")
            raise ColibriError("Colibri remains unavailable until actual cgroup memory.max, cpu.max and io.weight values are verified")
        cpu_percent = cpu_quota * 100 / cpu_period if cpu_period else 0
        if (not snapshot.unit or not snapshot.cgroup_path or not snapshot.namespace_id
                or snapshot.lifetime_limit_seconds < 1 or snapshot.lifetime_limit_seconds > 600
                or snapshot.network_policy != "authenticated-loopback-bridge"
                or snapshot.kill_mode != "control-group"
                or memory != self.plan.bounds.memory_max_bytes
                or abs(cpu_percent - self.plan.bounds.cpu_quota_percent) > 0.01
                or io_weight != self.plan.bounds.io_weight):
            self._stop_managed(handle, "host manager returned mismatched bounds, namespace, or cleanup mode")
            raise ColibriError("Colibri remains unavailable until manager-measured cgroup limits and control-group cleanup match the selected bounds")
        if not handle.wait_healthy(30):
            self._stop_managed(handle, "Colibri loopback health check failed")
            raise ColibriError("Colibri loopback API did not become healthy")
        self._handle = handle

    @staticmethod
    def _stop_managed(handle: ManagedServiceHandle, reason: str) -> None:
        snapshot = handle.cgroup_limits
        stopped = handle.stop(reason)
        if (not isinstance(stopped, CgroupStopEvidence) or stopped.unit != snapshot.unit
                or stopped.cgroup_path != snapshot.cgroup_path or stopped.cgroup_procs_after):
            raise ColibriError("managed Colibri stop did not prove that its admitted cgroup is empty")

    def stop(self, reason: str = "requested") -> None:
        if self._handle is not None:
            self._stop_managed(self._handle, reason)
            self._handle = None

    def cancel_inference(self) -> None:
        # Current pinned server has no per-request cancel endpoint. Stopping the managed
        # process ensures a disconnected generation cannot continue using model/CPU resources.
        self.stop("inference cancelled")


def prepare_model_storage(manifest: ArtifactManifest, model_root: Path, reserve: StorageReserve) -> StoragePlan:
    return estimate_storage(manifest, model_root, reserve)
