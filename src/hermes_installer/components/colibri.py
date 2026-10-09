"""Pinned ARM64 Colibri build and experimental GLM-5.2 runtime planning."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Callable, Mapping, Protocol, Sequence

from hermes_installer.models.artifacts import ArtifactManifest, MODEL_ID, MODEL_REVISION
from hermes_installer.models.downloads import DownloadCancelled, StoragePlan, StorageReserve, estimate_storage

COLIBRI_REVISION = "bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850"
COLIBRI_STORE_ID = "artifact:colibri-source:7cc79d4bfdc851efb27b67295ceac1370312b5cd414d869887715d30b2d13174"
COLIBRI_ARCHIVE_SHA256 = "7cc79d4bfdc851efb27b67295ceac1370312b5cd414d869887715d30b2d13174"
COLIBRI_ARCHIVE_BYTES = 11_412_458
COLIBRI_TREE_FILE_COUNT = 1_191
COLIBRI_TREE_BYTES = 30_936_176
COLIBRI_ARCHIVE_ROOT = "colibri-bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850/"
BUILD_PACKAGES = ("build-essential", "python3", "libgomp1")


class ColibriError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class BuildEvidence:
    source_revision: str
    source_artifact_sha256: str
    source_tree_manifest_sha256: str
    architecture: str
    binary_sha256: str
    elf_machine: str
    openmp_verified: bool
    libgomp_runtime: str
    self_test_output: str | None
    self_test_status: str


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


class _TreeFile(Protocol):
    path: str
    sha256: str
    size_bytes: int
    executable: bool


class _ResolvedTree(Protocol):
    artifact_id: str
    path: Path
    sha256: str
    size_bytes: int
    tree_files: tuple[_TreeFile, ...]
    archive_format: str | None
    archive_root: str | None


class _ArtifactCatalog(Protocol):
    def materialize_store_id(self, store_id: str, staging_root: Path, *,
                             expected_uid: int = 0) -> _ResolvedTree: ...


def _source_rows(tree_files: Sequence[_TreeFile]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for item in tree_files:
        relative = PurePosixPath(item.path)
        if (not item.path or "\\" in item.path or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
                or type(item.size_bytes) is not int or item.size_bytes < 0
                or not re.fullmatch(r"[0-9a-f]{64}", item.sha256)
                or type(item.executable) is not bool):
            raise ColibriError("protected Colibri source catalog contains an invalid tree-file row")
        rows.append({"path": relative.as_posix(), "sha256": item.sha256,
                     "size_bytes": item.size_bytes, "executable": item.executable})
    return _checked_source_rows(rows)


def _checked_source_rows(rows: object) -> list[dict[str, object]]:
    if not isinstance(rows, list):
        raise ColibriError("Colibri source manifest is not a file-row list")
    checked: list[dict[str, object]] = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "sha256", "size_bytes", "executable"}:
            raise ColibriError("Colibri source manifest row has unexpected fields")
        path, digest = row["path"], row["sha256"]
        size, executable = row["size_bytes"], row["executable"]
        relative = PurePosixPath(path) if isinstance(path, str) else PurePosixPath("/")
        if (not isinstance(path, str) or not path or "\\" in path or relative.is_absolute()
                or any(part in {"", ".", ".."} for part in relative.parts)
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or type(size) is not int or size < 0 or type(executable) is not bool):
            raise ColibriError("Colibri source manifest contains an unsafe file row")
        checked.append({"path": relative.as_posix(), "sha256": digest,
                        "size_bytes": size, "executable": executable})
    checked.sort(key=lambda row: str(row["path"]))
    if (len(checked) != COLIBRI_TREE_FILE_COUNT
            or sum(int(row["size_bytes"]) for row in checked) != COLIBRI_TREE_BYTES
            or len({row["path"] for row in checked}) != len(checked)):
        raise ColibriError("Colibri source tree differs from the reviewed file inventory")
    return checked


def _verify_source_rows(root: Path, rows: Sequence[Mapping[str, object]]) -> None:
    for row in rows:
        parts = PurePosixPath(str(row["path"])).parts
        parent = root
        for part in parts[:-1]:
            parent = parent / part
            try:
                parent_info = parent.lstat()
            except OSError as exc:
                raise ColibriError(f"pinned Colibri source directory is missing: {row['path']}") from exc
            if not stat.S_ISDIR(parent_info.st_mode):
                raise ColibriError(f"pinned Colibri source directory is not a real directory: {row['path']}")
        path = root.joinpath(*parts)
        try:
            info = path.lstat()
        except OSError as exc:
            raise ColibriError(f"pinned Colibri source file is missing: {row['path']}") from exc
        if not stat.S_ISREG(info.st_mode) or info.st_size != row["size_bytes"]:
            raise ColibriError(f"pinned Colibri source file type or size changed: {row['path']}")
        if _sha256(path) != row["sha256"]:
            raise ColibriError(f"pinned Colibri source file digest changed: {row['path']}")
        if bool(info.st_mode & 0o111) != bool(row["executable"]):
            raise ColibriError(f"pinned Colibri source executable mode changed: {row['path']}")


def fetch_pinned_colibri_source(component_root: Path, *, catalog: _ArtifactCatalog,
                                staging_root: Path, expected_uid: int = 0) -> Path:
    """Materialize the protected source receipt; never fetch arbitrary Git/network input."""
    artifact = catalog.materialize_store_id(COLIBRI_STORE_ID, staging_root,
                                            expected_uid=expected_uid)
    if (artifact.artifact_id != "colibri-source" or artifact.sha256 != COLIBRI_ARCHIVE_SHA256
            or artifact.archive_format != "tar.gz" or artifact.archive_root != COLIBRI_ARCHIVE_ROOT
            or len(artifact.tree_files) != COLIBRI_TREE_FILE_COUNT
            or artifact.size_bytes != COLIBRI_TREE_BYTES):
        raise ColibriError("Colibri artifact receipt differs from its exact protected enrollment")
    rows = _source_rows(artifact.tree_files)
    immutable_root = artifact.path
    if immutable_root.is_symlink() or not immutable_root.is_dir():
        raise ColibriError("protected Colibri materialized tree is not a real directory")
    _verify_source_rows(immutable_root, rows)

    if component_root.is_symlink():
        raise ColibriError("Colibri component root cannot be a symlink")
    component_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    root_info = component_root.stat()
    if root_info.st_uid != os.geteuid() or root_info.st_mode & 0o077:
        raise ColibriError("Colibri component root must be private and owned by its managed service identity")
    destination = component_root / ("colibri-" + COLIBRI_REVISION)
    marker = destination / ".hermes-colibri-source.json"
    manifest_digest = hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"),
                                                ensure_ascii=False).encode("utf-8")).hexdigest()
    expected_marker = {"source_revision": COLIBRI_REVISION, "artifact_store_id": COLIBRI_STORE_ID,
                       "artifact_sha256": COLIBRI_ARCHIVE_SHA256,
                       "artifact_archive_bytes": COLIBRI_ARCHIVE_BYTES,
                       "tree_manifest_sha256": manifest_digest, "tree_files": rows}
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_dir() or marker.is_symlink() or not marker.is_file():
            raise ColibriError("existing Colibri build source is not a managed pinned source directory")
        try:
            existing = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise ColibriError("existing Colibri source marker is unreadable") from None
        if existing != expected_marker:
            raise ColibriError("existing Colibri source marker does not match its protected artifact receipt")
        _verify_source_rows(destination, rows)
        return destination

    temporary = component_root / (".colibri-stage-" + uuid.uuid4().hex)
    temporary.mkdir(mode=0o700)
    try:
        for row in rows:
            relative = PurePosixPath(str(row["path"]))
            source_file = immutable_root.joinpath(*relative.parts)
            target_file = temporary.joinpath(*relative.parts)
            target_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if not stat.S_ISREG(source_file.lstat().st_mode):
                raise ColibriError(f"catalog source entry is not a regular file: {relative}")
            descriptor = os.open(target_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                                 0o700 if row["executable"] else 0o600)
            digest = hashlib.sha256()
            size = 0
            with source_file.open("rb") as incoming, os.fdopen(descriptor, "wb") as outgoing:
                for block in iter(lambda: incoming.read(1024 * 1024), b""):
                    outgoing.write(block)
                    digest.update(block)
                    size += len(block)
                outgoing.flush()
                os.fsync(outgoing.fileno())
            if size != row["size_bytes"] or digest.hexdigest() != row["sha256"]:
                raise ColibriError(f"copied Colibri source failed its catalog digest: {relative}")
            target_file.chmod(0o700 if row["executable"] else 0o600)
        (temporary / ".hermes-colibri-source.json").write_text(
            json.dumps(expected_marker, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        if destination.exists() or destination.is_symlink():
            raise ColibriError("Colibri build source destination appeared during materialization")
        os.replace(temporary, destination)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    _verify_source_rows(destination, rows)
    return destination

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
    marker_path = source / ".hermes-colibri-source.json"
    if marker_path.is_symlink() or not marker_path.is_file():
        raise ColibriError("Colibri source is not materialized from the protected artifact catalog")
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        if not isinstance(marker, dict):
            raise ValueError("marker is not an object")
        source_rows = _checked_source_rows(marker["tree_files"])
        manifest_digest = hashlib.sha256(json.dumps(
            source_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")).hexdigest()
    except (OSError, ValueError, KeyError, TypeError):
        raise ColibriError("Colibri catalog source marker is malformed") from None
    if (marker.get("source_revision") != expected_revision
            or set(marker) != {"source_revision", "artifact_store_id", "artifact_sha256",
                               "artifact_archive_bytes", "tree_manifest_sha256", "tree_files"}
            or marker.get("artifact_store_id") != COLIBRI_STORE_ID
            or marker.get("artifact_sha256") != COLIBRI_ARCHIVE_SHA256
            or marker.get("artifact_archive_bytes") != COLIBRI_ARCHIVE_BYTES
            or marker.get("tree_manifest_sha256") != manifest_digest):
        raise ColibriError("Colibri source checkout does not match the reviewed artifact receipt")
    _verify_source_rows(source, source_rows)
    setup = source / "c" / "setup.sh"
    if setup.is_symlink() or not setup.is_file():
        raise ColibriError("pinned Colibri source is missing its reviewed c/setup.sh build entry point")
    for tool in ("gcc", "make", "python3"):
        checked = _run((tool, "--version"), timeout=10, runner=runner)
        if checked.returncode:
            raise ColibriError(f"Colibri build dependency {tool} is unavailable; install {', '.join(BUILD_PACKAGES)} through the managed host")
    # Match the upstream setup check and ensure it links and runs against ARM64 libgomp.
    probe_dir = Path(tempfile.mkdtemp(prefix=".hermes-colibri-omp-", dir=source / "c"))
    try:
        probe_c, probe_bin = probe_dir / "probe.c", probe_dir / "probe"
        probe_c.write_text("#include <omp.h>\nint main(void){int n=0;\n#pragma omp parallel reduction(+:n)\n n += 1; return n < 1;}\n", encoding="ascii")
        compile_result = _run(("gcc", "-fopenmp", str(probe_c), "-o", str(probe_bin)), timeout=60, runner=runner)
        if compile_result.returncode:
            raise ColibriError("OpenMP/libgomp compile probe failed; install the ARM64 libgomp runtime and compiler package")
        execute_result = _run((str(probe_bin),), timeout=15, runner=runner)
        if execute_result.returncode:
            raise ColibriError("OpenMP/libgomp runtime probe failed on the target")
    finally:
        shutil.rmtree(probe_dir, ignore_errors=True)
    env = {"PATH": "/usr/bin:/bin", "ARCH": "native", "LC_ALL": "C", "HOME": "/tmp"}
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
    self_test_line = next((line.strip() for line in build_result.stdout.splitlines()
                           if "engine self-test:" in line), None)
    tiny = source / "c" / "glm_tiny"
    reference = source / "c" / "ref_glm.json"
    tiny_available = (tiny.is_dir() and not tiny.is_symlink()
                      and reference.is_file() and not reference.is_symlink())
    if tiny_available and self_test_line is None:
        raise ColibriError("pinned Colibri setup omitted its self-test despite the checked-in tiny oracle")
    if self_test_line is not None:
        match = re.search(r"(\d+)/(\d+) positions", self_test_line)
        if match is None or not 30 <= int(match.group(1)) <= 32 or int(match.group(2)) != 32:
            raise ColibriError("pinned Colibri tiny-oracle self-test did not meet the documented 30-32/32 result")
        self_test_status = "passed"
    else:
        # The pinned Git tree does not contain the optional glm_tiny fixture. The
        # upstream setup script deliberately skips its test in that case.
        self_test_status = "not_run_fixture_absent"
    return BuildEvidence(expected_revision, COLIBRI_ARCHIVE_SHA256, manifest_digest,
                         "aarch64", _sha256(binary), elf, True,
                         next((line.strip() for line in linked.stdout.splitlines() if "libgomp.so" in line), "libgomp.so"),
                         self_test_line, self_test_status)


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
        if port != 8000:
            raise ValueError("the reviewed Colibri OpenAI-compatible route is fixed to loopback port 8000")
        workdir = working_directory.resolve(strict=True)
        launcher = workdir / "coli"
        if launcher.is_symlink() or not launcher.is_file():
            raise ColibriError("pinned Colibri Python launcher is missing from the reviewed c/ working directory")
        return cls(executable.resolve(strict=True), working_directory.resolve(strict=True),
                   model_directory.resolve(strict=True), "127.0.0.1", port, MODEL_ID,
                   MODEL_REVISION, api_key_reference, bounds,
                   (("COLI_MODEL", str(model_directory.resolve(strict=True))),))

    @property
    def argv(self) -> tuple[str, ...]:
        # The pinned upstream `coli` launcher is a Python script; the C engine is
        # its child. Never pass the credential in argv; the manager injects
        # COLI_API_KEY from api_key_reference into this one isolated service.
        launcher = self.working_directory / "coli"
        return (str(self.executable), str(launcher), "serve", "--host", self.bind_host,
                "--port", str(self.bind_port), "--model", str(self.model_directory),
                "--model-id", "glm-5.2-colibri", "--ngen", str(self.bounds.max_output_tokens))


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
