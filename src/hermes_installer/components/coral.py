"""Separate Coral Edge TPU runtime and delegate-used sample qualification."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from hermes_installer.models.artifacts import ArtifactError
from hermes_installer.models.artifacts import ArtifactFile
from hermes_installer.models.downloads import download_file

CORAL_SAMPLE_REPOSITORY = "google-coral/test_data"
CORAL_SAMPLE_REVISION = "104342d2d3480b3e66203073dac24f4e2dbb4c41"
CORAL_SAMPLE_FILE = "mobilenet_v2_1.0_224_quant_edgetpu.tflite"
CORAL_SAMPLE_SHA256 = "4315ee115507aab28c78809c0f384e5296527dd6a5dd53a1751b3eb9c91db6aa"
CORAL_SAMPLE_BYTES = 4_283_046
CORAL_SAMPLE_URL = f"https://raw.githubusercontent.com/{CORAL_SAMPLE_REPOSITORY}/{CORAL_SAMPLE_REVISION}/{CORAL_SAMPLE_FILE}"
CORAL_SAMPLE_METADATA = Path(__file__).resolve().parents[3] / "planning" / "coral-sample-artifact-metadata.json"
PCI_VENDOR = "1ac1"
PCI_DEVICE = "089a"
USB_VENDOR = "18d1"
USB_PRODUCTS = {"9302"}
PCI_RUNTIME_PACKAGES = ("gasket-dkms", "libedgetpu1-std")
USB_RUNTIME_PACKAGES = ("libedgetpu1-std",)
PYTHON_BUILD_PACKAGES = ("build-essential", "libssl-dev", "zlib1g-dev", "libbz2-dev",
                         "libreadline-dev", "libsqlite3-dev", "libffi-dev", "liblzma-dev")
PYTHON_MIN = (3, 6)
PYTHON_MAX = (3, 9)
CORAL_RUNTIME_METADATA = Path(__file__).resolve().parents[3] / "planning" / "coral-component-runtime-metadata.json"


class CoralError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CoralDevice:
    transport: str
    address: str
    vendor_id: str
    product_id: str
    device_node: str | None
    access_status: str

    @property
    def delegate_selector(self) -> str:
        if self.transport == "usb":
            return "usb:0"
        return "pci:0"


@dataclass(frozen=True, slots=True)
class CoralRuntimePlan:
    transport: str
    architecture: str
    runtime_packages: tuple[str, ...]
    isolated_python_requirement: str
    isolated_environment: Path
    device_group: str
    device_access_rule: str
    reboot_required: bool
    notes: tuple[str, ...]


def probe_coral_devices(*, sys_root: Path = Path("/sys"), dev_root: Path = Path("/dev")) -> tuple[CoralDevice, ...]:
    """Read Linux sysfs for Coral USB or PCIe devices and their actual access nodes."""
    found: list[CoralDevice] = []
    usb_root = sys_root / "bus" / "usb" / "devices"
    if usb_root.is_dir():
        for entry in sorted(usb_root.iterdir()):
            try:
                vendor = (entry / "idVendor").read_text(encoding="ascii").strip().lower()
                product = (entry / "idProduct").read_text(encoding="ascii").strip().lower()
            except (OSError, UnicodeError):
                continue
            if vendor == USB_VENDOR and product in USB_PRODUCTS:
                bus, address = entry / "busnum", entry / "devnum"
                if not bus.is_file() or not address.is_file():
                    continue
                node = dev_root / "bus" / "usb" / bus.read_text().strip() / address.read_text().strip()
                found.append(CoralDevice("usb", entry.name, vendor, product,
                    str(node) if node.exists() else None,
                    "accessible" if node.exists() and os.access(node, os.R_OK | os.W_OK) else "permission_denied"))
    pci_root = sys_root / "bus" / "pci" / "devices"
    if pci_root.is_dir():
        for entry in sorted(pci_root.iterdir()):
            try:
                vendor = (entry / "vendor").read_text(encoding="ascii").strip().lower().removeprefix("0x")
                product = (entry / "device").read_text(encoding="ascii").strip().lower().removeprefix("0x")
            except (OSError, UnicodeError):
                continue
            if vendor == PCI_VENDOR and product == PCI_DEVICE:
                node = dev_root / "apex_0"
                found.append(CoralDevice("pcie", entry.name, vendor, product,
                    str(node) if node.exists() else None,
                    "accessible" if node.exists() and os.access(node, os.R_OK | os.W_OK) else "driver_or_permission_pending"))
    return tuple(found)


def choose_coral_device(devices: Sequence[CoralDevice], *, preferred: str | None = None) -> CoralDevice:
    if preferred not in (None, "usb", "pcie"):
        raise ValueError("Coral preference must be usb or pcie")
    candidates = [d for d in devices if d.access_status == "accessible" and (preferred is None or d.transport == preferred)]
    if not candidates:
        if devices:
            raise CoralError("Coral device is present but the installer-owned runtime cannot access its device node")
        raise CoralError("no compatible Coral USB or PCIe Edge TPU is present")
    if preferred is None and {d.transport for d in candidates} == {"usb", "pcie"}:
        # A user preference is required if both are connected; do not guess which node
        # the runtime will bind to.
        raise CoralError("both USB and PCIe Coral devices are present; select the device transport")
    if len(candidates) != 1:
        raise CoralError("multiple Coral devices match the selected transport; isolate one device before qualification")
    return candidates[0]


def runtime_plan(device: CoralDevice, *, component_root: Path, architecture: str,
                 hermes_python: Path, compatible_python: Path | None = None) -> CoralRuntimePlan:
    if architecture.casefold() not in {"aarch64", "arm64"}:
        raise CoralError("this Coral runtime plan is for native Linux ARM64 only")
    driver_packages = USB_RUNTIME_PACKAGES if device.transport == "usb" else PCI_RUNTIME_PACKAGES
    packages = tuple(dict.fromkeys((*PYTHON_BUILD_PACKAGES, *driver_packages)))
    notes: list[str] = []
    python_req = "isolated CPython 3.6 through 3.9 with ARM64 TensorFlow Lite runtime; host/Hermes Python is not changed"
    env = component_root.resolve() / "venvs" / "coral-edge-tpu"
    if compatible_python:
        selected = compatible_python.resolve(strict=True)
        if selected == hermes_python.resolve(strict=True) or selected == Path(sys.executable).resolve(strict=True):
            raise CoralError("Coral's legacy Python cannot replace or reuse Hermes or installer Python")
        check = subprocess.run([str(selected), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=5)
        if check.returncode:
            raise CoralError("candidate isolated Coral Python could not report its version")
        parts = tuple(int(v) for v in check.stdout.strip().split(".")[:2])
        if not (PYTHON_MIN <= parts <= PYTHON_MAX):
            raise CoralError("official Coral Python packages support only CPython 3.6 through 3.9")
        notes.append(f"selected compatible component interpreter at {selected}")
    else:
        notes.append("blocked until a separately provisioned, pinned ARM64 CPython 3.9 component interpreter is available")
    if device.transport == "pcie":
        notes.extend(("PCIe requires the Apex gasket driver and a reboot after managed driver installation",
                      "grant the dedicated Coral service only the apex device group; do not broaden access"))
    else:
        notes.append("USB uses the official standard Edge TPU runtime and its scoped udev access rule")
    return CoralRuntimePlan(device.transport, architecture, packages, python_req, env, "apex",
        'SUBSYSTEM=="apex", MODE="0660", GROUP="apex"' if device.transport == "pcie" else
        'official libedgetpu USB rule, restricted to the Coral runtime device',
        device.transport == "pcie", tuple(notes))


def provision_coral_device(plan: CoralRuntimePlan, *, selected: bool,
                           install_managed_packages: Callable[[tuple[str, ...]], object],
                           sys_root: Path = Path("/sys"), dev_root: Path = Path("/dev")) -> tuple[str, tuple[CoralDevice, ...]]:
    """Request only the selected official runtime/driver packages through host package custody."""
    if not selected:
        raise PermissionError("Coral driver and runtime provisioning requires explicit selection")
    if plan.architecture.casefold() not in {"aarch64", "arm64"}:
        raise CoralError("Coral package provisioning is restricted to native Linux ARM64")
    result = install_managed_packages(plan.runtime_packages)
    code = getattr(result, "exit_code", getattr(result, "returncode", None))
    if code != 0:
        raise CoralError("managed package installer did not install the selected Coral runtime dependencies")
    if plan.reboot_required:
        return "pending_reboot", probe_coral_devices(sys_root=sys_root, dev_root=dev_root)
    devices = probe_coral_devices(sys_root=sys_root, dev_root=dev_root)
    selected_device = choose_coral_device(devices, preferred=plan.transport)
    return "device_accessible", (selected_device,)


def load_coral_sample_artifact(metadata_path: Path = CORAL_SAMPLE_METADATA) -> ArtifactFile:
    try:
        pin = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoralError(f"reviewed official Coral sample metadata is unavailable: {exc}") from exc
    expected = (CORAL_SAMPLE_REPOSITORY, CORAL_SAMPLE_REVISION, CORAL_SAMPLE_FILE,
                CORAL_SAMPLE_URL, CORAL_SAMPLE_SHA256, CORAL_SAMPLE_BYTES)
    observed = (pin.get("seed"), pin.get("commit"), pin.get("artifact"), pin.get("artifact_url"),
                pin.get("artifact_sha256"), pin.get("artifact_bytes"))
    if observed != expected:
        raise CoralError("official compiled Coral sample differs from the reviewed immutable pin")
    if not str(pin.get("license", "")).startswith("Apache-2.0"):
        raise CoralError("official compiled Coral sample license pin changed")
    return ArtifactFile(CORAL_SAMPLE_FILE, CORAL_SAMPLE_BYTES, CORAL_SAMPLE_SHA256,
                        "sha256", CORAL_SAMPLE_URL)


def load_coral_runtime_artifacts(metadata_path: Path = CORAL_RUNTIME_METADATA) -> dict[str, ArtifactFile]:
    """Load the Sol-reviewed source and exact wheel pins; reject a partial Python lock."""
    try:
        raw = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CoralError(f"pinned Coral runtime metadata is unavailable: {exc}") from exc
    expected = {"python/cpython": ("3.9.25", 20_183_236, "00e07d7c0f2f0cc002432d1ee84d2a40dae404a99303e3f97701c10966c91834"),
                "tensorflow/tflite-runtime": ("2.14.0", 2_325_666, "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02"),
                "numpy/numpy": ("1.26.4", 14_226_281, "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764")}
    found: dict[str, ArtifactFile] = {}
    for pin in raw.get("pins", ()):
        name = pin.get("identity")
        if name not in expected:
            continue
        version, size, digest = expected[name]
        if (pin.get("version"), pin.get("artifact_bytes"), pin.get("artifact_sha256")) != (version, size, digest):
            raise CoralError(f"reviewed Coral runtime pin changed for {name}")
        if name == "python/cpython" and "EOL2025-10-31" not in str(pin.get("maintenance", "")):
            raise CoralError("CPython 3.9 maintenance status must remain explicitly identified as EOL")
        if name == "tensorflow/tflite-runtime" and "glibc>=2.34" not in str(pin.get("abi", "")):
            raise CoralError("pinned Coral TFLite ABI is not qualified for the required ARM64 glibc")
        if name == "numpy/numpy" and "aarch64" not in str(pin.get("abi", "")):
            raise CoralError("pinned Coral NumPy ABI is not ARM64")
        url = pin.get("url")
        if not isinstance(url, str) or not url.startswith("https://"):
            raise CoralError(f"reviewed Coral runtime URL is invalid for {name}")
        filename = Path(url.split("?", 1)[0]).name
        found[name] = ArtifactFile(filename, size, digest, "sha256", url)
    if found.keys() != expected.keys():
        raise CoralError("complete reviewed CPython/NumPy/TFLite runtime pins are required")
    return found


def _private_component_root(path: Path) -> Path:
    if path.is_symlink():
        raise CoralError("Coral component root cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise CoralError("Coral component root must be owned by its dedicated installer identity with mode 0700")
    return resolved


def _run_managed_command(run_command: Callable[..., object], argv: Sequence[str], *, cwd: Path,
                         timeout: float, env: Mapping[str, str]) -> str:
    """All build/install subprocesses must be delegated to the host's bounded manager."""
    result = run_command(tuple(argv), cwd=cwd, timeout=timeout, env=dict(env))
    code = getattr(result, "exit_code", getattr(result, "returncode", None))
    output = getattr(result, "stdout", "") or ""
    if code != 0:
        raise CoralError(f"managed Coral runtime command failed ({code}): {' '.join(argv[:3])}; {str(output)[-1200:]}")
    return str(output)


def provision_coral_python(component_root: Path, *, selected: bool,
                           run_command: Callable[..., object],
                           metadata_path: Path = CORAL_RUNTIME_METADATA,
                           opener: Callable[..., object] = urllib.request.urlopen) -> Path:
    """Build the pinned legacy runtime and install only two hash-pinned wheels offline.

    This intentionally requires the managed-process adapter; no direct subprocess, system
    Python mutation, pip resolver, network package index, or lazy installer is used here.
    """
    if not selected:
        raise PermissionError("the isolated Coral runtime must be selected before provisioning")
    if platform.system() != "Linux" or platform.machine().casefold() not in {"aarch64", "arm64"}:
        raise CoralError("the isolated Coral CPython runtime can be built only on native Linux ARM64")
    libc_name, libc_version = platform.libc_ver()
    try:
        glibc = tuple(int(v) for v in libc_version.split(".")[:2]) if libc_name == "glibc" else ()
    except ValueError:
        glibc = ()
    if glibc < (2, 34):
        raise CoralError("pinned TFLite wheel requires Linux ARM64 glibc 2.34 or newer")
    component_root = _private_component_root(component_root)
    artifacts = load_coral_runtime_artifacts(metadata_path)
    cache = component_root / "cache" / "coral-runtime"
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    downloaded = {key: download_file(value, cache / value.name, opener=opener) for key, value in artifacts.items()}
    source_root = component_root / "build" / "cpython-3.9.25"
    source_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    extracted = source_root / "Python-3.9.25"
    if not extracted.exists():
        with tarfile.open(downloaded["python/cpython"], "r:xz") as archive:
            root = extracted.resolve()
            for member in archive.getmembers():
                target = (extracted / member.name).resolve()
                if root not in target.parents and target != root:
                    raise CoralError("CPython source archive contains a path traversal")
                if member.isdir():
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                elif member.isfile():
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    source = archive.extractfile(member)
                    if source is None:
                        raise CoralError("CPython source archive contains an unreadable regular file")
                    with source, target.open("xb") as sink:
                        shutil.copyfileobj(source, sink)
                    target.chmod(member.mode & 0o755)
                else:
                    raise CoralError("CPython source archive contains a link or special file")
    prefix = component_root / "runtimes" / "cpython-3.9.25"
    venv = component_root / "venvs" / "coral-edge-tpu-3.9.25"
    marker = prefix / ".hermes-coral-runtime.json"
    expected_marker = {name: artifact.digest for name, artifact in artifacts.items()}
    if marker.is_file() and not marker.is_symlink():
        try:
            existing = json.loads(marker.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            existing = {}
        if existing.get("pins") == expected_marker and existing.get("state") == "ready" and (venv / "bin" / "python").is_file():
            _run_managed_command(run_command, (str(venv / "bin" / "python"), "-c",
                "import importlib.metadata as m,sys; assert sys.version_info[:2]==(3,9); assert m.version('numpy')=='1.26.4'; assert m.version('tflite-runtime')=='2.14.0'"),
                cwd=component_root, timeout=20, env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1", "PIP_NO_INDEX": "1"})
            return venv / "bin" / "python"
        if (existing.get("pins") == expected_marker and existing.get("state") in {"provisioning", "failed"}
                and not prefix.is_symlink() and prefix.is_dir()):
            shutil.rmtree(prefix)
            if venv.is_symlink():
                raise CoralError("incomplete Coral venv path is an unexpected symlink")
            if venv.exists():
                shutil.rmtree(venv)
        else:
            raise CoralError("existing Coral runtime path is not the reviewed managed generation")
    elif prefix.exists() or prefix.is_symlink() or venv.exists() or venv.is_symlink():
        raise CoralError("unowned or incomplete Coral runtime path exists; inspect and remove only through recovery")
    prefix.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    venv.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    prefix.mkdir(mode=0o700)
    marker.write_text(json.dumps({"schema": 1, "pins": expected_marker,
                                  "python_version": "3.9.25", "state": "provisioning"}, sort_keys=True) + "\n",
                      encoding="utf-8")
    marker.chmod(0o600)
    build_env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(component_root / "tmp"),
                 "PYTHONNOUSERSITE": "1", "PIP_NO_INDEX": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1"}
    (component_root / "tmp").mkdir(mode=0o700, exist_ok=True)
    try:
        _run_managed_command(run_command, ("./configure", "--prefix=" + str(prefix), "--with-ensurepip=install"),
                             cwd=extracted, timeout=300, env=build_env)
        _run_managed_command(run_command, ("make", "-j2"), cwd=extracted, timeout=600, env=build_env)
        _run_managed_command(run_command, ("make", "altinstall"), cwd=extracted, timeout=600, env=build_env)
        interpreter = prefix / "bin" / "python3.9"
        if not interpreter.is_file() or interpreter.is_symlink():
            raise CoralError("managed CPython build did not produce the pinned isolated interpreter")
        _run_managed_command(run_command, (str(interpreter), "-m", "venv", str(venv)),
                             cwd=component_root, timeout=60, env=build_env)
        python = venv / "bin" / "python"
        wheels = (str(downloaded["numpy/numpy"]), str(downloaded["tensorflow/tflite-runtime"]))
        _run_managed_command(run_command, (str(python), "-m", "pip", "install", "--no-index", "--no-deps",
                                           "--no-input", "--no-cache-dir", *wheels),
                             cwd=component_root, timeout=120, env=build_env)
        _run_managed_command(run_command, (str(python), "-c", "import numpy,tflite_runtime.interpreter,sys; assert sys.version_info[:2]==(3,9)"),
                             cwd=component_root, timeout=20, env=build_env)
        marker.write_text(json.dumps({"schema": 1, "pins": expected_marker,
            "python_version": "3.9.25", "maintenance": "EOL2025-10-31", "state": "ready"}, sort_keys=True) + "\n", encoding="utf-8")
        marker.chmod(0o400)
        return python
    except BaseException:
        # The private, pin-matching provisioning marker authorizes safe retry cleanup.
        marker.chmod(0o600)
        marker.write_text(json.dumps({"schema": 1, "pins": expected_marker,
            "python_version": "3.9.25", "state": "failed"}, sort_keys=True) + "\n", encoding="utf-8")
        raise


def download_official_sample(destination: Path, *, opener: Callable[..., object] = urllib.request.urlopen,
                             selected: bool = False, cancel=None) -> Path:
    """Fetch the 4.3 MB official compiled sample only after Coral qualification is selected."""
    if not selected:
        raise PermissionError("the official Coral sample must be selected before download")
    sample = load_coral_sample_artifact()
    result = download_file(sample, destination, cancel=cancel, timeout=30, opener=opener)
    result.chmod(0o444)
    return result


def _verify_sample(path: Path) -> None:
    if path.stat().st_size != CORAL_SAMPLE_BYTES:
        raise ArtifactError("official compiled Coral sample has the wrong byte length")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != CORAL_SAMPLE_SHA256:
        raise ArtifactError("official compiled Coral sample SHA-256 does not match the pin")


@dataclass(frozen=True, slots=True)
class CoralInferenceEvidence:
    status: str
    transport: str
    device_address: str
    device_vendor_id: str
    device_product_id: str
    model_sha256: str
    runtime_sha256: str
    runtime_version: str
    delegate_library: str
    delegate_loaded: bool
    delegate_used: bool
    delegated_operation_count: int
    inference_performed: bool
    output_sha256: str | None
    elapsed_seconds: float | None
    python_version: str
    architecture: str
    failure_reason: str | None = None

    def to_json(self) -> str:
        from dataclasses import asdict
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"


def assess_inference_evidence(raw: Mapping[str, object], device: CoralDevice,
                              *, sample_path: Path, runtime_path: Path) -> CoralInferenceEvidence:
    _verify_sample(sample_path)
    runtime_sha = _sha256(runtime_path)
    if raw.get("model_sha256") != CORAL_SAMPLE_SHA256:
        raise ArtifactError("evidence does not identify the pinned official compiled Coral model")
    if raw.get("transport") != device.transport or raw.get("device_address") != device.address:
        raise ArtifactError("inference evidence does not match the selected physical Coral device")
    delegate_loaded = raw.get("delegate_loaded") is True
    delegate_used = raw.get("delegate_used") is True
    performed = raw.get("inference_performed") is True
    try:
        delegated_ops = int(raw.get("delegated_operation_count", 0))
    except (TypeError, ValueError):
        delegated_ops = 0
    output_sha = raw.get("output_sha256")
    if not delegate_loaded:
        raise CoralError("TPU delegate could not be loaded; CPU fallback is prohibited")
    if not performed or not delegate_used or delegated_ops < 1:
        raise CoralError("Coral proof requires a completed inference with at least one Edge TPU delegated operation")
    if not isinstance(output_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", output_sha):
        raise CoralError("delegate-used inference output digest is missing")
    try:
        elapsed = float(raw.get("elapsed_seconds", 0))
    except (TypeError, ValueError):
        elapsed = 0.0
    if elapsed <= 0:
        raise CoralError("delegate-used inference elapsed time is missing")
    if raw.get("runtime_sha256") != runtime_sha:
        raise ArtifactError("evidence runtime digest does not match the selected Edge TPU runtime")
    if raw.get("python_version") != "3.9" or raw.get("architecture", "").casefold() not in {"aarch64", "arm64"}:
        raise CoralError("Coral inference must run on the isolated CPython 3.9 ARM64 component runtime")
    if raw.get("hermes_python_changed") is True:
        raise CoralError("Coral qualification must preserve Hermes Python and use an isolated compatible runtime")
    return CoralInferenceEvidence("verified_delegate_used", device.transport, device.address,
        device.vendor_id, device.product_id, CORAL_SAMPLE_SHA256, runtime_sha,
        str(raw.get("runtime_version", "")), str(raw.get("delegate_library", "libedgetpu.so.1")),
        True, True, delegated_ops, True, output_sha, elapsed,
        str(raw.get("python_version", "")), str(raw.get("architecture", "")))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
