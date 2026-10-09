"""Separate Coral Edge TPU runtime and delegate-used sample qualification."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from hermes_installer.models.artifacts import ArtifactError
from hermes_installer.models.artifacts import ArtifactFile

CORAL_SAMPLE_REPOSITORY = "google-coral/test_data"
CORAL_SAMPLE_REVISION = "104342d2d3480b3e66203073dac24f4e2dbb4c41"
CORAL_SAMPLE_FILE = "mobilenet_v2_1.0_224_quant_edgetpu.tflite"
CORAL_SAMPLE_SHA256 = "4315ee115507aab28c78809c0f384e5296527dd6a5dd53a1751b3eb9c91db6aa"
CORAL_SAMPLE_BYTES = 4_283_046
CORAL_SAMPLE_STORE_ID = f"artifact:coral-compiled-sample:{CORAL_SAMPLE_SHA256}"
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
CORAL_RUNTIME_METADATA = Path(__file__).resolve().parents[3] / "planning" / "coral-component-runtime-metadata.json"
CORAL_RUNTIME_STORE_IDS = {
    "python/cpython": "coral-python39-source",
    "tensorflow/tflite-runtime": "coral-tflite-runtime-cp39-arm64",
    "numpy/numpy": "coral-numpy-cp39-arm64",
}
CORAL_PACKAGE_SET_ID = "coral-cp39-runtime-v1"
CORAL_TFLITE_WHEEL_SHA256 = "be198b7dc4401204be54a15884d9e336389790eb707439524540f5a9329fdd02"
CORAL_NUMPY_WHEEL_SHA256 = "d5241e0a80d808d70546c697135da2c613f30e28251ff8307eb72ba696945764"


class CoralError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class CoralPackageSetReceipt:
    package_set_id: str
    manifest_sha256: str
    enrollment_id: str
    generation: str
    runtime_build_attestation_digest: str
    wheel_sha256: tuple[str, ...]
    installed_tree_sha256: str
    status: str
    receipt_id: str


def install_coral_runtime_package_set(authority_client, *,
                                      enrollment_id: str, generation: str,
                                      manifest_sha256: str, timeout: float = 600,
                                      cancelled: Callable[[], bool] | None = None) -> CoralPackageSetReceipt:
    """Mint an exact one-effect grant and install only the protected Coral set."""
    from hermes_installer.authority.package_sets import install_package_set, package_set_request
    from hermes_installer.authority.types import AuthorityDenied

    if (not isinstance(enrollment_id, str) or not enrollment_id
            or not isinstance(generation, str) or not generation
            or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 600):
        raise ValueError("Coral package-set enrollment, generation and bounded timeout are required")
    try:
        target, _payload, digest = package_set_request(package_set_id=CORAL_PACKAGE_SET_ID,
            manifest_sha256=manifest_sha256, enrollment_id=enrollment_id, generation=generation)
        context = authority_client.context(purpose="hermes-bootstrap",
            intent="install-coral-runtime-package-set", operation="package.install",
            final_payload_digest=digest, lease_seconds=float(timeout), cancelled=cancelled)
        authorization = authority_client.authorize_effect(context, capability="hermes-bootstrap",
            target=target, recipient=None, request_digest=digest, retry_index=0,
            cancelled=cancelled)
        receipt = install_package_set(authority_client, authorization,
            package_set_id=CORAL_PACKAGE_SET_ID, manifest_sha256=manifest_sha256,
            enrollment_id=enrollment_id, generation=generation, timeout=timeout,
            cancelled=cancelled)
    except (AuthorityDenied, AttributeError, TypeError, ValueError) as exc:
        raise CoralError(f"root package-set effect denied: {exc}") from exc
    return CoralPackageSetReceipt(receipt.package_set_id, receipt.manifest_sha256,
        receipt.enrollment_id, receipt.generation, receipt.runtime_build_attestation_digest,
        tuple(receipt.wheel_sha256), receipt.installed_tree_sha256, receipt.status,
        receipt.broker_receipt_id)


@dataclass(frozen=True, slots=True)
class CoralDevice:
    transport: str
    address: str
    vendor_id: str
    product_id: str
    device_node: str | None
    access_status: str
    sysfs_path: str | None = None
    device_major: int | None = None
    device_minor: int | None = None
    device_inode: int | None = None
    interface_identity: str | None = None
    interface_sysfs_path: str | None = None
    driver_identity: str | None = None

    @property
    def delegate_selector(self) -> str:
        if self.transport == "usb":
            return "usb:0"
        return "pci:0"

    @property
    def identity_sha256(self) -> str:
        """Stable selected-device identity; never treats a transport enum as identity."""
        payload = {
            "transport": self.transport,
            "address": self.address,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "sysfs_path": self.sysfs_path,
            "device_node": self.device_node,
            "device_major": self.device_major,
            "device_minor": self.device_minor,
            "device_inode": self.device_inode,
            "interface_identity": self.interface_identity,
            "interface_sysfs_path": self.interface_sysfs_path,
            "driver_identity": self.driver_identity,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":"),
                                           ensure_ascii=True).encode("ascii")).hexdigest()

    def host_binding_request(self) -> dict[str, object]:
        """Return the exact identity a root enrollment must bind to a private worker."""
        if (self.device_node is None or self.sysfs_path is None
                or type(self.device_major) is not int or type(self.device_minor) is not int
                or type(self.device_inode) is not int):
            raise CoralError("Coral device lacks a complete kernel identity for root-owned binding")
        if self.transport == "usb" and (not self.interface_identity or not self.interface_sysfs_path):
            raise CoralError("Coral USB device lacks the exact interface identity required for root-owned binding")
        if self.transport == "pcie" and not self.driver_identity:
            raise CoralError("Coral PCIe device lacks the bound driver identity required for root-owned binding")
        if self.transport not in {"usb", "pcie"}:
            raise CoralError("Coral transport is not enrolled for root-owned binding")
        return {
            "schema": 1,
            "transport": "pci" if self.transport == "pcie" else "usb",
            "physical_identity": self.address,
            "address": self.address,
            "vendor_id": self.vendor_id,
            "product_id": self.product_id,
            "sysfs_path": self.sysfs_path,
            "device_node": self.device_node,
            "device_major": self.device_major,
            "device_minor": self.device_minor,
            "device_inode": self.device_inode,
            "major": self.device_major,
            "minor": self.device_minor,
            "inode": self.device_inode,
            "interface_identity": self.interface_identity,
            "interface_sysfs_path": self.interface_sysfs_path,
            "driver_identity": self.driver_identity,
            "driver": self.driver_identity,
            # This digest is a local observation check only. Root custody creates
            # the generation-bound DeviceIdentity.selection_digest independently.
            "observed_identity_sha256": self.identity_sha256,
        }


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
                node_info = None
                try:
                    node_info = node.lstat()
                except OSError:
                    pass
                is_device = node_info is not None and stat.S_ISCHR(node_info.st_mode)
                interface_entries = sorted((sys_root / "bus" / "usb" / "devices").glob(entry.name + ":*"))
                for interface in interface_entries:
                    try:
                        interface_id = interface.name
                        if not re.fullmatch(re.escape(entry.name) + r":[0-9]+\.[0-9]+", interface_id):
                            continue
                        (interface / "bInterfaceNumber").read_text(encoding="ascii").strip()
                        interface_path = str(interface.resolve(strict=True))
                    except (OSError, UnicodeError):
                        continue
                    found.append(CoralDevice("usb", entry.name, vendor, product,
                        str(node) if is_device else None,
                        "accessible" if is_device and os.access(node, os.R_OK | os.W_OK) else "permission_denied",
                        str(entry.resolve(strict=True)), os.major(node_info.st_rdev) if is_device else None,
                        os.minor(node_info.st_rdev) if is_device else None,
                        node_info.st_ino if is_device else None,
                        interface_id, interface_path))
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
                node_info = None
                try:
                    node_info = node.lstat()
                except OSError:
                    pass
                is_device = node_info is not None and stat.S_ISCHR(node_info.st_mode)
                driver_link = entry / "driver"
                try:
                    driver_identity = driver_link.resolve(strict=True).name if driver_link.is_symlink() else None
                except OSError:
                    driver_identity = None
                found.append(CoralDevice("pcie", entry.name, vendor, product,
                    str(node) if is_device else None,
                    "accessible" if is_device and os.access(node, os.R_OK | os.W_OK) else "driver_or_permission_pending",
                    str(entry.resolve(strict=True)), os.major(node_info.st_rdev) if is_device else None,
                    os.minor(node_info.st_rdev) if is_device else None,
                    node_info.st_ino if is_device else None, driver_identity=driver_identity))
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
                 hermes_python: Path, compatible_python: Path | None = None,
                 run_command: Callable[..., object] | None = None) -> CoralRuntimePlan:
    if architecture.casefold() not in {"aarch64", "arm64"}:
        raise CoralError("this Coral runtime plan is for native Linux ARM64 only")
    driver_packages = USB_RUNTIME_PACKAGES if device.transport == "usb" else PCI_RUNTIME_PACKAGES
    packages = tuple(dict.fromkeys((*PYTHON_BUILD_PACKAGES, *driver_packages)))
    notes: list[str] = []
    python_req = "isolated CPython 3.9 with ARM64 TensorFlow Lite runtime; host/Hermes Python is not changed"
    env = component_root.resolve() / "venvs" / "coral-edge-tpu"
    if compatible_python is not None:
        if compatible_python.is_symlink():
            raise CoralError("candidate Coral interpreter cannot be reached through a symlink")
        selected = compatible_python.resolve(strict=True)
        if selected == hermes_python.resolve(strict=True) or selected == Path(sys.executable).resolve(strict=True):
            raise CoralError("Coral's legacy Python cannot replace or reuse Hermes or installer Python")
        if selected.is_symlink() or not selected.is_file() or not os.access(selected, os.X_OK):
            raise CoralError("candidate Coral interpreter must be a regular isolated executable")
        if run_command is None:
            raise CoralError("Coral Python compatibility requires a bounded host-managed process probe")
        output = _run_managed_command(run_command,
            (str(selected), "-c", "import sys; print('%d.%d' % sys.version_info[:2])"),
            cwd=component_root.resolve(strict=True), timeout=5,
            env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"})
        try:
            parts = tuple(int(v) for v in output.strip().split(".")[:2])
        except ValueError:
            parts = ()
        if parts != (3, 9):
            raise CoralError("pinned official Coral Python packages require exact CPython 3.9")
        notes.append(f"selected compatible component interpreter at {selected}")
        notes.append("CPython 3.9 reached EOL on 2025-10-31; this is a legacy compatibility path")
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


def resolve_coral_runtime_artifacts(catalog, staging_root: Path, *, expected_uid: int = 0):
    """Resolve and rehash the three immutable Coral inputs through the host catalog."""
    pins = load_coral_runtime_artifacts()
    resolved = {}
    for identity, metadata in pins.items():
        artifact_id = CORAL_RUNTIME_STORE_IDS[identity]
        store_id = f"artifact:{artifact_id}:{metadata.digest}"
        artifact = catalog.resolve_store_id(store_id, staging_root, expected_uid=expected_uid)
        if (artifact.artifact_id != artifact_id or artifact.sha256 != metadata.digest
                or artifact.size_bytes != metadata.size or artifact.path.is_symlink()
                or not artifact.path.is_file() or artifact.path.stat().st_size != metadata.size):
            raise CoralError(f"protected Coral runtime receipt differs from the exact {identity} pin")
        if _sha256(artifact.path) != metadata.digest:
            raise CoralError(f"protected Coral runtime bytes failed the {identity} SHA-256 pin")
        resolved[identity] = artifact
    return resolved


def _private_component_root(path: Path) -> Path:
    if path.is_symlink():
        raise CoralError("Coral component root cannot be a symlink")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise CoralError("Coral component root must be owned by its dedicated installer identity with mode 0700")
    return resolved


def _private_child(root: Path, *parts: str) -> Path:
    current = root
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise CoralError("Coral runtime paths cannot traverse symlinked component directories")
        if not current.exists():
            current.mkdir(mode=0o700)
        info = current.stat()
        if not current.is_dir() or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise CoralError("Coral runtime subdirectories must be private and owned by the component identity")
    return current


def _run_managed_command(run_command: Callable[..., object], argv: Sequence[str], *, cwd: Path,
                         timeout: float, env: Mapping[str, str]) -> str:
    """All build/install subprocesses must be delegated to the host's bounded manager."""
    result = run_command(tuple(argv), cwd=cwd, timeout=timeout, env=dict(env))
    code = getattr(result, "exit_code", getattr(result, "returncode", None))
    output = getattr(result, "stdout", "") or ""
    if code != 0:
        raise CoralError(f"managed Coral runtime command failed ({code}): {' '.join(argv[:3])}; {str(output)[-1200:]}")
    return str(output)


def provision_coral_python(component_root: Path, *, selected: bool, catalog=None,
                           staging_root: Path | None = None, expected_uid: int = 0) -> Path:
    """Fail closed until the enrolled protected package-set effect is callable."""
    if not selected:
        raise PermissionError("the isolated Coral runtime must be selected before provisioning")
    if catalog is None or staging_root is None:
        raise CoralError("Coral runtime provisioning requires its protected artifact-catalog receipts")
    resolve_coral_runtime_artifacts(catalog, staging_root, expected_uid=expected_uid)
    raise CoralError(
        "Coral activation remains unavailable: the reviewed coral-cp39-runtime-v1 package-set contract "
        "exists, but this host API has no published package-set effect client or enrolled CPython 3.9 "
        "build attestation/runtime generation; no package install was attempted"
    )

def download_official_sample(destination: Path, *, selected: bool = False, cancel=None, catalog=None,
                             staging_root: Path | None = None, expected_uid: int = 0) -> Path:
    """Copy the official compiled sample from its root-catalog receipt after selection."""
    if not selected:
        raise PermissionError("the official Coral sample must be selected before download")
    if cancel is not None and (cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())):
        raise CoralError("official Coral sample copy was cancelled")
    if catalog is None or staging_root is None:
        raise CoralError("official Coral sample remains unavailable until its protected artifact catalog receipt is supplied")
    artifact = catalog.resolve_store_id(CORAL_SAMPLE_STORE_ID, staging_root, expected_uid=expected_uid)
    if (artifact.artifact_id != "coral-compiled-sample" or artifact.sha256 != CORAL_SAMPLE_SHA256
            or artifact.size_bytes != CORAL_SAMPLE_BYTES or artifact.path.is_symlink()
            or not artifact.path.is_file()):
        raise CoralError("protected Coral sample artifact receipt differs from the exact official pin")
    _verify_sample(artifact.path)
    if destination.is_symlink():
        raise CoralError("Coral sample destination cannot be a symlink")
    if destination.parent.is_symlink():
        raise CoralError("Coral sample directory cannot be a symlink")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = destination.parent.stat()
    if parent_info.st_uid != os.geteuid() or parent_info.st_mode & 0o077:
        raise CoralError("Coral sample directory must be private and owned by the component identity")
    if destination.exists():
        if not destination.is_file():
            raise CoralError("Coral sample destination is not a regular file")
        _verify_sample(destination)
        return destination
    temporary = destination.with_name("." + destination.name + "." + uuid.uuid4().hex + ".part")
    digest = hashlib.sha256()
    size = 0
    try:
        with artifact.path.open("rb") as incoming, temporary.open("xb") as outgoing:
            for block in iter(lambda: incoming.read(128 * 1024), b""):
                if cancel is not None and (cancel.is_set() if hasattr(cancel, "is_set") else bool(cancel())):
                    raise CoralError("official Coral sample copy was cancelled")
                outgoing.write(block)
                digest.update(block)
                size += len(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        if size != CORAL_SAMPLE_BYTES or digest.hexdigest() != CORAL_SAMPLE_SHA256:
            raise CoralError("copied official Coral sample failed its exact size/digest pin")
        temporary.chmod(0o444)
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        return destination
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _verify_sample(path: Path) -> None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size != CORAL_SAMPLE_BYTES:
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
    device_identity_sha256: str
    failure_reason: str | None = None

    def to_json(self) -> str:
        from dataclasses import asdict
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"


def assess_inference_evidence(raw: Mapping[str, object], device: CoralDevice,
                              *, sample_path: Path, runtime_path: Path,
                              root_selection_digest: str) -> CoralInferenceEvidence:
    if not re.fullmatch(r"[0-9a-f]{64}", root_selection_digest):
        raise CoralError("root-attested generation-bound device selection digest is required")
    _verify_sample(sample_path)
    if runtime_path.is_symlink() or not runtime_path.is_file():
        raise ArtifactError("selected Edge TPU runtime library must be a regular non-symlink file")
    runtime_sha = _sha256(runtime_path)
    if raw.get("model_sha256") != CORAL_SAMPLE_SHA256:
        raise ArtifactError("evidence does not identify the pinned official compiled Coral model")
    if raw.get("transport") != device.transport or raw.get("device_address") != device.address:
        raise ArtifactError("inference evidence does not match the selected physical Coral device")
    identity = raw.get("device_identity_sha256")
    if identity != root_selection_digest or not isinstance(identity, str):
        raise ArtifactError("inference evidence does not match the root-attested device selection digest")
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
    if raw.get("hermes_python_changed") is not False:
        raise CoralError("Coral qualification must preserve Hermes Python and use an isolated compatible runtime")
    return CoralInferenceEvidence("verified_delegate_used", device.transport, device.address,
        device.vendor_id, device.product_id, CORAL_SAMPLE_SHA256, runtime_sha,
        str(raw.get("runtime_version", "")), str(raw.get("delegate_library", "libedgetpu.so.1")),
        True, True, delegated_ops, True, output_sha, elapsed,
        str(raw.get("python_version", "")), str(raw.get("architecture", "")), identity)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
