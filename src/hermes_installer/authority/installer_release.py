"""Stage-zero proof for the installed root setup release and current actor.

The deployment receipt and immutable closure manifest are produced by the
root installer deployment stage. Verification is deliberately independent of
the later root-setup-selection.json and active worker authority.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import secrets
import select
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending, _process_start_time, _verify_import_search_path

DEPLOYMENT_RECEIPT_PATH = Path("/var/lib/hermes-installer/deployments/current.json")
RELEASE_STORE_ROOT = Path("/usr/lib/hermes-installer/releases")
RELEASE_ID = "hermes-installer-root-release-v1"
BASELINE_TAG_OBJECT = "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
BASELINE_COMMIT = "653ac5fbc7a02613c9951859a7d794599603459b"
TEMPLATE = (
    "installer-bootstrap-compiler-template-v1",
    "templates/bootstrap-compiler-template-v1.json",
    "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5",
    4281,
)
PLAN_TEMPLATE = (
    "installer-root-setup-plan-template-v1",
    "templates/root-setup-plan-template-v1.json",
    "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5",
    920,
)
AUTHENTIK_TEMPLATE = (
    "installer-authentik-policy-template-v1",
    "templates/authentik-policy-template-v1.json",
    "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8",
    261,
)
PREPARED_BASE_TEMPLATE = (
    "installer-prepared-authority-base-template-v1",
    "templates/prepared-authority-base-template-v1.json",
    "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953",
    369,
)
RECEIPT_BINDINGS_TEMPLATE = (
    "installer-bootstrap-receipt-bindings-template-v1",
    "templates/bootstrap-receipt-bindings-template-v1.json",
    "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609",
    10195,
)
COMPOSIO_READER_TEMPLATE = (
    "installer-composio-whatsapp-catalog-read-policy-v1",
    "templates/composio-whatsapp-catalog-read-policy-v1.json",
    "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5",
    528,
)
EXISTING_MODEL_STORE_TEMPLATE = (
    "installer-existing-model-store-root-template-v1",
    "templates/existing-model-store-root-template-v1.json",
    "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f",
    712,
)
FIXED_TEMPLATES = (TEMPLATE, PLAN_TEMPLATE, AUTHENTIK_TEMPLATE,
                   PREPARED_BASE_TEMPLATE, RECEIPT_BINDINGS_TEMPLATE,
                   COMPOSIO_READER_TEMPLATE, EXISTING_MODEL_STORE_TEMPLATE)
REVIEWED_SOURCE_MODULES = (
    ("installer-module:hermes_installer.components.native_plugins",
     "lib/python/hermes_installer/components/native_plugins.py",
     "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7", 28_259),
    ("installer-module:hermes_installer.components.public_registries",
     "lib/python/hermes_installer/components/public_registries.py",
     "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f", 29_374),
    ("installer-native-invocations-module-v137",
     "src/hermes_installer/native_invocations.py",
     "78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226", 40_107),
    ("installer-native-boundary-module-v137",
     "src/hermes_installer/native_boundary.py",
     "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb", 14_356),
    ("installer-native-source-definitions-module-v137",
     "src/hermes_installer/authority/native_source_definitions.py",
     "084ff4e844782234f628f54a566882fb245ef44ae08e6c271d1654fcafe937e7", 10_063),
)
REVIEWED_SOURCE_ARTIFACTS = (
    ("glm52-artifact-metadata-v1", "planning/glm52-artifact-metadata.json",
     "b42e3fa6fd5c287b95fcda4d370697bd4c0ef226767ddc08fae4e5bebcfecd1a", 56_232, "baseline"),
    ("glm52-upstream-mit-license-cf457fa",
     "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-upstream-MIT-LICENSE.txt",
     "f4a18c6ae40b0a8e7d2b7667f52f6e1994e54a46430d2e172b73cb8c9b5eb0d7", 1_065, "amendment"),
    ("glm52-quantized-readme-6bbb01e",
     "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-quantized-README.md",
     "85fc4cf947276c376f09ad1226926ebc03eefbb99d184cd05f34412d32d8406b", 17_468, "amendment"),
)
LAUNCHER_PATH = "bin/hermes-installer-root-setup"
INTERPRETER_PATH = "runtime/bin/python"
PLAN_PATH = "plans/root-setup-plan-v1.json"
ARTIFACT_CATALOG_PATH = "catalog/artifacts.json"
MAX_RECEIPT_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_FILES = 50_000
MAX_FILE_BYTES = 512 * 1024 * 1024
ROLES = frozenset({"launcher", "interpreter", "module", "template", "plan",
                   "artifact-catalog", "bootstrap-policy", "baseline", "amendment"})
_SEAL = object()
_SHA = re.compile(r"[0-9a-f]{64}")
_COMMIT = re.compile(r"[0-9a-f]{40}")
_RECEIPT_ID = re.compile(r"[A-Za-z0-9_.:-]{1,160}")


class InstallerReleaseError(BootstrapEnrollmentError):
    """Installed release or root actor failed stage-zero verification."""


@dataclass(frozen=True, slots=True)
class VerifiedReleaseFile:
    artifact_id: str
    roles: tuple[str, ...]
    relative_path: str
    sha256: str
    size_bytes: int
    device: int
    inode: int
    mode: int

    @property
    def role(self) -> str:
        """Compatibility convenience; multi-role membership remains explicit."""
        if len(self.roles) != 1:
            raise AttributeError("release file has multiple roles")
        return self.roles[0]


class VerifiedInstallerReleaseReceipt:
    """Sealed proof of one held immutable root deployment release."""
    __slots__ = ("release_root", "release_commit", "deployment_receipt_sha256",
                 "root_device", "root_inode", "closure_manifest_relative_path",
                 "closure_manifest_sha256", "baseline_tag_object", "baseline_commit",
                 "baseline_tree_sha256", "amendment_manifest_sha256", "files",
                 "selected_plan_artifact_id", "selected_plan_sha256", "_root_fd", "_seal",
                 "_uid", "_closed")

    def __init__(self, seal: object, *, release_root: Path, release_commit: str,
                 deployment_receipt_sha256: str, root_device: int, root_inode: int,
                 closure_manifest_relative_path: str, closure_manifest_sha256: str,
                 baseline_tag_object: str, baseline_commit: str, baseline_tree_sha256: str,
                 amendment_manifest_sha256: str, files: tuple[VerifiedReleaseFile, ...],
                 selected_plan_artifact_id: str, selected_plan_sha256: str,
                 root_fd: int, expected_uid: int):
        if seal is not _SEAL:
            raise TypeError("release receipts can only be minted by InstalledRootReleaseVerifier")
        self.release_root = release_root
        self.release_commit = release_commit
        self.deployment_receipt_sha256 = deployment_receipt_sha256
        self.root_device, self.root_inode = root_device, root_inode
        self.closure_manifest_relative_path = closure_manifest_relative_path
        self.closure_manifest_sha256 = closure_manifest_sha256
        self.baseline_tag_object, self.baseline_commit = baseline_tag_object, baseline_commit
        self.baseline_tree_sha256, self.amendment_manifest_sha256 = baseline_tree_sha256, amendment_manifest_sha256
        self.files = files
        self.selected_plan_artifact_id, self.selected_plan_sha256 = selected_plan_artifact_id, selected_plan_sha256
        self._root_fd, self._seal, self._uid, self._closed = root_fd, seal, expected_uid, False

    def verify_current(self) -> None:
        if self._seal is not _SEAL or self._closed or self._root_fd < 0:
            raise InstallerReleaseError("installer release receipt is not live")
        root = os.fstat(self._root_fd)
        if (root.st_uid != self._uid or not stat.S_ISDIR(root.st_mode)
                or root.st_dev != self.root_device or root.st_ino != self.root_inode
                or stat.S_IMODE(root.st_mode) & 0o222):
            raise InstallerReleaseError("held installer release custody changed")
        for entry in self.files:
            info = _hash_release_file(self._root_fd, entry.relative_path, entry.sha256,
                                      expected_uid=self._uid, expected_size=entry.size_bytes)
            if (info.st_dev != entry.device or info.st_ino != entry.inode
                    or stat.S_IMODE(info.st_mode) != entry.mode):
                raise InstallerReleaseError("held installer release closure changed")

    @property
    def module_closure_sha256(self) -> str:
        rows = {row.relative_path: row.sha256 for row in self.files if "module" in row.roles}
        return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False).encode("utf-8")).hexdigest()

    def open_file(self, artifact_id: str) -> int:
        """Return a no-follow FD for a verified artifact ID in this release."""
        self.verify_current()
        matches = [item for item in self.files if item.artifact_id == artifact_id]
        if len(matches) != 1:
            raise InstallerReleaseError("requested release artifact is not uniquely enrolled")
        item = matches[0]
        return _open_verified_fd(self._root_fd, item.relative_path, item.sha256,
                                 expected_uid=self._uid, expected_size=item.size_bytes)

    def resolve_reviewed_source_module(self, artifact_id: str) -> VerifiedReleaseFile:
        """Return the exact held row for a finite target-adapter source module."""
        self.verify_current()
        expected = {row[0]: row[1:] for row in REVIEWED_SOURCE_MODULES}
        identity = expected.get(artifact_id)
        if identity is None:
            raise InstallerReleaseError("source module is outside the finite reviewed release set")
        matches = [row for row in self.files if row.artifact_id == artifact_id]
        if len(matches) != 1:
            raise InstallerReleaseError("reviewed source module is absent or ambiguous")
        row = matches[0]
        relative_path, digest, size = identity
        if ("module" not in row.roles or row.relative_path != relative_path
                or row.sha256 != digest or row.size_bytes != size):
            raise InstallerReleaseError("reviewed source module differs from its pinned release row")
        return row

    def open_reviewed_source_module(self, artifact_id: str) -> int:
        """Open no-follow bytes for one of the two reviewed target modules."""
        row = self.resolve_reviewed_source_module(artifact_id)
        return _open_verified_fd(self._root_fd, row.relative_path, row.sha256,
                                 expected_uid=self._uid, expected_size=row.size_bytes)

    def resolve_reviewed_source_artifact(self, artifact_id: str) -> VerifiedReleaseFile:
        """Resolve one reviewed source blob to its held baseline/amendment member."""
        self.verify_current()
        expected = {row[0]: row[1:] for row in REVIEWED_SOURCE_ARTIFACTS}
        identity = expected.get(artifact_id)
        if identity is None:
            raise InstallerReleaseError("source artifact is outside the finite reviewed release set")
        relative_path, digest, size, role = identity
        matches = [row for row in self.files if row.relative_path == relative_path]
        if len(matches) != 1:
            raise InstallerReleaseError("reviewed source artifact member is absent or ambiguous")
        row = matches[0]
        if (row.sha256, row.size_bytes, row.roles) != (digest, size, (role,)):
            raise InstallerReleaseError("reviewed source artifact differs from its held release member")
        return row

    def open_reviewed_source_artifact(self, artifact_id: str) -> int:
        """Open verified bytes for a reviewed catalog source without exposing a path."""
        row = self.resolve_reviewed_source_artifact(artifact_id)
        return _open_verified_fd(self._root_fd, row.relative_path, row.sha256,
                                 expected_uid=self._uid, expected_size=row.size_bytes)

    def close(self) -> None:
        if not self._closed:
            os.close(self._root_fd)
            self._root_fd, self._closed = -1, True

    def __enter__(self) -> "VerifiedInstallerReleaseReceipt":
        self.verify_current()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class RootActorObservation:
    """PIDFD-bound observation of the exact installed root setup actor."""
    __slots__ = ("pid", "uid", "gid", "start_time", "launcher", "interpreter",
                 "module_origins", "namespace_inodes", "isolated_import_facts",
                 "_pidfd", "_seal", "_closed")

    def __init__(self, seal: object, *, pid: int, uid: int, gid: int, start_time: int,
                 launcher: tuple[str, int, int, str], interpreter: tuple[str, int, int, str],
                 module_origins: tuple[tuple[str, str, int, int, str], ...],
                 namespace_inodes: tuple[tuple[str, int], ...],
                 isolated_import_facts: tuple[str, ...], pidfd: int):
        if seal is not _SEAL:
            raise TypeError("actor observations can only be minted by InstalledRootReleaseVerifier")
        self.pid, self.uid, self.gid, self.start_time = pid, uid, gid, start_time
        self.launcher, self.interpreter = launcher, interpreter
        self.module_origins, self.namespace_inodes = module_origins, namespace_inodes
        self.isolated_import_facts = isolated_import_facts
        self._pidfd, self._seal, self._closed = pidfd, seal, False

    def verify_current(self, release: VerifiedInstallerReleaseReceipt) -> None:
        if self._seal is not _SEAL or self._closed:
            raise InstallerReleaseError("root actor observation is not live")
        release.verify_current()
        poller = select.poll()
        poller.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise InstallerReleaseError("observed root actor has exited")
        if (os.getpid() != self.pid or os.getuid() != self.uid or os.geteuid() != 0
                or os.getgid() != self.gid or _process_start_time(self.pid) != self.start_time
                or self.uid != 0 or self.gid != 0):
            raise InstallerReleaseError("current process identity differs from root actor observation")
        if _namespace_inodes(self.pid) != self.namespace_inodes:
            raise InstallerReleaseError("root actor namespace identity changed")
        for path, device, inode, digest in (self.launcher, self.interpreter):
            _verify_actor_path(Path(path), digest, device, inode)
        try:
            kernel_executable = Path(f"/proc/{self.pid}/exe").resolve(strict=True)
        except OSError:
            raise InstallerReleaseError("kernel executable identity is unavailable") from None
        if kernel_executable != Path(self.interpreter[0]):
            raise InstallerReleaseError("kernel executable differs from pinned setup interpreter")
        for name, module in tuple(sys.modules.items()):
            if name == "hermes_installer" or name.startswith("hermes_installer."):
                origin = getattr(getattr(module, "__spec__", None), "origin", None)
                if origin is None or not any(item[0] == name and item[1] == origin for item in self.module_origins):
                    raise InstallerReleaseError("unreviewed Hermes installer module is loaded")
        for module, origin, device, inode, digest in self.module_origins:
            current = sys.modules.get(module)
            actual_origin = getattr(getattr(current, "__spec__", None), "origin", None)
            if current is None or actual_origin != origin:
                raise InstallerReleaseError("root actor imported module origin changed")
            _verify_actor_path(Path(origin), digest, device, inode)
        current_import_facts = _isolated_import_facts()
        if current_import_facts != self.isolated_import_facts:
            raise InstallerReleaseError("root actor import environment changed")

    def close(self) -> None:
        if not self._closed:
            os.close(self._pidfd)
            self._pidfd, self._closed = -1, True

    def __enter__(self) -> "RootActorObservation":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class InstalledRootReleaseVerifier:
    """Fixed-path, root-only preselection release and actor verifier."""

    @classmethod
    def from_current_root_process(cls) -> tuple[VerifiedInstallerReleaseReceipt, RootActorObservation]:
        if not _linux() or os.getuid() != 0 or os.geteuid() != 0:
            raise BootstrapEnrollmentPending("stage-zero verification requires the installed Linux root process")
        receipt = cls._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH, expected_uid=0)
        release = cls._mint_release(receipt, expected_uid=0)
        actor: RootActorObservation | None = None
        try:
            actor = cls._observe_actor(release)
            actor.verify_current(release)
            return release, actor
        except Exception:
            if actor is not None:
                actor.close()
            release.close()
            raise

    @classmethod
    def verify_installed_release(cls) -> VerifiedInstallerReleaseReceipt:
        """Alias matching the stage-zero deployment contract (root actor included separately)."""
        receipt = cls._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH, expected_uid=0)
        return cls._mint_release(receipt, expected_uid=0)

    @classmethod
    def _load_deployment_receipt(cls, path: Path, *, expected_uid: int) -> Mapping[str, Any]:
        if path != DEPLOYMENT_RECEIPT_PATH:
            raise InstallerReleaseError("deployment receipt path override is forbidden")
        raw, _ = _read_fixed_file(path, MAX_RECEIPT_BYTES, expected_uid, required_mode=0o600)
        try:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
        except (UnicodeError, ValueError, json.JSONDecodeError):
            raise InstallerReleaseError("installed release deployment receipt is malformed") from None
        fields = {"schema", "receipt_id", "candidate_git_sha", "release_root", "release_device",
                  "release_inode", "closure_manifest_relative_path", "closure_manifest_sha256",
                  "baseline_tree_sha256", "published_monotonic"}
        if not isinstance(value, dict) or set(value) != fields or value["schema"] != 1:
            raise InstallerReleaseError("installed release deployment receipt has an invalid schema")
        candidate = value["candidate_git_sha"]
        if (not isinstance(candidate, str) or not _COMMIT.fullmatch(candidate)
                or not isinstance(value["receipt_id"], str) or not _RECEIPT_ID.fullmatch(value["receipt_id"])):
            raise InstallerReleaseError("installed release identity is not approved")
        fixed_root = RELEASE_STORE_ROOT / candidate
        if value["release_root"] != str(fixed_root):
            raise InstallerReleaseError("installed release root differs from fixed candidate path")
        if (type(value["release_device"]) is not int or value["release_device"] < 0
                or type(value["release_inode"]) is not int or value["release_inode"] <= 0):
            raise InstallerReleaseError("installed release root identity is malformed")
        for key in ("closure_manifest_sha256", "baseline_tree_sha256"):
            if not isinstance(value[key], str) or not _SHA.fullmatch(value[key]):
                raise InstallerReleaseError("installed release digest is malformed")
        _validate_relative(value["closure_manifest_relative_path"])
        if (type(value["published_monotonic"]) not in (int, float)
                or not math.isfinite(value["published_monotonic"]) or value["published_monotonic"] <= 0):
            raise InstallerReleaseError("installed release publication time is malformed")
        return MappingProxyType({**value, "_receipt_sha256": hashlib.sha256(raw).hexdigest()})

    @classmethod
    def _mint_release(cls, receipt: Mapping[str, Any], *, expected_uid: int) -> VerifiedInstallerReleaseReceipt:
        root = Path(receipt["release_root"])
        try:
            _verify_parents(root.parent, expected_uid)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            raise InstallerReleaseError("deployed release root cannot be opened without following links") from None
        try:
            root_info = os.fstat(root_fd)
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != expected_uid
                    or stat.S_IMODE(root_info.st_mode) & 0o222
                    or root_info.st_dev != receipt["release_device"]
                    or root_info.st_ino != receipt["release_inode"]):
                raise InstallerReleaseError("deployed release root custody is unsafe")
            manifest_fd = _open_verified_fd(root_fd, receipt["closure_manifest_relative_path"],
                                            receipt["closure_manifest_sha256"], expected_uid=expected_uid,
                                            maximum=MAX_MANIFEST_BYTES)
            try:
                manifest_bytes = _read_fd_bounded(manifest_fd, MAX_MANIFEST_BYTES)
            finally:
                os.close(manifest_fd)
            manifest_info = os.stat(receipt["closure_manifest_relative_path"], dir_fd=root_fd, follow_symlinks=False)
            if (not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_uid != expected_uid
                    or stat.S_IMODE(manifest_info.st_mode) != 0o444 or manifest_info.st_nlink != 1):
                raise InstallerReleaseError("release closure manifest must be immutable root-owned mode 0444")
            manifest = _parse_manifest(manifest_bytes, receipt["candidate_git_sha"])
            rows = _verify_file_rows(root_fd, manifest, expected_uid)
            _verify_complete_tree(root_fd, {row.relative_path for row in rows},
                                  receipt["closure_manifest_relative_path"], expected_uid)
            if not secrets.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), receipt["closure_manifest_sha256"]):
                raise InstallerReleaseError("release closure manifest bytes changed")
            baseline_tree = _verify_baseline(root_fd, rows, expected_uid)
            if not secrets.compare_digest(baseline_tree, receipt["baseline_tree_sha256"]):
                raise InstallerReleaseError("frozen baseline tree digest differs from deployment receipt")
            amendment_digest = _amendment_digest(rows)
            plan_id, plan_sha = _fixed_roles(rows, receipt["closure_manifest_relative_path"])
            return VerifiedInstallerReleaseReceipt(
                _SEAL, release_root=root, release_commit=receipt["candidate_git_sha"],
                deployment_receipt_sha256=receipt["_receipt_sha256"], root_device=root_info.st_dev,
                root_inode=root_info.st_ino,
                closure_manifest_relative_path=receipt["closure_manifest_relative_path"],
                closure_manifest_sha256=receipt["closure_manifest_sha256"],
                baseline_tag_object=BASELINE_TAG_OBJECT,
                baseline_commit=BASELINE_COMMIT, baseline_tree_sha256=baseline_tree,
                amendment_manifest_sha256=amendment_digest, files=tuple(rows),
                selected_plan_artifact_id=plan_id, selected_plan_sha256=plan_sha,
                root_fd=root_fd, expected_uid=expected_uid)
        except Exception:
            os.close(root_fd)
            raise

    @classmethod
    def _observe_actor(cls, release: VerifiedInstallerReleaseReceipt) -> RootActorObservation:
        if not hasattr(os, "pidfd_open"):
            raise BootstrapEnrollmentPending("Linux PIDFD support is required for stage-zero setup")
        by_role: dict[str, list[VerifiedReleaseFile]] = {}
        for entry in release.files:
            for role in entry.roles:
                by_role.setdefault(role, []).append(entry)
        launcher, interpreter = by_role["launcher"][0], by_role["interpreter"][0]
        expected_launcher = release.release_root / launcher.relative_path
        expected_interpreter = release.release_root / interpreter.relative_path
        if Path(sys.argv[0]).resolve() != expected_launcher:
            raise InstallerReleaseError("current process is not the installed root setup launcher")
        if Path(sys.executable).resolve() != expected_interpreter:
            raise InstallerReleaseError("current interpreter differs from the installed release")
        module_rows = [item for item in release.files if "module" in item.roles]
        modules: list[tuple[str, str, int, int, str]] = []
        for item in module_rows:
            module_name = _module_name(item.relative_path)
            module = sys.modules.get(module_name)
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
            expected_origin = str(release.release_root / item.relative_path)
            if module is not None and origin == expected_origin:
                modules.append((module_name, origin, item.device, item.inode, item.sha256))
        if not modules:
            raise InstallerReleaseError("no imported installer module matches the deployed release closure")
        pid = os.getpid()
        pidfd = os.pidfd_open(pid, 0)
        observation = RootActorObservation(
            _SEAL, pid=pid, uid=os.getuid(), gid=os.getgid(), start_time=_process_start_time(pid),
            launcher=(str(expected_launcher), launcher.device, launcher.inode, launcher.sha256),
            interpreter=(str(expected_interpreter), interpreter.device, interpreter.inode, interpreter.sha256),
            module_origins=tuple(modules), namespace_inodes=_namespace_inodes(pid),
            isolated_import_facts=_isolated_import_facts(), pidfd=pidfd)
        return observation


def _parse_manifest(raw: bytes, candidate: str) -> Mapping[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseError("installed release closure manifest is malformed") from None
    if not isinstance(value, dict) or set(value) != {"schema", "candidate_git_sha", "files"}:
        raise InstallerReleaseError("installed release closure manifest schema is invalid")
    if value["schema"] != 1 or value["candidate_git_sha"] != candidate:
        raise InstallerReleaseError("installed release closure manifest candidate differs")
    rows = value["files"]
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_FILES:
        raise InstallerReleaseError("installed release closure manifest file count is invalid")
    paths = [row.get("relative_path") if isinstance(row, dict) else None for row in rows]
    if any(not isinstance(p, str) for p in paths) or paths != sorted(paths) or len(set(paths)) != len(paths):
        raise InstallerReleaseError("installed release closure paths are not sorted and unique")
    return MappingProxyType(value)


def _verify_file_rows(root_fd: int, manifest: Mapping[str, Any], expected_uid: int) -> list[VerifiedReleaseFile]:
    result: list[VerifiedReleaseFile] = []
    for row in manifest["files"]:
        if not isinstance(row, dict) or set(row) != {"relative_path", "sha256", "size_bytes", "mode", "roles"}:
            raise InstallerReleaseError("installed release closure file row is malformed")
        path, digest, size, mode, roles = (row[k] for k in ("relative_path", "sha256", "size_bytes", "mode", "roles"))
        _validate_relative(path)
        if (not isinstance(digest, str) or not _SHA.fullmatch(digest)
                or type(size) is not int or size < 0 or size > MAX_FILE_BYTES
                or type(mode) is not int or mode < 0 or mode > 0o7777
                or not isinstance(roles, list) or not roles
                or any(not isinstance(role, str) or role not in ROLES for role in roles)
                or len(set(roles)) != len(roles) or roles != sorted(roles)):
            raise InstallerReleaseError("installed release closure file metadata is malformed")
        info = _hash_release_file(root_fd, path, digest, expected_uid=expected_uid, expected_size=size)
        if stat.S_IMODE(info.st_mode) != mode:
            raise InstallerReleaseError("installed release file mode differs from closure manifest")
        if path.startswith("plans/2026-10-09-v1/") and "baseline" not in roles:
            raise InstallerReleaseError("frozen baseline file lacks baseline role")
        if path.startswith("plans/amendments/") and "amendment" not in roles:
            raise InstallerReleaseError("append-only amendment lacks amendment role")
        if "amendment" in roles and not path.startswith("plans/amendments/"):
            raise InstallerReleaseError("amendment role is outside append-only amendments")
        _validate_fixed_layout_role(path, digest, size, roles)
        artifact_id = _artifact_id_for(path, roles)
        result.append(VerifiedReleaseFile(artifact_id, tuple(roles), path, digest, size,
                                          info.st_dev, info.st_ino, mode))
    return result


def _fixed_roles(rows: list[VerifiedReleaseFile], manifest_rel: str) -> tuple[str, str]:
    by_role: dict[str, list[VerifiedReleaseFile]] = {}
    for row in rows:
        for role in row.roles:
            by_role.setdefault(role, []).append(row)
    for role in ("launcher", "interpreter", "module", "template", "plan", "artifact-catalog", "baseline", "amendment"):
        if role not in by_role:
            raise InstallerReleaseError(f"installed release is missing required {role} closure")
    if len(by_role["launcher"]) != 1 or len(by_role["interpreter"]) != 1:
        raise InstallerReleaseError("installed release launcher/interpreter role is ambiguous")
    expected_fixed = {
        "launcher": ("installer-root-setup-launcher-v1", LAUNCHER_PATH),
        "interpreter": ("installer-root-setup-interpreter-v1", INTERPRETER_PATH),
        "plan": ("installer-root-setup-plan-v1", PLAN_PATH),
        "artifact-catalog": ("installer-protected-artifact-catalog-v1", ARTIFACT_CATALOG_PATH),
    }
    for role, (artifact_id, relative_path) in expected_fixed.items():
        role_rows = by_role[role]
        if len(role_rows) != 1 or (role_rows[0].artifact_id, role_rows[0].relative_path) != (artifact_id, relative_path):
            raise InstallerReleaseError(f"installed {role} role differs from the current fixed release layout")
    expected_templates = {artifact_id: (relative_path, digest, size)
                          for artifact_id, relative_path, digest, size in FIXED_TEMPLATES}
    actual_templates = {row.artifact_id: (row.relative_path, row.sha256, row.size_bytes)
                        for row in by_role["template"]}
    if actual_templates != expected_templates or len(by_role["template"]) != len(FIXED_TEMPLATES):
        raise InstallerReleaseError("installed templates differ from the current fixed artifact layout")
    if any("bootstrap-policy" in row.roles for row in rows):
        raise InstallerReleaseError("generated bootstrap policy cannot be a base release role")
    modules = [row for row in by_role["module"]]
    if not modules or any(row.artifact_id != _artifact_id_for(row.relative_path, ["module"])
                          for row in modules):
        raise InstallerReleaseError("installed module IDs differ from the finite source/import mapping")
    module_by_id = {row.artifact_id: row for row in modules}
    for artifact_id, relative_path, digest, size in REVIEWED_SOURCE_MODULES:
        row = module_by_id.get(artifact_id)
        if row is None or (row.relative_path, row.sha256, row.size_bytes) != (relative_path, digest, size):
            raise InstallerReleaseError("finite native target source module differs from its reviewed pin")
    plan = by_role["plan"]
    if len(plan) != 1:
        raise InstallerReleaseError("installed root setup plan is absent or ambiguous")
    if any(row.relative_path == manifest_rel for row in rows):
        raise InstallerReleaseError("closure manifest cannot include itself")
    for row in by_role["launcher"] + by_role["interpreter"]:
        if not row.mode & 0o111:
            raise InstallerReleaseError("installed launcher/interpreter is not executable")
    return plan[0].artifact_id, plan[0].sha256


def _verify_complete_tree(root_fd: int, listed: set[str], manifest_path: str, expected_uid: int) -> None:
    expected = listed | {manifest_path}
    found: set[str] = set()
    device = os.fstat(root_fd).st_dev

    def walk(directory_fd: int, prefix: str) -> None:
        scan_fd = os.dup(directory_fd)
        try:
            with os.scandir(scan_fd) as entries:
                for entry in entries:
                    name = entry.name
                    if name in {".", ".."} or "/" in name:
                        raise InstallerReleaseError("release directory contains an invalid entry name")
                    rel = f"{prefix}/{name}" if prefix else name
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(info.st_mode):
                        raise InstallerReleaseError("release tree contains a symlink")
                    if stat.S_ISDIR(info.st_mode):
                        if (info.st_uid != expected_uid or info.st_dev != device
                                or stat.S_IMODE(info.st_mode) & 0o222):
                            raise InstallerReleaseError("release tree directory custody is unsafe")
                        child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                           dir_fd=directory_fd)
                        try:
                            walk(child_fd, rel)
                        finally:
                            os.close(child_fd)
                    elif stat.S_ISREG(info.st_mode):
                        if info.st_uid != expected_uid or info.st_dev != device or info.st_nlink != 1:
                            raise InstallerReleaseError("release tree file custody is unsafe")
                        found.add(rel)
                    else:
                        raise InstallerReleaseError("release tree contains a special file")
        except OSError:
            raise InstallerReleaseError("release tree cannot be enumerated safely") from None
        finally:
            os.close(scan_fd)

    walk(root_fd, "")
    if found != expected:
        raise InstallerReleaseError("release manifest is not the complete installed file closure")


def _verify_baseline(root_fd: int, rows: list[VerifiedReleaseFile], expected_uid: int) -> str:
    prefix = "plans/2026-10-09-v1/"
    baseline = {row.relative_path[len(prefix):]: row.sha256 for row in rows
                if row.relative_path.startswith(prefix)}
    if "hashes.json" not in baseline:
        raise InstallerReleaseError("frozen baseline hashes manifest is missing")
    row = next(item for item in rows if item.relative_path == prefix + "hashes.json")
    if "baseline" not in row.roles:
        raise InstallerReleaseError("frozen baseline manifest lacks baseline role")
    fd = _open_verified_fd(root_fd, row.relative_path, row.sha256, expected_uid=expected_uid,
                           expected_size=row.size_bytes, maximum=8 * 1024 * 1024)
    try:
        hashes = _parse_json_fd(fd, 8 * 1024 * 1024)
    finally:
        os.close(fd)
    if (not isinstance(hashes, dict) or hashes.get("schema_version") != 1
            or hashes.get("algorithm") != "sha256"
            or hashes.get("baseline_tag") != "hermes-installer-plan-2026-10-09-v1"
            or not isinstance(hashes.get("files"), dict)):
        raise InstallerReleaseError("frozen baseline hashes.json does not match the protected tag")
    if not set(hashes["files"]).issubset(baseline):
        raise InstallerReleaseError("frozen baseline snapshot coverage is incomplete")
    for repo_path, digest in hashes["files"].items():
        if not _safe_relative(repo_path) or not isinstance(digest, str) or not _SHA.fullmatch(digest):
            raise InstallerReleaseError("frozen baseline snapshot row is malformed")
        entry = baseline.get(repo_path)
        if entry != digest:
            raise InstallerReleaseError("release baseline bytes disagree with frozen hashes.json")
    tree = hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode("utf-8")).hexdigest()
    return tree


def _amendment_digest(rows: list[VerifiedReleaseFile]) -> str:
    selected = {row.relative_path: row.sha256 for row in rows if "amendment" in row.roles}
    if not selected:
        raise InstallerReleaseError("installed release has no reviewed amendment closure")
    return hashlib.sha256(json.dumps(selected, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=False).encode("utf-8")).hexdigest()


def _artifact_id_for(path: str, roles: list[str]) -> str:
    if "launcher" in roles:
        return "installer-root-setup-launcher-v1"
    if "interpreter" in roles:
        return "installer-root-setup-interpreter-v1"
    if "template" in roles:
        for artifact_id, relative_path, _digest, _size in FIXED_TEMPLATES:
            if path == relative_path:
                return artifact_id
    if "plan" in roles:
        return "installer-root-setup-plan-v1"
    if "artifact-catalog" in roles and path == ARTIFACT_CATALOG_PATH:
        return "installer-protected-artifact-catalog-v1"
    if "module" in roles:
        for artifact_id, relative_path, _digest, _size in REVIEWED_SOURCE_MODULES:
            if path == relative_path:
                return artifact_id
        return "installer-module:" + _module_name(path)
    return "release-file:" + hashlib.sha256(path.encode("utf-8")).hexdigest()[:32]


def _validate_fixed_layout_role(path: str, digest: str, size: int, roles: list[str]) -> None:
    fixed_paths = {
        LAUNCHER_PATH: ("launcher", "installer-root-setup-launcher-v1"),
        INTERPRETER_PATH: ("interpreter", "installer-root-setup-interpreter-v1"),
        PLAN_PATH: ("plan", "installer-root-setup-plan-v1"),
        ARTIFACT_CATALOG_PATH: ("artifact-catalog", "installer-protected-artifact-catalog-v1"),
    }
    fixed_templates = {relative_path: (artifact_id, expected_digest, expected_size)
                       for artifact_id, relative_path, expected_digest, expected_size in FIXED_TEMPLATES}
    expected_fixed_role = fixed_paths.get(path)
    if expected_fixed_role is not None and roles != [expected_fixed_role[0]]:
        raise InstallerReleaseError("fixed release artifact must carry only its exact role")
    role_paths = {role: relative_path for relative_path, (role, _artifact_id) in fixed_paths.items()}
    for role, expected_path in role_paths.items():
        if role in roles and path != expected_path:
            raise InstallerReleaseError(f"installed {role} role path differs from the fixed release layout")
    if path in fixed_templates and roles != ["template"]:
        raise InstallerReleaseError("fixed release template must carry only its template role")
    if "template" in roles and roles != ["template"]:
        raise InstallerReleaseError("template closure files must carry only the template role")
    if path.startswith("templates/") and path not in fixed_templates:
        raise InstallerReleaseError("release contains an unrecognized installed template path")
    if path.startswith("lib/python/") and roles != ["module"]:
        raise InstallerReleaseError("lib/python release files must have the exact module role")
    if "module" in roles and not (path.startswith("lib/python/")
                                  or path in {item[1] for item in REVIEWED_SOURCE_MODULES}):
        raise InstallerReleaseError("module role is outside the finite source/import closure")
    if path.startswith("plans/2026-10-09-v1/") and roles != ["baseline"]:
        raise InstallerReleaseError("frozen baseline files must carry only their baseline role")
    if "baseline" in roles and not path.startswith("plans/2026-10-09-v1/"):
        raise InstallerReleaseError("baseline role is outside the frozen baseline tree")
    if path.startswith("plans/amendments/") and roles != ["amendment"]:
        raise InstallerReleaseError("append-only amendment source files must carry only their amendment role")
    if expected_fixed_role is not None and _artifact_id_for(path, roles) != expected_fixed_role[1]:
        raise InstallerReleaseError("fixed release artifact ID differs from its exact path role")
    if roles == ["template"]:
        if not any(path == item[1] and digest == item[2] and size == item[3]
                   for item in FIXED_TEMPLATES):
            raise InstallerReleaseError("installed template bytes differ from their exact protected role pin")
    if "module" in roles:
        _module_name(path)
    if "bootstrap-policy" in roles:
        raise InstallerReleaseError("generated bootstrap policy is not part of the deployed base release")


def _read_fixed_file(path: Path, maximum: int, expected_uid: int, *, required_mode: int | None = None) -> tuple[bytes, os.stat_result]:
    if path != DEPLOYMENT_RECEIPT_PATH:
        raise InstallerReleaseError("deployment receipt path override is forbidden")
    try:
        _verify_parents(path.parent, expected_uid)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseError("installed release deployment receipt is unavailable") from None
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_nlink != 1
                or before.st_size > maximum or stat.S_IMODE(before.st_mode) != required_mode):
            raise InstallerReleaseError("installed release deployment receipt custody is unsafe")
        raw = _read_fd_bounded(fd, maximum)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise InstallerReleaseError("installed release deployment receipt changed while reading")
        return raw, before
    finally:
        os.close(fd)


def _read_fd_bounded(fd: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    total = 0
    os.lseek(fd, 0, os.SEEK_SET)
    while True:
        block = os.read(fd, min(65536, maximum - total + 1))
        if not block:
            break
        chunks.append(block); total += len(block)
        if total > maximum:
            raise InstallerReleaseError("installed release metadata exceeds byte limit")
    return b"".join(chunks)


def _verify_parents(path: Path, expected_uid: int) -> None:
    cursor = Path(path.anchor)
    for part in path.parts[1:]:
        cursor /= part
        info = os.lstat(cursor)
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != expected_uid or stat.S_IMODE(info.st_mode) & 0o022):
            raise InstallerReleaseError("deployment receipt parent directory custody is unsafe")


def _hash_release_file(root_fd: int, relative: str, expected: str, *, expected_uid: int,
                       expected_size: int | None = None) -> os.stat_result:
    fd = _open_verified_fd(root_fd, relative, expected, expected_uid=expected_uid,
                           expected_size=expected_size, maximum=MAX_FILE_BYTES)
    try:
        return os.fstat(fd)
    finally:
        os.close(fd)


def _open_verified_fd(root_fd: int, relative: str, expected: str, *, expected_uid: int,
                      expected_size: int | None = None, maximum: int = MAX_FILE_BYTES) -> int:
    _validate_relative(relative)
    if not _SHA.fullmatch(expected):
        raise InstallerReleaseError("deployed release digest is malformed")
    root_info = os.fstat(root_fd)
    parent = os.dup(root_fd)
    try:
        parts = relative.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != expected_uid
                    or info.st_dev != root_info.st_dev or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                raise InstallerReleaseError("deployed release parent directory is unsafe")
            os.close(parent); parent = child
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError:
        raise InstallerReleaseError("deployed release path cannot be opened without following links") from None
    finally:
        os.close(parent)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or before.st_nlink != 1
                or before.st_dev != root_info.st_dev or stat.S_IMODE(before.st_mode) & 0o022
                or before.st_size > maximum or (expected_size is not None and before.st_size != expected_size)):
            raise InstallerReleaseError("deployed release file custody or size is unsafe")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
                or not secrets.compare_digest(digest.hexdigest(), expected)):
            raise InstallerReleaseError("deployed release file bytes or inode differ from receipt")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except Exception:
        os.close(fd)
        raise


def _verify_actor_path(path: Path, digest: str, device: int, inode: int) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        raise InstallerReleaseError("observed actor executable/module cannot be opened safely") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022
                or info.st_dev != device or info.st_ino != inode):
            raise InstallerReleaseError("observed actor executable/module identity changed")
        digestor = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digestor.update(chunk)
        if digestor.hexdigest() != digest:
            raise InstallerReleaseError("observed actor executable/module bytes changed")
    finally:
        os.close(fd)


def _module_name(relative: str) -> str:
    source_names = {
        "src/hermes_installer/components/native_plugins.py": "hermes_installer.components.native_plugins",
        "src/hermes_installer/components/public_registries.py": "hermes_installer.components.public_registries",
        "src/hermes_installer/native_invocations.py": "hermes_installer.native_invocations",
        "src/hermes_installer/native_boundary.py": "hermes_installer.native_boundary",
        "src/hermes_installer/authority/native_source_definitions.py":
            "hermes_installer.authority.native_source_definitions",
    }
    if relative in source_names:
        return source_names[relative]
    prefix = "lib/python/"
    if not relative.startswith(prefix) or not relative.endswith(".py"):
        raise InstallerReleaseError("installer module closure path is outside the fixed lib/python tree")
    subpath = relative[len(prefix):-3]
    if subpath == "__init__":
        raise InstallerReleaseError("installer module closure has a root package initializer")
    if subpath.endswith("/__init__"):
        subpath = subpath[:-9]
    result = subpath.replace("/", ".")
    if not result or any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part)
                         for part in result.split(".")):
        raise InstallerReleaseError("installer module closure name is malformed")
    return result


def _isolated_import_facts() -> tuple[str, ...]:
    if (os.environ.get("PYTHONPATH") or os.environ.get("PYTHONHOME")
            or not sys.flags.no_user_site or sys.flags.isolated == 0
            or any(not isinstance(entry, str) or not entry or not Path(entry).is_absolute() for entry in sys.path)):
        raise InstallerReleaseError("root setup Python import environment is not isolated")
    paths = tuple(os.path.realpath(entry) for entry in sys.path)
    for entry in paths:
        _verify_import_search_path(Path(entry))
    if os.path.realpath(os.getcwd()) in paths:
        raise InstallerReleaseError("root setup current directory is an import path")
    return paths


def _namespace_inodes(pid: int) -> tuple[tuple[str, int], ...]:
    values = []
    try:
        for name in ("mnt", "pid", "user", "net", "ipc", "uts"):
            values.append((name, os.stat(f"/proc/{pid}/ns/{name}").st_ino))
    except OSError:
        raise BootstrapEnrollmentPending("root actor namespaces cannot be observed") from None
    return tuple(values)


def _parse_json_fd(fd: int, maximum: int) -> Any:
    try:
        return json.loads(_read_fd_bounded(fd, maximum).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise InstallerReleaseError("protected JSON artifact is malformed") from None


def _validate_relative(value: Any) -> None:
    if (not isinstance(value, str) or not 0 < len(value) <= 1024 or value.startswith("/")
            or "\\" in value or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise InstallerReleaseError("deployed release path is not a portable normalized relative path")


def _safe_relative(value: Any) -> bool:
    try:
        _validate_relative(value)
        return True
    except InstallerReleaseError:
        return False


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _linux() -> bool:
    return sys.platform.startswith("linux") and Path("/proc/self/status").exists()
