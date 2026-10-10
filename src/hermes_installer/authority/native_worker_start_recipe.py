"""Finite source-owned recipe for the pinned native Hermes worker.

This module describes the official Hermes CLI process which the root process
custodian starts.  It is not a process launcher and its recipe is not evidence
that a process is loaded, ready, or authorized for effects.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from hermes_installer.hermes_source import (
    HERMES_SOURCE_ARTIFACT_ID,
    HERMES_SOURCE_BYTES,
    HERMES_SOURCE_COMMIT,
    HERMES_SOURCE_SHA256,
    HERMES_SOURCE_TREE_MANIFEST_SHA256,
    VerifiedHermesSource,
)
from .pm_runtime import VerifiedPMRuntimeProjection


RECIPE_ID = "native-owner-overlay-worker-v1"
SOURCE_PRODUCER_ID = "installer-native-hermes-worker-start-adapter-v183"
ARGV_SUFFIX = ("-m", "hermes_cli.main", "chat", "--query-file", "-", "--oneshot", "--quiet")
LOADER_CHANNEL_FD_NAME = "hermes-loader-progress"
LOADER_PHASES = ("entrypoint-imported", "actions-registered", "ready")
ENVIRONMENT_RECIPE_ID = "root-selected-hermes-private-worker-environment-v1"
ENVIRONMENT_BINDING_NAMES = (
    "HOME", "HERMES_HOME", "LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES",
)

# These bytes are from the exact Git tree named above.  The source archive
# verifier proves the tree identity; these per-file hashes make the CLI/parser
# lifecycle consumed by this adapter explicit and reviewable.
_HERMES_MEMBERS = (
    ("pyproject.toml", "cadde2f6a92574d292103f43abf66408b1d841cd9ea332ca7f3e3dfc5dcc87fd", 47_942),
    ("hermes_cli/main.py", "a6293934e0ef99849d7a2f3c040256c2466f6fc0382b876bf750f8bd8e6cb912", 151_586),
    ("hermes_cli/plugins.py", "a618a69581355e5fe56cb3d2250fc02647315359aae7fa0e6bd4dccc4ed3d3ad", 129_098),
    ("hermes_cli/_parser.py", "75fa3070d9cdcbeaa3fc1424e9c3dba06a403b9d43c74aaccc3b82829edf366c", 24_553),
    ("plugins/plugin_loader.py", "b4d4e730df8d8163e45d4fb9dd305f61a1c6fb724ed4c3c7768eac880abba320", 12_129),
)


class NativeWorkerRecipeUnavailable(PermissionError):
    """The selected Hermes source/runtime does not prove the fixed start API."""


@dataclass(frozen=True, slots=True)
class NativeWorkerSourceMember:
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeHermesWorkerStartRecipe:
    """Typed root-only projection; deliberately carries no mutable authority."""

    recipe_id: str
    source_artifact_id: str
    source_commit: str
    source_archive_sha256: str
    source_tree_manifest_sha256: str
    source_members: tuple[NativeWorkerSourceMember, ...]
    pm_runtime_receipt_handle: str
    pm_runtime_closure_sha256: str
    pm_python_member_sha256: str
    installer_member_receipt_handles: tuple[str, ...]
    installer_members: tuple[NativeWorkerSourceMember, ...]
    worker_member_receipt_handles: tuple[str, ...]
    worker_members: tuple[NativeWorkerSourceMember, ...]
    argv_suffix: tuple[str, ...]
    environment_recipe_id: str
    environment_binding_names: tuple[str, ...]
    loader_channel_fd_name: str
    loader_phases: tuple[str, ...]
    recipe_sha256: str
    _issuer: object = field(repr=False, compare=False)
    receipt_handle: str = field(repr=False)

    def public_projection(self) -> dict[str, Any]:
        """Return the non-secret fixed recipe facts, never paths or proof claims."""
        return {
            "schema": 1,
            "recipe_id": self.recipe_id,
            "source_artifact_id": self.source_artifact_id,
            "source_commit": self.source_commit,
            "source_archive_sha256": self.source_archive_sha256,
            "source_tree_manifest_sha256": self.source_tree_manifest_sha256,
            "source_members": [
                {"relative_path": row.relative_path, "sha256": row.sha256,
                 "size_bytes": row.size_bytes} for row in self.source_members
            ],
            "pm_runtime_closure_sha256": self.pm_runtime_closure_sha256,
            "pm_python_member_sha256": self.pm_python_member_sha256,
            "installer_members": [
                {"relative_path": row.relative_path, "sha256": row.sha256,
                 "size_bytes": row.size_bytes} for row in self.installer_members
            ],
            "worker_members": [
                {"relative_path": row.relative_path, "sha256": row.sha256,
                 "size_bytes": row.size_bytes} for row in self.worker_members
            ],
            "argv_suffix": list(self.argv_suffix),
            "environment_recipe_id": self.environment_recipe_id,
            "environment_binding_names": list(self.environment_binding_names),
            "loader_channel_fd_name": self.loader_channel_fd_name,
            "loader_phases": list(self.loader_phases),
            "recipe_sha256": self.recipe_sha256,
        }


_WORKER_MEMBER_PINS = {
    "src/hermes_installer/native_invocations.py": "78a3452289df5b7343e5c650ea8620d51b3aa1056e2eedea02cc3a0bff7b8226",
    "src/hermes_installer/native_boundary.py": "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb",
}
_INSTALLER_MEMBER_PINS = {
    "lib/python/hermes_installer/native_plugin_loader.py":
        ("installer-module:hermes_installer.native_plugin_loader",
         "807e44082ee51b212e1a7bebcdc858dfffe09772820542f012a1956542ecac3d", 115_924),
    "lib/python/hermes_installer/native_boundary_patch.py":
        ("installer-module:hermes_installer.native_boundary_patch",
         "fe1bfca7de02408c27891f0d6830da938ee7f18c84ee6b34bdd766f8e1645159", 22_888),
    "lib/python/hermes_installer/native_plugin_bindings.py":
        ("installer-module:hermes_installer.native_plugin_bindings",
         "7cdb0f08ed59c8fc08f1eb7cc892d0059cd6bd81a4da1a94efa6e7b5218d36cc", 16_387),
    "lib/python/hermes_installer/registry/resource_backends.py":
        ("installer-module:hermes_installer.registry.resource_backends",
         "e59813aa36754a0e08fece9c9c2a83ec9c21a6807935a6c83f7b09cca6792414", 27_026),
}
_PRODUCER_MEMBER = (
    "lib/python/hermes_installer/authority/native_worker_start_recipe.py",
    "installer-module:hermes_installer.authority.native_worker_start_recipe",
)


def _read_source_member(root: Path, relative: str) -> bytes:
    """Read a fixed regular source member without following its final symlink."""
    parts = relative.split("/")
    if not parts or any(part in {"", ".", ".."} for part in parts):
        raise NativeWorkerRecipeUnavailable("pinned Hermes source member path is invalid")
    fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
            os.close(fd)
            fd = next_fd
        leaf = os.open(parts[-1], os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                       | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
        try:
            info = os.fstat(leaf)
            if not stat.S_ISREG(info.st_mode):
                raise NativeWorkerRecipeUnavailable("pinned Hermes source member is not a regular file")
            chunks = []
            while True:
                chunk = os.read(leaf, 1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            os.close(leaf)
    except OSError:
        raise NativeWorkerRecipeUnavailable("pinned Hermes source member is unavailable") from None
    finally:
        os.close(fd)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def audit_pinned_hermes_source(source: VerifiedHermesSource) -> tuple[NativeWorkerSourceMember, ...]:
    """Recheck the source owner's exact CLI, registration, and loader members."""
    if type(source) is not VerifiedHermesSource:
        raise NativeWorkerRecipeUnavailable("Hermes source resolver returned an unverified source type")
    if (source.artifact_id != HERMES_SOURCE_ARTIFACT_ID
            or source.archive_sha256 != HERMES_SOURCE_SHA256
            or source.archive_size_bytes != HERMES_SOURCE_BYTES
            or source.commit != HERMES_SOURCE_COMMIT
            or source.archive_tree_manifest_sha256 != HERMES_SOURCE_TREE_MANIFEST_SHA256):
        raise NativeWorkerRecipeUnavailable("Hermes source identity differs from the enrolled official snapshot")
    rows = []
    contents = {}
    for relative, expected_sha, expected_size in _HERMES_MEMBERS:
        data = _read_source_member(source.tree_path, relative)
        if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha:
            raise NativeWorkerRecipeUnavailable("pinned upstream Hermes start/registration member differs")
        rows.append(NativeWorkerSourceMember(relative, expected_sha, expected_size))
        contents[relative] = data
    if (b'hermes = "hermes_cli.main:main"' not in contents["pyproject.toml"]
            or b'--query-file' not in contents["hermes_cli/_parser.py"]
            or b'--oneshot' not in contents["hermes_cli/_parser.py"]
            or b'def _read_query_file' not in contents["hermes_cli/main.py"]
            or b'def cmd_chat' not in contents["hermes_cli/main.py"]
            or b"def register_tool" not in contents["hermes_cli/plugins.py"]
            or b"def _discover_and_load_inner" not in contents["hermes_cli/plugins.py"]
            or b"register(ctx)" not in contents["plugins/plugin_loader.py"]):
        raise NativeWorkerRecipeUnavailable("upstream official CLI or plugin registration lifecycle changed")
    return tuple(rows)


class RootNativeHermesWorkerStartRecipeSource:
    """Compile the one permitted native worker recipe from held root evidence.

    Source/runtime projections and release-member receipts are obtained from
    the live setup binding.  A caller cannot supply argv, paths, environment,
    source hashes, or role IDs.
    """

    def __init__(self, installation_binding: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if type(installation_binding) is not RootSelectedInstallationBinding:
            raise NativeWorkerRecipeUnavailable("a current root selected-installation binding is required")
        self._binding = installation_binding
        self._issuer_token = object()
        self._issued: dict[str, RootNativeHermesWorkerStartRecipe] = {}

    def compile(self) -> RootNativeHermesWorkerStartRecipe:
        """Issue one typed source recipe after current custody revalidation."""
        recipe = self._compile()
        self._issued[recipe.receipt_handle] = recipe
        return recipe

    def verify_current(self, recipe: RootNativeHermesWorkerStartRecipe) -> RootNativeHermesWorkerStartRecipe:
        """Require producer membership and re-resolve all held source inputs."""
        if (type(recipe) is not RootNativeHermesWorkerStartRecipe
                or recipe._issuer is not self._issuer_token
                or self._issued.get(recipe.receipt_handle) is not recipe):
            raise NativeWorkerRecipeUnavailable("worker recipe receipt is not a current issuer member")
        current = self._compile()
        if (current.recipe_sha256 != recipe.recipe_sha256
                or current.installer_member_receipt_handles != recipe.installer_member_receipt_handles
                or current.worker_member_receipt_handles != recipe.worker_member_receipt_handles):
            self._issued.pop(recipe.receipt_handle, None)
            raise NativeWorkerRecipeUnavailable("worker recipe source or runtime custody changed")
        return recipe

    def _compile(self) -> RootNativeHermesWorkerStartRecipe:
        from .bootstrap_runtime_factory import RootPreparedReleaseMemberReceipt

        try:
            source = self._binding.resolve_current_hermes_source()
            runtime = self._binding.resolve_current_pm_runtime_projection()
            worker_receipts = self._binding.resolve_prepared_worker_role_module_receipts()
            installer_provider = getattr(
                self._binding, "resolve_prepared_native_worker_start_source_module_receipts", None)
            if not callable(installer_provider):
                raise NativeWorkerRecipeUnavailable(
                    "held native worker start installer-source resolver is not installed")
            installer_receipts = installer_provider()
        except NativeWorkerRecipeUnavailable:
            raise
        except Exception:
            raise NativeWorkerRecipeUnavailable("current held Hermes source, PM runtime, or worker role members are unavailable") from None
        if type(runtime) is not VerifiedPMRuntimeProjection:
            raise NativeWorkerRecipeUnavailable("PM runtime resolver returned an unheld projection")
        if (runtime.selection.version_info != (3, 14, 7)
                or runtime.selection.implementation != "cpython"
                or runtime.selection.machine not in {"aarch64", "arm64"}
                or runtime.executable_member.sha256 != "566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001"):
            raise NativeWorkerRecipeUnavailable("official PM Python 3.14 ARM64 executable custody is unavailable")
        if not isinstance(worker_receipts, tuple) or len(worker_receipts) != len(_WORKER_MEMBER_PINS):
            raise NativeWorkerRecipeUnavailable("the exact two native worker role members are unavailable")
        retained: list[tuple[Any, NativeWorkerSourceMember]] = []
        seen: set[str] = set()
        for receipt in worker_receipts:
            if type(receipt) is not RootPreparedReleaseMemberReceipt:
                raise NativeWorkerRecipeUnavailable("worker source resolver returned a non-held receipt")
            expected_sha = _WORKER_MEMBER_PINS.get(receipt.relative_path)
            if (expected_sha is None or receipt.relative_path in seen or receipt.sha256 != expected_sha):
                raise NativeWorkerRecipeUnavailable("worker role source membership differs from the fixed native role set")
            data = receipt.read_current()
            if len(data) != receipt.size_bytes or hashlib.sha256(data).hexdigest() != expected_sha:
                raise NativeWorkerRecipeUnavailable("worker role source bytes differ from their held receipt")
            seen.add(receipt.relative_path)
            retained.append((receipt, NativeWorkerSourceMember(
                receipt.relative_path, expected_sha, len(data))))
        if seen != set(_WORKER_MEMBER_PINS):
            raise NativeWorkerRecipeUnavailable("the exact native worker role source set is incomplete")
        if (not isinstance(installer_receipts, tuple)
                or len(installer_receipts) != len(_INSTALLER_MEMBER_PINS) + 1):
            raise NativeWorkerRecipeUnavailable("the exact root native worker start source closure is unavailable")
        from .bootstrap_runtime_factory import RootInstalledReleaseMemberReceipt
        installer_rows: list[tuple[Any, NativeWorkerSourceMember]] = []
        installer_seen: set[str] = set()
        for receipt in installer_receipts:
            if type(receipt) is not RootInstalledReleaseMemberReceipt:
                raise NativeWorkerRecipeUnavailable("installer source resolver returned an unheld module receipt")
            path = receipt.relative_path
            expected = _INSTALLER_MEMBER_PINS.get(path)
            if path == _PRODUCER_MEMBER[0]:
                expected_id = _PRODUCER_MEMBER[1]
                expected_sha = receipt.sha256  # self hash is supplied by the held release receipt
                expected_size = receipt.size_bytes
            elif expected is not None:
                expected_id, expected_sha, expected_size = expected
            else:
                raise NativeWorkerRecipeUnavailable("installer source resolver returned an unexpected module")
            if (path in installer_seen or receipt.artifact_id != expected_id
                    or receipt.role != "module" or receipt.sha256 != expected_sha
                    or receipt.size_bytes != expected_size or len(expected_sha) != 64
                    or expected_size <= 0):
                raise NativeWorkerRecipeUnavailable("installer module receipt differs from the reviewed fixed closure")
            data = receipt.read_current()
            if len(data) != expected_size or hashlib.sha256(data).hexdigest() != expected_sha:
                raise NativeWorkerRecipeUnavailable("installer module bytes differ from their held release receipts")
            installer_seen.add(path)
            installer_rows.append((receipt, NativeWorkerSourceMember(path, expected_sha, expected_size)))
        if installer_seen != {*_INSTALLER_MEMBER_PINS, _PRODUCER_MEMBER[0]}:
            raise NativeWorkerRecipeUnavailable("installer module receipt closure is incomplete")
        source_rows = audit_pinned_hermes_source(source)
        if (not runtime.selection.receipt_handle or not runtime.base_closure_sha256
                or runtime.executable_member.fd is None):
            raise NativeWorkerRecipeUnavailable("held PM interpreter closure is incomplete")
        payload = {
            "schema": 1,
            "recipe_id": RECIPE_ID,
            "source_artifact_id": source.artifact_id,
            "source_commit": source.commit,
            "source_archive_sha256": source.archive_sha256,
            "source_tree_manifest_sha256": source.archive_tree_manifest_sha256,
            "source_members": [{"relative_path": row.relative_path, "sha256": row.sha256,
                                "size_bytes": row.size_bytes} for row in source_rows],
            "pm_runtime_closure_sha256": runtime.base_closure_sha256,
            "pm_python_member_sha256": runtime.executable_member.sha256,
            "installer_members": [{"relative_path": row.relative_path, "sha256": row.sha256,
                                   "size_bytes": row.size_bytes} for _, row in installer_rows],
            "worker_members": [{"relative_path": row.relative_path, "sha256": row.sha256,
                                "size_bytes": row.size_bytes} for _, row in retained],
            "argv_suffix": list(ARGV_SUFFIX),
            "environment_recipe_id": ENVIRONMENT_RECIPE_ID,
            "environment_binding_names": list(ENVIRONMENT_BINDING_NAMES),
            "loader_channel_fd_name": LOADER_CHANNEL_FD_NAME,
            "loader_phases": list(LOADER_PHASES),
        }
        digest = hashlib.sha256(_canonical(payload)).hexdigest()
        return RootNativeHermesWorkerStartRecipe(
            recipe_id=RECIPE_ID,
            source_artifact_id=source.artifact_id,
            source_commit=source.commit,
            source_archive_sha256=source.archive_sha256,
            source_tree_manifest_sha256=source.archive_tree_manifest_sha256,
            source_members=tuple(source_rows),
            pm_runtime_receipt_handle=runtime.selection.receipt_handle,
            pm_runtime_closure_sha256=runtime.base_closure_sha256,
            pm_python_member_sha256=runtime.executable_member.sha256,
            installer_member_receipt_handles=tuple(receipt.receipt_handle for receipt, _ in installer_rows),
            installer_members=tuple(row for _, row in installer_rows),
            worker_member_receipt_handles=tuple(receipt.receipt_handle for receipt, _ in retained),
            worker_members=tuple(row for _, row in retained),
            argv_suffix=ARGV_SUFFIX,
            environment_recipe_id=ENVIRONMENT_RECIPE_ID,
            environment_binding_names=ENVIRONMENT_BINDING_NAMES,
            loader_channel_fd_name=LOADER_CHANNEL_FD_NAME,
            loader_phases=LOADER_PHASES,
            recipe_sha256=digest,
            _issuer=self._issuer_token,
            receipt_handle=secrets.token_urlsafe(36),
        )


__all__ = [
    "ENVIRONMENT_BINDING_NAMES", "ENVIRONMENT_RECIPE_ID", "LOADER_CHANNEL_FD_NAME",
    "LOADER_PHASES", "NativeWorkerRecipeUnavailable",
    "NativeWorkerSourceMember", "RECIPE_ID", "RootNativeHermesWorkerStartRecipe",
    "RootNativeHermesWorkerStartRecipeSource", "audit_pinned_hermes_source",
]
