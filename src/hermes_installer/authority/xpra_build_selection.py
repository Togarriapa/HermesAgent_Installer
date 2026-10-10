"""Root-selected inputs for the fixed Xpra source transform build.

This module is deliberately separate from worker-selected native builds.  It
binds the setup transaction to the exact Xpra source, the selected official PM
Python runtime, and the installed transform module.  It never accepts paths,
argv, or a build profile from the setup caller.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import re
import secrets
import stat
import sys
import tempfile
import time
from types import SimpleNamespace
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from .bootstrap_enrollment import RootLocalCatalogArtifactFetcher
from .pm_runtime import VerifiedPMRuntimeSelection

SOURCE_ARTIFACT_ID = "xpra-source-521b0d2e762c770b2641d258b93d23575fa9cbea"
SOURCE_SHA256 = "20b55586457df5aed8453b0d1b446e4dd954f2027d814f1eb7c0a96227ef1c80"
SOURCE_MANIFEST_SHA256 = "108ab4e20dc62160fa3617f1622054b8b1ff3784ec2916f4a0e051aa961cec63"
SOURCE_COMMIT = "521b0d2e762c770b2641d258b93d23575fa9cbea"
TRANSFORM_MODULE_ID = "installer-xpra-root-xauthority-transform-module-v1"
TRANSFORM_MODULE_SHA256 = "3342afa5311fef5008a35317a526c75b3d1531d21e92d1f8aae87dba38b0a7d1"
TRANSFORM_MODULE_BYTES = 59_621
BUILD_TARGET = "xpra-root-xauthority-transform:start"
BUILD_OPERATION_ID = "xpra-root-xauthority-transform-v1"
_SELECTION_SEAL = object()
_SOURCE_SEAL = object()
_SETUP_GRANT_SEAL = object()


class XpraBuildSelectionDenied(PermissionError):
    """A source, PM, release, setup, or build-service selection is stale."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _full_manifest_sha256(tree_files: tuple[Any, ...]) -> str:
    rows = []
    seen: set[str] = set()
    for row in sorted(tree_files, key=lambda item: item.path):
        if (not isinstance(row.path, str) or row.path in seen
                or type(row.size_bytes) is not int or row.size_bytes < 0
                or type(row.executable) is not bool
                or not isinstance(row.sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", row.sha256)):
            raise XpraBuildSelectionDenied("Xpra source tree manifest is malformed")
        seen.add(row.path)
        kind = getattr(row, "kind", "file")
        if kind not in {"file", "symlink"}:
            raise XpraBuildSelectionDenied("Xpra source tree contains an unsupported member kind")
        item = {"path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes,
                "executable": row.executable, "kind": kind}
        link_target = getattr(row, "link_target", None)
        if kind == "symlink":
            if not isinstance(link_target, str):
                raise XpraBuildSelectionDenied("Xpra source symlink lacks its reviewed target")
            item["link_target"] = link_target
        elif link_target is not None:
            raise XpraBuildSelectionDenied("regular Xpra source member has a symlink target")
        rows.append(item)
    return hashlib.sha256(_canonical(rows)).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RootXpraSourceReceipt:
    """Root-retained source tree from the fixed source artifact receipt."""

    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    artifact_id: str
    archive_sha256: str
    archive_size_bytes: int
    full_manifest_sha256: str
    tree: Any = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SOURCE_SEAL:
            raise TypeError("Xpra source receipts are issued only by the root setup producer")


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedXpraBuildSelection:
    """Sealed, one-use selection joining every fixed Xpra build input."""

    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    build_service_enrollment_id: str
    build_service_generation: str
    source_artifact_id: str
    source_sha256: str
    source_receipt_handle: str
    source_manifest_sha256: str
    compiled_source_manifest_sha256: str
    pm_runtime_receipt_handle: str
    builder_artifact_id: str
    builder_sha256: str
    toolchain_artifact_id: str
    toolchain_sha256: str
    output_root_id: str
    recipe_sha256: str
    controller_binding_handle: str
    expires_monotonic: float
    source: RootXpraSourceReceipt = field(repr=False, compare=False)
    pm_runtime: VerifiedPMRuntimeSelection = field(repr=False, compare=False)
    module_receipt: "RootXpraTransformModuleReceipt" = field(repr=False, compare=False)
    build_profile: Any = field(repr=False, compare=False)
    setup_build_subject: Any = field(repr=False, compare=False)
    output_root: Any = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)
    _producer_id: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SELECTION_SEAL:
            raise TypeError("Xpra build selections are issued only by the root producer")


@dataclass(frozen=True, slots=True, repr=False)
class RootXpraTransformModuleReceipt:
    """Root-owned receipt for the exact installed transform module bytes."""

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    release_commit: str
    deployment_receipt_sha256: str
    _session: Any = field(repr=False, compare=False)
    _device: int = field(repr=False, compare=False)
    _inode: int = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SOURCE_SEAL:
            raise TypeError("Xpra module receipts are issued only by the root setup producer")

    def read_current(self) -> bytes:
        session = self._session
        session._check_live()
        release, actor = session._factory._release, session._factory._actor
        release.verify_current()
        actor.verify_current(release)
        fd = release.open_file(self.artifact_id)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_size != self.size_bytes or info.st_dev != self._device
                    or info.st_ino != self._inode or info.st_mode & 0o222):
                raise XpraBuildSelectionDenied("installed Xpra module inode or mode changed")
            body = bytearray()
            while len(body) <= self.size_bytes:
                block = os.read(fd, min(65536, self.size_bytes + 1 - len(body)))
                if not block:
                    break
                body.extend(block)
            if len(body) != self.size_bytes or hashlib.sha256(body).hexdigest() != self.sha256:
                raise XpraBuildSelectionDenied("installed Xpra module bytes changed")
            return bytes(body)
        finally:
            os.close(fd)


@dataclass(frozen=True, slots=True, repr=False)
class RootXpraSetupBuildGrant:
    """One-use setup-only authorization for the fixed Xpra transformation.

    This is intentionally not an ``EffectAuthorization`` and cannot authorize
    a worker operation.  It is consumed only by the root setup build adapter.
    """

    grant_id: str
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    build_service_id: str
    build_service_generation: str
    target: str
    operation_id: str
    parameters_digest: str
    controller_binding_handle: str
    expires_monotonic: float
    _issuer_id: str = field(repr=False, compare=False)
    _signature: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SETUP_GRANT_SEAL:
            raise TypeError("Xpra setup build grants are issued by the root setup authority")


class RootXpraSetupBuildGrantIssuer:
    """Issue and consume the distinct, exact Xpra setup-build admission."""

    def __init__(self, producer: "RootXpraBuildSelectionProducer", *,
                 signing_key: bytes, monotonic: Callable[[], float] = time.monotonic):
        if (type(producer) is not RootXpraBuildSelectionProducer
                or os.geteuid() != 0 or not isinstance(signing_key, bytes)
                or len(signing_key) != 32):
            raise XpraBuildSelectionDenied("root Xpra setup grant issuer is unavailable")
        self.producer = producer
        self._key = bytes(signing_key)
        self.monotonic = monotonic
        self.issuer_id = secrets.token_urlsafe(24)
        self._issued: dict[str, RootXpraSetupBuildGrant] = {}
        self._spent: set[str] = set()

    def issue(self, selection: RootSelectedXpraBuildSelection) -> RootXpraSetupBuildGrant:
        selected = self.producer.consume(selection)
        body = {
            "grant_id": secrets.token_urlsafe(32),
            "selection_handle": selected.selection_handle,
            "setup_session_id": selected.setup_session_id,
            "transaction_handle": selected.transaction_handle,
            "prepared_generation_id": selected.prepared_generation_id,
            "prepared_generation_digest": selected.prepared_generation_digest,
            "build_service_id": selected.setup_build_subject.id,
            "build_service_generation": selected.setup_build_subject.generation,
            "target": BUILD_TARGET,
            "operation_id": BUILD_OPERATION_ID,
            "parameters_digest": hashlib.sha256(_canonical({})).hexdigest(),
            "controller_binding_handle": selected.controller_binding_handle,
            "expires_monotonic": min(selected.expires_monotonic, self.monotonic() + 30.0),
        }
        signature = hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()
        grant = RootXpraSetupBuildGrant(
            **body, _issuer_id=self.issuer_id, _signature=signature,
            _seal=_SETUP_GRANT_SEAL,
        )
        self._issued[grant.grant_id] = grant
        return grant

    def consume(self, grant: RootXpraSetupBuildGrant,
                selection: RootSelectedXpraBuildSelection) -> RootXpraSetupBuildGrant:
        if (type(grant) is not RootXpraSetupBuildGrant or grant._seal is not _SETUP_GRANT_SEAL
                or grant._issuer_id != self.issuer_id or self._issued.get(grant.grant_id) is not grant
                or grant.grant_id in self._spent or self.monotonic() >= grant.expires_monotonic
                or type(selection) is not RootSelectedXpraBuildSelection
                or grant.selection_handle != selection.selection_handle
                or grant.setup_session_id != selection.setup_session_id
                or grant.transaction_handle != selection.transaction_handle
                or grant.prepared_generation_id != selection.prepared_generation_id
                or grant.prepared_generation_digest != selection.prepared_generation_digest
                or grant.build_service_id != selection.setup_build_subject.id
                or grant.build_service_generation != selection.setup_build_subject.generation
                or grant.target != BUILD_TARGET or grant.operation_id != BUILD_OPERATION_ID
                or grant.parameters_digest != hashlib.sha256(_canonical({})).hexdigest()
                or grant.controller_binding_handle != selection.controller_binding_handle):
            raise XpraBuildSelectionDenied("setup build grant is stale, forged, mismatched, or already consumed")
        body = {name: getattr(grant, name) for name in (
            "grant_id", "selection_handle", "setup_session_id", "transaction_handle",
            "prepared_generation_id", "prepared_generation_digest", "build_service_id",
            "build_service_generation", "target", "operation_id", "parameters_digest",
            "controller_binding_handle", "expires_monotonic")}
        if not secrets.compare_digest(
                grant._signature, hmac.new(self._key, _canonical(body), hashlib.sha256).hexdigest()):
            raise XpraBuildSelectionDenied("setup build grant signature is invalid")
        # Reopen all source, PM, module, subject and controller selections before
        # spending the admission. The returned selection is the live same object.
        self.producer.revalidate(selection)
        self._spent.add(grant.grant_id)
        return grant

class RootXpraSetupBuildExecutor:
    """Stage selected inputs, run the fixed manager job, and publish its receipt."""

    def __init__(self, *, producer: "RootXpraBuildSelectionProducer",
                 grant_issuer: RootXpraSetupBuildGrantIssuer, launcher: Any,
                 store: Any, fact_inspector: Any, artifact_staging_root: Path,
                 monotonic: Callable[[], float] = time.monotonic):
        from .build_execution import ContentAddressedBuildStore
        if (os.geteuid() != 0 or type(producer) is not RootXpraBuildSelectionProducer
                or type(grant_issuer) is not RootXpraSetupBuildGrantIssuer
                or grant_issuer.producer is not producer
                or not callable(getattr(launcher, "run_selected_setup_build", None))
                or not callable(getattr(launcher, "bind_setup_build_grant_issuer", None))
                or type(store) is not ContentAddressedBuildStore or store.owner_uid != 0
                or not callable(getattr(fact_inspector, "inspect_build_output", None))
                or not isinstance(artifact_staging_root, Path)
                or not artifact_staging_root.is_absolute()):
            raise XpraBuildSelectionDenied("root Xpra setup build executor dependencies are incomplete")
        self.producer = producer
        self.grants = grant_issuer
        self.launcher = launcher
        self.launcher.bind_setup_build_grant_issuer(grant_issuer)
        self.store = store
        self.fact_inspector = fact_inspector
        self.staging_root = artifact_staging_root
        self.monotonic = monotonic

    def execute(self, selection: RootSelectedXpraBuildSelection,
                grant: RootXpraSetupBuildGrant, *, timeout: float = 300.0,
                cancelled: Callable[[], bool] = lambda: False) -> Any:
        from .build_execution import (
            BuildOutputSpec, ManagedBuildResult, ResolvedBuildInputs,
        )
        if (isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= 300 or not callable(cancelled)):
            raise XpraBuildSelectionDenied("Xpra build deadline or cancellation binding is invalid")
        self.producer.revalidate(selection)
        subject = selection.setup_build_subject.verify_current()
        if subject != selection.setup_build_subject:
            raise XpraBuildSelectionDenied("prepared Xpra service changed before managed launch")
        live = self.producer.session._factory.session_store._live(
            self.producer.session._handle)
        controller = self.producer._current_controller(self.producer.session)
        if (controller.controller_binding_handle != grant.controller_binding_handle
                or live.pidfd < 0 or cancelled()):
            raise XpraBuildSelectionDenied("current setup controller or cancellation state is invalid")
        source_projection = toolchain_projection = output_path = None
        output_root_fd: int | None = None
        deadline = self.monotonic() + min(float(timeout), 300.0)
        try:
            source_projection, source_rows, source_tree_digest = self._stage_regular_source(
                selection.source.tree)
            toolchain_projection, toolchain_rows, toolchain_digest = self._stage_module(
                selection.module_receipt)
            output_capability = selection.output_root
            output_root_fd = output_capability.open_current()
            output_info = os.fstat(output_root_fd)
            if (not stat.S_ISDIR(output_info.st_mode)
                    or output_info.st_uid != subject.service_uid
                    or output_info.st_gid != subject.service_gid
                    or stat.S_IMODE(output_info.st_mode) != 0o700):
                raise XpraBuildSelectionDenied("prepared output-root descriptor identity changed")
            output_root_id = output_capability.output_root_id
            output_path = Path(f"/proc/self/fd/{output_root_fd}")
            profile = selection.build_profile
            output_specs = {name: BuildOutputSpec(
                row.relative_path, row.kind, row.maximum_bytes,
                row.executable_role, row.target_facts)
                for name, row in profile.output_specs.items()}
            request_digest = hashlib.sha256(_canonical({
                "selection_handle": selection.selection_handle,
                "recipe_sha256": selection.recipe_sha256,
                "grant_id": grant.grant_id,
                "operation_id": BUILD_OPERATION_ID,
                "parameters": {},
            })).hexdigest()
            inputs = ResolvedBuildInputs(
                target_id=BUILD_TARGET, generation=profile.generation,
                service_generation_digest=profile.service_generation_digest,
                build_service_enrollment_id=subject.id,
                build_service_generation=subject.generation,
                enrollment_id=subject.id, operation_id=BUILD_OPERATION_ID,
                selection_digest=request_digest,
                source_artifact_id=SOURCE_ARTIFACT_ID, source_sha256=SOURCE_SHA256,
                source_root=source_projection, source_tree_files=source_rows,
                source_tree_manifest_sha256=source_tree_digest,
                toolchain_artifact_id=TRANSFORM_MODULE_ID,
                toolchain_sha256=TRANSFORM_MODULE_SHA256,
                toolchain_root=toolchain_projection, toolchain_tree_files=toolchain_rows,
                toolchain_tree_manifest_sha256=toolchain_digest,
                builder_artifact_id=profile.builder_artifact_id,
                builder_sha256=profile.builder_sha256,
                builder_executable=selection.pm_runtime.python_path,
                argv_recipe=profile.argv_recipe, environment=profile.environment,
                output_specs=output_specs, output_root=None,
                output_root_id=output_root_id, output_owner_uid=subject.service_uid,
                output_owner_gid=subject.service_gid,
                output_root_fd=output_root_fd,
                max_lifetime_seconds=min(300, profile.max_lifetime_seconds),
                original_source_manifest_sha256=selection.source_manifest_sha256,
                source_projection_root=source_projection,
                toolchain_projection_root=toolchain_projection,
            )
            if cancelled() or self.monotonic() >= deadline:
                raise XpraBuildSelectionDenied("Xpra setup build was cancelled before launch")
            process = self.launcher.run_selected_setup_build(
                inputs, selection=selection, grant=grant, controller_pidfd=live.pidfd,
                timeout=max(0.0, min(deadline - self.monotonic(), inputs.max_lifetime_seconds)),
                cancelled=lambda: cancelled() or self.monotonic() >= deadline,
            )
            if not isinstance(process, ManagedBuildResult):
                raise XpraBuildSelectionDenied("managed Xpra build terminal receipt is unavailable")
            if cancelled() or self.monotonic() >= deadline:
                raise XpraBuildSelectionDenied("Xpra setup build lease expired before output attestation")
            receipt = self.store.publish(
                profile, enrollment_id=subject.id, operation_id=BUILD_OPERATION_ID,
                process=process, fact_inspector=self.fact_inspector,
                cancelled=lambda: cancelled() or self.monotonic() >= deadline,
                output_root=output_path, build_inputs=inputs,
                before_activate=output_capability.remove_contents_current,
            )
            return receipt
        finally:
            if output_root_fd is not None:
                try:
                    selection.output_root.remove_contents_current()
                finally:
                    os.close(output_root_fd)
            if source_projection is not None:
                self._remove_projection(source_projection)
            if toolchain_projection is not None:
                self._remove_projection(toolchain_projection)

    def _stage_regular_source(self, source: Any) -> tuple[Path, tuple[Any, ...], str]:
        from ..artifacts import TreeFile
        from .build_execution import _canonical
        if (source.artifact_id != SOURCE_ARTIFACT_ID or source.sha256 != SOURCE_SHA256
                or _full_manifest_sha256(tuple(source.tree_files)) != SOURCE_MANIFEST_SHA256):
            raise XpraBuildSelectionDenied("verified Xpra source observation no longer matches its pin")
        rows = tuple(sorted((row for row in source.tree_files if row.kind == "file"),
                            key=lambda row: row.path))
        root = Path(tempfile.mkdtemp(prefix=".xpra-setup-source-", dir=self.staging_root))
        os.chown(root, 0, 0, follow_symlinks=False)
        try:
            for row in rows:
                source_path = source.path / row.path
                info = source_path.lstat()
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                        or info.st_size != row.size_bytes):
                    raise XpraBuildSelectionDenied("Xpra source member custody changed")
                srcfd = os.open(source_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                | getattr(os, "O_CLOEXEC", 0))
                try:
                    if os.fstat(srcfd).st_ino != info.st_ino or os.fstat(srcfd).st_dev != info.st_dev:
                        raise XpraBuildSelectionDenied("Xpra source member inode changed")
                    destination = root / row.path
                    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    dstfd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                    | getattr(os, "O_NOFOLLOW", 0)
                                    | getattr(os, "O_CLOEXEC", 0), 0o600)
                    digest = hashlib.sha256()
                    size = 0
                    try:
                        while block := os.read(srcfd, 131072):
                            digest.update(block)
                            size += len(block)
                            view = memoryview(block)
                            while view:
                                view = view[os.write(dstfd, view):]
                        os.fsync(dstfd)
                    finally:
                        os.close(dstfd)
                    if size != row.size_bytes or digest.hexdigest() != row.sha256:
                        raise XpraBuildSelectionDenied("Xpra source member changed while copied")
                    os.chmod(destination, 0o555 if row.executable else 0o444,
                             follow_symlinks=False)
                finally:
                    os.close(srcfd)
            for current, directories, _files in os.walk(root, topdown=False):
                for name in directories:
                    os.chown(Path(current) / name, 0, 0, follow_symlinks=False)
                    os.chmod(Path(current) / name, 0o555, follow_symlinks=False)
                if Path(current) != root:
                    os.chown(current, 0, 0, follow_symlinks=False)
                    os.chmod(current, 0o555, follow_symlinks=False)
            os.chmod(root, 0o555, follow_symlinks=False)
        except BaseException:
            self._remove_projection(root)
            raise
        projected = tuple(TreeFile(row.path, row.sha256, row.size_bytes, row.executable)
                          for row in rows)
        manifest = hashlib.sha256(_canonical([{
            "path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes,
            "executable": row.executable,
        } for row in projected])).hexdigest()
        return root, projected, manifest

    def _stage_module(self, receipt: RootXpraTransformModuleReceipt) -> tuple[Path, tuple[Any, ...], str]:
        from ..artifacts import TreeFile
        from .build_execution import _canonical
        body = receipt.read_current()
        if (receipt.artifact_id != TRANSFORM_MODULE_ID or receipt.sha256 != TRANSFORM_MODULE_SHA256
                or len(body) != TRANSFORM_MODULE_BYTES):
            raise XpraBuildSelectionDenied("installed Xpra transform module receipt changed")
        root = Path(tempfile.mkdtemp(prefix=".xpra-setup-module-", dir=self.staging_root))
        os.chown(root, 0, 0, follow_symlinks=False)
        try:
            path = root / "xpra_root_xauthority.py"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o444)
            try:
                view = memoryview(body)
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
            row = TreeFile("xpra_root_xauthority.py", TRANSFORM_MODULE_SHA256,
                           TRANSFORM_MODULE_BYTES, False)
            os.chmod(root, 0o555, follow_symlinks=False)
        except BaseException:
            self._remove_projection(root)
            raise
        manifest = hashlib.sha256(_canonical([{
            "path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes,
            "executable": row.executable,
        }])).hexdigest()
        return root, (row,), manifest

    def _remove_projection(self, path: Path) -> None:
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise XpraBuildSelectionDenied("root Xpra input projection custody changed")
        for current, directories, files in os.walk(path, topdown=False, followlinks=False):
            for filename in files:
                item = Path(current) / filename
                member = item.lstat()
                if not stat.S_ISREG(member.st_mode) or member.st_uid != 0:
                    raise XpraBuildSelectionDenied("Xpra input projection contains an unexpected member")
                os.chmod(item, 0o600, follow_symlinks=False)
                item.unlink()
            for name in directories:
                item = Path(current) / name
                directory = item.lstat()
                if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0:
                    raise XpraBuildSelectionDenied("Xpra input projection directory changed")
                os.chmod(item, 0o700, follow_symlinks=False)
                item.rmdir()
        os.chmod(path, 0o700, follow_symlinks=False)
        path.rmdir()

    @staticmethod
    def _remove_output_root(path: Path, uid: int, gid: int) -> None:
        try:
            info = path.lstat()
        except FileNotFoundError:
            return
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != uid or info.st_gid != gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise XpraBuildSelectionDenied("Xpra output root custody changed during cleanup")
        for current, directories, files in os.walk(path, topdown=False, followlinks=False):
            for filename in files:
                item = Path(current) / filename
                member = item.lstat()
                if not stat.S_ISREG(member.st_mode) or member.st_uid != uid or member.st_nlink != 1:
                    raise XpraBuildSelectionDenied("Xpra output contains an unexpected file")
                os.chmod(item, 0o600, follow_symlinks=False)
                item.unlink()
            for name in directories:
                item = Path(current) / name
                member = item.lstat()
                if not stat.S_ISDIR(member.st_mode) or member.st_uid != uid:
                    raise XpraBuildSelectionDenied("Xpra output contains an unexpected directory")
                os.chmod(item, 0o700, follow_symlinks=False)
                item.rmdir()
        os.chmod(path, 0o700, follow_symlinks=False)
        path.rmdir()


class RootXpraBuildSelectionProducer:
    """Build the exact current selection from real setup-owned receipts.

    The dedicated service identity comes from the current sealed setup-only
    subject. It never resolves an active worker service profile or accepts a
    caller-provided build profile.
    """

    def __init__(self, session: Any, *,
                 monotonic: Callable[[], float] = time.monotonic,
                 lifetime_seconds: float = 300.0):
        if (os.geteuid() != 0 or not callable(getattr(session, "_check_live", None))
                or not callable(getattr(session, "_resolve_current_pm_runtime", None))
                or not callable(getattr(session, "_refresh_authorization", None))
                or not 1 <= lifetime_seconds <= 300):
            raise XpraBuildSelectionDenied("root setup selection bindings are unavailable")
        self.session = session
        self.monotonic = monotonic
        self.lifetime_seconds = lifetime_seconds
        self.producer_id = secrets.token_urlsafe(32)
        self._sources: dict[str, RootXpraSourceReceipt] = {}
        self._selections: dict[str, RootSelectedXpraBuildSelection] = {}
        self._consumed: set[str] = set()

    def provision_source(self) -> str:
        """Fetch and retain only the fixed Xpra source, returning an opaque handle."""
        session = self.session
        try:
            session._check_live()
            session._refresh_authorization()
            prepared = session._last_receipt
            auth = session._authorization
            if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                    or prepared.transaction_handle != auth.transaction_handle
                    or SOURCE_ARTIFACT_ID not in session._factory.resolver.resolve(
                        auth.plan_artifact_id).allowed_artifact_ids):
                raise ValueError("current plan does not select this fixed source")
            catalog = session._factory._catalog
            spec = catalog._artifact(SOURCE_ARTIFACT_ID, SOURCE_SHA256)
            if (spec.size_bytes is None or not spec.tree_files
                    or spec.archive_format not in {"tar", "tar.gz", "tgz"}
                    or spec.size_bytes > 256 * 1024 * 1024
                    or spec.max_tree_bytes > 1_500_000_000):
                raise ValueError("source row is not the finite reviewed Xpra archive")
            fetcher = RootLocalCatalogArtifactFetcher(
                catalog=catalog, artifact_root=session._factory._receipt_registry.artifact_root,
                session_store=session._factory.session_store, session_handle=session._handle,
            )
            store_id, fetch_receipt_id = fetcher.fetch_selected_artifact(
                session._handle, SOURCE_ARTIFACT_ID)
            receipt_handle = session._factory._receipt_registry.mint(
                store_id=store_id, receipt_id=fetch_receipt_id,
                setup_authorization=auth)
            artifact_id, archive_sha = session._factory._receipt_registry.lookup(receipt_handle, auth)
            if artifact_id != SOURCE_ARTIFACT_ID or archive_sha != SOURCE_SHA256:
                raise ValueError("source receipt resolves to another artifact")
            tree = catalog.materialize_tree(
                SOURCE_ARTIFACT_ID, SOURCE_SHA256,
                session._factory._receipt_registry.artifact_root, expected_uid=0)
            manifest_sha = _full_manifest_sha256(tuple(tree.tree_files))
            if manifest_sha != SOURCE_MANIFEST_SHA256:
                raise ValueError("source tree differs from its full manifest pin")
            handle = secrets.token_urlsafe(36)
            source = RootXpraSourceReceipt(
                handle, session._handle.session_id, auth.transaction_handle,
                prepared.generation_id, prepared.generation_digest, SOURCE_ARTIFACT_ID,
                SOURCE_SHA256, tree.size_bytes, manifest_sha, tree, session, _SOURCE_SEAL,
            )
            self._sources[handle] = source
            return handle
        except XpraBuildSelectionDenied:
            raise
        except Exception:
            raise XpraBuildSelectionDenied(
                "fixed Xpra source is unavailable or not selected by the current root plan; resume source provisioning"
            ) from None

    def select(self, source_receipt_handle: str, pm_runtime_receipt_handle: str) -> RootSelectedXpraBuildSelection:
        """Join the fixed source, PM receipt, release module and protected build subject."""
        session = self.session
        try:
            session._check_live()
            session._refresh_authorization()
            prepared, auth = session._last_receipt, session._authorization
            if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                    or not isinstance(source_receipt_handle, str)
                    or not isinstance(pm_runtime_receipt_handle, str)
                    or pm_runtime_receipt_handle != session._pm_runtime_handle):
                raise ValueError("prepared source or PM receipt is not current")
            source = self._sources.get(source_receipt_handle)
            if (source is None or source._session is not session
                    or source.setup_session_id != session._handle.session_id
                    or source.transaction_handle != auth.transaction_handle
                    or source.prepared_generation_id != prepared.generation_id
                    or source.prepared_generation_digest != prepared.generation_digest
                    or _full_manifest_sha256(tuple(source.tree.tree_files)) != SOURCE_MANIFEST_SHA256):
                raise ValueError("source receipt is stale or no longer selected")
            pm = session._resolve_current_pm_runtime()
            if (not isinstance(pm, VerifiedPMRuntimeSelection)
                    or pm.receipt_handle != pm_runtime_receipt_handle
                    or pm.transaction_handle != auth.transaction_handle
                    or pm.prepared_generation_id != prepared.generation_id
                    or pm.uid != 0 or pm.implementation.lower() != "cpython"
                    or tuple(pm.version_info[:2]) != (3, 14)
                    or sys.platform != "linux"
                    or platform.machine().lower() not in {"aarch64", "arm64"}):
                raise ValueError("current selected PM runtime is absent")

            binding = getattr(session, "_selected_installation", None)
            if binding is None:
                raise ValueError("current sealed installation binding is unavailable")
            resolve_subject = getattr(binding, "resolve_prepared_build_service", None)
            if not callable(resolve_subject):
                raise ValueError("prepared Xpra build subject is not implemented by the root setup factory")
            subject = resolve_subject("xpra-root-xauthority-transform-v1")

            # The exact transform module must be part of this installed release
            # and actually loaded by the current root actor. It is not resolved
            # from the caller or from the source archive.
            module_receipt = self._current_module_receipt()
            module_bytes = module_receipt.read_current()
            if (len(module_bytes) != TRANSFORM_MODULE_BYTES
                    or hashlib.sha256(module_bytes).hexdigest() != TRANSFORM_MODULE_SHA256):
                raise ValueError("installed transform module is not the pinned current release member")
            controller = self._current_controller(session)
            if (getattr(controller, "setup_session_id", None) != session._handle.session_id
                    or getattr(controller, "transaction_handle", None) != auth.transaction_handle
                    or getattr(controller, "prepared_generation_id", None) != prepared.generation_id
                    or getattr(controller, "pid", None) != os.getpid()
                    or getattr(controller, "pidfd", None) is None):
                raise ValueError("current setup controller custody is absent")
            now = self.monotonic()
            handle = secrets.token_urlsafe(36)
            output_root = subject.create_output_root()
            output_root_id = output_root.output_root_id
            output_fd = output_root.open_current()
            try:
                output_info = os.fstat(output_fd)
                if (not stat.S_ISDIR(output_info.st_mode)
                        or output_info.st_uid != subject.service_uid
                        or output_info.st_gid != subject.service_gid
                        or stat.S_IMODE(output_info.st_mode) != 0o700):
                    raise ValueError("root output-root descriptor identity is invalid")
            finally:
                os.close(output_fd)
            profile = self._fixed_build_profile(subject, pm, prepared, output_root_id)
            recipe_digest = self._recipe_digest(profile, source, pm, module_receipt)
            selection = RootSelectedXpraBuildSelection(
                1, handle, session._handle.session_id, auth.transaction_handle,
                prepared.generation_id, prepared.generation_digest,
                profile.build_service_enrollment_id, profile.build_service_generation,
                SOURCE_ARTIFACT_ID, SOURCE_SHA256, source.receipt_handle,
                SOURCE_MANIFEST_SHA256, self._compiled_source_manifest(source),
                pm_runtime_receipt_handle, profile.builder_artifact_id, pm.runtime_sha256,
                TRANSFORM_MODULE_ID, TRANSFORM_MODULE_SHA256, output_root_id,
                recipe_digest, controller.controller_binding_handle,
                now + self.lifetime_seconds, source, pm, module_receipt, profile,
                subject, output_root, session, self.producer_id, _SELECTION_SEAL,
            )
            self._selections[handle] = selection
            return selection
        except XpraBuildSelectionDenied:
            raise
        except Exception:
            raise XpraBuildSelectionDenied(
                "Xpra source, PM runtime, module, build service, or setup controller selection is not current"
            ) from None

    @staticmethod
    def _fixed_build_profile(subject: Any, pm: VerifiedPMRuntimeSelection,
                             prepared: Any, output_root_id: str) -> Any:
        """Compile the finite Sol Xpra recipe against this setup-only subject."""
        from ..protected_enrollment import FixedBuildOutputSpec, FixedBuildProfile
        subject_fields = {
            "profile_id": "hermes-installer-build-v1",
            "template_artifact_id": "installer-prepared-build-service-template-v1",
            "template_sha256": "0d98bdabf27185d769f55de12e9242d5286e07d11e5d62369c2eeedf1fa4b967",
            "allowed_operation_ids": (BUILD_OPERATION_ID,),
            "allowed_targets": (BUILD_TARGET,),
        }
        for name, expected in subject_fields.items():
            actual = getattr(subject, name, None)
            if name in {"allowed_operation_ids", "allowed_targets"}:
                if tuple(actual or ()) != expected:
                    raise ValueError("prepared build subject does not match the fixed Xpra template")
            elif actual != expected:
                raise ValueError("prepared build subject does not match the fixed Xpra template")
        if (type(subject.service_uid) is not int or subject.service_uid <= 0
                or type(subject.service_gid) is not int or subject.service_gid <= 0
                or not isinstance(subject.generation, str) or not subject.generation
                or not isinstance(subject.id, str) or not subject.id.startswith("setup-build:")):
            raise ValueError("prepared build subject identity is invalid")
        builder_id = "pm-executable-" + hashlib.sha256(_canonical({
            "receipt_handle": pm.receipt_handle, "device": pm.device,
            "inode": pm.inode, "sha256": pm.runtime_sha256,
        })).hexdigest()
        generation = "xpra-setup-" + hashlib.sha256(_canonical({
            "transaction_handle": subject.transaction_handle,
            "prepared_generation_id": subject.prepared_generation_id,
            "prepared_generation_digest": subject.prepared_generation_digest,
            "service_generation": subject.generation,
            "operation_id": BUILD_OPERATION_ID,
        })).hexdigest()
        facts = {
            "encoding": "deterministic tar emitted by pinned module",
            "source_commit": SOURCE_COMMIT,
            "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
            "manifest_member": "hermes-installer-xpra-root-xauthority-overlay-v1.json",
            "required_observed_facts": [
                "source_tree_digest", "transform_module_sha256", "patched_file_sha256s",
                "transformed_tree_sha256", "output_archive_sha256", "patch_manifest_sha256",
            ],
        }
        return FixedBuildProfile(
            target_id=BUILD_TARGET, generation=generation,
            build_service_enrollment_id=subject.id,
            build_service_generation=subject.generation,
            source_artifact_id=SOURCE_ARTIFACT_ID, source_sha256=SOURCE_SHA256,
            toolchain_artifact_id=TRANSFORM_MODULE_ID,
            toolchain_sha256=TRANSFORM_MODULE_SHA256,
            builder_artifact_id=builder_id, builder_sha256=pm.runtime_sha256,
            argv_recipe=(
                {"build_path": {"mount_id": "builder", "relative_path": ""}},
                {"literal": "-I"},
                {"build_path": {"mount_id": "toolchain", "relative_path": "xpra_root_xauthority.py"}},
            ), environment={}, max_lifetime_seconds=300,
            output_root_id=output_root_id, output_root=None,
            output_owner_uid=subject.service_uid,
            output_specs={"xpra-overlay.tar": FixedBuildOutputSpec(
                "xpra-overlay.tar", "file", 134_217_728, "data", facts)},
            service_generation_digest=prepared.generation_digest,
        )

    @staticmethod
    def _current_controller(session: Any) -> Any:
        store = session._factory.session_store
        live = store._live(session._handle)
        pid = live.record.get("root_actor_identity", {}).get("pid")
        if type(pid) is not int or pid != os.getpid() or live.pidfd < 0:
            raise XpraBuildSelectionDenied("current setup actor has no retained PIDFD")
        try:
            with open("/proc/self/stat", "rt", encoding="ascii") as stream:
                stat_fields = stream.read().rsplit(")", 1)[1].split()
            start_ticks = int(stat_fields[19])
        except (OSError, ValueError, IndexError):
            raise XpraBuildSelectionDenied("current setup actor start identity is unavailable") from None
        binding = hashlib.sha256(_canonical({
            "session_id": session._handle.session_id, "pid": pid,
            "start_ticks": start_ticks,
            "pidfd_device": os.fstat(live.pidfd).st_dev,
            "pidfd_inode": os.fstat(live.pidfd).st_ino,
        })).hexdigest()
        return SimpleNamespace(
            setup_session_id=session._handle.session_id,
            transaction_handle=session._authorization.transaction_handle,
            prepared_generation_id=session._last_receipt.generation_id,
            pid=pid, pidfd=live.pidfd, start_ticks=start_ticks,
            controller_binding_handle=binding,
        )

    def _current_module_receipt(self) -> RootXpraTransformModuleReceipt:
        session = self.session
        release, actor = session._factory._release, session._factory._actor
        release.verify_current()
        actor.verify_current(release)
        rows = [row for row in release.files if row.artifact_id == TRANSFORM_MODULE_ID
                and row.relative_path == "src/hermes_installer/remote/xpra_root_xauthority.py"
                and row.sha256 == TRANSFORM_MODULE_SHA256 and row.size_bytes == TRANSFORM_MODULE_BYTES
                and "module" in row.roles]
        if len(rows) != 1:
            raise XpraBuildSelectionDenied("pinned Xpra transform module is not installed in the held release")
        descriptor = rows[0]
        loaded = [row for row in actor.module_origins
                  if row[1] == str(release.release_root / descriptor.relative_path)
                  and row[4] == TRANSFORM_MODULE_SHA256]
        if len(loaded) != 1:
            raise XpraBuildSelectionDenied("pinned Xpra transform module is not loaded by the current root actor")
        handle = secrets.token_urlsafe(36)
        fd = release.open_file(descriptor.artifact_id)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_size != TRANSFORM_MODULE_BYTES:
                raise XpraBuildSelectionDenied("installed transform module file identity is invalid")
            module_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(fd)
        receipt = RootXpraTransformModuleReceipt(
            artifact_id=descriptor.artifact_id, relative_path=descriptor.relative_path,
            sha256=descriptor.sha256, size_bytes=descriptor.size_bytes,
            release_commit=release.release_commit,
            deployment_receipt_sha256=release.deployment_receipt_sha256,
            _session=session, _device=module_identity[0], _inode=module_identity[1],
            _seal=_SOURCE_SEAL,
        )
        return receipt

    @staticmethod
    def _compiled_source_manifest(source: RootXpraSourceReceipt) -> str:
        rows = [{"path": row.path, "sha256": row.sha256, "size_bytes": row.size_bytes,
                 "executable": row.executable}
                for row in sorted(source.tree.tree_files, key=lambda item: item.path)
                if getattr(row, "kind", "file") == "file"]
        return hashlib.sha256(_canonical(rows)).hexdigest()

    @staticmethod
    def _recipe_digest(profile: Any, source: RootXpraSourceReceipt,
                       pm: VerifiedPMRuntimeSelection,
                       module: RootXpraTransformModuleReceipt) -> str:
        recipe = {
            "operation_id": BUILD_OPERATION_ID, "target_id": BUILD_TARGET,
            "profile_generation": profile.generation,
            "service_generation_digest": profile.service_generation_digest,
            "source_artifact_id": source.artifact_id,
            "source_sha256": source.archive_sha256,
            "source_manifest_sha256": source.full_manifest_sha256,
            "compiled_source_manifest_sha256": RootXpraBuildSelectionProducer._compiled_source_manifest(source),
            "pm_receipt_handle": pm.receipt_handle,
            "builder_executable_sha256": pm.runtime_sha256,
            "builder_device": pm.device, "builder_inode": pm.inode,
            "toolchain_artifact_id": module.artifact_id,
            "toolchain_sha256": module.sha256,
            "argv_recipe": [
                {"build_path": {"mount_id": "builder", "relative_path": ""}},
                {"literal": "-I"},
                {"build_path": {"mount_id": "toolchain", "relative_path": "xpra_root_xauthority.py"}},
            ],
            "parameters": {},
        }
        return hashlib.sha256(_canonical(recipe)).hexdigest()

    def consume(self, selection: RootSelectedXpraBuildSelection) -> RootSelectedXpraBuildSelection:
        """Revalidate and spend exactly one current selected build recipe."""
        if (type(selection) is not RootSelectedXpraBuildSelection
                or selection._seal is not _SELECTION_SEAL
                or selection._session is not self.session
                or selection._producer_id != self.producer_id
                or self._selections.get(selection.selection_handle) is not selection
                or selection.selection_handle in self._consumed
                or self.monotonic() >= selection.expires_monotonic):
            raise XpraBuildSelectionDenied("Xpra setup build selection is forged, stale, or already spent")
        self.revalidate(selection)
        self._consumed.add(selection.selection_handle)
        return selection

    def revalidate(self, selection: RootSelectedXpraBuildSelection) -> None:
        """Reopen every selected proof without creating a new job root or selection."""
        if (type(selection) is not RootSelectedXpraBuildSelection
                or selection._seal is not _SELECTION_SEAL
                or selection._session is not self.session
                or selection._producer_id != self.producer_id
                or self._selections.get(selection.selection_handle) is not selection
                or self.monotonic() >= selection.expires_monotonic):
            raise XpraBuildSelectionDenied("Xpra selection is forged, stale, or expired")
        session = self.session
        session._check_live()
        session._refresh_authorization()
        prepared, auth = session._last_receipt, session._authorization
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or prepared.generation_id != selection.prepared_generation_id
                or prepared.generation_digest != selection.prepared_generation_digest
                or auth.transaction_handle != selection.transaction_handle
                or session._handle.session_id != selection.setup_session_id):
            raise XpraBuildSelectionDenied("prepared root selection has changed")
        if (selection.source_receipt_handle not in self._sources
                or self._sources[selection.source_receipt_handle] is not selection.source
                or _full_manifest_sha256(tuple(selection.source.tree.tree_files)) != SOURCE_MANIFEST_SHA256):
            raise XpraBuildSelectionDenied("selected Xpra source observation has changed")
        try:
            receipt_artifact, receipt_digest = session._factory._receipt_registry.lookup(
                selection.source.receipt_handle, auth)
        except Exception:
            raise XpraBuildSelectionDenied("selected root Xpra source receipt is no longer current") from None
        if receipt_artifact != SOURCE_ARTIFACT_ID or receipt_digest != SOURCE_SHA256:
            raise XpraBuildSelectionDenied("root Xpra source receipt resolves to another pin")
        try:
            catalog = session._factory._catalog
            current_tree = catalog.materialize_tree(
                SOURCE_ARTIFACT_ID, SOURCE_SHA256,
                session._factory._receipt_registry.artifact_root, expected_uid=0)
        except Exception:
            raise XpraBuildSelectionDenied("pinned Xpra source tree is no longer current") from None
        if (current_tree.path != selection.source.tree.path
                or tuple(current_tree.tree_files) != tuple(selection.source.tree.tree_files)
                or current_tree.tree_manifest_sha256 != selection.source.tree.tree_manifest_sha256):
            raise XpraBuildSelectionDenied("pinned Xpra source tree identity changed")
        pm = session._resolve_current_pm_runtime()
        if (pm != selection.pm_runtime or pm.receipt_handle != selection.pm_runtime_receipt_handle
                or pm.runtime_sha256 != selection.builder_sha256):
            raise XpraBuildSelectionDenied("selected PM runtime executable has changed")
        if selection.module_receipt.read_current() == b"":
            raise XpraBuildSelectionDenied("selected transform module is empty")
        binding = getattr(session, "_selected_installation", None)
        resolve_subject = getattr(binding, "resolve_prepared_build_service", None)
        if not callable(resolve_subject):
            raise XpraBuildSelectionDenied("prepared build subject resolver is unavailable")
        subject = resolve_subject("xpra-root-xauthority-transform-v1")
        if subject != selection.setup_build_subject:
            raise XpraBuildSelectionDenied("prepared build subject has changed")
        current_profile = self._fixed_build_profile(
            subject, pm, prepared, selection.output_root_id)
        if self._recipe_digest(current_profile, selection.source, pm,
                               selection.module_receipt) != selection.recipe_sha256:
            raise XpraBuildSelectionDenied("fixed Xpra recipe changed before build admission")
        output_fd = None
        try:
            output_fd = selection.output_root.open_current()
            output_info = os.fstat(output_fd)
        except OSError:
            raise XpraBuildSelectionDenied("selected private Xpra output root is unavailable") from None
        finally:
            if output_fd is not None:
                os.close(output_fd)
        if (selection.output_root.output_root_id != selection.output_root_id
                or selection.output_root.service_selection_handle != subject.service_selection_handle
                or not stat.S_ISDIR(output_info.st_mode)
                or output_info.st_uid != subject.service_uid
                or output_info.st_gid != subject.service_gid
                or stat.S_IMODE(output_info.st_mode) != 0o700):
            raise XpraBuildSelectionDenied("selected private Xpra output root custody changed")
        controller = self._current_controller(session)
        if (getattr(controller, "controller_binding_handle", None)
                != selection.controller_binding_handle
                or getattr(controller, "setup_session_id", None) != selection.setup_session_id
                or getattr(controller, "pid", None) != os.getpid()
                or getattr(controller, "pidfd", None) is None):
            raise XpraBuildSelectionDenied("setup controller binding has changed")
