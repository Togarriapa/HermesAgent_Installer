"""Root composition adapter for protected native schema source receipts."""
from __future__ import annotations

import os
import re
import stat
import hashlib
import secrets
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.artifacts import (
    RootSchemaDerivationReceiptRegistry,
    SchemaDerivationDenied,
    SchemaDerivationPending,
)
from hermes_installer.authority.bootstrap_enrollment import (
    RootArtifactReceiptRegistry,
    _read_json_if_owned,
)
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.protected_enrollment import RootJournalSelection


_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTITY_FIELDS = frozenset({
    "schema_id", "sha256", "schema_kind", "native_package_id",
    "native_package_generation", "adapter_id", "action_id",
})
_AUTHORITY_JOURNAL_ROOT_ID = "installer-authority-journal-v1"
_BOOTSTRAP_RECEIPTS_ROOT = "bootstrap-receipts"
_CATALOG_OBSERVATION_SEAL = object()


@dataclass(frozen=True, slots=True)
class RootSourceArtifactReceiptRuntime:
    """One root-owned, generation-bound schema receipt assembly.

    The artifact receipt registry is reconstructed as a reader over the
    durable root registry path; the derivation registry and verifier are held
    together so every schema lookup uses the exact current catalog/bindings.
    """

    artifact_receipts: RootArtifactReceiptRegistry
    derivations: RootSchemaDerivationReceiptRegistry
    verifier: "RootSourceArtifactReceiptVerifier"
    root_journal: RootJournalSelection


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedCatalogArtifactObservation:
    """Held root-only observation of immutable catalog bytes or a source tree.

    Paths are never part of the public DTO. Callers receive safe file-descriptor
    operations, while the observer revalidates catalog membership, generation,
    owner, inode, hash and (for trees) every file row before returning bytes.
    """

    artifact_id: str
    sha256: str
    size_bytes: int
    version: str
    tree_manifest_sha256: str | None
    _observer_id: str
    _fd: int
    _device: int
    _inode: int
    _seal: object

    def __post_init__(self) -> None:
        if self._seal is not _CATALOG_OBSERVATION_SEAL:
            raise TypeError("catalog artifact observations are minted by the root observer")

    @property
    def is_tree(self) -> bool:
        return self.tree_manifest_sha256 is not None

    def open_blob(self) -> int:
        if self.is_tree:
            raise SourceArtifactReceiptDenied("source tree observation is not a blob")
        return os.dup(self._fd)

    def open_member(self, relative_path: str, *, observer: "RootCatalogArtifactObserver") -> int:
        return observer.open_member(self, relative_path)

    def close(self) -> None:
        if self._fd >= 0:
            os.close(self._fd)
            object.__setattr__(self, "_fd", -1)


class RootCatalogArtifactObserver:
    """Resolve immutable artifact observations from the loaded root catalog."""

    def __init__(self, runtime_bindings: RootRuntimeBindings, protected_enrollment: Any,
                 *, expected_uid: int = 0) -> None:
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not isinstance(runtime_bindings, RootRuntimeBindings)
                or not isinstance(runtime_bindings.artifact_catalog, ArtifactCatalog)
                or getattr(protected_enrollment, "protected_enrollment_digest", None)
                   != runtime_bindings.enrollment_catalog.digest
                or not isinstance(getattr(protected_enrollment, "artifact_staging_directory", None), Path)
                or not protected_enrollment.artifact_staging_directory.is_absolute()):
            raise SourceArtifactReceiptDenied("root catalog artifact observation bindings are unavailable")
        self.runtime_bindings = runtime_bindings
        self.protected_enrollment = protected_enrollment
        self.expected_uid = expected_uid
        self._observer_id = secrets.token_urlsafe(32)

    @classmethod
    def from_root_runtime(cls, runtime_bindings: RootRuntimeBindings,
                          protected_enrollment: Any, *, expected_uid: int = 0
                          ) -> "RootCatalogArtifactObserver":
        return cls(runtime_bindings, protected_enrollment, expected_uid=expected_uid)

    def observe(self, artifact_id: str, sha256: str, *, materialize_tree: bool = False
                ) -> VerifiedCatalogArtifactObservation:
        if os.geteuid() != self.expected_uid or self.expected_uid != 0:
            raise SourceArtifactReceiptDenied("catalog artifact observation requires root")
        try:
            catalog = self.runtime_bindings.artifact_catalog
            spec = catalog._artifact(artifact_id, sha256)
            if materialize_tree:
                if not spec.tree_files or not spec.archive_format:
                    raise ValueError
                resolved = catalog.materialize_tree(
                    artifact_id, sha256, self.protected_enrollment.artifact_staging_directory,
                    expected_uid=self.expected_uid,
                )
                fd = os.open(resolved.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.expected_uid
                        or stat.S_IMODE(info.st_mode) != 0o555):
                    os.close(fd)
                    raise ValueError
                tree_sha = spec.tree_manifest_sha256
                size = sum(item.size_bytes for item in spec.tree_files)
            else:
                if spec.tree_files:
                    raise ValueError
                resolved = catalog.resolve(
                    artifact_id, sha256, self.protected_enrollment.artifact_staging_directory,
                    expected_uid=self.expected_uid,
                )
                fd = os.open(resolved.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or info.st_nlink != 1 or info.st_mode & 0o222
                        or info.st_size != spec.size_bytes or info.st_size > spec.max_bytes
                        or self._hash_fd(fd, spec.max_bytes) != sha256):
                    os.close(fd)
                    raise ValueError
                tree_sha = None
                size = info.st_size
            path_info = resolved.path.lstat()
            if (stat.S_ISLNK(path_info.st_mode)
                    or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)):
                os.close(fd)
                raise ValueError
            return VerifiedCatalogArtifactObservation(
                artifact_id, sha256, size, spec.version, tree_sha, self._observer_id,
                fd, info.st_dev, info.st_ino, _CATALOG_OBSERVATION_SEAL,
            )
        except SourceArtifactReceiptDenied:
            raise
        except Exception:
            raise SourceArtifactReceiptDenied("artifact is absent from the immutable root catalog or CAS") from None

    def verify_current(self, observation: VerifiedCatalogArtifactObservation) -> bool:
        if (os.geteuid() != self.expected_uid or self.expected_uid != 0
                or type(observation) is not VerifiedCatalogArtifactObservation
                or observation._seal is not _CATALOG_OBSERVATION_SEAL
                or observation._observer_id != self._observer_id
                or self.runtime_bindings.enrollment_catalog.digest
                   != self.protected_enrollment.protected_enrollment_digest):
            raise SourceArtifactReceiptDenied("catalog artifact observation is forged or stale")
        try:
            info = os.fstat(observation._fd)
            if ((info.st_dev, info.st_ino) != (observation._device, observation._inode)
                    or info.st_uid != self.expected_uid):
                raise ValueError
            spec = self.runtime_bindings.artifact_catalog._artifact(
                observation.artifact_id, observation.sha256,
            )
            if spec.version != observation.version:
                raise ValueError
            if observation.is_tree:
                if (spec.tree_manifest_sha256 != observation.tree_manifest_sha256
                        or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o555):
                    raise ValueError
                self._verify_tree_members(observation, spec)
            else:
                if (spec.tree_files or info.st_size != observation.size_bytes
                        or observation.size_bytes != spec.size_bytes
                        or self._hash_fd(observation._fd, spec.max_bytes) != observation.sha256):
                    raise ValueError
            return True
        except SourceArtifactReceiptDenied:
            raise
        except Exception:
            raise SourceArtifactReceiptDenied("held catalog artifact observation failed revalidation") from None

    def open_member(self, observation: VerifiedCatalogArtifactObservation,
                    relative_path: str) -> int:
        if not self.verify_current(observation) or not observation.is_tree:
            raise SourceArtifactReceiptDenied("source tree observation is stale or has no members")
        return self._open_member_unchecked(observation, relative_path)

    def _open_member_unchecked(self, observation: VerifiedCatalogArtifactObservation,
                               relative_path: str) -> int:
        spec = self.runtime_bindings.artifact_catalog._artifact(observation.artifact_id, observation.sha256)
        parts = self._safe_member(relative_path)
        matches = [row for row in spec.tree_files if row.path == relative_path and row.kind == "file"]
        if len(matches) != 1:
            raise SourceArtifactReceiptDenied("source member is not an enrolled regular file")
        current_fd = os.dup(observation._fd)
        try:
            for part in parts[:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                  dir_fd=current_fd)
                directory_info = os.fstat(next_fd)
                if (not stat.S_ISDIR(directory_info.st_mode)
                        or directory_info.st_uid != self.expected_uid
                        or stat.S_IMODE(directory_info.st_mode) != 0o555):
                    os.close(next_fd)
                    raise ValueError
                os.close(current_fd)
                current_fd = next_fd
            result = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=current_fd)
            info = os.fstat(result)
            row = matches[0]
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                    or info.st_nlink != 1 or info.st_size != row.size_bytes
                    or stat.S_IMODE(info.st_mode) != (0o555 if row.executable else 0o444)
                    or self._hash_fd(result, row.size_bytes) != row.sha256):
                os.close(result)
                raise ValueError
            return result
        except SourceArtifactReceiptDenied:
            raise
        except Exception:
            raise SourceArtifactReceiptDenied("source tree member changed or escaped its held root") from None
        finally:
            os.close(current_fd)

    def _verify_tree_members(self, observation: VerifiedCatalogArtifactObservation, spec: Any) -> None:
        expected = {row.path: row for row in spec.tree_files}
        observed: set[str] = set()

        def walk(directory_fd: int, prefix: str = "") -> None:
            for name in os.listdir(directory_fd):
                if (not isinstance(name, str) or name in {"", ".", ".."}
                        or "/" in name or "\\" in name or "\x00" in name):
                    raise ValueError
                relative = f"{prefix}/{name}" if prefix else name
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    if (info.st_uid != self.expected_uid or info.st_nlink < 2
                            or stat.S_IMODE(info.st_mode) != 0o555):
                        raise ValueError
                    child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                       dir_fd=directory_fd)
                    try:
                        held = os.fstat(child_fd)
                        if (held.st_dev, held.st_ino) != (info.st_dev, info.st_ino):
                            raise ValueError
                        walk(child_fd, relative)
                    finally:
                        os.close(child_fd)
                    continue
                row = expected.get(relative)
                if row is None or row.kind not in {"file", "symlink"}:
                    raise ValueError
                if row.kind == "symlink":
                    if not stat.S_ISLNK(info.st_mode) or info.st_uid != self.expected_uid:
                        raise ValueError
                    target = os.readlink(name, dir_fd=directory_fd)
                    raw_target = target.encode("utf-8")
                    if (target != row.link_target or len(raw_target) != row.size_bytes
                            or hashlib.sha256(raw_target).hexdigest() != row.sha256):
                        raise ValueError
                else:
                    if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                            or info.st_nlink != 1
                            or stat.S_IMODE(info.st_mode) != (0o555 if row.executable else 0o444)
                            or info.st_size != row.size_bytes):
                        raise ValueError
                    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                 dir_fd=directory_fd)
                    try:
                        held = os.fstat(fd)
                        if ((held.st_dev, held.st_ino) != (info.st_dev, info.st_ino)
                                or self._hash_fd(fd, row.size_bytes) != row.sha256):
                            raise ValueError
                    finally:
                        os.close(fd)
                observed.add(relative)

        walk(observation._fd)
        if observed != set(expected):
            raise ValueError

    @staticmethod
    def _safe_member(value: str) -> tuple[str, ...]:
        path = PurePosixPath(value)
        if (not isinstance(value, str) or not value or "\\" in value or "\x00" in value
                or path.is_absolute() or path.as_posix() != value
                or any(part in {"", ".", ".."} for part in path.parts)):
            raise SourceArtifactReceiptDenied("source member path is not normalized")
        return path.parts

    @staticmethod
    def _hash_fd(fd: int, maximum: int) -> str:
        digest = hashlib.sha256()
        offset = 0
        while offset <= maximum:
            block = os.pread(fd, min(64 * 1024, maximum + 1 - offset), offset)
            if not block:
                break
            digest.update(block)
            offset += len(block)
        if offset > maximum:
            raise ValueError
        return digest.hexdigest()


def build_root_schema_receipt_runtime(
    runtime_bindings: RootRuntimeBindings,
    protected_enrollment: Any,
    *,
    mcp_discovery_registry: Any | None = None,
    expected_uid: int = 0,
) -> RootSourceArtifactReceiptRuntime:
    """Hydrate schema verification from the active root catalogs and journal.

    ``protected_enrollment`` is the already signature-verified object returned
    by the fixed root loader. Its artifact staging path is never accepted from
    a caller or worker. ``mcp_discovery_registry`` must be a real root-owned
    authenticated discovery observer; when absent, packaged schemas still
    resolve while tools/list-derived schemas remain pending.
    """
    if (os.geteuid() != expected_uid or expected_uid != 0
            or not isinstance(runtime_bindings, RootRuntimeBindings)
            or not isinstance(runtime_bindings.artifact_catalog, ArtifactCatalog)
            or getattr(protected_enrollment, "protected_enrollment_digest", None)
                != runtime_bindings.enrollment_catalog.digest
            or not isinstance(getattr(protected_enrollment, "artifact_staging_directory", None), Path)):
        raise SourceArtifactReceiptDenied("protected source receipt runtime inputs are unavailable")
    artifact_root = protected_enrollment.artifact_staging_directory
    if not artifact_root.is_absolute():
        raise SourceArtifactReceiptDenied("protected artifact store root is not absolute")
    try:
        journal = runtime_bindings.resolve_root_journal(
            _AUTHORITY_JOURNAL_ROOT_ID,
            expected_active_generation_digest=runtime_bindings.enrollment_catalog.digest,
        )
    except Exception:
        raise SourceArtifactReceiptDenied("current protected authority journal is unavailable") from None
    if (not isinstance(journal, RootJournalSelection)
            or journal.root_id != _AUTHORITY_JOURNAL_ROOT_ID
            or journal.service_generation_digest != runtime_bindings.enrollment_catalog.digest
            or not journal.path.is_absolute() or journal.device < 0 or journal.inode <= 0):
        raise SourceArtifactReceiptDenied("current protected authority journal selection is invalid")
    receipt_root = journal.path / _BOOTSTRAP_RECEIPTS_ROOT
    if receipt_root != Path("/var/lib/hermes-installer/authority-journal/bootstrap-receipts"):
        raise SourceArtifactReceiptDenied("bootstrap receipt store differs from its fixed root journal location")
    receipt_registry = RootArtifactReceiptRegistry(
        root=receipt_root,
        catalog=runtime_bindings.artifact_catalog,
        artifact_root=artifact_root,
    )
    try:
        derivations = RootSchemaDerivationReceiptRegistry.from_root_runtime(
            runtime_bindings.artifact_catalog, receipt_registry, runtime_bindings,
            mcp_discovery_registry, journal, expected_uid=expected_uid,
        )
        verifier = RootSourceArtifactReceiptVerifier.from_root_runtime(
            runtime_bindings, derivations, expected_uid=expected_uid,
        )
    except Exception:
        raise SourceArtifactReceiptDenied("root schema derivation registry could not be assembled") from None
    return RootSourceArtifactReceiptRuntime(receipt_registry, derivations, verifier, journal)


class SourceArtifactReceiptDenied(PermissionError):
    """The handle does not prove the selected schema's active source bytes."""


@dataclass(frozen=True, slots=True)
class RootSourceArtifactReceiptVerifier:
    """Callable supplied to ``NativeMCPProtectedSchemaCatalog`` by root only.

    It re-resolves the action/schema row from the protected runtime bindings,
    requires the derivation handle to be the row's exact current receipt, and
    then asks the retained root derivation registry to revalidate source,
    parent receipts, service generation, selection, lease, and bytes.
    """

    runtime_bindings: RootRuntimeBindings
    derivation_registry: RootSchemaDerivationReceiptRegistry
    expected_uid: int = 0

    @classmethod
    def from_root_runtime(
        cls,
        runtime_bindings: RootRuntimeBindings,
        derivation_registry: RootSchemaDerivationReceiptRegistry,
        *,
        expected_uid: int = 0,
    ) -> "RootSourceArtifactReceiptVerifier":
        if (os.geteuid() != expected_uid or expected_uid != 0
                or not isinstance(runtime_bindings, RootRuntimeBindings)
                or not isinstance(derivation_registry, RootSchemaDerivationReceiptRegistry)
                or runtime_bindings.artifact_catalog is not derivation_registry.protected_artifact_catalog
                or runtime_bindings.enrollment_catalog.digest
                    != derivation_registry.root_journal.service_generation_digest
                or not callable(getattr(runtime_bindings, "resolve_native_schema_record", None))):
            raise SourceArtifactReceiptDenied("root native schema receipt bindings are unavailable")
        return cls(runtime_bindings, derivation_registry, expected_uid)

    def verify_source_receipt(self, handle: str, identity: Mapping[str, str]) -> bool:
        """Verify one exact active schema row and its immutable derivation."""
        if os.geteuid() != self.expected_uid or self.expected_uid != 0:
            raise SourceArtifactReceiptDenied("schema receipt verification requires root")
        if (not isinstance(handle, str) or not 32 <= len(handle) <= 128
                or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                       for char in handle)
                or not isinstance(identity, Mapping) or set(identity) != _IDENTITY_FIELDS
                or any(not isinstance(value, str) for value in identity.values())
                or not isinstance(identity.get("sha256"), str)
                or not _SHA.fullmatch(identity["sha256"])):
            raise SourceArtifactReceiptDenied("native schema receipt identity is malformed")
        try:
            row = self.runtime_bindings.resolve_native_schema_record(
                identity["schema_id"], identity["native_package_id"],
                identity["native_package_generation"], identity["adapter_id"],
                identity["action_id"], identity["schema_kind"],
            )
        except Exception:
            raise SourceArtifactReceiptDenied("schema identity is not selected by the active protected action") from None
        if (not isinstance(row, Mapping) or row.get("id") != identity["schema_id"]
                or row.get("sha256") != identity["sha256"]
                or row.get("source_receipt_handle") != handle):
            raise SourceArtifactReceiptDenied("schema receipt handle differs from active protected selection")
        derivation_handle = row.get("derivation_receipt_handle")
        row_size = row.get("size_bytes")
        if type(row_size) is not int or not 1 <= row_size <= 256 * 1024:
            raise SourceArtifactReceiptDenied("schema row has no exact bounded byte size")
        if derivation_handle is None:
            self._verify_direct_source_receipt(handle, row["artifact_id"], row["sha256"], row_size)
        else:
            try:
                self.derivation_registry.resolve_schema_derivation(
                    derivation_handle, artifact_id=row["artifact_id"],
                    artifact_sha256=row["sha256"], size_bytes=row_size,
                    service_generation_digest=self.runtime_bindings.enrollment_catalog.digest,
                )
                if row["artifact_id"].startswith("native-mcp-schema:"):
                    # The authenticated tools/list witness binds this source response
                    # receipt separately from the derived child receipt.
                    self._read_dynamic_mcp_schema(row["artifact_id"], row["sha256"])
            except SchemaDerivationPending as exc:
                raise SourceArtifactReceiptDenied(str(exc)) from None
            except SchemaDerivationDenied as exc:
                raise SourceArtifactReceiptDenied(str(exc)) from None
            except Exception:
                raise SourceArtifactReceiptDenied("schema source derivation is unavailable") from None
        return True

    def _verify_direct_source_receipt(self, handle: str, artifact_id: str,
                                     sha256: str, size_bytes: int) -> None:
        """Validate a direct packaged-schema source receipt against root CAS."""
        path = self.derivation_registry.artifact_receipt_registry.root / f"{handle}.json"
        try:
            record = _read_json_if_owned(path)
            expected = {
                "schema", "handle", "receipt_id", "setup_session_id", "transaction_handle",
                "target_id", "operation_target_id", "plan_digest", "operator_uid",
                "artifact_role", "artifact_id", "sha256", "size_bytes",
            }
            if (not isinstance(record, Mapping) or set(record) != expected
                    or record.get("schema") != 1 or record.get("handle") != handle
                    or record.get("artifact_id") != artifact_id
                    or record.get("artifact_role") != artifact_id
                    or record.get("sha256") != sha256 or record.get("size_bytes") != size_bytes):
                raise ValueError
            spec = self.runtime_bindings.artifact_catalog._artifact(artifact_id, sha256)
            resolved = self.runtime_bindings.artifact_catalog.resolve(
                artifact_id, sha256,
                self.derivation_registry.artifact_receipt_registry.artifact_root,
                expected_uid=self.expected_uid,
            )
            if spec.size_bytes != size_bytes or resolved.size_bytes != size_bytes:
                raise ValueError
        except Exception:
            raise SourceArtifactReceiptDenied("direct schema source receipt is not current in root CAS") from None

    def read_artifact(self, artifact_id: str, sha256: str) -> bytes:
        """Read exact, bounded bytes from the selected immutable root CAS."""
        if os.geteuid() != self.expected_uid or self.expected_uid != 0:
            raise SourceArtifactReceiptDenied("schema artifact read requires root")
        if (not isinstance(artifact_id, str) or not isinstance(sha256, str)
                or not _SHA.fullmatch(sha256)):
            raise SourceArtifactReceiptDenied("schema artifact selector is malformed")
        if artifact_id.startswith("native-mcp-schema:"):
            return self._read_dynamic_mcp_schema(artifact_id, sha256)
        try:
            spec = self.runtime_bindings.artifact_catalog._artifact(artifact_id, sha256)
            if spec.size_bytes is None or not 1 <= spec.size_bytes <= 256 * 1024:
                raise ValueError
            artifact = self.runtime_bindings.artifact_catalog.resolve(
                artifact_id, sha256,
                self.derivation_registry.artifact_receipt_registry.artifact_root,
                expected_uid=self.expected_uid,
            )
            if artifact.size_bytes != spec.size_bytes or artifact.sha256 != sha256:
                raise ValueError
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            fd = os.open(artifact.path, flags)
            try:
                info = os.fstat(fd)
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.expected_uid
                        or info.st_nlink != 1 or info.st_size != spec.size_bytes
                        or info.st_size > 256 * 1024):
                    raise ValueError
                chunks = bytearray()
                while len(chunks) <= 256 * 1024:
                    block = os.read(fd, min(64 * 1024, 256 * 1024 + 1 - len(chunks)))
                    if not block:
                        break
                    chunks.extend(block)
                if len(chunks) != spec.size_bytes:
                    raise ValueError
            finally:
                os.close(fd)
            import hashlib
            body = bytes(chunks)
            if hashlib.sha256(body).hexdigest() != sha256:
                raise ValueError
            return body
        except Exception:
            raise SourceArtifactReceiptDenied("schema bytes are absent from protected root CAS") from None

    def _read_dynamic_mcp_schema(self, artifact_id: str, sha256: str) -> bytes:
        """Resolve a dynamic schema only through the active protected binding and receipt."""
        from hermes_installer.mcp.native_dispatch import NativeMCPToolBinding

        if artifact_id != f"native-mcp-schema:{sha256}":
            raise SourceArtifactReceiptDenied("dynamic schema artifact ID is not digest-bound")
        rows = [row for row in self.runtime_bindings.native_schema_artifact_records
                if row.get("artifact_id") == artifact_id and row.get("sha256") == sha256
                and row.get("schema_kind") in {"arguments", "result"}]
        if len(rows) != 1:
            raise SourceArtifactReceiptDenied("dynamic schema is not uniquely selected in the active generation")
        schema_row = rows[0]
        role = schema_row["schema_kind"]
        bindings = []
        for candidate in self.runtime_bindings.native_mcp_tool_binding_records:
            if (candidate.get("id") != schema_row.get("action_id")
                    or candidate.get("native_package_id") != schema_row.get("native_package_id")
                    or candidate.get("native_package_generation") != schema_row.get("native_package_generation")
                    or candidate.get("handler_artifact_id") != schema_row.get("adapter_id")
                    or candidate.get("request_schema_id" if role == "arguments" else "result_schema_id")
                       != schema_row.get("id")):
                continue
            try:
                selected = self.runtime_bindings.resolve_native_mcp_tool_bindings(
                    candidate["profile_id"], candidate["process_generation"],
                    self.runtime_bindings.enrollment_catalog.digest,
                )
                for selected_row in selected:
                    if selected_row.get("id") == candidate.get("id"):
                        bindings.append(NativeMCPToolBinding.from_protected_record(selected_row))
            except Exception:
                continue
        if len(bindings) != 1:
            raise SourceArtifactReceiptDenied("dynamic schema has no unique current protected MCP binding")
        try:
            artifact = self.derivation_registry.resolve_schema_artifact(
                schema_row["derivation_receipt_handle"], selected_binding=bindings[0], schema_role=role,
            )
            if (artifact.artifact_id != artifact_id or artifact.sha256 != sha256
                    or artifact.size_bytes != schema_row.get("size_bytes")
                    or artifact.schema_role != role
                    or artifact.source_receipt_handle != schema_row.get("source_receipt_handle")
                    or artifact.derivation_receipt_handle != schema_row.get("derivation_receipt_handle")
                    or artifact.native_binding_id != bindings[0].id):
                raise ValueError
            return artifact.canonical_schema_bytes
        except Exception:
            raise SourceArtifactReceiptDenied("dynamic schema receipt is stale or differs from active binding") from None

    def _schema_size(self, artifact_id: str, sha256: str) -> int:
        spec = self.runtime_bindings.artifact_catalog._artifact(artifact_id, sha256)
        if spec.size_bytes is None or not 1 <= spec.size_bytes <= 256 * 1024:
            raise SourceArtifactReceiptDenied("schema artifact lacks an exact protected byte size")
        return spec.size_bytes
