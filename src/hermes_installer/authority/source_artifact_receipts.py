"""Root composition adapter for protected native schema source receipts."""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.artifacts import (
    RootSchemaDerivationReceiptRegistry,
    SchemaDerivationDenied,
    SchemaDerivationPending,
)
from hermes_installer.authority.bootstrap_enrollment import RootArtifactReceiptRegistry
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.protected_enrollment import RootJournalSelection


_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_IDENTITY_FIELDS = frozenset({
    "schema_id", "sha256", "schema_kind", "native_package_id",
    "native_package_generation", "adapter_id", "action_id",
})
_AUTHORITY_JOURNAL_ROOT_ID = "installer-authority-journal-v1"
_BOOTSTRAP_RECEIPTS_ROOT = "bootstrap-receipts"


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
        try:
            self.derivation_registry.resolve_schema_derivation(
                handle, artifact_id=row["artifact_id"],
                artifact_sha256=row["sha256"],
                size_bytes=self._schema_size(row["artifact_id"], row["sha256"]),
                service_generation_digest=self.runtime_bindings.enrollment_catalog.digest,
            )
        except SchemaDerivationPending as exc:
            raise SourceArtifactReceiptDenied(str(exc)) from None
        except SchemaDerivationDenied as exc:
            raise SourceArtifactReceiptDenied(str(exc)) from None
        except Exception:
            raise SourceArtifactReceiptDenied("schema source derivation is unavailable") from None
        return True

    def read_artifact(self, artifact_id: str, sha256: str) -> bytes:
        """Read exact, bounded bytes from the selected immutable root CAS."""
        if os.geteuid() != self.expected_uid or self.expected_uid != 0:
            raise SourceArtifactReceiptDenied("schema artifact read requires root")
        if (not isinstance(artifact_id, str) or not isinstance(sha256, str)
                or not _SHA.fullmatch(sha256)):
            raise SourceArtifactReceiptDenied("schema artifact selector is malformed")
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

    def _schema_size(self, artifact_id: str, sha256: str) -> int:
        spec = self.runtime_bindings.artifact_catalog._artifact(artifact_id, sha256)
        if spec.size_bytes is None or not 1 <= spec.size_bytes <= 256 * 1024:
            raise SourceArtifactReceiptDenied("schema artifact lacks an exact protected byte size")
        return spec.size_bytes
