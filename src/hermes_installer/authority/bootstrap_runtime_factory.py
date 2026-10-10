"""Installed root setup assembly for the first Hermes service generation.

The selection file, release tree, artifact catalog and bootstrap-policy document
are all read from the root deployment trust source. This module deliberately
does not accept caller supplied policy rows, paths, hashes or ``EnrollmentPolicy``
objects. Runtime activation accepts only setup-scoped receipt handles that the
same root registry resolves to immutable CAS objects.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import pwd
import re
import secrets
import stat
import sys
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from ..artifacts import ArtifactCatalog, load_protected_catalog
from ..hermes_source import HERMES_SOURCE_ARTIFACT_ID
from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    BootstrapEnrollmentRequest,
    EnrollmentPolicy,
    EnrollmentReceipt,
    InstalledRootSetupActorVerifier,
    RootArtifactReceiptRegistry,
    RootBootstrapEnrollment,
    RootSetupActorVerifier,
    RootSetupSessionHandle,
    RootSetupSessionStore,
    ServiceIdentity,
    SystemIdentityAdapter,
    VerifiedArtifactReceipt,
    VerifiedRootSetupAuthorization,
    VerifiedRootSetupPlan,
    _canonical,
    _ensure_root_directory,
    _secure_directory_identity,
    _open_immutable_release_root,
    _read_secure_root_bytes,
    _unique_pairs,
    _validate_sha256,
    _verify_release_file_at,
)


_SELECTION_PATH = Path("/etc/hermes-installer/root-setup-selection.json")
_SELECTION_ID = "installer-root-setup-selection-v1"
_PLAN_ID = "installer-root-setup-plan-v1"
_LAUNCHER_ID = "installer-root-setup-launcher-v1"
_INTERPRETER_ID = "installer-root-setup-interpreter-v1"
_CATALOG_ID = "installer-protected-artifact-catalog-v1"
_POLICY_ID = "installer-bootstrap-policy-v1"
_TEMPLATE_ID = "installer-bootstrap-compiler-template-v1"
_IDENTITY_TEMPLATE_ID = "installer-authentik-policy-template-v1"
_PREPARED_BASE_TEMPLATE_ID = "installer-prepared-authority-base-template-v1"
_PLAN_TEMPLATE_ID = "installer-root-setup-plan-template-v1"
_POLICY_GENERATION_ID = "installer-bootstrap-policy-generation-v1"
_SERVICE_PARENT_ROOT = "/var/lib/hermes-installer/services/hermes-agent-native-v1"
_STORE_ID = "installer-bootstrap-artifact-store-v1"
_JOURNAL_ID = "installer-authority-journal-v1"
_COMPOSIO_SCOPE = "composio-project-catalog-read"
_COMPOSIO_OPERATION = "composio.whatsapp.catalog.read"
_COMPOSIO_ORIGIN = "https://backend.composio.dev"
_COMPOSIO_TOOLKIT_VERSION = "20260721_00"
_COMPOSIO_POLICY_ARTIFACT_ID = "installer-composio-whatsapp-catalog-read-policy-v1"
_COMPOSIO_POLICY_PATH = "templates/composio-whatsapp-catalog-read-policy-v1.json"
_COMPOSIO_POLICY_SHA256 = "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5"
_RECEIPT_TEMPLATE_ID = "installer-bootstrap-receipt-bindings-template-v1"
_CAPABILITY_MAP_TEMPLATE_ID = "installer-reviewed-native-capability-map-v1"
_APPLICATION_QUALIFICATION_WORKFLOWS = (
    ("qualify-browser-use-v1", "browser-use", "browser-fixture"),
    ("qualify-graphify-v1", "graphify", "graphify-code-fixture"),
    ("qualify-hyperframes-v1", "hyperframes", "hyperframes-render-fixture"),
    ("qualify-scrapegraph-v1", "scrapegraph-ai", "scrapegraph-local-fixture"),
)
_XPRA_TRANSFORM_MODULE = (
    "installer-xpra-root-xauthority-transform-module-v1",
    "src/hermes_installer/remote/xpra_root_xauthority.py",
    "3342afa5311fef5008a35317a526c75b3d1531d21e92d1f8aae87dba38b0a7d1",
    59_621,
    "xpra-root-xauthority-transform-module",
)
_CAPABILITY_MAP_TEMPLATE_SHA256 = "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565"
_CAPABILITY_MAP_TEMPLATE_PATH = "templates/reviewed-native-capability-map-v1.json"
_CAPABILITY_MAP_TEMPLATE_SIZE = 2026
_RECEIPT_TEMPLATE_SHA256 = "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609"
_RECEIPT_TEMPLATE_PATH = "templates/bootstrap-receipt-bindings-template-v1.json"
_RECEIPT_TEMPLATE_SIZE = 10195
_COMPOSIO_POLICY = {
    "credential_scope": _COMPOSIO_SCOPE,
    "detail_prefix": "/api/v3.1/triggers_types/",
    "id": "installer-composio-whatsapp-catalog-read-policy-v1",
    "list_path": "/api/v3.1/triggers_types",
    "max_lease_seconds": 30, "max_page_items": 50, "max_pages": 10,
    "max_response_bytes": 2 * 1024 * 1024, "max_total_items": 500,
    "methods": ["GET"], "operation": _COMPOSIO_OPERATION,
    "origin": _COMPOSIO_ORIGIN, "redirects": "deny",
    "schema": 1, "toolkit_slug": "whatsapp",
    "version_source": "selected-channel-pinned-version", "writes": "deny",
}
_GEN = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_ID = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


def _fail(message: str) -> None:
    raise BootstrapEnrollmentPending(message)


def _plain_json(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain_json(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True)
class _Selection:
    installer_release_commit: str
    release_root: Path
    release_root_id: str
    deployment_receipt_sha256: str
    release_device: int
    release_inode: int
    policy_generation: Mapping[str, Any]
    policy_root: Path
    policy_device: int
    policy_inode: int
    selection_digest: str
    launcher: Mapping[str, Any]
    interpreter: Mapping[str, Any]
    modules: tuple[Mapping[str, Any], ...]
    plans: tuple[Mapping[str, Any], ...]
    artifact_catalog: Mapping[str, Any]
    artifact_store: Mapping[str, Any]
    bootstrap_policies: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True)
class VerifiedRootBootstrapPolicy:
    """Parsed policy bytes pinned by the installed selection catalog."""

    artifact_id: str
    sha256: str
    plan_artifact_id: str
    source_artifact_id: str
    identity_policy: Mapping[str, Any]
    root_policy: Mapping[str, Any]
    authority_base_template: Mapping[str, Any]
    service_record_templates: tuple[Mapping[str, Any], ...]
    catalog_selections: Mapping[str, tuple[Mapping[str, Any], ...]]
    receipt_binding_rules: tuple[Mapping[str, Any], ...]


@dataclass(frozen=True, slots=True, repr=False)
class RootRuntimeArtifactReceipt:
    """Opaque root-minted reference to one verified setup CAS object."""

    role: str
    artifact_id: str
    sha256: str
    generation: str
    receipt_handle: str
    size_bytes: int
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootReleaseModuleReceipt:
    """Live source identity for one module held by the installed release.

    This receipt is intentionally distinct from a downloaded component/source
    receipt. It proves only the immutable installer module bytes and remains
    usable only while the issuing root setup session and release actor live.
    """

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    release_commit: str
    deployment_receipt_sha256: str
    source_receipt_handle: str
    _session_id: str = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def read_current(self) -> bytes:
        """Read the exact installed module through the held release FD."""
        return self._session._read_release_member_receipt(self)


@dataclass(frozen=True, slots=True, repr=False)
class RootInstalledReleaseMemberReceipt:
    """Held-release member identity for fixed root build/toolchain inputs."""

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    release_commit: str
    deployment_receipt_sha256: str
    receipt_handle: str
    _session_id: str = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def read_current(self) -> bytes:
        return self._session._read_installed_release_member_receipt(self)


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeRegistrationSchemaReceipt:
    """Receipt for one exact reviewed result-schema artifact in root CAS."""

    artifact_id: str
    sha256: str
    size_bytes: int
    relative_path: str
    artifact_receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    expires_monotonic: float
    _schema_receipt: Any = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def read_current(self) -> bytes:
        return self._session._read_native_registration_schema_receipt(self)


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedInstallationBinding:
    """Opaque session binding; never exposes service or journal paths."""

    _session: "RootBootstrapSession" = field(repr=False)
    _seal: str = field(repr=False)

    def authorize_native_materialization(
            self, *, enrollment_id: str, service_generation: str,
            resource_profile_id: str) -> NativeMaterializationSelection:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentError("installation binding does not belong to its root setup session")
        selected = self._session._authorize_native_materialization(
            enrollment_id=enrollment_id, service_generation=service_generation,
            resource_profile_id=resource_profile_id)
        from .native_materialization import NativeMaterializationSelection
        return NativeMaterializationSelection(
            enrollment_id=selected.enrollment_id,
            service_generation=selected.service_generation,
            service_profile_id=selected.service_profile_id,
            protected_enrollment_digest=selected.protected_enrollment_digest,
            service_uid=selected.service_uid, service_gid=selected.service_gid,
            home_root_id=selected.home_root_id, data_root_id=selected.data_root_id,
            source_artifact_id=selected.source_artifact_id,
            source_receipt_handle=selected.source_receipt_handle,
            pm_runtime_handle=selected.pm_runtime_handle)

    def resolve_private_roots(self, selection: Any) -> "_RootPrivateInstallationRoots":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentError("installation binding does not belong to its root setup session")
        return self._session._resolve_private_installation_roots(selection)

    def resolve_selected_resource_profile(self, receipt_handle: str) -> "RootSelectedResourceProfile":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("resource profile selection is not owned by this setup session")
        return self._session.resolve_selected_resource_profile(receipt_handle)

    def observe_application_qualification_workflow(self) -> str:
        """Ask the live root TTY to select one fixed non-authority workflow."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application workflow choice is not owned by this setup session")
        return self._session.observe_application_qualification_workflow()

    def resolve_application_setup_choice(self, selection_handle: str) -> "RootSelectedApplicationQualificationChoice":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application workflow choice is not owned by this setup session")
        return self._session.resolve_application_setup_choice(selection_handle)

    def resolve_current_active_enrollment(self) -> EnrollmentReceipt:
        """Return only the actual current committed enrollment from this live session."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active enrollment is not owned by this setup session")
        return self._session._resolve_current_active_enrollment()

    def resolve_current_pm_runtime(self) -> Any:
        """Resolve the current official PM environment without accepting a path."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("PM runtime is not owned by this setup session")
        return self._session._resolve_current_pm_runtime()

    def resolve_current_hermes_source(self) -> Any:
        """Resolve the current pinned Hermes source handoff root-privately."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("Hermes source is not owned by this setup session")
        return self._session._resolve_current_hermes_source()

    def resolve_installed_xpra_transform_module(self) -> RootInstalledReleaseMemberReceipt:
        """Resolve the fixed, release-pinned Xpra transform module for root build custody."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("installed Xpra toolchain is not owned by this setup session")
        return self._session._resolve_installed_xpra_transform_module()

    def resolve_native_bootstrap_assembly(
            self, prepared_setup_receipt_handle: str,
            native_materialization_receipt_handle: str) -> "RootNativeBootstrapAssemblySelection":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native assembly binding is not owned by this setup session")
        return self._session._resolve_native_bootstrap_assembly(
            prepared_setup_receipt_handle, native_materialization_receipt_handle)

    def resolve_current_native_bootstrap_assembly(
            self, selection_handle: str) -> "RootNativeBootstrapAssemblySelection":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native assembly binding is not owned by this setup session")
        return self._session._resolve_current_native_bootstrap_assembly(selection_handle)

    def resolve_native_assembly_definitions(self, selection_handle: str) -> "RootNativeAssemblyDefinitions":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native assembly binding is not owned by this setup session")
        return self._session._resolve_native_assembly_definitions(selection_handle)

    def resolve_native_registration_projection(self, selection_handle: str) -> tuple[Any, ...]:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native registration binding is not owned by this setup session")
        return self._session._resolve_native_registration_projection(selection_handle)

    def resolve_native_assembly_member(self, selection_handle: str,
                                       artifact_receipt_handle: str) -> bytes:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native assembly binding is not owned by this setup session")
        return self._session._resolve_native_assembly_member(
            selection_handle, artifact_receipt_handle)

    def resolve_release_member_receipt(self, selection_handle: str,
                                      artifact_id: str) -> RootReleaseModuleReceipt:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("release member binding is not owned by this setup session")
        return self._session._resolve_release_member_receipt(selection_handle, artifact_id)

    def mint_native_registration_schema_receipt(self, artifact_id: str) -> RootNativeRegistrationSchemaReceipt:
        """Fetch and receipt only one of the exact reviewed local result schemas."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native schema receipt is not owned by this setup session")
        return self._session._mint_native_registration_schema_receipt(artifact_id)

    def resolve_native_registration_schema_receipt(
            self, receipt_handle: str) -> RootNativeRegistrationSchemaReceipt:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native schema receipt is not owned by this setup session")
        return self._session._resolve_native_registration_schema_receipt(receipt_handle)

    def verify_native_publication_receipt(self, reservation: Any, publication_receipt: Any) -> bool:
        """Re-resolve the durable active CAS before native output receipts are spent."""
        from .native_output_receipts import NativeOutputReservation
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver, RootSetupPublicationReceipt,
        )
        if (not secrets.compare_digest(self._seal, self._session._seal)
                or not isinstance(reservation, NativeOutputReservation)
                or not isinstance(publication_receipt, RootSetupPublicationReceipt)):
            return False
        session = self._session
        try:
            session._check_live()
            session._refresh_authorization()
            prepared = session._last_receipt
            if (prepared is None or prepared.state != "prepared"
                    or reservation.prepared_generation_id != prepared.generation_id
                    or publication_receipt.transaction_handle != session._authorization.transaction_handle
                    or publication_receipt.prepared_generation_id != prepared.generation_id
                    or publication_receipt.publication_handle != reservation.publication_handle
                    or publication_receipt.claim_digest != reservation.claim_digest
                    or not set(reservation.receipt_ids).issubset(
                        publication_receipt.materialization_receipt_handles)):
                return False
            current = PolicyPublicationReceiptResolver.verify_current_active_claim(
                publication_handle=reservation.publication_handle,
                claim_digest=reservation.claim_digest,
                prepared_generation_id=reservation.prepared_generation_id,
                transaction_handle=session._authorization.transaction_handle,
                expected_materialization_receipt_handles=tuple(
                    publication_receipt.materialization_receipt_handles),
            )
            return (isinstance(current, RootSetupPublicationReceipt)
                    and current == publication_receipt)
        except Exception:
            return False

    def authorize_native_output(self, *, artifact_role: str, output_kind: str,
                                member_tree_sha256: str, output_sha256: str,
                                output_size_bytes: int) -> Any:
        """Resolve fixed output roles from current root-held source/assembly proofs."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native output binding is not owned by this setup session")
        session = self._session
        session._check_live()
        session._refresh_authorization()
        prepared = session._last_receipt
        if prepared is None or prepared.state != "prepared":
            raise BootstrapEnrollmentPending("native outputs require the current committed prepared generation")
        if artifact_role == "resources-source-bundle":
            from .native_output_receipts import NativeOutputSelection
            resource_artifact_id = "resources-source-113f42d33be9e0c8f0f47f5ca998e687323dec83"
            resource_sha = "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
            resource_size = 295_368
            producer_id = "installer-module:hermes_installer.authority.native_output_receipts"
            module_row = next((row for row in session._factory._release.files
                               if row.artifact_id == producer_id and "module" in row.roles), None)
            if (output_kind != "source-archive" or output_sha256 != resource_sha
                    or output_size_bytes != resource_size or module_row is None
                    or not _SHA.fullmatch(member_tree_sha256)):
                raise BootstrapEnrollmentPending("Resources source output differs from the pinned packaged source or producer")
            release_rows = {row.artifact_id: row for row in session._factory._release.files}
            source_row = release_rows.get(resource_artifact_id)
            if (source_row is None or source_row.sha256 != resource_sha or source_row.size_bytes != resource_size
                    or source_row.relative_path != "src/hermes_installer/registry/bundle_data/hermes-agent-resources-2.3.1.tar.gz"):
                raise BootstrapEnrollmentPending("verified release lacks the fixed Resources source member")
            plan = session._factory.resolver.resolve(_PLAN_ID)
            if resource_artifact_id not in plan.allowed_artifact_ids:
                raise BootstrapEnrollmentPending("current setup plan excludes the Resources source")
            session._factory._release.verify_current()
            session._factory._actor.verify_current(session._factory._release)
            return NativeOutputSelection(
                artifact_id=resource_artifact_id, artifact_role=artifact_role,
                output_kind=output_kind, package_id="hermes-agent-native-package-v1",
                profile_id="hermes-agent-native-v1", generation=prepared.generation_id,
                setup_session_id=session._handle.session_id,
                transaction_handle=session._authorization.transaction_handle,
                plan_digest=session._authorization.plan_digest,
                prepared_generation_id=prepared.generation_id,
                compiler_artifact_id=None, compiler_sha256=None,
                producer_artifact_id=producer_id, producer_sha256=module_row.sha256,
                source_receipt_handles=(), member_tree_sha256=member_tree_sha256,
                output_sha256=output_sha256, output_size_bytes=output_size_bytes,
                compiled_closure_sha256=None,
                expires_monotonic=min(prepared.expires_monotonic, time.monotonic() + 30.0),
            )
        native_packages = session._policy.catalog_selections.get("native_packages", ())
        if not native_packages:
            raise BootstrapEnrollmentPending(
                "the selected prepared policy has no root-authorized native package/compiler selection")
        # Until the reviewed package/output role join is supplied by installed
        # policy, unknown role construction is never allowed through this seam.
        raise BootstrapEnrollmentPending(
            "native output role cannot be authorized without a source-pinned compiler deployment receipt")

    def revalidate_native_output(self, selection: Any) -> bool:
        from .native_output_receipts import NativeOutputSelection
        if not secrets.compare_digest(self._seal, self._session._seal):
            return False
        if not isinstance(selection, NativeOutputSelection):
            return False
        try:
            session = self._session
            session._check_live()
            session._refresh_authorization()
            prepared = session._last_receipt
            # Current contracts contain no root-selected package/compiler binding
            # in the prepared policy. Matching scalar fields cannot substitute for
            # that missing sealed source, so this remains deliberately fail-closed.
            if (prepared is None or prepared.state != "prepared"
                    or selection.setup_session_id != session._handle.session_id
                    or selection.transaction_handle != session._authorization.transaction_handle
                    or selection.prepared_generation_id != prepared.generation_id):
                return False
            if selection.artifact_role == "resources-source-bundle":
                current = self.authorize_native_output(
                    artifact_role=selection.artifact_role,
                    output_kind=selection.output_kind,
                    member_tree_sha256=selection.member_tree_sha256,
                    output_sha256=selection.output_sha256,
                    output_size_bytes=selection.output_size_bytes,
                )
                return current == selection
            return False
        except Exception:
            return False

    def resolve_packaged_resources_source(self, *, prepared_setup_receipt_handle: str,
                                          verified_installer_release_receipt: Any) -> bytes:
        """Read the exact pinned Resources archive from the held release closure."""
        from .installer_release import VerifiedInstallerReleaseReceipt
        if (not secrets.compare_digest(self._seal, self._session._seal)
                or not isinstance(verified_installer_release_receipt, VerifiedInstallerReleaseReceipt)
                or verified_installer_release_receipt is not self._session._factory._release):
            raise BootstrapEnrollmentPending("Resources source request is outside the held setup release")
        session = self._session
        session.resolve_prepared_receipt(prepared_setup_receipt_handle)
        artifact_id = "resources-source-113f42d33be9e0c8f0f47f5ca998e687323dec83"
        expected_sha = "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
        expected_size = 295_368
        plan = session._factory.resolver.resolve(session._authorization.plan_artifact_id)
        if artifact_id not in plan.allowed_artifact_ids:
            raise BootstrapEnrollmentPending("selected plan does not allow the pinned Resources source")
        row = next((item for item in verified_installer_release_receipt.files
                    if item.artifact_id == artifact_id), None)
        if (row is None or row.sha256 != expected_sha or row.size_bytes != expected_size
                or row.relative_path != "src/hermes_installer/registry/bundle_data/hermes-agent-resources-2.3.1.tar.gz"):
            raise BootstrapEnrollmentPending("installed release has no exact pinned Resources source artifact")
        fd = verified_installer_release_receipt.open_file(artifact_id)
        try:
            chunks = bytearray()
            while len(chunks) <= expected_size:
                block = os.read(fd, min(64 * 1024, expected_size + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
            payload = bytes(chunks)
        finally:
            os.close(fd)
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_sha:
            raise BootstrapEnrollmentPending("Resources source artifact changed after release verification")
        verified_installer_release_receipt.verify_current()
        session._check_live()
        return payload


@dataclass(frozen=True, slots=True, repr=False)
class _BoundNativeSelection:
    enrollment_id: str
    service_generation: str
    service_profile_id: str
    protected_enrollment_digest: str
    service_uid: int
    service_gid: int
    home_root_id: str
    data_root_id: str
    source_artifact_id: str
    source_receipt_handle: str
    pm_runtime_handle: str
    resource_profile_selection_receipt_handle: str
    resources_source_receipt_handle: str
    _session_id: str = field(repr=False)
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedResourceProfile:
    """Root TTY choice joined to the exact prepared transaction and source."""

    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    resources_source_receipt_handle: str
    resources_source_artifact_id: str
    resources_source_sha256: str
    resources_revision: str
    profile_id: str
    profile_member_path: str
    profile_member_sha256: str
    choice_observation_id: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootSelectedApplicationQualificationChoice:
    """Root-TTY workflow selector; it grants no application or runtime authority."""

    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    workflow_id: str
    application_id: str
    workload_id: str
    choice_observation_id: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeBundle:
    """Path-free result of the root-owned pre-active resource/runtime sequence."""

    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    hermes_source_receipt_handle: str
    pm_runtime_receipt_handle: str
    resources_source_receipt_handle: str
    resource_profile_selection_receipt_handle: str
    materialization_receipt_handle: str
    materialization_receipt: Any = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeBootstrapAssemblySelection:
    """One-use proof binding prepared setup, source, runtime and native compiler facts."""

    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    prepared_generation_id: str
    protected_enrollment_digest: str
    enrollment_id: str
    service_profile_id: str
    service_generation: str
    resource_profile_id: str
    package_id: str
    native_package_generation: str
    compiler_artifact_id: str
    compiler_sha256: str
    compiler_release_receipt_handle: str
    compiler_module_closure_sha256: str
    pm_runtime_receipt_handle: str
    materialization_receipt_handle: str
    hermes_source_receipt_handle: str
    resources_source_receipt_handle: str
    definitions_handle: str
    definitions_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _registry_seal: object = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeAssemblyMember:
    """A retained selected file identity; its bytes are resolved by the root registry."""

    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    artifact_receipt_handle: str


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeAssemblyDefinitions:
    """Immutable selected source/action/schema projection for the native assembler."""

    selection_handle: str
    definitions_sha256: str
    adapter_records: tuple[Mapping[str, Any], ...]
    dependency_records: tuple[Mapping[str, Any], ...]
    native_schema_records: tuple[Mapping[str, Any], ...]
    native_schema_bytes: tuple[tuple[str, bytes], ...]
    source_issuer_records: tuple[Mapping[str, Any], ...]
    native_mcp_tool_bindings: tuple[Mapping[str, Any], ...]
    action_records: tuple[Mapping[str, Any], ...]
    workflow_records: tuple[Mapping[str, Any], ...]
    action_registration_records: tuple[Mapping[str, Any], ...]
    registration_records: tuple[Mapping[str, Any], ...]
    candidate_records: tuple[Mapping[str, Any], ...]
    closure_members: tuple[RootNativeAssemblyMember, ...]
    boundary_overlay_receipt_handle: str
    boundary_overlay_bytes: bytes
    boundary_overlay_source_commit: str
    effect_selection_receipt_handles: tuple[str, ...]
    _registry_seal: object = field(repr=False, compare=False)
    release_module_receipts: tuple[RootReleaseModuleReceipt, ...] = ()
    result_schema_receipts: tuple[RootNativeRegistrationSchemaReceipt, ...] = ()


@dataclass(frozen=True, slots=True, repr=False)
class _RootPrivateInstallationRoots:
    home_root: Path
    data_root: Path
    journal_root: Path
    hermes_source_tree: Path


@dataclass(frozen=True, slots=True)
class RootSetupChoices:
    """Root UI choices accepted by stage zero; no policy rows or paths."""

    mode: str
    target_account_name: str
    selected_principal_binding_receipt_handle: str | None
    selected_component_ids: tuple[str, ...]
    owned_adoption_receipt_handles: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class VerifiedIdentityPolicyTemplate:
    artifact_id: str
    sha256: str
    policy_revision: str
    identity_effect_authority: bool
    identity_read_paths: tuple[str, ...]
    max_identity_lease_seconds: int


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedReviewedNativeCapabilityMap:
    """Installed, release-pinned finite capability source for stage-zero setup."""

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    document: Mapping[str, Any] = field(repr=False)
    _session_handle: str = field(repr=False)
    _registry_seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootInitialCompilationSession:
    schema: int
    phase: str
    compilation_session_handle: str
    compilation_transaction_handle: str
    verified_release_receipt_handle: str
    actor_observation_receipt_handle: str
    plan_artifact_id: str
    plan_sha256: str
    closed_template_artifact_id: str
    closed_template_sha256: str
    choices_sha256: str
    source_catalog_sha256: str
    expected_predecessor_catalog_sha256: str | None
    issued_monotonic: float
    expires_monotonic: float
    _choices: RootSetupChoices = field(repr=False)
    _release: Any = field(repr=False)
    _actor: Any = field(repr=False)
    _root_journal_root: Mapping[str, Any] = field(repr=False)
    _seal: str = field(repr=False)

    @property
    def principal_selection_receipt_handle(self) -> str | None:
        return self._choices.selected_principal_binding_receipt_handle


@dataclass(frozen=True, slots=True)
class PendingInitialCompilation:
    state: str
    compilation_session: RootInitialCompilationSession
    next_step: str


@dataclass(frozen=True, slots=True, repr=False)
class CompiledRootSetupPublication:
    """One-use strict bytes produced from a stage-zero session and sealed facts."""

    schema: int
    policy_bytes: bytes
    artifact_catalog_bytes: bytes
    selection_document: Mapping[str, Any]
    source_receipt_handles: tuple[str, ...]
    _session: RootInitialCompilationSession = field(repr=False)
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class _RootCompilerPublicationClaim:
    publication_handle: str
    session: RootInitialCompilationSession
    transaction_handle: str
    plan_artifact_id: str
    plan_sha256: str
    bootstrap_policy_artifact_id: str
    bootstrap_policy_sha256: str
    selection_catalog_sha256: str
    release_commit: str
    root_journal_root_id: str
    observed_root_receipt_handle: str
    policy_bytes: bytes
    artifact_catalog_bytes: bytes
    selection_document: Mapping[str, Any]
    source_receipt_handles: tuple[str, ...]
    template_artifact_id: str
    template_sha256: str
    choices_sha256: str
    source_catalog_sha256: str
    expected_predecessor_catalog_sha256: str | None
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootInitialPublicationHandoff:
    schema: int
    handoff_handle: str
    compilation_session_handle: str
    compilation_transaction_handle: str
    publication_receipt_handle: str
    publication_sha256: str
    plan_sha256: str
    choices_sha256: str
    principal_selection_receipt_handle: str | None
    artifact_receipt_handles: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    normal_setup_session_id: str | None = None
    normal_transaction_handle: str | None = None
    _publication_receipt: Any = field(default=None, repr=False)
    _initial_session: RootInitialCompilationSession | None = field(default=None, repr=False)
    _registry_seal: str = field(default="", repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootComposioCatalogReadAuthorization:
    schema: int
    authorization_handle: str
    session_handle: str
    transaction_handle: str
    plan_sha256: str
    principal_id: str
    project_id: str
    credential_reference_id: str
    required_scope: str
    operation: str
    target: str
    toolkit_version: str
    request_policy_artifact_id: str
    request_policy_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _principal_receipt_handle: str = field(repr=False)
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootComposioCatalogGetGrant:
    grant_id: str
    authorization_handle: str
    session_handle: str
    transaction_handle: str
    plan_sha256: str
    principal_id: str
    project_id: str
    credential_reference_id: str
    path: str
    query: Mapping[str, Any]
    origin: str
    method: str
    toolkit_version: str
    request_policy_artifact_id: str
    request_policy_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _detail_slug: str | None = field(repr=False)
    _seal: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RootComposioCatalogExchangeReceipt:
    schema: int
    receipt_handle: str
    authorization_handle: str
    session_handle: str
    transaction_handle: str
    principal_id: str
    project_id: str
    toolkit_version: str
    operation: str
    request_policy_artifact_id: str
    request_policy_sha256: str
    request_sha256: str
    response_sha256: str
    response_size_bytes: int
    page_sequence: int
    parent_response_receipt_handle: str | None
    selected_slug: str | None
    issued_monotonic: float
    expires_monotonic: float


# v68/v77 use the domain name "catalog read receipt" for the one immutable
# exchange object that carries both request and response digest domains.
RootComposioCatalogReadReceipt = RootComposioCatalogExchangeReceipt


class InstalledBootstrapPolicyResolver:
    """Resolve the strict extended selection and its exact deployed policy."""

    def __init__(self, selection_path: Path = _SELECTION_PATH):
        if not selection_path.is_absolute():
            raise ValueError("installed root selection path must be absolute")
        self.selection_path = selection_path
        self._selection: _Selection | None = None
        self._catalog: ArtifactCatalog | None = None
        self._plans: dict[str, VerifiedRootSetupPlan] = {}
        self._policies: dict[tuple[str, str], VerifiedRootBootstrapPolicy] = {}

    @property
    def catalog(self) -> ArtifactCatalog:
        if self._catalog is None:
            self._load_selection()
        assert self._catalog is not None
        return self._catalog

    @property
    def artifact_root(self) -> Path:
        selection = self._load_selection()
        journal = Path("/var/lib/hermes-installer/authority-journal")
        if selection.artifact_store["journal_root_id"] != _JOURNAL_ID:
            _fail("selected bootstrap artifact store names an unsupported journal root")
        if (selection.artifact_store["root_id"] != _STORE_ID
                or selection.artifact_store["relative_path"] != "bootstrap-artifacts"
                or selection.artifact_store["owner_uid"] != 0
                or selection.artifact_store["owner_gid"] != 0
                or selection.artifact_store["mode"] != 0o700):
            _fail("installed root selection has no fixed root-owned bootstrap artifact store")
        return journal / "bootstrap-artifacts"

    @property
    def journal_root(self) -> Path:
        selection = self._load_selection()
        if selection.artifact_store["journal_root_id"] != _JOURNAL_ID:
            _fail("installed root selection has no fixed authority journal root")
        return Path("/var/lib/hermes-installer/authority-journal")

    def resolve(self, artifact_id: str) -> VerifiedRootSetupPlan:
        if artifact_id != _PLAN_ID:
            _fail("root setup plan is not the fixed reviewed installer plan")
        selection = self._load_selection()
        if artifact_id in self._plans:
            return self._plans[artifact_id]
        plan_rows = [row for row in selection.plans if row["artifact_id"] == artifact_id]
        if len(plan_rows) != 1:
            _fail("fixed root setup plan is absent or ambiguous in the installed selection")
        row = plan_rows[0]
        root_fd = _open_immutable_release_root(selection.release_root,
                                               selection.release_device,
                                               selection.release_inode)
        try:
            launcher_path, launcher_sha = self._fixed_file(
                selection.launcher, _LAUNCHER_ID, selection.release_root, root_fd)
            interpreter_path, interpreter_sha = self._fixed_file(
                selection.interpreter, _INTERPRETER_ID, selection.release_root, root_fd)
            modules: list[tuple[str, Path, str]] = []
            for module in selection.modules:
                path = self._verified_relative(module, module["artifact_id"], selection.release_root, root_fd)
                modules.append((module["module_name"], path, module["sha256"]))
            plan_path = self._verified_relative(row, artifact_id, selection.release_root, root_fd)
            del plan_path
            plan = VerifiedRootSetupPlan(
                artifact_id=artifact_id, digest=row["sha256"],
                launcher_artifact_id=_LAUNCHER_ID, launcher_sha256=launcher_sha,
                launcher_path=launcher_path, interpreter_path=interpreter_path,
                interpreter_sha256=interpreter_sha, module_closure=tuple(modules),
                allowed_artifact_ids=tuple(row["allowed_artifact_ids"]),
            )
        finally:
            os.close(root_fd)
        self._plans[artifact_id] = plan
        return plan

    def resolve_policy(self, plan_artifact_id: str, *, compilation_phase: str = "active") -> VerifiedRootBootstrapPolicy:
        if plan_artifact_id != _PLAN_ID:
            _fail("bootstrap policy requires the fixed selected root setup plan")
        if compilation_phase not in {"prepared", "active"}:
            _fail("bootstrap policy parser requires a root-selected compilation phase")
        selection = self._load_selection()
        cache_key = (plan_artifact_id, compilation_phase)
        if cache_key in self._policies:
            return self._policies[cache_key]
        plan_rows = [row for row in selection.plans if row["artifact_id"] == plan_artifact_id]
        policy_rows = [row for row in selection.bootstrap_policies if row["artifact_id"] == _POLICY_ID]
        if len(plan_rows) != 1 or len(policy_rows) != 1:
            _fail("installed root selection lacks one selected bootstrap policy")
        plan_row, policy_row = plan_rows[0], policy_rows[0]
        if (plan_row.get("bootstrap_policy_artifact_id") != _POLICY_ID
                or policy_row["relative_path"] != "plans/bootstrap-policy-v1.json"):
            _fail("selected root plan does not join the fixed bootstrap policy source")
        self.resolve(_PLAN_ID)
        root_fd = self._open_policy_generation(selection)
        try:
            policy_path = self._verified_relative(policy_row, _POLICY_ID,
                                                  selection.policy_root, root_fd)
        finally:
            os.close(root_fd)
        raw = self._read_release_file(policy_path, maximum=2 * 1024 * 1024,
                                      expected_sha256=policy_row["sha256"])
        doc = self._json(raw, "installed bootstrap policy")
        if raw != _canonical(doc, ensure_ascii=False):
            _fail("installed bootstrap policy bytes are not canonical UTF-8 JSON")
        policy = self._parse_policy(doc, policy_row["sha256"], plan_row, selection,
                                    compilation_phase=compilation_phase)
        self._policies[cache_key] = policy
        return policy

    def _load_selection(self) -> _Selection:
        if self._selection is not None:
            return self._selection
        if os.geteuid() != 0 or not self._linux():
            _fail("installed root bootstrap selection is available only to the Linux root launcher")
        raw = _read_secure_root_bytes(self.selection_path, 2 * 1024 * 1024, 0o600)
        doc = self._json(raw, "installed root selection")
        fields = {"schema", "selection_id", "installer_release_commit", "release_root", "policy_generation",
                  "launcher", "interpreter", "module_closure", "plans", "catalog_sha256",
                  "artifact_catalog", "artifact_store", "bootstrap_policies"}
        if (set(doc) != fields or type(doc["schema"]) is not int or doc["schema"] != 1
                or doc["selection_id"] != _SELECTION_ID
                or not isinstance(doc["installer_release_commit"], str)
                or not re.fullmatch(r"[0-9a-f]{40}", doc["installer_release_commit"])):
            _fail("installed root setup selection has an unsupported strict schema")
        digest = doc["catalog_sha256"]
        _validate_sha256(digest, "root setup selection")
        unsigned = {key: item for key, item in doc.items() if key != "catalog_sha256"}
        if not secrets.compare_digest(hashlib.sha256(_canonical(unsigned, ensure_ascii=False)).hexdigest(), digest):
            _fail("installed root setup selection catalog digest is invalid")
        release = doc["release_root"]
        if (not isinstance(release, dict)
                or set(release) != {"root_id", "absolute_path", "device", "inode", "deployment_receipt_sha256"}
                or release["root_id"] != f"installer-release:{doc['installer_release_commit']}"
                or not isinstance(release["absolute_path"], str)
                or not Path(release["absolute_path"]).is_absolute()
                or type(release["device"]) is not int or release["device"] < 0
                or type(release["inode"]) is not int or release["inode"] < 1):
            _fail("installed root release custody identity is malformed")
        _validate_sha256(release["deployment_receipt_sha256"], "release deployment receipt")
        root = Path(release["absolute_path"])
        generation = doc["policy_generation"]
        generation_fields = {"id", "publication_sha256", "root_path", "device", "inode",
                             "publication_receipt_handle"}
        if (not isinstance(generation, dict) or set(generation) != generation_fields
                or generation["id"] != "installer-bootstrap-policy-generation-v1"
                or not isinstance(generation["publication_sha256"], str)
                or not _SHA.fullmatch(generation["publication_sha256"])
                or generation["root_path"] != str(Path("/var/lib/hermes-installer/policy-generations") /
                                                   generation["publication_sha256"])
                or type(generation["device"]) is not int or generation["device"] < 0
                or type(generation["inode"]) is not int or generation["inode"] < 1
                or not isinstance(generation["publication_receipt_handle"], str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", generation["publication_receipt_handle"])):
            _fail("installed root policy-generation selection is malformed")
        policy_root = Path(generation["root_path"])
        policy_device, policy_inode = generation["device"], generation["inode"]
        if (not isinstance(doc["module_closure"], list) or not doc["module_closure"]
                or len(doc["module_closure"]) > 1024
                or not isinstance(doc["plans"], list) or not 1 <= len(doc["plans"]) <= 16
                or not isinstance(doc["bootstrap_policies"], list)
                or not 1 <= len(doc["bootstrap_policies"]) <= 16):
            _fail("installed root setup selection row bounds are invalid")
        launcher = self._selection_row(doc["launcher"], {"artifact_id", "relative_path", "sha256"})
        interpreter = self._selection_row(doc["interpreter"], {"artifact_id", "relative_path", "sha256"})
        if launcher["artifact_id"] != _LAUNCHER_ID or interpreter["artifact_id"] != _INTERPRETER_ID:
            _fail("installed launcher or interpreter has an unsupported fixed role")
        modules = []
        for row in doc["module_closure"]:
            item = self._selection_row(row, {"module_name", "artifact_id", "relative_path", "sha256"})
            if not isinstance(item["module_name"], str) or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_.]{0,191}", item["module_name"]):
                _fail("installed root module closure contains an invalid module name")
            modules.append(item)
        plans = []
        plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object",
                       "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                       "allowed_artifact_ids", "bootstrap_policy_artifact_id"}
        for row in doc["plans"]:
            item = self._selection_row(row, plan_fields)
            if (item["baseline_tag_object"] != "c47c90cf2e0a6b1cd5779257fdcba9e487ee08f8"
                    or item["baseline_commit"] != "653ac5fbc7a02613c9951859a7d794599603459b"
                    or not isinstance(item["allowed_artifact_ids"], list)
                    or not item["allowed_artifact_ids"] or len(item["allowed_artifact_ids"]) > 4096
                    or len(set(item["allowed_artifact_ids"])) != len(item["allowed_artifact_ids"])):
                _fail("installed root plan provenance or artifact allowlist is malformed")
            for artifact in item["allowed_artifact_ids"]:
                if not isinstance(artifact, str) or not _ID.fullmatch(artifact):
                    _fail("selected plan artifact allowlist contains an invalid ID")
            plans.append(item)
        policies = []
        for row in doc["bootstrap_policies"]:
            policies.append(self._selection_row(row, {"artifact_id", "relative_path", "sha256"}))
        if len({row["artifact_id"] for row in [launcher, interpreter, *modules, *plans, *policies]}) != 2 + len(modules) + len(plans) + len(policies):
            _fail("installed root setup selection contains duplicate artifact IDs")
        if len({row["relative_path"] for row in [launcher, interpreter, *modules, *plans, *policies]}) != 2 + len(modules) + len(plans) + len(policies):
            _fail("installed root setup selection contains duplicate relative paths")
        artifact_catalog = self._selection_row(doc["artifact_catalog"], {"artifact_id", "relative_path", "sha256"})
        if (artifact_catalog["artifact_id"] != _CATALOG_ID
                or artifact_catalog["relative_path"] != "catalog/artifacts.json"):
            _fail("installed root artifact catalog is not the fixed selected catalog")
        store = doc["artifact_store"]
        store_fields = {"root_id", "journal_root_id", "relative_path", "owner_uid", "owner_gid", "mode"}
        if not isinstance(store, dict) or set(store) != store_fields:
            _fail("installed root bootstrap artifact store row is malformed")
        self._load_catalog(policy_root, policy_device, policy_inode, artifact_catalog, tuple(plans))
        self._selection = _Selection(doc["installer_release_commit"], root, release["root_id"],
                                     release["deployment_receipt_sha256"],
                                     release["device"], release["inode"],
                                     generation, policy_root, policy_device, policy_inode,
                                     digest, launcher, interpreter, tuple(modules), tuple(plans),
                                     artifact_catalog, store, tuple(policies))
        return self._selection

    def _load_catalog(self, root: Path, device: int, inode: int,
                      row: Mapping[str, Any], plans: tuple[Mapping[str, Any], ...]) -> None:
        root_fd = self._open_policy_generation_path(root, device, inode)
        try:
            path = self._verified_relative(row, _CATALOG_ID, root, root_fd)
        finally:
            os.close(root_fd)
        raw = self._read_release_file(path, maximum=16 * 1024 * 1024,
                                      expected_sha256=row["sha256"])
        if not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), row["sha256"]):
            _fail("installed artifact catalog bytes do not match the root selection pin")
        try:
            self._catalog = load_protected_catalog(path, expected_uid=0)
        except Exception:
            _fail("installed protected artifact catalog failed strict parsing")
        for plan in plans:
            if any(artifact_id not in self._catalog.artifacts for artifact_id in plan["allowed_artifact_ids"]):
                _fail("selected root plan allows an artifact absent from the exact protected catalog")

    @staticmethod
    def _open_policy_generation(selection: _Selection) -> int:
        return InstalledBootstrapPolicyResolver._open_policy_generation_path(
            selection.policy_root, selection.policy_device, selection.policy_inode)

    @staticmethod
    def _open_policy_generation_path(path: Path, device: int, inode: int) -> int:
        if (path.parent != Path("/var/lib/hermes-installer/policy-generations")
                or not _SHA.fullmatch(path.name)):
            _fail("selected policy generation path is not the fixed content-addressed location")
        fd = _open_immutable_release_root(path, device, inode)
        info = os.fstat(fd)
        if info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o555:
            os.close(fd)
            _fail("selected policy generation is not sealed root-owned 0555 custody")
        return fd

    def _parse_policy(self, doc: Any, digest: str, plan_row: Mapping[str, Any],
                      selection: _Selection, *, compilation_phase: str = "active") -> VerifiedRootBootstrapPolicy:
        fields = {"schema", "id", "source_artifact_id", "identity_policy", "root_policy",
                  "authority_base_template", "service_record_templates", "catalog_selections",
                  "receipt_binding_rules"}
        if (not isinstance(doc, dict) or set(doc) != fields or type(doc["schema"]) is not int
                or doc["schema"] != 1 or doc["id"] != _POLICY_ID
                or plan_row["bootstrap_policy_artifact_id"] != _POLICY_ID):
            _fail("installed bootstrap policy document does not match the selected strict schema")
        _validate_sha256(digest, "installed bootstrap policy")
        source_id = doc["source_artifact_id"]
        if source_id != HERMES_SOURCE_ARTIFACT_ID or source_id not in plan_row["allowed_artifact_ids"]:
            _fail("bootstrap policy does not select the pinned official Hermes source")
        identity_fields = {"service_profile_id", "principal_id", "service_account_name",
                           "exclusive_group_name", "uid_allocation"}
        identity = doc["identity_policy"]
        if (not isinstance(identity, dict) or set(identity) != identity_fields
                or any(not isinstance(identity[key], str) or not _ID.fullmatch(identity[key])
                       for key in identity_fields)
                or identity["uid_allocation"] != "root-dedicated-account"
                or identity["service_account_name"] != identity["exclusive_group_name"]):
            _fail("bootstrap service identity policy is incomplete or unsupported")
        root_fields = {"journal_root_id", "service_home_root_id", "service_work_root_id",
                       "service_data_root_id", "service_parent_root"}
        roots = doc["root_policy"]
        root_ids = ("journal_root_id", "service_home_root_id", "service_work_root_id", "service_data_root_id")
        if (not isinstance(roots, dict) or set(roots) != root_fields
                or any(not isinstance(roots[key], str) or not _ID.fullmatch(roots[key])
                       for key in root_ids)
                or len({roots[key] for key in root_ids}) != len(root_ids)
                or roots["journal_root_id"] != _JOURNAL_ID
                or roots["service_parent_root"] != _SERVICE_PARENT_ROOT):
            _fail("bootstrap service root policy does not use the selected private root layout")
        base = doc["authority_base_template"]
        self._validate_authority_base_template(base)
        templates = doc["service_record_templates"]
        if not isinstance(templates, list) or not 1 <= len(templates) <= 64:
            _fail("bootstrap service-record template list is empty or oversized")
        normalized_templates = []
        for row in templates:
            if not isinstance(row, dict) or set(row) != {"id", "record", "receipt_bindings"}:
                _fail("bootstrap service-record template envelope is malformed")
            if not isinstance(row["id"], str) or not _ID.fullmatch(row["id"]):
                _fail("bootstrap service-record template ID is malformed")
            record = row["record"]
            if not isinstance(record, dict):
                _fail("bootstrap service-record template body is malformed")
            if (record.get("profile_id") != identity["service_profile_id"]
                    or record.get("principal_id") != identity["principal_id"]
                    or record.get("service_user") != identity["service_account_name"]):
                _fail("bootstrap service template does not join its selected identity policy")
            bindings = row["receipt_bindings"]
            if not isinstance(bindings, list) or len(bindings) > 256:
                _fail("bootstrap receipt-binding list is malformed")
            normalized = []
            seen_paths: set[tuple[Any, ...]] = set()
            for binding in bindings:
                if not isinstance(binding, dict) or set(binding) != {"field_path", "receipt_role", "receipt_field"}:
                    _fail("bootstrap receipt binding does not match the strict binding schema")
                path = binding["field_path"]
                if (not isinstance(path, list) or not path
                        or any(type(part) not in {str, int} or type(part) is int and part < 0 for part in path)
                        or not isinstance(binding["receipt_role"], str)
                        or binding["receipt_role"] not in {
                            "official-agent-source", "official-installer-script", "official-pm-lock",
                            "official-pm-runtime", "native-launcher", "installed-agent-closure",
                            "resources-source-bundle", "native-compiled-closure",
                            "native-entrypoint-manifest", "native-action-resolver",
                            "native-boundary-overlay", "native-candidate-index", "native-health"}
                        or not isinstance(binding["receipt_field"], str)
                        or not InstalledBootstrapPolicyResolver._receipt_field_allowed(
                            binding["receipt_role"], binding["receipt_field"])):
                    _fail("bootstrap receipt binding role, path, or field is unsupported")
                frozen_path = tuple(path)
                if frozen_path in seen_paths:
                    _fail("bootstrap receipt bindings target a duplicate field")
                seen_paths.add(frozen_path)
                normalized.append({**binding, "field_path": list(path)})
            normalized_templates.append({"id": row["id"], "record": copy.deepcopy(record),
                                         "receipt_bindings": tuple(normalized)})
        selection_fields = {"protected_devices", "protected_build_records", "native_packages",
                            "memory_enrollments", "operation_parameter_schemas", "source_issuers",
                            "resource_jobs", "remote_session_enrollments", "resource_backend_enrollments",
                            "resource_body_recipes", "resource_scope_bindings", "resource_validators",
                            "root_journal_roots", "resource_controller_roles",
                            "native_mcp_tool_bindings", "remote_observation_enrollments",
                            "native_schema_artifacts", "composio_channel_enrollments",
                            "channel_delivery_bindings"}
        catalogs = doc["catalog_selections"]
        if not isinstance(catalogs, dict) or set(catalogs) != selection_fields:
            _fail("bootstrap catalog selections do not cover the exact enrollment schema")
        clean_catalogs = {}
        for name, rows in catalogs.items():
            if not isinstance(rows, list) or len(rows) > 1024 or any(not isinstance(row, dict) for row in rows):
                _fail("bootstrap catalog selection rows are malformed")
            clean_catalogs[name] = tuple(copy.deepcopy(rows))
        if any(clean_catalogs[name] for name in selection_fields - {"root_journal_roots"}):
            # Nonempty secondary catalogs need their own exact nested-schema
            # validator and selected policy receipts. The current bootstrap
            # policy supports only the finite service profile and source set.
            _fail("bootstrap policy requests an unimplemented protected catalog enrollment")
        binding_rules = self._validate_receipt_binding_rules(
            doc["receipt_binding_rules"], plan_row["allowed_artifact_ids"],
            dormant_prepared=(compilation_phase == "prepared"))
        return VerifiedRootBootstrapPolicy(
            artifact_id=_POLICY_ID, sha256=digest, plan_artifact_id=plan_row["artifact_id"],
            source_artifact_id=source_id, identity_policy=dict(identity), root_policy=dict(roots),
            authority_base_template=copy.deepcopy(base),
            service_record_templates=tuple(normalized_templates),
            catalog_selections=clean_catalogs, receipt_binding_rules=tuple(copy.deepcopy(binding_rules)),
        )

    @staticmethod
    def _validate_receipt_binding_rules(value: Any,
                                        allowed_plan_artifacts: list[str], *,
                                        dormant_prepared: bool = False) -> list[dict[str, Any]]:
        """Validate the finite role/output/phase join before any receipt is used."""
        roles = {
            "official-agent-source", "official-installer-script", "official-pm-lock",
            "official-pm-runtime", "resources-source-bundle", "native-compiled-closure",
            "native-entrypoint-manifest", "native-action-resolver", "native-boundary-overlay",
            "native-candidate-index", "native-health",
        }
        outputs = {"source-archive", "pm-runtime", "compiled-closure", "entrypoint-json",
                   "resolver-json", "boundary-overlay", "candidate-index-json", "native-health"}
        output_for_role = {
            "official-agent-source": {"source-archive"},
            "official-installer-script": {"source-archive"},
            "official-pm-lock": {"source-archive"},
            "official-pm-runtime": {"pm-runtime"},
            "resources-source-bundle": {"source-archive"},
            "native-compiled-closure": {"compiled-closure"},
            "native-entrypoint-manifest": {"entrypoint-json"},
            "native-action-resolver": {"resolver-json"},
            "native-boundary-overlay": {"boundary-overlay"},
            "native-candidate-index": {"candidate-index-json"},
            "native-health": {"native-health"},
        }
        phases = {"prepared-source", "runnable", "functional-health"}
        if not isinstance(value, list) or len(value) > 256:
            _fail("bootstrap receipt binding rules are malformed")
        result: list[dict[str, Any]] = []
        seen_roles: set[str] = set()
        for row in value:
            if not isinstance(row, dict) or set(row) != {
                    "receipt_role", "allowed_artifact_ids", "allowed_output_kinds",
                    "required_phase", "field_bindings"}:
                _fail("bootstrap receipt binding rule has unknown or missing fields")
            role = row["receipt_role"]
            ids, kinds, phase, bindings = (row["allowed_artifact_ids"],
                                           row["allowed_output_kinds"],
                                           row["required_phase"], row["field_bindings"])
            if (not isinstance(role, str) or role not in roles or role in seen_roles or not isinstance(ids, list)
                    or len(ids) > 256
                    or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in ids)
                    or len(set(ids)) != len(ids)
                    or not isinstance(kinds, list) or not kinds
                    or any(not isinstance(item, str) or item not in outputs for item in kinds)
                    or len(set(kinds)) != len(kinds)
                    or set(kinds) != output_for_role.get(role)
                    or not isinstance(phase, str) or phase not in phases
                    or not isinstance(bindings, list) or len(bindings) > 256):
                _fail("bootstrap receipt binding rule values are malformed")
            if (not ids and (not dormant_prepared or phase not in {"runnable", "functional-health"}
                             or role not in {
                    "official-pm-runtime", "native-compiled-closure", "native-entrypoint-manifest",
                    "native-action-resolver", "native-boundary-overlay", "native-candidate-index",
                    "native-health"})):
                _fail("only dormant prepared runtime/output roles may have no selected artifact IDs")
            if role in {"official-agent-source", "official-installer-script", "official-pm-lock",
                        "official-pm-runtime", "resources-source-bundle"}:
                if any(item not in allowed_plan_artifacts for item in ids):
                    _fail("source receipt rule allows an artifact outside the selected plan")
            if role == "native-health" and phase != "functional-health":
                _fail("native health receipt can bind only functional-health fields")
            if role != "native-health" and phase == "functional-health":
                _fail("functional-health phase is reserved for native health receipts")
            clean_bindings = []
            for binding in bindings:
                if (not isinstance(binding, dict)
                        or set(binding) != {"field_path", "receipt_role", "receipt_field"}
                        or binding["receipt_role"] != role
                        or not isinstance(binding["field_path"], list) or not binding["field_path"]
                        or any(type(part) not in {str, int} or type(part) is int and part < 0
                               for part in binding["field_path"])
                        or not isinstance(binding["receipt_field"], str)
                        or not InstalledBootstrapPolicyResolver._receipt_field_allowed(
                            role, binding["receipt_field"])):
                    _fail("bootstrap receipt rule field binding is malformed or cross-role")
                clean_bindings.append(copy.deepcopy(binding))
            result.append({"receipt_role": role, "allowed_artifact_ids": list(ids),
                           "allowed_output_kinds": list(kinds), "required_phase": phase,
                           "field_bindings": clean_bindings})
            seen_roles.add(role)
        return result

    @staticmethod
    def _receipt_field_allowed(role: str, field_name: str) -> bool:
        common = {"artifact_id", "sha256", "generation", "receipt_handle"}
        role_specific = {
            "official-pm-runtime": {"catalog_executable_path", "executable_artifact_id",
                                    "executable_sha256", "runtime_artifact_ids",
                                    "package_runtime_records"},
            "native-compiled-closure": {"child_artifact_refs"},
        }
        return field_name in common | role_specific.get(role, set())

    @staticmethod
    def _validate_authority_base_template(value: Any) -> None:
        required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                    "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                    "native_bridges", "normalization_policies", "delegations", "service_generations"}
        root_bound_key = value.get("key_id") == {"root_binding": "authority_key.key_id"} if isinstance(value, dict) else False
        if (not isinstance(value, dict) or set(value) != required or type(value["schema"]) is not int
                or value["schema"] != 1
                or not (root_bound_key or isinstance(value["key_id"], str) and value["key_id"])
                or any(not isinstance(value[name], dict) for name in required - {"schema", "key_id"})):
            _fail("bootstrap authority-base template does not match the protected authority schema")
        if any(value[name] for name in ("principals", "rules", "authentik", "process_profiles", "provider_enrollments",
                                        "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges",
                                        "normalization_policies", "delegations")):
            _fail("bootstrap authority base cannot pre-enable services or worker authority")
        generation = value["service_generations"]
        if generation == {"root_binding": "prepared_service_generation.exact_empty_snapshot"}:
            if not root_bound_key:
                _fail("prepared authority base template bindings must be paired")
            return
        from .enrollment import _validate_service_generations
        try:
            normalized = _validate_service_generations(generation)
        except Exception:
            _fail("prepared authority base requires a valid root-bound service snapshot")
        empty_snapshot_catalogs = (
            "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
            "operation_parameter_schemas", "source_issuers", "resource_jobs",
            "remote_session_enrollments", "resource_backend_enrollments", "resource_body_recipes",
            "resource_scope_bindings", "resource_validators", "resource_controller_roles",
            "native_mcp_tool_bindings", "remote_observation_enrollments", "native_schema_artifacts",
            "composio_channel_enrollments", "channel_delivery_bindings",
        )
        if (normalized["service_records"]
                or any(normalized[name] for name in empty_snapshot_catalogs)
                or len(normalized["root_journal_roots"]) != 1):
            _fail("prepared authority base must bind the exact empty root-journal service snapshot")

    @staticmethod
    def _selection_row(value: Any, keys: set[str]) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != keys:
            _fail("installed root selection row has unknown or missing fields")
        if "artifact_id" in value and (not isinstance(value["artifact_id"], str) or not _ID.fullmatch(value["artifact_id"])):
            _fail("installed root selection artifact ID is malformed")
        if "sha256" in value:
            _validate_sha256(value["sha256"], "installed root selection file")
        if "relative_path" in value:
            path = value["relative_path"]
            if (not isinstance(path, str) or not path or path.startswith("/") or "\\" in path
                    or any(part in {"", ".", ".."} for part in path.split("/"))):
                _fail("installed root selection path is not normalized and relative")
        return dict(value)

    @classmethod
    def _verified_relative(cls, row: Mapping[str, Any], artifact_id: str, root: Path, root_fd: int) -> Path:
        if row.get("artifact_id") != artifact_id:
            _fail("installed root selection row has the wrong fixed artifact role")
        cls._selection_row(dict(row), set(row))
        relative = row["relative_path"]
        _verify_release_file_at(root_fd, relative, row["sha256"])
        return root.joinpath(*relative.split("/"))

    @classmethod
    def _fixed_file(cls, row: Mapping[str, Any], artifact_id: str, root: Path, root_fd: int) -> tuple[Path, str]:
        if set(row) != {"artifact_id", "relative_path", "sha256"}:
            _fail("installed root launcher or interpreter row is malformed")
        path = cls._verified_relative(row, artifact_id, root, root_fd)
        info = path.stat(follow_symlinks=False)
        if not info.st_mode & 0o111:
            _fail("installed root launcher or interpreter is not executable")
        return path, row["sha256"]

    @staticmethod
    def _read_release_file(path: Path, *, maximum: int,
                           expected_sha256: str | None = None) -> bytes:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_mode & 0o222 or info.st_size > maximum):
                _fail("installed release artifact is not an immutable root-owned regular file")
            chunks = []
            total = 0
            while True:
                block = os.read(fd, min(131072, maximum + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > maximum:
                    _fail("installed release artifact exceeds its read bound")
            after = os.fstat(fd)
            if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
                    info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
                _fail("installed release artifact changed during read")
            raw = b"".join(chunks)
            if (expected_sha256 is not None
                    and not secrets.compare_digest(hashlib.sha256(raw).hexdigest(), expected_sha256)):
                _fail("installed release bytes changed after the selected pin was verified")
            return raw
        finally:
            os.close(fd)

    @staticmethod
    def _json(raw: bytes, label: str) -> Any:
        try:
            return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                              parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, json.JSONDecodeError, ValueError):
            _fail(f"{label} is malformed JSON")

    @staticmethod
    def _linux() -> bool:
        return os.name == "posix" and Path("/proc/sys/kernel/ostype").exists()


class RootInitialCompilationRegistry:
    """Issue root-local, short-lived stage-zero compilation contexts."""

    def __init__(self, release: Any, actor: Any, root_journal: Path):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        if (not isinstance(release, VerifiedInstallerReleaseReceipt)
                or not isinstance(actor, RootActorObservation)
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or root_journal != Path("/var/lib/hermes-installer/authority-journal")):
            raise BootstrapEnrollmentPending("stage-zero compiler requires sealed release, actor and fixed journal")
        if os.geteuid() != 0 or not InstalledBootstrapPolicyResolver._linux():
            raise BootstrapEnrollmentPending("stage-zero compilation requires installed Linux root authority")
        actor.verify_current(release)
        self.release, self.actor, self.root_journal = release, actor, root_journal
        _ensure_root_directory(root_journal)
        self._journal_identity = _secure_directory_identity(root_journal)
        self._actor_receipt_root = root_journal / "initial-compilation-actors"
        _ensure_root_directory(self._actor_receipt_root)
        self._seal = secrets.token_hex(32)
        self._sessions: dict[str, RootInitialCompilationSession] = {}
        self.actor_verifier = InstalledRootSetupActorVerifier()
        self._publications: dict[str, tuple[RootInitialCompilationSession, CompiledRootSetupPublication,
                                            str, bool]] = {}
        self._handoffs: dict[str, Mapping[str, Any]] = {}
        self._adopted_handoffs: dict[str, RootInitialPublicationHandoff] = {}
        self._session_store: Any | None = None

    @classmethod
    def from_installed_release(cls, verified_release_receipt: Any,
                               installed_actor_verifier: Any,
                               root_journal: Path) -> "RootInitialCompilationRegistry":
        return cls(verified_release_receipt, installed_actor_verifier, root_journal)

    def begin_initial_compilation(self, explicit_choices: RootSetupChoices) -> RootInitialCompilationSession:
        choices = self._validate_choices(explicit_choices)
        if choices.mode != "install":
            raise BootstrapEnrollmentPending("repair and resume require the currently installed root selection")
        self._validate_release_closure()
        now = time.monotonic()
        session_handle = secrets.token_hex(32)
        transaction_handle = secrets.token_hex(32)
        release_handle = secrets.token_hex(32)
        actor_handle = secrets.token_hex(32)
        template, _template_bytes = self._release_file(_TEMPLATE_ID)
        source_catalog, _catalog_bytes = self._release_file(_CATALOG_ID)
        choice_body = {
            "mode": choices.mode, "target_account_name": choices.target_account_name,
            "selected_principal_binding_receipt_handle": choices.selected_principal_binding_receipt_handle,
            "selected_component_ids": list(choices.selected_component_ids),
            "owned_adoption_receipt_handles": list(choices.owned_adoption_receipt_handles),
        }
        session = RootInitialCompilationSession(
            1, "initial-compilation", session_handle, transaction_handle, release_handle, actor_handle,
            self.release.selected_plan_artifact_id, self.release.selected_plan_sha256,
            _TEMPLATE_ID, template.sha256,
            hashlib.sha256(_canonical(choice_body, ensure_ascii=False)).hexdigest(),
            source_catalog.sha256, None, now, now + 300.0, choices,
            self.release, self.actor, MappingProxyType(self._root_journal_row()), self._seal,
        )
        self._sessions[session_handle] = session
        self._write_actor_receipt(session)
        return session

    def resolve_initial_session(self, compilation_session_handle: str) -> RootInitialCompilationSession:
        if not isinstance(compilation_session_handle, str) or not re.fullmatch(r"[0-9a-f]{64}", compilation_session_handle):
            raise BootstrapEnrollmentPending("stage-zero compilation session handle is malformed")
        session = self._sessions.get(compilation_session_handle)
        if session is None:
            raise BootstrapEnrollmentPending("stage-zero compilation session is absent or belongs to another registry")
        self.verify_initial_session(session)
        return session

    def bind_selected_principal(self, stage0_session_handle: str,
                                principal_receipt_handle: str,
                                principal_registry: Any) -> RootInitialCompilationSession:
        """Advance the same stage-zero context after root Authentik selection.

        The session and transaction IDs remain fixed so the identity and
        principal receipts stay bound to the original root actor observation.
        Only the registry can attach the typed principal receipt to the sealed
        choices and refresh its actor journal record.
        """
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        if not isinstance(principal_registry, RootSetupPrincipalSelectionRegistry):
            raise BootstrapEnrollmentPending("initial policy requires the concrete root principal registry")
        session = self.resolve_initial_session(stage0_session_handle)
        if (not isinstance(principal_receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", principal_receipt_handle)
                or session._choices.selected_principal_binding_receipt_handle is not None):
            raise BootstrapEnrollmentPending("stage-zero principal receipt is malformed or already selected")
        selected = principal_registry.resolve_selected_principal(
            principal_receipt_handle, session.compilation_session_handle,
            session.compilation_transaction_handle, session.plan_sha256)
        choices = replace(session._choices,
                          selected_principal_binding_receipt_handle=principal_receipt_handle)
        choice_body = {
            "mode": choices.mode, "target_account_name": choices.target_account_name,
            "selected_principal_binding_receipt_handle": principal_receipt_handle,
            "selected_component_ids": list(choices.selected_component_ids),
            "owned_adoption_receipt_handles": list(choices.owned_adoption_receipt_handles),
        }
        updated = replace(session, choices_sha256=hashlib.sha256(
            _canonical(choice_body, ensure_ascii=False)).hexdigest(), _choices=choices)
        self.verify_initial_session(session)
        self._sessions[stage0_session_handle] = updated
        self._write_actor_receipt(updated)
        # Re-resolution checks the replacement is now the sole current object.
        return self.resolve_initial_session(stage0_session_handle)

    def resolve_setup_plan(self, session: RootInitialCompilationSession) -> VerifiedRootSetupPlan:
        """Return the exact installed plan bound to a live stage-zero session."""
        self.verify_initial_session(session)
        files = {row.artifact_id: row for row in self.release.files}
        launcher = files.get(_LAUNCHER_ID)
        interpreter = files.get(_INTERPRETER_ID)
        selected = files.get(session.plan_artifact_id)
        modules = [row for row in self.release.files if "module" in row.roles]
        if launcher is None or interpreter is None or selected is None or not modules:
            raise BootstrapEnrollmentPending("installed release lacks the exact setup executable closure")
        module_closure = []
        for row in modules:
            if not row.relative_path.startswith("lib/python/") or not row.relative_path.endswith(".py"):
                raise BootstrapEnrollmentPending("selected release module path is not importable source")
            module_name = row.artifact_id.removeprefix("installer-module:")
            if module_name == row.artifact_id:
                raise BootstrapEnrollmentPending("installed module artifact has no canonical import identity")
            module_closure.append((module_name, self.release.release_root / row.relative_path, row.sha256))
        return VerifiedRootSetupPlan(
            artifact_id=session.plan_artifact_id, digest=session.plan_sha256,
            launcher_artifact_id=_LAUNCHER_ID, launcher_sha256=launcher.sha256,
            launcher_path=self.release.release_root / launcher.relative_path,
            interpreter_path=self.release.release_root / interpreter.relative_path,
            interpreter_sha256=interpreter.sha256, module_closure=tuple(module_closure),
            allowed_artifact_ids=tuple(self._allowed_plan_artifact_ids(session)))

    def resolve_actor_plan(self, stage0_session_handle: str) -> VerifiedRootSetupPlan:
        session = self.resolve_initial_session(stage0_session_handle)
        return self.resolve_setup_plan(session)

    def resolve_identity_policy_template(self, stage0_session_handle: str) -> VerifiedIdentityPolicyTemplate:
        session = self.resolve_initial_session(stage0_session_handle)
        descriptor, raw = self._release_file(_IDENTITY_TEMPLATE_ID)
        value = self._json(raw, "selected Authentik identity policy template")
        expected_paths = ("/api/v3/core/users/me/", "/api/v3/core/groups/{root_observed_group_id}/")
        if (descriptor.relative_path != "templates/authentik-policy-template-v1.json"
                or descriptor.sha256 != "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8"
                or not isinstance(value, dict)
                or set(value) != {"id", "identity_effect_authority", "identity_read_paths",
                                  "max_identity_lease_seconds", "policy_revision", "schema"}
                or value["id"] != _IDENTITY_TEMPLATE_ID or type(value["schema"]) is not int
                or value["schema"] != 1
                or value["identity_effect_authority"] is not False
                or value["identity_read_paths"] != list(expected_paths)
                or type(value["max_identity_lease_seconds"]) is not int
                or value["max_identity_lease_seconds"] != 30
                or value["policy_revision"] != "authentik-policy-v1"):
            raise BootstrapEnrollmentPending("installed identity policy template differs from reviewed v49 bytes")
        self.verify_initial_session(session)
        return VerifiedIdentityPolicyTemplate(
            _IDENTITY_TEMPLATE_ID, descriptor.sha256, value["policy_revision"],
            False, expected_paths, 30)

    def resolve_reviewed_capability_map(
            self, stage0_session_handle: str) -> VerifiedReviewedNativeCapabilityMap:
        """Resolve only the immutable reviewed capability map from this live release.

        This is source material, not an authorization decision. Selected capabilities
        still require current identity, effect-rule, and enrolled-action receipts.
        """
        session = self.resolve_initial_session(stage0_session_handle)
        descriptor, raw = self._release_file(_CAPABILITY_MAP_TEMPLATE_ID)
        if (not isinstance(raw, bytes) or len(raw) != _CAPABILITY_MAP_TEMPLATE_SIZE
                or hashlib.sha256(raw).hexdigest() != _CAPABILITY_MAP_TEMPLATE_SHA256):
            raise BootstrapEnrollmentPending("reviewed native capability map bytes changed after pin verification")
        value = InstalledBootstrapPolicyResolver._json(raw, "reviewed native capability map")
        fields = {"id", "namespace_id_recipe", "namespace_policy", "normal_selection_rule",
                  "ordinary_member_capability_candidates", "prepared_capabilities", "profile_id",
                  "projection", "schema", "system_gate", "system_member_additional_capability_sources"}
        candidates = ["provider-dispatch", "memory-retrieval", "memory-capture", "memory-extraction",
                      "memory-embedding", "memory-export", "memory-backup", "memory-restore", "memory-delete"]
        sources = ["selected-native-adapter-records.capability",
                   "selected-resource-execution-records.capability",
                   "selected-mcp-binding-records.capability",
                   "selected-application-runtime-records.capability"]
        if (descriptor.relative_path != _CAPABILITY_MAP_TEMPLATE_PATH
                or descriptor.sha256 != _CAPABILITY_MAP_TEMPLATE_SHA256
                or descriptor.size_bytes != _CAPABILITY_MAP_TEMPLATE_SIZE
                or "template" not in descriptor.roles
                or not isinstance(value, dict) or set(value) != fields
                or value.get("id") != _CAPABILITY_MAP_TEMPLATE_ID
                or type(value.get("schema")) is not int or value["schema"] != 1
                or value.get("profile_id") != "hermes-agent-native-v1"
                or value.get("prepared_capabilities") != []
                or value.get("ordinary_member_capability_candidates") != candidates
                or value.get("system_member_additional_capability_sources") != sources
                or value.get("namespace_policy") != "per-selected-principal-native-profile-v1"
                or value.get("namespace_id_recipe") !=
                   "hermes-native-<first32hex(SHA256(UTF8(principal_id + NUL + profile_id)))>"):
            raise BootstrapEnrollmentPending("installed release lacks the exact v91 reviewed capability map")
        self.verify_initial_session(session)
        return VerifiedReviewedNativeCapabilityMap(
            _CAPABILITY_MAP_TEMPLATE_ID, _CAPABILITY_MAP_TEMPLATE_PATH,
            _CAPABILITY_MAP_TEMPLATE_SHA256, _CAPABILITY_MAP_TEMPLATE_SIZE,
            MappingProxyType(copy.deepcopy(value)), session.compilation_session_handle, self._seal)

    def resolve_adopted_reviewed_capability_map(
            self, normal_session_handle: RootSetupSessionHandle) -> VerifiedReviewedNativeCapabilityMap:
        """Re-resolve the same pinned map under a live adopted setup session."""
        if (self._session_store is None or not isinstance(normal_session_handle, RootSetupSessionHandle)
                or normal_session_handle.session_id not in self._adopted_handoffs):
            raise BootstrapEnrollmentPending("normal setup session has no adopted initial publication")
        live = self._session_store._live(normal_session_handle)
        authorization = self._session_store._proof(live)
        handoff = self._adopted_handoffs[normal_session_handle.session_id]
        if (handoff.normal_setup_session_id != normal_session_handle.session_id
                or handoff.normal_transaction_handle != authorization.transaction_handle
                or handoff.plan_sha256 != authorization.plan_digest
                or handoff.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("adopted setup handoff no longer authorizes its reviewed map")
        self.actor.verify_current(self.release)
        self._validate_release_closure()
        descriptor, raw = self._release_file(_CAPABILITY_MAP_TEMPLATE_ID)
        if (descriptor.relative_path != _CAPABILITY_MAP_TEMPLATE_PATH
                or descriptor.sha256 != _CAPABILITY_MAP_TEMPLATE_SHA256
                or descriptor.size_bytes != _CAPABILITY_MAP_TEMPLATE_SIZE
                or hashlib.sha256(raw).hexdigest() != _CAPABILITY_MAP_TEMPLATE_SHA256):
            raise BootstrapEnrollmentPending("adopted setup reviewed capability map pin changed")
        document = InstalledBootstrapPolicyResolver._json(raw, "reviewed native capability map")
        if (not isinstance(document, dict) or document.get("id") != _CAPABILITY_MAP_TEMPLATE_ID
                or document.get("prepared_capabilities") != []):
            raise BootstrapEnrollmentPending("adopted setup reviewed capability map is malformed")
        return VerifiedReviewedNativeCapabilityMap(
            _CAPABILITY_MAP_TEMPLATE_ID, _CAPABILITY_MAP_TEMPLATE_PATH,
            _CAPABILITY_MAP_TEMPLATE_SHA256, _CAPABILITY_MAP_TEMPLATE_SIZE,
            MappingProxyType(copy.deepcopy(document)), normal_session_handle.session_id, self._seal)

    def _allowed_plan_artifact_ids(self, session: RootInitialCompilationSession) -> tuple[str, ...]:
        descriptor, raw = self._release_file(session.plan_artifact_id)
        value = self._json(raw, "selected installer plan")
        fields = {"schema", "id", "candidate_git_sha", "baseline_tag", "baseline_tag_object",
                  "baseline_commit", "baseline_tree_sha256", "amendment_manifest_sha256",
                  "allowed_artifact_ids", "bootstrap_policy_artifact_id", "template_artifact_ids",
                  "initial_acceptance_ids"}
        allowed = value.get("allowed_artifact_ids") if isinstance(value, dict) else None
        expected_acceptance = [f"AC{number:02d}" for number in range(1, 19)]
        if (not isinstance(value, dict) or set(value) != fields
                or type(value.get("schema")) is not int or value.get("schema") != 1
                or value.get("id") != session.plan_artifact_id
                or value.get("candidate_git_sha") != self.release.release_commit
                or value.get("baseline_tag") != "hermes-installer-plan-2026-10-09-v1"
                or value.get("baseline_tag_object") != self.release.baseline_tag_object
                or value.get("baseline_commit") != self.release.baseline_commit
                or value.get("baseline_tree_sha256") != self.release.baseline_tree_sha256
                or value.get("amendment_manifest_sha256") != self.release.amendment_manifest_sha256
                or value.get("bootstrap_policy_artifact_id") != _POLICY_ID
                or value.get("template_artifact_ids") != [
                    _TEMPLATE_ID, _IDENTITY_TEMPLATE_ID, _PREPARED_BASE_TEMPLATE_ID,
                    _RECEIPT_TEMPLATE_ID, _COMPOSIO_POLICY_ARTIFACT_ID]
                or value.get("initial_acceptance_ids") != expected_acceptance
                or not isinstance(allowed, list) or not 1 <= len(allowed) <= 4096
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in allowed)
                or allowed != sorted(set(allowed))):
            raise BootstrapEnrollmentPending("selected installed plan has no exact allowlist")
        catalog = self._json(self._release_file(_CATALOG_ID)[1], "installed artifact catalog")
        if not isinstance(catalog, dict) or not isinstance(catalog.get("artifacts"), list):
            raise BootstrapEnrollmentPending("selected release artifact catalog is malformed")
        catalog_ids = {row.get("artifact_id") for row in catalog["artifacts"]
                       if isinstance(row, dict) and isinstance(row.get("sha256"), str)
                       and _SHA.fullmatch(row["sha256"])}
        allowed_ids = tuple(allowed)
        if (any(not isinstance(item, str) or not _ID.fullmatch(item) or item not in catalog_ids
                for item in allowed_ids)
                or allowed_ids != tuple(sorted(catalog_ids))):
            raise BootstrapEnrollmentPending("selected plan allowlist does not join the installed artifact catalog")
        return allowed_ids

    def verify_initial_session(self, session: RootInitialCompilationSession, *,
                               published_receipt: Any | None = None) -> None:
        if (not isinstance(session, RootInitialCompilationSession)
                or session.phase != "initial-compilation"
                or self._sessions.get(session.compilation_session_handle) is not session
                or not secrets.compare_digest(session._seal, self._seal)
                or session._release is not self.release or session._actor is not self.actor
                or session.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("stage-zero compilation context is stale or belongs to another root registry")
        parent_info = os.stat(_SELECTION_PATH.parent, follow_symlinks=False)
        if (stat.S_ISLNK(parent_info.st_mode) or not stat.S_ISDIR(parent_info.st_mode)
                or parent_info.st_uid != 0):
            raise BootstrapEnrollmentPending("initial root selection parent is not a root-owned directory")
        try:
            selection_info = os.stat(_SELECTION_PATH, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            if stat.S_ISLNK(selection_info.st_mode) or not stat.S_ISREG(selection_info.st_mode):
                raise BootstrapEnrollmentPending("unexpected root selection object blocks initial setup")
            # The sole permitted transition from absence is this registry's
            # publisher-minted prepared publication for the same transaction.
            # It is needed to complete the one-use stage-zero handoff after the
            # atomic root selection CAS, never for compiling or overwriting.
            from .setup_policy_publication import RootSetupPublicationReceipt
            if not isinstance(published_receipt, RootSetupPublicationReceipt):
                raise BootstrapEnrollmentPending("initial setup requires verified absence of an existing root selection")
            raw = _read_secure_root_bytes(_SELECTION_PATH, 2 * 1024 * 1024, 0o600)
            installed = self._json(raw, "published initial root selection")
            generation = installed.get("policy_generation") if isinstance(installed, dict) else None
            if (not isinstance(generation, dict)
                    or installed.get("catalog_sha256") != published_receipt.current_selection_catalog_sha256
                    or generation.get("publication_sha256") != published_receipt.publication_sha256
                    or published_receipt.transaction_handle != session.compilation_transaction_handle
                    or published_receipt.state != "prepared"):
                raise BootstrapEnrollmentPending("published root selection is not this stage-zero transaction")
        self.actor.verify_current(self.release)
        self._validate_release_closure()
        actor_receipt = _read_secure_root_bytes(
            self._actor_receipt_root / f"{session.actor_observation_receipt_handle}.json", 64 * 1024, 0o600)
        if self._json(actor_receipt, "stage-zero actor observation") != self._actor_receipt_document(session):
            raise BootstrapEnrollmentPending("stage-zero actor observation journal receipt changed")
        current = _secure_directory_identity(self.root_journal)
        if (current.st_dev, current.st_ino) != (session._root_journal_root["device"],
                                                session._root_journal_root["inode"]):
            raise BootstrapEnrollmentPending("stage-zero root authority journal identity changed")

    def _actor_receipt_document(self, session: RootInitialCompilationSession) -> dict[str, Any]:
        actor = self.actor
        actor_closure = {
            "launcher": list(actor.launcher), "interpreter": list(actor.interpreter),
            "module_origins": [list(row) for row in actor.module_origins],
            "namespace_inodes": [list(row) for row in actor.namespace_inodes],
            "isolated_import_facts": list(actor.isolated_import_facts),
        }
        return {
            "schema": 1, "receipt_handle": session.actor_observation_receipt_handle,
            "phase": "initial-compilation", "compilation_session_handle": session.compilation_session_handle,
            "compilation_transaction_handle": session.compilation_transaction_handle,
            "release_commit": self.release.release_commit,
            "deployment_receipt_sha256": self.release.deployment_receipt_sha256,
            "plan_artifact_id": session.plan_artifact_id, "plan_sha256": session.plan_sha256,
            "template_artifact_id": session.closed_template_artifact_id,
            "template_sha256": session.closed_template_sha256,
            "source_catalog_sha256": session.source_catalog_sha256,
            "actor_pid": actor.pid, "actor_uid": actor.uid, "actor_gid": actor.gid,
            "actor_start_time": actor.start_time,
            "actor_closure_sha256": hashlib.sha256(_canonical(actor_closure, ensure_ascii=False)).hexdigest(),
            "journal_root": dict(session._root_journal_root),
            "issued_monotonic": session.issued_monotonic,
            "expires_monotonic": session.expires_monotonic,
        }

    def _write_actor_receipt(self, session: RootInitialCompilationSession) -> None:
        _atomic_root_file(
            self._actor_receipt_root / f"{session.actor_observation_receipt_handle}.json",
            _canonical(self._actor_receipt_document(session), ensure_ascii=False), 0o600)

    def store_compilation(self, session: RootInitialCompilationSession,
                          compiled: CompiledRootSetupPublication) -> str:
        """Store compiler bytes behind a root-only one-use publication handle."""
        self.verify_initial_session(session)
        if (not isinstance(compiled, CompiledRootSetupPublication) or compiled.schema != 1
                or compiled._session is not session
                or not secrets.compare_digest(compiled._seal, self._seal)
                or not isinstance(compiled.policy_bytes, bytes)
                or not isinstance(compiled.artifact_catalog_bytes, bytes)
                or not isinstance(compiled.selection_document, Mapping)
                or not isinstance(compiled.source_receipt_handles, tuple)):
            raise BootstrapEnrollmentError("compiled publication is not owned by this stage-zero compiler")
        document = dict(compiled.selection_document)
        fields = {"schema", "selection_id", "installer_release_commit", "release_root", "launcher",
                  "interpreter", "module_closure", "plans", "catalog_sha256", "artifact_catalog",
                  "artifact_store", "bootstrap_policies"}
        if set(document) != fields or document.get("schema") != 1 or document.get("selection_id") != _SELECTION_ID:
            raise BootstrapEnrollmentError("compiled root selection has unknown or missing fields")
        if (document.get("installer_release_commit") != self.release.release_commit
                or document.get("release_root", {}).get("absolute_path") != str(self.release.release_root)
                or document.get("release_root", {}).get("device") != self.release.root_device
                or document.get("release_root", {}).get("inode") != self.release.root_inode
                or document.get("release_root", {}).get("deployment_receipt_sha256")
                   != self.release.deployment_receipt_sha256):
            raise BootstrapEnrollmentError("compiled selection does not bind the current sealed release")
        plan_rows = document.get("plans")
        if not isinstance(plan_rows, list) or len(plan_rows) != 1 or not isinstance(plan_rows[0], dict):
            raise BootstrapEnrollmentError("compiled selection must contain only its verified setup plan")
        plan = plan_rows[0]
        plan_file = next((row for row in self.release.files
                          if row.artifact_id == session.plan_artifact_id), None)
        plan_fields = {"artifact_id", "relative_path", "sha256", "baseline_tag_object", "baseline_commit",
                       "baseline_tree_sha256", "amendment_manifest_sha256", "allowed_artifact_ids",
                       "bootstrap_policy_artifact_id"}
        expected_allowed = self._allowed_plan_artifact_ids(session)
        if (plan_file is None or set(plan) != plan_fields or plan["artifact_id"] != session.plan_artifact_id
                or plan["relative_path"] != plan_file.relative_path
                or plan["sha256"] != session.plan_sha256 or plan["bootstrap_policy_artifact_id"] != _POLICY_ID
                or plan["baseline_tag_object"] != self.release.baseline_tag_object
                or plan["baseline_commit"] != self.release.baseline_commit
                or plan["baseline_tree_sha256"] != self.release.baseline_tree_sha256
                or plan["amendment_manifest_sha256"] != self.release.amendment_manifest_sha256
                or plan["allowed_artifact_ids"] != list(expected_allowed)):
            raise BootstrapEnrollmentError("compiled root plan does not exactly join its selected release")
        policy_sha = hashlib.sha256(compiled.policy_bytes).hexdigest()
        policy_rows = document.get("bootstrap_policies")
        if (not isinstance(policy_rows, list) or len(policy_rows) != 1
                or policy_rows[0] != {"artifact_id": _POLICY_ID,
                                      "relative_path": "plans/bootstrap-policy-v1.json",
                                      "sha256": policy_sha}):
            raise BootstrapEnrollmentError("compiled selection does not pin the exact policy bytes")
        source_catalog = self._json(self._release_file(_CATALOG_ID)[1], "installed artifact catalog")
        if (not isinstance(source_catalog, dict) or set(source_catalog) != {"schema", "artifacts", "packages"}
                or source_catalog.get("schema") != 1 or not isinstance(source_catalog.get("artifacts"), list)):
            raise BootstrapEnrollmentError("selected release artifact catalog is malformed")
        allowed_catalog_ids = {row.get("artifact_id") for row in source_catalog["artifacts"]
                               if isinstance(row, dict)}
        if (not plan["allowed_artifact_ids"]
                or any(item not in allowed_catalog_ids for item in plan["allowed_artifact_ids"])):
            raise BootstrapEnrollmentError("compiled plan allowlist does not join the installed artifact catalog")
        selection_digest = document.get("catalog_sha256")
        unsigned = {key: value for key, value in document.items() if key != "catalog_sha256"}
        if (not isinstance(selection_digest, str) or not _SHA.fullmatch(selection_digest)
                or hashlib.sha256(_canonical(unsigned, ensure_ascii=False)).hexdigest() != selection_digest):
            raise BootstrapEnrollmentError("compiled selection catalog digest is invalid")
        if any(not isinstance(handle, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", handle)
               for handle in compiled.source_receipt_handles):
            raise BootstrapEnrollmentError("compiled source receipt handle is malformed")
        handle = secrets.token_hex(32)
        self._publications[handle] = (session, compiled, selection_digest, False)
        return handle

    def package_compilation(
            self, session: RootInitialCompilationSession, policy_bytes: bytes,
            artifact_catalog_bytes: bytes, selection_document: Mapping[str, Any], *,
            source_receipt_handles: tuple[str, ...] = ()) -> CompiledRootSetupPublication:
        """Seal strict renderer output to this exact live stage-zero session.

        This is deliberately a package operation rather than a policy-row
        callback: the renderer supplies canonical bytes, while this registry
        binds them to its unforgeable session seal and the store path performs
        the complete schema, release, plan and digest validation.
        """
        self.verify_initial_session(session)
        if (not isinstance(policy_bytes, bytes) or not policy_bytes
                or len(policy_bytes) > 2 * 1024 * 1024
                or not isinstance(artifact_catalog_bytes, bytes) or not artifact_catalog_bytes
                or len(artifact_catalog_bytes) > 16 * 1024 * 1024
                or not isinstance(selection_document, Mapping)
                or not isinstance(source_receipt_handles, tuple)):
            raise BootstrapEnrollmentError("compiler output is outside the bounded strict publication schema")
        document = dict(selection_document)
        if document.get("catalog_sha256") != hashlib.sha256(
                _canonical({key: value for key, value in document.items() if key != "catalog_sha256"},
                           ensure_ascii=False)).hexdigest():
            raise BootstrapEnrollmentError("compiler selection digest does not match its canonical document")
        compiled = CompiledRootSetupPublication(
            1, policy_bytes, artifact_catalog_bytes, copy.deepcopy(document),
            source_receipt_handles, session, self._seal)
        return compiled

    def claim_compilation(self, publication_handle: str,
                          expected_selection_catalog_sha256: str | None) -> _RootCompilerPublicationClaim:
        row = self._publications.get(publication_handle)
        if row is None or row[3]:
            raise BootstrapEnrollmentPending("compiler publication handle is absent or already claimed")
        session, compiled, digest, _claimed = row
        self.verify_initial_session(session)
        if expected_selection_catalog_sha256 is not None and not _SHA.fullmatch(expected_selection_catalog_sha256):
            raise BootstrapEnrollmentError("publication predecessor catalog digest is malformed")
        if expected_selection_catalog_sha256 != session.expected_predecessor_catalog_sha256:
            raise BootstrapEnrollmentError("publication predecessor differs from the stage-zero observed selection")
        self._publications[publication_handle] = (session, compiled, digest, True)
        policy = self._json(compiled.policy_bytes, "compiled bootstrap policy")
        if not isinstance(policy, dict) or policy.get("id") != _POLICY_ID:
            raise BootstrapEnrollmentError("compiler bytes are not the fixed bootstrap policy document")
        plan = dict(compiled.selection_document["plans"][0])
        return _RootCompilerPublicationClaim(
            publication_handle, session, session.compilation_transaction_handle,
            session.plan_artifact_id, session.plan_sha256, _POLICY_ID,
            hashlib.sha256(compiled.policy_bytes).hexdigest(), digest, self.release.release_commit,
            _JOURNAL_ID, session.actor_observation_receipt_handle, compiled.policy_bytes,
            compiled.artifact_catalog_bytes, copy.deepcopy(dict(compiled.selection_document)),
            compiled.source_receipt_handles, session.closed_template_artifact_id,
            session.closed_template_sha256, session.choices_sha256, session.source_catalog_sha256,
            expected_selection_catalog_sha256, self._seal,
        )

    def verify_current_compilation(self, claim: _RootCompilerPublicationClaim) -> None:
        if (not isinstance(claim, _RootCompilerPublicationClaim)
                or not secrets.compare_digest(claim._seal, self._seal)):
            raise BootstrapEnrollmentError("compiler claim is not owned by this root registry")
        self.verify_initial_session(claim.session)
        row = self._publications.get(claim.publication_handle)
        if row is None or row[0] is not claim.session or not row[3]:
            raise BootstrapEnrollmentPending("compiler publication claim is stale")

    def release_compilation(self, publication_handle: str) -> None:
        row = self._publications.get(publication_handle)
        if row is not None and row[3]:
            self._publications[publication_handle] = (*row[:3], False)

    def complete_publication(self, receipt: Any) -> str:
        from .setup_policy_publication import RootSetupPublicationReceipt
        if not isinstance(receipt, RootSetupPublicationReceipt):
            raise BootstrapEnrollmentError("initial publication requires a publisher-minted receipt")
        matches = [(handle, row) for handle, row in self._publications.items()
                   if row[0].compilation_transaction_handle == receipt.transaction_handle and row[3]]
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("publication receipt does not join one current compiler claim")
        publication_handle, (session, compiled, _digest, _claimed) = matches[0]
        self.verify_initial_session(session, published_receipt=receipt)
        if (receipt.transaction_handle != session.compilation_transaction_handle
                or receipt.policy_sha256 != hashlib.sha256(compiled.policy_bytes).hexdigest()
                or receipt.artifact_catalog_sha256 != hashlib.sha256(compiled.artifact_catalog_bytes).hexdigest()
                or receipt.input_receipt_handles != (session.actor_observation_receipt_handle,
                                                     *compiled.source_receipt_handles)
                or receipt.previous_selection_catalog_sha256 is not None
                or receipt.state != "prepared"):
            raise BootstrapEnrollmentPending("publication receipt does not bind the exact compiled generation")
        handoff_handle = secrets.token_hex(32)
        handoff = RootInitialPublicationHandoff(
            1, handoff_handle, session.compilation_session_handle,
            session.compilation_transaction_handle, receipt.receipt_handle,
            receipt.publication_sha256, session.plan_sha256, session.choices_sha256,
            session._choices.selected_principal_binding_receipt_handle,
            compiled.source_receipt_handles, time.monotonic(), session.expires_monotonic,
            _publication_receipt=receipt, _initial_session=session, _registry_seal=self._seal)
        self._handoffs[handoff_handle] = {"publication_receipt": receipt,
                                         "publication_receipt_handle": receipt.receipt_handle,
                                         "session": session,
                                         "typed": handoff,
                                         "compilation_session_handle": session.compilation_session_handle,
                                         "compilation_transaction_handle": session.compilation_transaction_handle,
                                         "plan_sha256": session.plan_sha256,
                                         "choices_sha256": session.choices_sha256,
                                         "principal_selection_receipt_handle":
                                             session._choices.selected_principal_binding_receipt_handle,
                                         "artifact_receipt_handles": compiled.source_receipt_handles}
        self._publications.pop(publication_handle, None)
        self._sessions.pop(session.compilation_session_handle, None)
        return handoff_handle

    def finish_publication(self, receipt: Any) -> str:
        return self.complete_publication(receipt)

    def resolve_handoff_for_receipt(self, publication_receipt_handle: str) -> str:
        if not isinstance(publication_receipt_handle, str) or not _ID.fullmatch(publication_receipt_handle):
            raise BootstrapEnrollmentError("publication receipt handle is malformed")
        matches = [handle for handle, row in self._handoffs.items()
                   if row["publication_receipt_handle"] == publication_receipt_handle]
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("initial publication handoff is absent or already adopted")
        handle = matches[0]
        row = self._handoffs[handle]
        session = row["session"]
        if session.expires_monotonic <= time.monotonic():
            self._handoffs.pop(handle, None)
            raise BootstrapEnrollmentPending("initial publication handoff expired")
        self.actor.verify_current(self.release)
        receipt = row["publication_receipt"]
        try:
            current = _read_secure_root_bytes(_SELECTION_PATH, 2 * 1024 * 1024, 0o600)
            document = InstalledBootstrapPolicyResolver._json(current, "published root selection")
        except (OSError, BootstrapEnrollmentPending):
            raise BootstrapEnrollmentPending("initial publication selection is not currently installed") from None
        generation = document.get("policy_generation") if isinstance(document, dict) else None
        if (not isinstance(generation, dict)
                or generation.get("publication_sha256") != receipt.publication_sha256
                or document.get("catalog_sha256") != receipt.current_selection_catalog_sha256):
            raise BootstrapEnrollmentPending("initial publication is not the currently selected root generation")
        return handle

    def resolve_handoff(self, handoff_handle: str) -> RootInitialPublicationHandoff:
        row = self._handoffs.get(handoff_handle)
        if row is None:
            raise BootstrapEnrollmentPending("initial publication handoff is absent or already adopted")
        typed = row["typed"]
        if (not isinstance(typed, RootInitialPublicationHandoff)
                or not secrets.compare_digest(typed._registry_seal, self._seal)
                or typed.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("initial publication handoff is expired or unsealed")
        self.resolve_handoff_for_receipt(typed.publication_receipt_handle)
        return typed

    def adopt_handoff(self, handoff_handle: str, normal_session_handle: RootSetupSessionHandle,
                      session_store: RootSetupSessionStore) -> RootInitialPublicationHandoff:
        from .bootstrap_enrollment import RootSetupSessionStore as StoreType
        if not isinstance(session_store, StoreType):
            raise BootstrapEnrollmentError("initial handoff requires the concrete installed root session store")
        handoff = self.resolve_handoff(handoff_handle)
        live = session_store._live(normal_session_handle)
        authorization = session_store._proof(live)
        initial = handoff._initial_session
        if (initial is None or authorization.plan_artifact_id != initial.plan_artifact_id
                or authorization.plan_digest != initial.plan_sha256
                or authorization.mode != initial._choices.mode):
            raise BootstrapEnrollmentPending("new setup session does not join the exact stage-zero handoff")
        if self._session_store is not None and self._session_store is not session_store:
            raise BootstrapEnrollmentError("handoff registry is already bound to another root setup store")
        self._session_store = session_store
        adopted = RootInitialPublicationHandoff(
            handoff.schema, handoff.handoff_handle, handoff.compilation_session_handle,
            handoff.compilation_transaction_handle, handoff.publication_receipt_handle,
            handoff.publication_sha256, handoff.plan_sha256, handoff.choices_sha256,
            handoff.principal_selection_receipt_handle, handoff.artifact_receipt_handles,
            handoff.issued_monotonic, handoff.expires_monotonic,
            normal_session_handle.session_id, authorization.transaction_handle,
            handoff._publication_receipt, initial, self._seal)
        self._handoffs.pop(handoff_handle, None)
        self._adopted_handoffs[normal_session_handle.session_id] = adopted
        return adopted

    def resolve_adopted_handoff(self, normal_session_handle: RootSetupSessionHandle) -> RootInitialPublicationHandoff:
        if self._session_store is None:
            raise BootstrapEnrollmentPending("no root setup handoff has been adopted")
        live = self._session_store._live(normal_session_handle)
        authorization = self._session_store._proof(live)
        adopted = self._adopted_handoffs.get(normal_session_handle.session_id)
        if (adopted is None or adopted.normal_transaction_handle != authorization.transaction_handle
                or adopted.normal_setup_session_id != normal_session_handle.session_id
                or adopted.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(adopted._registry_seal, self._seal)):
            raise BootstrapEnrollmentPending("normal setup session has no current adopted initial handoff")
        self.actor.verify_current(self.release)
        return adopted

    def _root_journal_row(self) -> Mapping[str, Any]:
        info = _secure_directory_identity(self.root_journal)
        return {
            "root_id": _JOURNAL_ID, "absolute_path": str(self.root_journal),
            "owner_uid": 0, "owner_gid": 0, "mode": 0o700,
            "device": info.st_dev, "inode": info.st_ino,
            "generation": f"journal-{info.st_dev:x}-{info.st_ino:x}",
            "purpose": "authority-journal",
        }

    def _validate_release_closure(self) -> None:
        from .installer_release import InstallerReleaseError
        try:
            self.actor.verify_current(self.release)
            files = {row.artifact_id: row for row in self.release.files}
            required_ids = (_LAUNCHER_ID, _INTERPRETER_ID, _PLAN_ID, _CATALOG_ID,
                            _PLAN_TEMPLATE_ID,
                            _TEMPLATE_ID, _IDENTITY_TEMPLATE_ID,
                            _PREPARED_BASE_TEMPLATE_ID, _COMPOSIO_POLICY_ARTIFACT_ID,
                            _RECEIPT_TEMPLATE_ID, _CAPABILITY_MAP_TEMPLATE_ID)
            if any(artifact_id not in files for artifact_id in required_ids):
                raise BootstrapEnrollmentPending("installed release closure is missing a fixed setup input")
            template = files[_TEMPLATE_ID]
            identity_template = files[_IDENTITY_TEMPLATE_ID]
            prepared_base_template = files[_PREPARED_BASE_TEMPLATE_ID]
            composio_policy = files[_COMPOSIO_POLICY_ARTIFACT_ID]
            receipt_template = files[_RECEIPT_TEMPLATE_ID]
            capability_map = files[_CAPABILITY_MAP_TEMPLATE_ID]
            plan_template = files[_PLAN_TEMPLATE_ID]
            plan = files[self.release.selected_plan_artifact_id]
            catalog = files[_CATALOG_ID]
            if (template.sha256 != "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5"
                    or template.relative_path != "plans/amendments/2026-10-09-closed-bootstrap-compiler-template-v30/bootstrap-compiler-template-v1.json"
                    or plan.sha256 != self.release.selected_plan_sha256
                    or "plan" not in plan.roles or "artifact-catalog" not in catalog.roles):
                raise BootstrapEnrollmentPending("installed release does not include the exact selected compiler inputs")
            if (identity_template.sha256 != "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8"
                    or identity_template.relative_path != "templates/authentik-policy-template-v1.json"):
                raise BootstrapEnrollmentPending("installed release lacks the exact selected identity-policy template")
            if (prepared_base_template.sha256 != "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953"
                    or prepared_base_template.relative_path != "templates/prepared-authority-base-template-v1.json"
                    or "template" not in prepared_base_template.roles):
                raise BootstrapEnrollmentPending("installed release lacks the exact v63 prepared authority-base template")
            if (composio_policy.sha256 != _COMPOSIO_POLICY_SHA256
                    or composio_policy.relative_path != _COMPOSIO_POLICY_PATH
                    or composio_policy.size_bytes != 528 or "template" not in composio_policy.roles):
                raise BootstrapEnrollmentPending("installed release lacks the exact v63 Composio reader policy")
            if (receipt_template.sha256 != _RECEIPT_TEMPLATE_SHA256
                    or receipt_template.relative_path != _RECEIPT_TEMPLATE_PATH
                    or receipt_template.size_bytes != _RECEIPT_TEMPLATE_SIZE
                    or "template" not in receipt_template.roles):
                raise BootstrapEnrollmentPending("installed release lacks the exact v72 receipt-binding template")
            if (capability_map.sha256 != _CAPABILITY_MAP_TEMPLATE_SHA256
                    or capability_map.relative_path != _CAPABILITY_MAP_TEMPLATE_PATH
                    or capability_map.size_bytes != _CAPABILITY_MAP_TEMPLATE_SIZE
                    or "template" not in capability_map.roles):
                raise BootstrapEnrollmentPending("installed release lacks the exact v91 capability-map template")
            if (plan_template.sha256 != "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5"
                    or plan_template.relative_path != "templates/root-setup-plan-template-v1.json"
                    or plan_template.size_bytes != 920
                    or "template" not in plan_template.roles):
                raise BootstrapEnrollmentPending("installed release lacks the exact v81 setup-plan template")
        except InstallerReleaseError:
            raise BootstrapEnrollmentPending("installed release or root actor changed during stage-zero compilation") from None

    def _release_file(self, artifact_id: str) -> Any:
        self._validate_release_closure()
        descriptor = {row.artifact_id: row for row in self.release.files}.get(artifact_id)
        if descriptor is None:
            raise BootstrapEnrollmentPending("required compiler artifact is absent from the installed release")
        fd = self.release.open_file(artifact_id)
        try:
            info = os.fstat(fd)
            if info.st_size != descriptor.size_bytes or not stat.S_ISREG(info.st_mode):
                raise BootstrapEnrollmentPending("installed compiler input is not the selected regular file")
            raw = bytearray()
            while len(raw) <= 16 * 1024 * 1024:
                block = os.read(fd, min(131072, 16 * 1024 * 1024 + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            if len(raw) != descriptor.size_bytes or hashlib.sha256(raw).hexdigest() != descriptor.sha256:
                raise BootstrapEnrollmentPending("installed compiler input bytes differ from release receipt")
            return descriptor, bytes(raw)
        finally:
            os.close(fd)

    @staticmethod
    def _validate_choices(value: Any) -> RootSetupChoices:
        if not isinstance(value, RootSetupChoices):
            raise BootstrapEnrollmentError("stage-zero setup choices must use the fixed typed schema")
        if (value.mode not in {"install", "repair", "resume"}
                or not isinstance(value.target_account_name, str)
                or not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", value.target_account_name)):
            raise BootstrapEnrollmentError("stage-zero mode or target account choice is malformed")
        try:
            account = pwd.getpwnam(value.target_account_name)
        except KeyError:
            raise BootstrapEnrollmentPending("selected local target account does not exist") from None
        if account.pw_uid <= 0 or account.pw_gid <= 0:
            raise BootstrapEnrollmentError("stage-zero setup cannot target root")
        principal = value.selected_principal_binding_receipt_handle
        if principal is not None and (not isinstance(principal, str)
                                      or not re.fullmatch(r"[0-9a-f]{64}", principal)):
            raise BootstrapEnrollmentError("selected principal receipt handle is malformed")
        if (not isinstance(value.selected_component_ids, tuple) or len(value.selected_component_ids) > 256
                or any(not isinstance(item, str) or not _ID.fullmatch(item)
                       for item in value.selected_component_ids)
                or len(set(value.selected_component_ids)) != len(value.selected_component_ids)
                or not isinstance(value.owned_adoption_receipt_handles, tuple)
                or len(value.owned_adoption_receipt_handles) > 256
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                       for item in value.owned_adoption_receipt_handles)
                or len(set(value.owned_adoption_receipt_handles)) != len(value.owned_adoption_receipt_handles)):
            raise BootstrapEnrollmentError("stage-zero selected component or adoption references are malformed")
        return value


class RootComposioSetupSelectionAuthority:
    """Root-only, one-use grant issuer for the fixed WhatsApp trigger catalog GET."""

    _SLUG = re.compile(r"[A-Z][A-Z0-9_]{0,127}\Z")
    _PROJECT = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
    _CURSOR = re.compile(r"[^\x00-\x20\x7f]{1,1024}\Z")

    def __init__(self, verified_release: Any, current_actor_verifier: Any,
                 initial_or_normal_session_registry: Any, root_credential_vault: Any,
                 root_journal: Path, *, principal_selection_registry: Any):
        from .installer_release import VerifiedInstallerReleaseReceipt
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        if (os.geteuid() != 0 or not InstalledBootstrapPolicyResolver._linux()
                or not isinstance(verified_release, VerifiedInstallerReleaseReceipt)
                or not callable(getattr(current_actor_verifier, "verify_current", None))
                or not callable(getattr(root_credential_vault, "resolve_project_reference", None))
                or not isinstance(principal_selection_registry, RootSetupPrincipalSelectionRegistry)
                or not isinstance(root_journal, Path) or root_journal != Path("/var/lib/hermes-installer/authority-journal")):
            raise BootstrapEnrollmentPending("Composio setup authority requires installed root actor, project-scoped vault, principal registry and fixed journal")
        if not (hasattr(initial_or_normal_session_registry, "resolve_initial_session")
                or isinstance(initial_or_normal_session_registry, RootSetupSessionStore)):
            raise BootstrapEnrollmentPending("Composio setup authority requires a concrete stage-zero or normal root session store")
        verified_release.verify_current()
        cls._verify_reader_policy(verified_release)
        _secure_directory_identity(root_journal)
        self.release = verified_release
        self.actor_verifier = current_actor_verifier
        self.sessions = initial_or_normal_session_registry
        self.vault = root_credential_vault
        self.principal_registry = principal_selection_registry
        self.root_journal = root_journal
        self._journal_identity = _secure_directory_identity(root_journal)
        self._root = root_journal / "composio-catalog-read"
        _ensure_root_directory(self._root)
        self._root_identity = _secure_directory_identity(self._root)
        self._seal = secrets.token_hex(32)
        self._authorizations: dict[str, RootComposioCatalogReadAuthorization] = {}
        self._grants: dict[str, RootComposioCatalogGetGrant] = {}
        self._used_grants: set[str] = set()
        self._next_cursor: dict[str, str | None] = {}
        self._seen_cursors: dict[str, set[str]] = {}
        self._page_count: dict[str, int] = {}
        self._pagination_finished: dict[str, bool] = {}
        self._last_page_receipt: dict[str, str | None] = {}
        self._catalog_records: dict[str, dict[str, tuple[Mapping[str, Any], str]]] = {}
        self._listed_rows: dict[str, int] = {}
        self._exchange_receipts: dict[str, RootComposioCatalogReadReceipt] = {}
        self._exchange_authorizations: dict[str, str] = {}
        self._exchange_detail_slugs: dict[str, str] = {}
        self._exchange_request_bytes: dict[str, bytes] = {}

    @staticmethod
    def _verify_reader_policy(release: Any) -> None:
        rows = [row for row in release.files if row.artifact_id == _COMPOSIO_POLICY_ARTIFACT_ID]
        if (len(rows) != 1 or rows[0].relative_path != _COMPOSIO_POLICY_PATH
                or rows[0].sha256 != _COMPOSIO_POLICY_SHA256 or rows[0].size_bytes != 528
                or "template" not in rows[0].roles):
            raise BootstrapEnrollmentPending("installed release lacks the exact v63 Composio reader policy template")
        fd = release.open_file(_COMPOSIO_POLICY_ARTIFACT_ID)
        try:
            raw = bytearray()
            while len(raw) <= 528:
                block = os.read(fd, 529 - len(raw))
                if not block:
                    break
                raw.extend(block)
        finally:
            os.close(fd)
        expected = json.dumps(_COMPOSIO_POLICY, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=True).encode("ascii")
        if (len(raw) != 528 or bytes(raw) != expected
                or hashlib.sha256(raw).hexdigest() != _COMPOSIO_POLICY_SHA256):
            raise BootstrapEnrollmentPending("installed Composio reader policy bytes differ from v63")

    @classmethod
    def from_root_setup(cls, verified_release: Any, current_actor_verifier: Any,
                        initial_or_normal_session_registry: Any, root_credential_vault: Any,
                        root_journal: Path, *, principal_selection_registry: Any
                        ) -> "RootComposioSetupSelectionAuthority":
        return cls(verified_release, current_actor_verifier,
                   initial_or_normal_session_registry, root_credential_vault,
                   root_journal, principal_selection_registry=principal_selection_registry)

    @property
    def request_policy_sha256(self) -> str:
        return _COMPOSIO_POLICY_SHA256

    def authorize_whatsapp_catalog_read(
            self, session_handle: Any, *, project_id: str,
            project_api_key_reference: str,
            principal_selection_receipt_handle: str,
            toolkit_version: str) -> RootComposioCatalogReadAuthorization:
        context = self._resolve_session(session_handle)
        if (not isinstance(project_id, str) or not self._PROJECT.fullmatch(project_id)
                or not isinstance(project_api_key_reference, str)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,96}", project_api_key_reference)
                or toolkit_version != _COMPOSIO_TOOLKIT_VERSION):
            raise BootstrapEnrollmentError("Composio setup selection is malformed or differs from the pinned toolkit version")
        expected_principal_handle = context["principal_receipt_handle"]
        if (not isinstance(expected_principal_handle, str)
                or not secrets.compare_digest(expected_principal_handle, principal_selection_receipt_handle)):
            raise BootstrapEnrollmentPending("Composio setup authorization requires the currently selected root principal receipt")
        principal = self._resolve_selected_principal(context, principal_selection_receipt_handle)
        if not isinstance(principal.principal_id, str) or not self._PROJECT.fullmatch(principal.principal_id):
            raise BootstrapEnrollmentPending("selected root principal is malformed")
        try:
            secret = self.vault.resolve_project_reference(
                project_api_key_reference, peer_uid=0, required_scope=_COMPOSIO_SCOPE,
                principal_id=principal.principal_id, project_id=project_id)
        except Exception:
            raise BootstrapEnrollmentPending("selected Composio project key is absent or not bound to this project, principal and scope") from None
        if not isinstance(secret, str) or not secret or len(secret) > 16384:
            raise BootstrapEnrollmentPending("selected Composio project key reference is invalid")
        del secret
        now = time.monotonic()
        expires = min(now + 30.0, context["expires_monotonic"], principal.expires_monotonic)
        if expires <= now:
            raise BootstrapEnrollmentPending("Composio setup authorization lease is already expired")
        handle = secrets.token_hex(32)
        authorization = RootComposioCatalogReadAuthorization(
            1, handle, context["session_id"], context["transaction_handle"],
            context["plan_sha256"], principal.principal_id, project_id,
            project_api_key_reference, _COMPOSIO_SCOPE, _COMPOSIO_OPERATION,
            f"composio:whatsapp:catalog:{toolkit_version}", toolkit_version,
            _COMPOSIO_POLICY_ARTIFACT_ID,
            _COMPOSIO_POLICY_SHA256, now, expires,
            principal_selection_receipt_handle, self._seal)
        self._authorizations[handle] = authorization
        self._next_cursor[handle] = None
        self._seen_cursors[handle] = set()
        self._page_count[handle] = 0
        self._catalog_records[handle] = {}
        self._listed_rows[handle] = 0
        self._pagination_finished[handle] = False
        self._last_page_receipt[handle] = None
        self._write_authorization(authorization)
        return authorization

    def authorize_catalog_get(self, authorization_handle: str, *,
                              trigger_slug: str | None = None) -> RootComposioCatalogGetGrant:
        authorization = self._resolve_authorization(authorization_handle)
        if any(grant.authorization_handle == authorization_handle
               for grant in self._grants.values()):
            raise BootstrapEnrollmentPending("a Composio catalog GET grant is already outstanding")
        cursor: str | None = None
        if trigger_slug is None:
            if self._pagination_finished[authorization_handle]:
                raise BootstrapEnrollmentPending("Composio catalog pagination is already complete")
            if self._page_count[authorization_handle] >= 10:
                raise BootstrapEnrollmentPending("Composio catalog pagination reached its reviewed page bound")
            cursor = self._next_cursor[authorization_handle]
            if cursor is not None and cursor in self._seen_cursors[authorization_handle]:
                raise BootstrapEnrollmentPending("Composio catalog cursor was already consumed")
            query: dict[str, Any] = {
                "toolkit_slugs": ["whatsapp"],
                "toolkit_versions": MappingProxyType({"whatsapp": authorization.toolkit_version}),
                "limit": 50,
            }
            if cursor is not None:
                query["cursor"] = cursor
            path = "/api/v3.1/triggers_types"
            self._page_count[authorization_handle] += 1
            if cursor is not None:
                self._seen_cursors[authorization_handle].add(cursor)
        else:
            if (not isinstance(trigger_slug, str) or not self._SLUG.fullmatch(trigger_slug)
                    or trigger_slug not in self._catalog_records[authorization_handle]):
                raise BootstrapEnrollmentPending("Composio trigger detail slug was not returned by this selected authenticated catalog")
            query = {"toolkit_versions": MappingProxyType({"whatsapp": authorization.toolkit_version})}
            path = f"/api/v3.1/triggers_types/{trigger_slug}"
        now = time.monotonic()
        handle = secrets.token_hex(32)
        grant = RootComposioCatalogGetGrant(
            handle, authorization_handle, authorization.session_handle,
            authorization.transaction_handle, authorization.plan_sha256,
            authorization.principal_id, authorization.project_id,
            authorization.credential_reference_id, path, MappingProxyType(query),
            _COMPOSIO_ORIGIN, "GET", authorization.toolkit_version,
            _COMPOSIO_POLICY_ARTIFACT_ID, authorization.request_policy_sha256,
            now, authorization.expires_monotonic,
            trigger_slug, self._seal)
        self._grants[handle] = grant
        return grant

    def resolve_project_credential(self, grant: RootComposioCatalogGetGrant) -> str:
        authorization = self._resolve_grant(grant)
        try:
            return self.vault.resolve_project_reference(
                authorization.credential_reference_id, peer_uid=0,
                required_scope=authorization.required_scope,
                principal_id=authorization.principal_id, project_id=authorization.project_id)
        except Exception:
            raise BootstrapEnrollmentPending("Composio project credential scope or binding changed") from None

    def record_catalog_exchange(self, grant: RootComposioCatalogGetGrant, *,
                                http_status: int, response_body: bytes) -> str:
        authorization = self._resolve_grant(grant)
        if (type(http_status) is not int or not 100 <= http_status <= 599
                or not isinstance(response_body, bytes)
                or len(response_body) > _COMPOSIO_POLICY["max_response_bytes"]):
            raise BootstrapEnrollmentError("Composio catalog response exceeds the fixed response bounds")
        now = time.monotonic()
        request = {"schema": 1, "method": grant.method, "origin": grant.origin,
                   "path": grant.path, "query": _plain_json(grant.query),
                   "authorization_handle": grant.authorization_handle,
                   "grant_id": grant.grant_id, "project_id": grant.project_id,
                   "principal_id": grant.principal_id,
                   "toolkit_version": grant.toolkit_version,
                   "request_policy_sha256": grant.request_policy_sha256}
        request_bytes = _canonical(request, ensure_ascii=True)
        request_sha = hashlib.sha256(request_bytes).hexdigest()
        response_sha = hashlib.sha256(response_body).hexdigest()
        exchange_handle = secrets.token_hex(32)
        response_dir = self._root / "responses"
        receipt_dir = self._root / "exchanges"
        _ensure_root_directory(response_dir)
        _ensure_root_directory(receipt_dir)
        body_path = response_dir / f"{response_sha}.json"
        if body_path.exists():
            existing = _read_secure_root_bytes(body_path, _COMPOSIO_POLICY["max_response_bytes"], 0o600)
            if existing != response_body:
                raise BootstrapEnrollmentPending("Composio response CAS digest collision")
        else:
            _atomic_root_file(body_path, response_body, 0o600)
        receipt = RootComposioCatalogExchangeReceipt(
            1, exchange_handle, authorization.authorization_handle,
            authorization.session_handle, authorization.transaction_handle,
            authorization.principal_id, authorization.project_id,
            authorization.toolkit_version, authorization.operation,
            _COMPOSIO_POLICY_ARTIFACT_ID, authorization.request_policy_sha256,
            request_sha, response_sha, len(response_body),
            self._page_count[authorization.authorization_handle],
            self._last_page_receipt[authorization.authorization_handle],
            grant._detail_slug, now, authorization.expires_monotonic)
        journal = {
            "schema": receipt.schema, "receipt_handle": receipt.receipt_handle,
            "authorization_handle": authorization.authorization_handle,
            "session_handle": receipt.session_handle,
            "transaction_handle": receipt.transaction_handle,
            "principal_id": receipt.principal_id,
            "project_id": authorization.project_id,
            "operation": receipt.operation,
            "toolkit_version": authorization.toolkit_version,
            "request_policy_artifact_id": _COMPOSIO_POLICY_ARTIFACT_ID,
            "request_policy_sha256": authorization.request_policy_sha256,
            "request_sha256": request_sha,
            "response_sha256": response_sha, "response_size_bytes": len(response_body),
            "page_sequence": receipt.page_sequence,
            "parent_response_receipt_handle": receipt.parent_response_receipt_handle,
            "selected_slug": receipt.selected_slug,
            "issued_monotonic": now,
            "expires_monotonic": authorization.expires_monotonic,
        }
        _atomic_root_file(receipt_dir / f"{exchange_handle}.json",
                          _canonical(journal, ensure_ascii=True), 0o600)
        self._used_grants.add(grant.grant_id)
        self._grants.pop(grant.grant_id, None)
        if grant._detail_slug is None and http_status == 200:
            self._observe_list_page(authorization, response_body)
            self._last_page_receipt[authorization.authorization_handle] = exchange_handle
        elif grant._detail_slug is not None and http_status == 200:
            self._observe_detail(authorization, grant._detail_slug, response_body)
        if http_status == 200:
            self._exchange_receipts[exchange_handle] = receipt
            self._exchange_authorizations[exchange_handle] = authorization.authorization_handle
            self._exchange_request_bytes[exchange_handle] = request_bytes
            if grant._detail_slug is not None:
                self._exchange_detail_slugs[exchange_handle] = grant._detail_slug
        return exchange_handle

    def resolve_catalog_exchange_receipt(
            self, exchange_receipt_handle: str) -> RootComposioCatalogReadReceipt:
        """Resolve one live, root-retained exchange receipt from this setup."""
        if (os.geteuid() != 0 or not isinstance(exchange_receipt_handle, str)
                or not re.fullmatch(r"[0-9a-f]{64}", exchange_receipt_handle)):
            raise BootstrapEnrollmentPending("Composio exchange receipt handle is malformed or unavailable")
        receipt = self._exchange_receipts.get(exchange_receipt_handle)
        authorization_handle = self._exchange_authorizations.get(exchange_receipt_handle)
        if (not isinstance(receipt, RootComposioCatalogReadReceipt)
                or authorization_handle != receipt.authorization_handle
                or receipt.receipt_handle != exchange_receipt_handle):
            raise BootstrapEnrollmentPending("Composio exchange receipt is not retained by this live setup authority")
        authorization = self._resolve_authorization(authorization_handle)
        if (receipt.session_handle != authorization.session_handle
                or receipt.transaction_handle != authorization.transaction_handle
                or receipt.principal_id != authorization.principal_id
                or receipt.project_id != authorization.project_id
                or receipt.toolkit_version != authorization.toolkit_version
                or receipt.operation != authorization.operation
                or receipt.request_policy_artifact_id != authorization.request_policy_artifact_id
                or receipt.request_policy_sha256 != authorization.request_policy_sha256
                or receipt.expires_monotonic > authorization.expires_monotonic
                or not receipt.issued_monotonic < time.monotonic() < receipt.expires_monotonic):
            raise BootstrapEnrollmentPending("Composio exchange receipt no longer joins the live selected setup")
        receipt_path = self._root / "exchanges" / f"{exchange_receipt_handle}.json"
        try:
            raw = _read_secure_root_bytes(receipt_path, 32 * 1024, 0o600)
            journal = json.loads(raw.decode("ascii"), object_pairs_hook=_unique_pairs)
        except Exception:
            raise BootstrapEnrollmentPending("Composio exchange receipt journal is absent or malformed") from None
        expected = {
            "schema": receipt.schema, "receipt_handle": receipt.receipt_handle,
            "authorization_handle": receipt.authorization_handle,
            "session_handle": receipt.session_handle,
            "transaction_handle": receipt.transaction_handle,
            "principal_id": receipt.principal_id, "project_id": receipt.project_id,
            "operation": receipt.operation, "toolkit_version": receipt.toolkit_version,
            "request_policy_artifact_id": receipt.request_policy_artifact_id,
            "request_policy_sha256": receipt.request_policy_sha256,
            "request_sha256": receipt.request_sha256,
            "response_sha256": receipt.response_sha256,
            "response_size_bytes": receipt.response_size_bytes,
            "page_sequence": receipt.page_sequence,
            "parent_response_receipt_handle": receipt.parent_response_receipt_handle,
            "selected_slug": receipt.selected_slug,
            "issued_monotonic": receipt.issued_monotonic,
            "expires_monotonic": receipt.expires_monotonic,
        }
        if not isinstance(journal, dict) or journal != expected:
            raise BootstrapEnrollmentPending("Composio exchange receipt journal differs from retained root facts")
        return receipt

    def resolve_catalog_request_bytes(self, exchange_receipt_handle: str) -> bytes:
        """Resolve the private canonical request evidence for one live exchange."""
        receipt = self.resolve_catalog_exchange_receipt(exchange_receipt_handle)
        request_bytes = self._exchange_request_bytes.get(exchange_receipt_handle)
        if (not isinstance(request_bytes, bytes)
                or not secrets.compare_digest(hashlib.sha256(request_bytes).hexdigest(),
                                              receipt.request_sha256)):
            raise BootstrapEnrollmentPending("Composio request evidence is absent or differs from its receipt")
        return request_bytes

    def resolve_catalog_response_bytes(self, exchange_receipt_handle: str) -> bytes:
        """Resolve exact private response bytes from the selected root response CAS."""
        receipt = self.resolve_catalog_exchange_receipt(exchange_receipt_handle)
        response_path = self._root / "responses" / f"{receipt.response_sha256}.json"
        try:
            body = _read_secure_root_bytes(
                response_path, _COMPOSIO_POLICY["max_response_bytes"], 0o600)
        except Exception:
            raise BootstrapEnrollmentPending("Composio response evidence is absent from root CAS") from None
        if (len(body) != receipt.response_size_bytes
                or not secrets.compare_digest(hashlib.sha256(body).hexdigest(), receipt.response_sha256)):
            raise BootstrapEnrollmentPending("Composio response bytes differ from its root exchange receipt")
        return body

    def read_verified_trigger_detail(self, exchange_receipt_handle: str,
                                     selected_returned_slug: str
                                     ) -> tuple[RootComposioCatalogReadReceipt, bytes]:
        """Return exact detail bytes only for the selected authenticated GET."""
        receipt = self.resolve_catalog_exchange_receipt(exchange_receipt_handle)
        slug = self._exchange_detail_slugs.get(exchange_receipt_handle)
        if (not isinstance(selected_returned_slug, str)
                or selected_returned_slug != slug or receipt.selected_slug != slug
                or slug not in self._catalog_records.get(receipt.authorization_handle, {})):
            raise BootstrapEnrollmentPending("Composio detail exchange did not inspect the selected catalog slug")
        self.resolve_catalog_request_bytes(exchange_receipt_handle)
        body = self.resolve_catalog_response_bytes(exchange_receipt_handle)
        authorization = self._resolve_authorization(receipt.authorization_handle)
        self._observe_detail(authorization, slug, body)
        return receipt, body

    def _observe_list_page(self, authorization: RootComposioCatalogReadAuthorization,
                           raw: bytes) -> None:
        document = InstalledBootstrapPolicyResolver._json(raw, "Composio trigger catalog response")
        if (not isinstance(document, dict) or not isinstance(document.get("items"), list)
                or len(document["items"]) > 50):
            raise BootstrapEnrollmentPending("Composio trigger catalog response does not match the fixed list schema")
        records = self._catalog_records[authorization.authorization_handle]
        if self._listed_rows[authorization.authorization_handle] + len(document["items"]) > 500:
            raise BootstrapEnrollmentPending("Composio trigger catalog exceeded 500 selected rows")
        for row in document["items"]:
            projection = self._trigger_projection(row, authorization.toolkit_version)
            slug = projection["slug"]
            if slug in records:
                raise BootstrapEnrollmentPending("Composio trigger catalog returned a duplicate slug")
            records[slug] = (MappingProxyType(projection), hashlib.sha256(
                _canonical(projection, ensure_ascii=True)).hexdigest())
        self._listed_rows[authorization.authorization_handle] += len(document["items"])
        cursor = document.get("next_cursor")
        if cursor in (None, ""):
            cursor = None
        if cursor is not None and (not isinstance(cursor, str) or not self._CURSOR.fullmatch(cursor)
                                   or cursor in self._seen_cursors[authorization.authorization_handle]):
            raise BootstrapEnrollmentPending("Composio catalog returned a malformed or replayed cursor")
        self._next_cursor[authorization.authorization_handle] = cursor
        self._pagination_finished[authorization.authorization_handle] = cursor is None

    def _observe_detail(self, authorization: RootComposioCatalogReadAuthorization,
                        slug: str, raw: bytes) -> None:
        row = InstalledBootstrapPolicyResolver._json(raw, "Composio trigger detail response")
        projection = self._trigger_projection(row, authorization.toolkit_version)
        expected = self._catalog_records[authorization.authorization_handle].get(slug)
        digest = hashlib.sha256(_canonical(projection, ensure_ascii=True)).hexdigest()
        if expected is None or projection["slug"] != slug or not secrets.compare_digest(expected[1], digest):
            raise BootstrapEnrollmentPending("Composio trigger detail does not match its authenticated selected catalog row")

    def _trigger_projection(self, row: Any, toolkit_version: str) -> dict[str, Any]:
        if (not isinstance(row, dict) or not isinstance(row.get("slug"), str)
                or not self._SLUG.fullmatch(row["slug"])
                or row.get("version") != toolkit_version
                or not isinstance(row.get("toolkit"), dict)
                or row["toolkit"].get("slug") != "whatsapp"):
            raise BootstrapEnrollmentPending("Composio trigger response row is not the selected WhatsApp version")
        required_fields = {"slug", "name", "description", "type", "config", "payload", "version", "toolkit"}
        optional_fields = {"instructions", "requires_webhook_endpoint_setup"}
        if not required_fields <= set(row) or set(row) - required_fields - optional_fields:
            raise BootstrapEnrollmentPending("Composio trigger response row has unknown or missing fields")
        if (not isinstance(row["name"], str) or len(row["name"]) > 1024
                or not isinstance(row["description"], str) or len(row["description"]) > 8192
                or "instructions" in row and (not isinstance(row["instructions"], str)
                                                or len(row["instructions"]) > 16384)
                or ("requires_webhook_endpoint_setup" in row
                    and type(row["requires_webhook_endpoint_setup"]) is not bool)
                or not isinstance(row["type"], str)
                or not isinstance(row["config"], dict) or not isinstance(row["payload"], dict)):
            raise BootstrapEnrollmentPending("Composio trigger response fields exceed the fixed schema bounds")
        projected = {key: row[key] for key in (
            "slug", "name", "description", "instructions", "type", "config", "payload",
            "requires_webhook_endpoint_setup") if key in row}
        projected["toolkit"] = {"slug": "whatsapp", "version": toolkit_version}
        encoded = _canonical(projected, ensure_ascii=True)
        if len(encoded) > 256 * 1024:
            raise BootstrapEnrollmentPending("Composio trigger schema projection exceeds 256 KiB")
        return projected

    def _resolve_authorization(self, handle: str) -> RootComposioCatalogReadAuthorization:
        if not isinstance(handle, str) or not re.fullmatch(r"[0-9a-f]{64}", handle):
            raise BootstrapEnrollmentPending("Composio setup authorization handle is malformed")
        authorization = self._authorizations.get(handle)
        if (authorization is None or authorization.expires_monotonic <= time.monotonic()
                or not secrets.compare_digest(authorization._seal, self._seal)):
            raise BootstrapEnrollmentPending("Composio setup authorization is absent, expired or unsealed")
        context = self._resolve_session(authorization.session_handle)
        if (context["transaction_handle"] != authorization.transaction_handle
                or context["plan_sha256"] != authorization.plan_sha256
                or context["principal_receipt_handle"] != authorization._principal_receipt_handle):
            raise BootstrapEnrollmentPending("Composio setup authorization no longer joins current root session state")
        if (_secure_directory_identity(self.root_journal) != self._journal_identity
                or _secure_directory_identity(self._root) != self._root_identity):
            raise BootstrapEnrollmentPending("Composio receipt journal custody changed during setup")
        principal = self._resolve_selected_principal(context, authorization._principal_receipt_handle)
        if principal.principal_id != authorization.principal_id:
            raise BootstrapEnrollmentPending("Composio selected principal changed during setup")
        self.release.verify_current()
        self._verify_reader_policy(self.release)
        self.actor_verifier.verify_current(context["plan"])
        return authorization

    def _resolve_grant(self, grant: RootComposioCatalogGetGrant) -> RootComposioCatalogReadAuthorization:
        if (not isinstance(grant, RootComposioCatalogGetGrant)
                or not secrets.compare_digest(grant._seal, self._seal)
                or grant.grant_id in self._used_grants
                or self._grants.get(grant.grant_id) is not grant
                or grant.expires_monotonic <= time.monotonic()
                or grant.origin != _COMPOSIO_ORIGIN or grant.method != "GET"
                or grant.request_policy_artifact_id != _COMPOSIO_POLICY_ARTIFACT_ID
                or grant.request_policy_sha256 != _COMPOSIO_POLICY_SHA256):
            raise BootstrapEnrollmentPending("Composio catalog GET grant is stale, replayed or altered")
        authorization = self._resolve_authorization(grant.authorization_handle)
        query = _plain_json(grant.query)
        if grant._detail_slug is None:
            expected_query = {"toolkit_slugs": ["whatsapp"],
                              "toolkit_versions": {"whatsapp": authorization.toolkit_version},
                              "limit": 50}
            cursor = self._next_cursor[authorization.authorization_handle]
            if cursor is not None:
                expected_query["cursor"] = cursor
            expected_path = "/api/v3.1/triggers_types"
        else:
            expected_query = {"toolkit_versions": {"whatsapp": authorization.toolkit_version}}
            expected_path = f"/api/v3.1/triggers_types/{grant._detail_slug}"
        if grant.path != expected_path or query != expected_query:
            raise BootstrapEnrollmentPending("Composio GET grant does not match its fixed request policy")
        if (grant.session_handle != authorization.session_handle
                or grant.transaction_handle != authorization.transaction_handle
                or grant.plan_sha256 != authorization.plan_sha256
                or grant.principal_id != authorization.principal_id
                or grant.project_id != authorization.project_id
                or grant.credential_reference_id != authorization.credential_reference_id
                or grant.toolkit_version != authorization.toolkit_version
                or grant.request_policy_artifact_id != authorization.request_policy_artifact_id
                or grant.request_policy_sha256 != authorization.request_policy_sha256):
            raise BootstrapEnrollmentPending("Composio GET grant does not join its selected authorization")
        return authorization

    def _resolve_session(self, session_handle: Any) -> Mapping[str, Any]:
        if hasattr(self.sessions, "resolve_initial_session"):
            if not isinstance(session_handle, str):
                raise BootstrapEnrollmentPending("stage-zero Composio authorization requires an opaque initial-session handle")
            session = self.sessions.resolve_initial_session(session_handle)
            plan = self.sessions.resolve_actor_plan(session_handle)
            principal_handle = session.principal_selection_receipt_handle
            expiry = session.expires_monotonic
            session_id = session.compilation_session_handle
            transaction = session.compilation_transaction_handle
            plan_sha = session.plan_sha256
            session.actor.verify_current(self.release)
        else:
            if not isinstance(session_handle, RootSetupSessionHandle):
                raise BootstrapEnrollmentPending("normal Composio authorization requires the typed live root session")
            live = self.sessions._live(session_handle)
            authorization = self.sessions._proof(live)
            plan = self.sessions.plan_resolver.resolve(authorization.plan_artifact_id)
            principal_handle = None
            handoff_resolver = getattr(self.sessions, "initial_compilation_registry", None)
            if handoff_resolver is not None:
                handoff = handoff_resolver.resolve_adopted_handoff(session_handle)
                principal_handle = handoff.principal_selection_receipt_handle
            expiry = live.record["expires_monotonic"]
            session_id = session_handle.session_id
            transaction = authorization.transaction_handle
            plan_sha = authorization.plan_digest
        if (not isinstance(plan, VerifiedRootSetupPlan) or plan.digest != plan_sha
                or not isinstance(principal_handle, str)):
            raise BootstrapEnrollmentPending("current root setup lacks a verified selected-principal lineage")
        self.actor_verifier.verify_current(plan)
        return MappingProxyType({
            "session_id": session_id, "transaction_handle": transaction,
            "plan_sha256": plan_sha, "principal_receipt_handle": principal_handle,
            "expires_monotonic": expiry, "plan": plan,
            "phase": "initial-compilation" if hasattr(self.sessions, "resolve_initial_session") else "normal",
            "session_handle": session_handle,
        })

    def _resolve_selected_principal(self, context: Mapping[str, Any], receipt_handle: str) -> Any:
        if context["phase"] == "initial-compilation":
            return self.principal_registry.resolve_selected_principal(
                receipt_handle, context["session_id"], context["transaction_handle"],
                context["plan_sha256"])
        resolver = getattr(self.principal_registry, "resolve_adopted_initial_principal", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending("adopted setup principal resolver is unavailable")
        principal = resolver(self.sessions, context["session_handle"])
        if (not isinstance(principal.principal_id, str)
                or not self._PROJECT.fullmatch(principal.principal_id)):
            raise BootstrapEnrollmentPending("adopted setup principal is malformed")
        return principal

    def _write_authorization(self, authorization: RootComposioCatalogReadAuthorization) -> None:
        record = {
            "schema": 1, "authorization_handle": authorization.authorization_handle,
            "session_handle": authorization.session_handle,
            "transaction_handle": authorization.transaction_handle,
            "plan_sha256": authorization.plan_sha256,
            "principal_id": authorization.principal_id,
            "project_id": authorization.project_id,
            "credential_reference_id": authorization.credential_reference_id,
            "required_scope": authorization.required_scope,
            "operation": authorization.operation, "target": authorization.target,
            "toolkit_version": authorization.toolkit_version,
            "request_policy_artifact_id": authorization.request_policy_artifact_id,
            "request_policy_sha256": authorization.request_policy_sha256,
            "issued_monotonic": authorization.issued_monotonic,
            "expires_monotonic": authorization.expires_monotonic,
        }
        _atomic_root_file(self._root / f"{authorization.authorization_handle}.json",
                          _canonical(record, ensure_ascii=True), 0o600)


class RootSetupPolicyFactory:
    """Construct prepared and runnable EnrollmentPolicy values from pinned bytes."""

    def __init__(self, resolver: InstalledBootstrapPolicyResolver):
        self.resolver = resolver

    def prepare(self, authorization: VerifiedRootSetupAuthorization) -> EnrollmentPolicy:
        policy = self.resolver.resolve_policy(authorization.plan_artifact_id,
                                              compilation_phase="prepared")
        roots = policy.root_policy
        parent = Path(roots["service_parent_root"])
        self._root_journal_join(authorization)
        selection = policy.catalog_selections
        return EnrollmentPolicy(
            service_profile_id=policy.identity_policy["service_profile_id"],
            principal_id=policy.identity_policy["principal_id"],
            generation_id="prepared-" + secrets.token_hex(16),
            source_artifact_id=policy.source_artifact_id,
            records=(), activation_state="prepared",
            resource_controller_roles=selection["resource_controller_roles"],
            native_mcp_tool_bindings=selection["native_mcp_tool_bindings"],
            remote_observation_enrollments=selection["remote_observation_enrollments"],
            native_schema_artifacts=selection.get("native_schema_artifacts", ()),
            composio_channel_enrollments=selection.get("composio_channel_enrollments", ()),
            channel_delivery_bindings=selection.get("channel_delivery_bindings", ()),
            authority_base=copy.deepcopy(policy.authority_base_template),
            home_root=parent / "home", work_root=parent / "work", data_root=parent / "data",
            root_journal_roots=(dict(authorization.root_journal_root),),
        )

    def activate_runnable(self, authorization: VerifiedRootSetupAuthorization,
                          identity: ServiceIdentity,
                          receipts: Mapping[str, RootRuntimeArtifactReceipt], *,
                          seal: str) -> EnrollmentPolicy:
        policy = self.resolver.resolve_policy(authorization.plan_artifact_id,
                                              compilation_phase="active")
        self._root_journal_join(authorization)
        if not receipts:
            _fail("runnable activation requires actual root-resolved runtime and launcher receipts")
        rows = []
        generation = "active-" + secrets.token_hex(16)
        parent = Path(policy.root_policy["service_parent_root"])
        roots = (parent / "home", parent / "work", parent / "data")
        for template in policy.service_record_templates:
            record = copy.deepcopy(template["record"])
            record["generation"] = generation
            record["service_uid"] = identity.uid
            record["service_gid"] = identity.gid
            record["service_user"] = identity.name
            record["roots"] = {
                "home_id": policy.root_policy["service_home_root_id"],
                "work_id": policy.root_policy["service_work_root_id"],
                "data_id": policy.root_policy["service_data_root_id"],
                "home": str(roots[0]), "work": str(roots[1]), "data": str(roots[2]),
            }
            for binding in template["receipt_bindings"]:
                role = binding["receipt_role"]
                receipt = receipts.get(role)
                rule = next((item for item in policy.receipt_binding_rules
                             if item["receipt_role"] == role), None)
                if (rule is None or rule["required_phase"] != "runnable"
                        or not isinstance(receipt, RootRuntimeArtifactReceipt)
                        or not secrets.compare_digest(receipt._seal, seal)
                        or receipt.role != role or not _ID.fullmatch(receipt.artifact_id)
                        or receipt.artifact_id not in rule["allowed_artifact_ids"]
                        or not _SHA.fullmatch(receipt.sha256)
                        or receipt.generation != authorization.transaction_handle):
                    _fail(f"required root runtime receipt for {role} is absent or not transaction-bound")
                value = getattr(receipt, binding["receipt_field"])
                self._set_template_field(record, binding["field_path"], value)
            rows.append(record)
        selection = policy.catalog_selections
        return EnrollmentPolicy(
            service_profile_id=policy.identity_policy["service_profile_id"],
            principal_id=policy.identity_policy["principal_id"],
            generation_id=generation, source_artifact_id=policy.source_artifact_id,
            records=tuple(rows),
            protected_devices=selection["protected_devices"],
            protected_build_records=selection["protected_build_records"],
            native_packages=selection["native_packages"],
            memory_enrollments=selection["memory_enrollments"],
            operation_parameter_schemas=selection["operation_parameter_schemas"],
            source_issuers=selection["source_issuers"], resource_jobs=selection["resource_jobs"],
            resource_controller_roles=selection["resource_controller_roles"],
            native_mcp_tool_bindings=selection["native_mcp_tool_bindings"],
            remote_observation_enrollments=selection["remote_observation_enrollments"],
            remote_session_enrollments=selection["remote_session_enrollments"],
            resource_backend_enrollments=selection["resource_backend_enrollments"],
            resource_body_recipes=selection["resource_body_recipes"],
            resource_scope_bindings=selection["resource_scope_bindings"],
            resource_validators=selection["resource_validators"],
            native_schema_artifacts=selection.get("native_schema_artifacts", ()),
            composio_channel_enrollments=selection.get("composio_channel_enrollments", ()),
            channel_delivery_bindings=selection.get("channel_delivery_bindings", ()),
            root_journal_roots=(dict(authorization.root_journal_root),), activation_state="active",
            authority_base=copy.deepcopy(policy.authority_base_template),
            home_root=roots[0], work_root=roots[1], data_root=roots[2],
        )

    @staticmethod
    def record_functional_health(_active_receipt: EnrollmentReceipt, _health_receipt: Any) -> None:
        # Functional enablement is intentionally delegated to the lifecycle's
        # root health-receipt journal consumer; this factory never turns a
        # caller status or run exit code into health authority.
        _fail("functional-health receipt consumption belongs to the installed root lifecycle observer")

    @staticmethod
    def _root_journal_join(authorization: VerifiedRootSetupAuthorization) -> None:
        row = authorization.root_journal_root
        fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
                  "device", "inode", "generation", "purpose"}
        if (not isinstance(row, Mapping) or set(row) != fields or row.get("root_id") != _JOURNAL_ID
                or row.get("absolute_path") != "/var/lib/hermes-installer/authority-journal"
                or row.get("owner_uid") != 0 or row.get("owner_gid") != 0
                or row.get("mode") != 0o700 or type(row.get("device")) is not int
                or row.get("device") < 0 or type(row.get("inode")) is not int
                or row.get("inode") <= 0 or not isinstance(row.get("generation"), str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", row["generation"])
                or row.get("purpose") != "authority-journal"):
            _fail("setup session has no current selected root journal identity")

    @staticmethod
    def _set_template_field(record: Any, path: list[str | int], value: Any) -> None:
        current = record
        for segment in path[:-1]:
            if isinstance(segment, int):
                if not isinstance(current, list) or segment >= len(current):
                    _fail("receipt binding path does not resolve inside the reviewed service template")
                current = current[segment]
            else:
                if not isinstance(current, dict) or segment not in current:
                    _fail("receipt binding path does not resolve inside the reviewed service template")
                current = current[segment]
        final = path[-1]
        if isinstance(final, int):
            if not isinstance(current, list) or final >= len(current):
                _fail("receipt binding index is outside the reviewed service template")
            current[final] = value
        else:
            if not isinstance(current, dict) or final not in current or current[final] is not None:
                _fail("receipt binding must replace one explicit null template slot")
            current[final] = value


class RootInitialSetupAggregate:
    """Concrete first-install composition before a selection catalog exists.

    This aggregate is created only by the installed Linux root actor from the
    already verified release and current PID observation. It owns stage-zero
    identity intake, root key selection, strict policy compilation and the
    filesystem publisher; none of those dependencies are supplied by the
    caller as callbacks or policy maps.
    """

    def __init__(self, release: Any, actor: Any, *,
                 root_journal: Path = Path("/var/lib/hermes-installer/authority-journal")):
        if root_journal != Path("/var/lib/hermes-installer/authority-journal"):
            raise BootstrapEnrollmentPending("first setup uses only the fixed root authority journal")
        from .enrollment import RootAuthorityKeySelectionRegistry, RootCredentialVault
        from .initial_policy_compiler import RootFirstStagePolicyCompiler
        from .setup_capabilities import ReviewedNativeCapabilitySelection
        from .setup_policy_publication import RootSetupPolicyGenerationPublisher
        from .setup_principal import (RootSetupAuthentikIdentityObserver,
                                      RootSetupIdentityIntake,
                                      RootSetupPrincipalSelectionRegistry)
        self.release, self.actor, self.root_journal = release, actor, root_journal
        self.initial_registry = RootInitialCompilationRegistry(release, actor, root_journal)
        self.vault = RootCredentialVault()
        self.identity_intake = RootSetupIdentityIntake.from_initial_compilation(
            self.initial_registry, self.initial_registry.actor_verifier, self.vault, root_journal)
        capability_selection = ReviewedNativeCapabilitySelection.from_initial_compilation(
            self.initial_registry)
        self.identity_observer = RootSetupAuthentikIdentityObserver.from_initial_compilation(
            self.initial_registry, self.identity_intake, self.vault, root_journal)
        self.principal_registry = RootSetupPrincipalSelectionRegistry.from_initial_compilation(
            self.initial_registry, self.identity_observer, capability_selection, root_journal)
        self.key_registry = RootAuthorityKeySelectionRegistry.from_installed_release(
            release, self.initial_registry.actor_verifier, root_journal,
            initial_compilation_registry=self.initial_registry)
        self.compiler = RootFirstStagePolicyCompiler.from_installed_release(
            release, actor, initial_compilation_registry=self.initial_registry,
            principal_selection_registry=self.principal_registry,
            authority_key_selection_registry=self.key_registry)
        self.publisher = RootSetupPolicyGenerationPublisher.from_root_setup(
            release, self.initial_registry, root_journal, self.initial_registry)
        self._closed = False
        self._transferred = False

    @classmethod
    def from_current_root_process(cls) -> "RootInitialSetupAggregate":
        from .installer_release import InstalledRootReleaseVerifier
        release, actor = InstalledRootReleaseVerifier.from_current_root_process()
        try:
            return cls(release, actor)
        except Exception:
            actor.close()
            release.close()
            raise

    def begin_install(self, target_account_name: str) -> RootInitialCompilationSession:
        self._require_open()
        return self.initial_registry.begin_initial_compilation(RootSetupChoices(
            "install", target_account_name, None, (), ()))

    def select_initial_identity(self, session_handle: str, *, https_origin: str,
                                system_group_id: str, recipient_group_id: str,
                                secure_existing_vault_reference: str | None = None) -> str:
        """Collect root-only Authentik evidence and bind the selected principal."""
        self._require_open()
        session = self.initial_registry.resolve_initial_session(session_handle)
        policy_handle = self.identity_intake.select_authentik_policy(
            session_handle, https_origin=https_origin,
            system_group_id=system_group_id, recipient_group_id=recipient_group_id)
        self.identity_intake.collect_authentik_actor_credential(
            session_handle, policy_handle,
            secure_existing_vault_reference=secure_existing_vault_reference)
        identity_handle = self.identity_observer.observe_selected_authentik_identity(
            session_handle, policy_handle)
        principal_handle = self.principal_registry.select_principal(session_handle, identity_handle)
        self.initial_registry.bind_selected_principal(
            session.compilation_session_handle, principal_handle, self.principal_registry)
        return principal_handle

    def publish_prepared_selection(self, session_handle: str) -> RootInitialPublicationHandoff:
        """Compile/publish prepared authority and return the one-use root handoff."""
        self._require_open()
        session = self.initial_registry.resolve_initial_session(session_handle)
        if session.principal_selection_receipt_handle is None:
            raise BootstrapEnrollmentPending("root-authenticated principal selection is required before publication")
        compiled = self.compiler.compile_initial_policy_for_session(session)
        publication_handle = self.initial_registry.store_compilation(session, compiled)
        receipt = self.publisher.publish(publication_handle, session.expected_predecessor_catalog_sha256)
        handoff_handle = self.initial_registry.resolve_handoff_for_receipt(receipt.receipt_handle)
        return self.initial_registry.resolve_handoff(handoff_handle)

    def adopt_prepared_selection(self, handoff_handle: str) -> tuple["RootBootstrapRuntimeFactory", "RootBootstrapSession"]:
        """Transfer held release/actor custody into the ordinary setup session."""
        self._require_open()
        factory = RootBootstrapRuntimeFactory(
            _release=self.release, _actor=self.actor,
            _initial_compilation_registry=self.initial_registry)
        self._transferred = True
        try:
            session = factory.begin_from_initial_publication(handoff_handle)
            return factory, session
        except Exception:
            factory.close()
            self._closed = True
            raise

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        for name in ("key_registry",):
            value = getattr(self, name, None)
            close = getattr(value, "close", None)
            if callable(close):
                close()
        if not self._transferred:
            self.actor.close()
            self.release.close()

    def _require_open(self) -> None:
        if self._closed:
            raise BootstrapEnrollmentPending("root initial setup aggregate is closed")
        self.actor.verify_current(self.release)


class RootBootstrapRuntimeFactory:
    """Production root-owned assembly for setup, prepared enrollment and activation."""

    def __init__(self, *, _release: Any | None = None, _actor: Any | None = None,
                 _initial_compilation_registry: "RootInitialCompilationRegistry | None" = None):
        if os.getuid() != 0 or os.geteuid() != 0 or not InstalledBootstrapPolicyResolver._linux():
            raise BootstrapEnrollmentPending("root bootstrap runtime exists only in the installed Linux root process")
        from .installer_release import (InstalledRootReleaseVerifier,
                                        RootActorObservation,
                                        VerifiedInstallerReleaseReceipt)
        if _release is None and _actor is None:
            _release, _actor = InstalledRootReleaseVerifier.from_current_root_process()
        if (not isinstance(_release, VerifiedInstallerReleaseReceipt)
                or not isinstance(_actor, RootActorObservation)):
            raise BootstrapEnrollmentPending("root runtime requires sealed installed-release and actor observations")
        _actor.verify_current(_release)
        self._release = _release
        self._actor = _actor
        if (_initial_compilation_registry is not None
                and (not isinstance(_initial_compilation_registry, RootInitialCompilationRegistry)
                     or _initial_compilation_registry.release is not _release
                     or _initial_compilation_registry.actor is not _actor)):
            raise BootstrapEnrollmentPending("initial publication registry is not bound to this held release actor")
        self._initial_compilation_registry = _initial_compilation_registry
        self.resolver = InstalledBootstrapPolicyResolver(_SELECTION_PATH)
        # Resolving the catalog authenticates the installed catalog bytes before
        # any root store or session object is constructed.
        try:
            catalog = self.resolver.catalog
            self._bind_verified_release()
            self.resolver.resolve_policy(_PLAN_ID, compilation_phase="prepared")
        except Exception:
            self._actor.close()
            self._release.close()
            raise
        journal_root = self.resolver.journal_root
        artifact_root = self.resolver.artifact_root
        _ensure_root_directory(journal_root)
        _ensure_root_directory(artifact_root)
        store_policy = self.resolver._load_selection().artifact_store
        artifact_info = artifact_root.lstat()
        if (artifact_info.st_uid != store_policy["owner_uid"]
                or artifact_info.st_gid != store_policy["owner_gid"]
                or stat.S_IMODE(artifact_info.st_mode) != store_policy["mode"]):
            raise BootstrapEnrollmentError("selected root artifact CAS directory ownership or mode is invalid")
        receipt_registry = RootArtifactReceiptRegistry(
            journal_root / "bootstrap-receipts", catalog=catalog, artifact_root=artifact_root)
        self.session_store = RootSetupSessionStore(
            plan_resolver=self.resolver,
            actor_verifier=InstalledRootSetupActorVerifier(),
            receipt_registry=receipt_registry,
            initial_compilation_registry=_initial_compilation_registry,
            session_root=journal_root / "setup-sessions",
            transaction_root=journal_root / "bootstrap-transactions",
            authority_path=Path("/etc/hermes-installer/authority.json"),
        )
        self.policy_factory = RootSetupPolicyFactory(self.resolver)
        self._catalog = catalog
        self._receipt_registry = receipt_registry
        self._seal = secrets.token_hex(32)
        self._native_assembly_seal = object()
        self._sessions: dict[str, RootBootstrapSession] = {}

    @classmethod
    def from_installed(cls) -> "RootBootstrapRuntimeFactory":
        return cls()

    def _bind_verified_release(self) -> None:
        self._actor.verify_current(self._release)
        selection = self.resolver._load_selection()
        if (selection.installer_release_commit != self._release.release_commit
                or selection.release_root != self._release.release_root
                or selection.release_device != self._release.root_device
                or selection.release_inode != self._release.root_inode
                or selection.deployment_receipt_sha256 != self._release.deployment_receipt_sha256):
            raise BootstrapEnrollmentPending("root selection is not joined to the current sealed release")
        release_files = {row.artifact_id: row for row in self._release.files}
        for row, artifact_id in ((selection.launcher, _LAUNCHER_ID),
                                 (selection.interpreter, _INTERPRETER_ID)):
            source = release_files.get(artifact_id)
            if (source is None or row["relative_path"] != source.relative_path
                    or row["sha256"] != source.sha256):
                raise BootstrapEnrollmentPending("selected root executable differs from the sealed release")
        for row in selection.modules:
            source = release_files.get(row["artifact_id"])
            if source is None or row["relative_path"] != source.relative_path or row["sha256"] != source.sha256:
                raise BootstrapEnrollmentPending("selected root module differs from the sealed release")
        plans = [row for row in selection.plans if row["artifact_id"] == self._release.selected_plan_artifact_id]
        if (len(plans) != 1 or plans[0]["sha256"] != self._release.selected_plan_sha256
                or plans[0]["baseline_tag_object"] != self._release.baseline_tag_object
                or plans[0]["baseline_commit"] != self._release.baseline_commit
                or plans[0]["baseline_tree_sha256"] != self._release.baseline_tree_sha256
                or plans[0]["amendment_manifest_sha256"] != self._release.amendment_manifest_sha256):
            raise BootstrapEnrollmentPending("selected setup plan provenance differs from the sealed release")
        if _PLAN_ID != self._release.selected_plan_artifact_id:
            raise BootstrapEnrollmentPending("installed release selected an unsupported setup plan")
        self.resolver.resolve(_PLAN_ID)

    def close(self) -> None:
        self._actor.close()
        self._release.close()

    def begin(self, mode: str, target_account_name: str) -> "RootBootstrapSession":
        self._actor.verify_current(self._release)
        handle = self.session_store.begin_local(mode=mode, selected_plan_artifact_id=_PLAN_ID,
                                                target_account_name=target_account_name)
        return self._wrap_live_session(handle)

    def begin_from_initial_publication(self, handoff_handle: str) -> "RootBootstrapSession":
        """Adopt the same-process stage-zero publication into a normal session."""
        if self._initial_compilation_registry is None:
            raise BootstrapEnrollmentPending("fresh setup has no retained stage-zero publication registry")
        handle = self.session_store.begin_from_initial_publication(handoff_handle)
        return self._wrap_live_session(handle)

    def _wrap_live_session(self, handle: RootSetupSessionHandle) -> "RootBootstrapSession":
        try:
            live = self.session_store._live(handle)
            authorization = self.session_store._proof(live)
            policy = self.resolver.resolve_policy(
                authorization.plan_artifact_id,
                compilation_phase="prepared" if authorization.mode == "install" else "active")
            identity_policy = policy.identity_policy
            marker = Path("/var/lib/hermes-installer/identities") / f"{identity_policy['service_account_name']}.json"
            identity = SystemIdentityAdapter(marker, name=identity_policy["service_account_name"])
            transaction = RootBootstrapEnrollment(
                policy_resolver=lambda _request, proof: self.policy_factory.prepare(proof),
                receipt_resolver=self._receipt_resolver,
                identity=identity,
                authority_path=Path("/etc/hermes-installer/authority.json"),
                transaction_root=self.session_store.transaction_root,
                artifact_root=self.session_store.receipt_registry.artifact_root,
                root_journal_path=self.session_store.session_root.parent,
            )
            session = RootBootstrapSession(self, handle, authorization, policy, identity,
                                           transaction, seal=self._seal)
            self._sessions[handle.session_id] = session
            return session
        except Exception:
            self.session_store.close_session(handle)
            raise

    def resolve_live_session(self, handle: RootSetupSessionHandle) -> "RootBootstrapSession":
        """Resolve a session only from this installed root factory's live registry."""
        if not isinstance(handle, RootSetupSessionHandle):
            raise BootstrapEnrollmentPending("root session resolution requires the typed live session handle")
        session = self._sessions.get(handle.session_id)
        if session is None or session._handle is not handle or session._factory is not self:
            raise BootstrapEnrollmentPending("root session handle is absent or belongs to another factory")
        session._check_live()
        live = self.session_store._live(handle)
        proof = self.session_store._proof(live)
        if (proof.transaction_handle != session._authorization.transaction_handle
                or proof.plan_digest != session._authorization.plan_digest):
            raise BootstrapEnrollmentPending("root session authorization changed after factory issuance")
        return session

    def resolve_live_session_id(self, session_id: str) -> "RootBootstrapSession":
        """Resolve an opaque root-issued session ID and recheck its current proof.

        This narrow accessor is for root-owned receipt resolvers whose typed
        receipt retains the session ID rather than the in-process handle object.
        It does not let a caller create or restore a session from an ID.
        """
        if not isinstance(session_id, str) or not re.fullmatch(r"[0-9a-f]{64}", session_id):
            raise BootstrapEnrollmentPending("root setup session ID is malformed")
        session = self._sessions.get(session_id)
        if session is None or session._factory is not self:
            raise BootstrapEnrollmentPending("root setup session ID is absent from this live factory")
        return self.resolve_live_session(session._handle)

    def _receipt_resolver(self, handle: str, *, setup_authorization: VerifiedRootSetupAuthorization) -> VerifiedArtifactReceipt:
        artifact_id, digest = self._receipt_registry.lookup(handle, setup_authorization)
        selected_plan = self.resolver.resolve(setup_authorization.plan_artifact_id)
        if artifact_id not in selected_plan.allowed_artifact_ids:
            raise BootstrapEnrollmentPending("root setup receipt artifact is outside the selected plan allowlist")
        value = self._read_receipt(handle)
        try:
            spec = self._catalog._artifact(artifact_id, digest)
            resolved = self._catalog.resolve(artifact_id, digest,
                                             self._receipt_registry.artifact_root, expected_uid=0)
        except Exception:
            raise BootstrapEnrollmentPending("root setup receipt no longer resolves to its selected immutable CAS object") from None
        if (set(value) != {"schema", "handle", "receipt_id", "setup_session_id",
                           "transaction_handle", "target_id", "operation_target_id",
                           "plan_digest", "operator_uid", "artifact_role", "artifact_id",
                           "sha256", "size_bytes"}
                or value.get("schema") != 1 or value.get("handle") != handle
                or value.get("setup_session_id") != setup_authorization.setup_session_id
                or value.get("transaction_handle") != setup_authorization.transaction_handle
                or value.get("target_id") != setup_authorization.target_id
                or value.get("plan_digest") != setup_authorization.plan_digest
                or value.get("operator_uid") != setup_authorization.operator_uid
                or value.get("artifact_id") != artifact_id or value.get("sha256") != digest
                or value.get("size_bytes") != resolved.size_bytes
                or not isinstance(value.get("receipt_id"), str) or not value["receipt_id"]):
            raise BootstrapEnrollmentError("root setup receipt does not match its CAS object")
        return VerifiedArtifactReceipt(value["receipt_id"], artifact_id, digest,
                                       resolved.path, spec.max_bytes)

    def _read_receipt(self, handle: str) -> Mapping[str, Any]:
        path = self._receipt_registry.root / f"{handle}.json"
        raw = _read_secure_root_bytes(path, 16 * 1024, 0o600)
        value = self.resolver._json(raw, "root artifact receipt")
        if not isinstance(value, dict) or value.get("handle") != handle:
            raise BootstrapEnrollmentError("root artifact receipt record is malformed")
        return value


class RootBootstrapSession:
    """Live root session facade; close always releases its PIDFD."""

    def __init__(self, factory: RootBootstrapRuntimeFactory, handle: RootSetupSessionHandle,
                 authorization: VerifiedRootSetupAuthorization, policy: VerifiedRootBootstrapPolicy,
                 identity: SystemIdentityAdapter, transaction: RootBootstrapEnrollment, *, seal: str):
        self._factory = factory
        self._handle = handle
        self._authorization = authorization
        self._policy = policy
        self._identity = identity
        self._transaction = transaction
        self._seal = seal
        self._runtime_receipts: dict[str, RootRuntimeArtifactReceipt] = {}
        self._last_receipt: EnrollmentReceipt | None = None
        self._closed = False
        self._source_receipt_handle: str | None = None
        self._source_handoff: Any | None = None
        self._native_output_receipts: Any | None = None
        self._pm_runtime_registry: Any | None = None
        self._pm_runtime_handle: str | None = None
        self._native_pm_bindings: set[tuple[str, str, str]] = set()
        self._resource_profiles: dict[str, RootSelectedResourceProfile] = {}
        self._resource_profile_tty_proofs: dict[str, Any] = {}
        self._application_setup_choices: dict[str, RootSelectedApplicationQualificationChoice] = {}
        self._application_choice_tty_proofs: dict[str, Any] = {}
        self._verified_resources: dict[str, tuple[Any, Any]] = {}
        self._native_materializer: Any | None = None
        self._native_materialization_receipts: dict[str, Any] = {}
        self._native_assembly_selections: dict[str, RootNativeBootstrapAssemblySelection] = {}
        self._release_member_receipts: dict[str, RootReleaseModuleReceipt] = {}
        self._installed_release_member_receipts: dict[str, RootInstalledReleaseMemberReceipt] = {}
        self._native_schema_receipts: dict[str, RootNativeRegistrationSchemaReceipt] = {}
        self._native_schema_receipts_by_artifact: dict[str, RootNativeRegistrationSchemaReceipt] = {}
        self._native_schema_receipt_registry: Any | None = None
        self._native_schema_receipt_registry_minted_for: tuple[str, str] | None = None
        self._source_provisioner = self._make_source_provisioner()
        self._selected_installation = RootSelectedInstallationBinding(self, seal)
        self._client = factory.session_store.bootstrap_client(
            handle, transaction, source_receipt_provider=self._source_receipt)

    @property
    def policy(self) -> VerifiedRootBootstrapPolicy:
        return self._policy

    @property
    def selected_installation(self) -> RootSelectedInstallationBinding:
        self._check_live()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("selected installation binding requires committed prepared custody")
        return self._selected_installation

    def provision(self) -> EnrollmentReceipt:
        self._check_live()
        if self._last_receipt is not None:
            raise BootstrapEnrollmentError("root setup preparation has already been published")
        receipt = self._client.provision((), self._authorization.transaction_handle)
        if receipt.state != "prepared" or receipt.enrollment_ids:
            raise BootstrapEnrollmentError("first setup did not publish the required empty prepared generation")
        self._last_receipt = receipt
        self._refresh_authorization()
        return receipt

    def _resolve_current_active_enrollment(self) -> EnrollmentReceipt:
        """Typed bridge for root composers; a prepared receipt never passes."""
        self._check_live()
        self._refresh_authorization()
        receipt = self._last_receipt
        if (not isinstance(receipt, EnrollmentReceipt)
                or receipt.state != "committed"
                or not receipt.enrollment_ids
                or receipt.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending(
                "current setup session has no committed active enrollment")
        return receipt

    def _resolve_current_pm_runtime(self) -> Any:
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or self._pm_runtime_registry is None or not self._pm_runtime_handle):
            raise BootstrapEnrollmentPending("current official PM runtime receipt is unavailable")
        from .pm_runtime import VerifiedPMRuntimeSelection
        selected = self._pm_runtime_registry.resolve_runtime(
            self._pm_runtime_handle, self._authorization.transaction_handle,
            prepared.generation_id)
        if (not isinstance(selected, VerifiedPMRuntimeSelection)
                or selected.setup_session_id != self._handle.session_id
                or selected.transaction_handle != self._authorization.transaction_handle
                or selected.prepared_generation_id != prepared.generation_id):
            raise BootstrapEnrollmentPending("official PM runtime receipt differs from current setup custody")
        return selected

    def _resolve_current_hermes_source(self) -> Any:
        self._check_live()
        self._refresh_authorization()
        if self._source_handoff is None or not self._source_receipt_handle:
            raise BootstrapEnrollmentPending("current pinned Hermes source receipt is unavailable")
        current = self._source_receipt(self._authorization)
        if current != self._source_receipt_handle or self._source_handoff.receipt_handle != current:
            raise BootstrapEnrollmentPending("Hermes source receipt differs from current setup authorization")
        return self._source_handoff

    def resolve_prepared_receipt(self, provision_receipt_handle: str) -> EnrollmentReceipt:
        """Resolve the current empty prepared commit retained by this live facade."""
        self._check_live()
        receipt = self._last_receipt
        if (receipt is None or receipt.state != "prepared"
                or not isinstance(provision_receipt_handle, str)
                or not secrets.compare_digest(receipt.provision_receipt_handle, provision_receipt_handle)
                or receipt.transaction_handle != self._authorization.transaction_handle
                or receipt.enrollment_ids):
            raise BootstrapEnrollmentPending("prepared setup receipt is absent or not the current empty-generation commit")
        return receipt

    def observe_application_qualification_workflow(self) -> str:
        """Record a finite non-authority qualification request at the root TTY.

        The workflow is intentionally just a request selector. Application
        source/runtime receipts and a current active service binding are still
        independently required before any qualification work can run.
        """
        self._check_live()
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise BootstrapEnrollmentPending("application qualification choice requires the root controlling TTY")
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("application qualification choice requires current empty prepared custody")
        self._refresh_authorization()
        if self._authorization.setup_session_id != self._handle.session_id:
            raise BootstrapEnrollmentPending("application qualification choice has no current setup actor")
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            print("\nRoot application qualification workflows:")
            for index, (workflow_id, application_id, workload_id) in enumerate(
                    _APPLICATION_QUALIFICATION_WORKFLOWS, 1):
                print(f"  {index}. {workflow_id} ({application_id})")
            selected_text = input("Select a workflow number: ").strip()
            _verify_root_tty_proof(proof)
            if (proof.controller_uid != 0 or proof.controller_gid != 0
                    or proof.controller_pid != os.getpid()):
                raise BootstrapEnrollmentPending("workflow choice is not joined to the live root setup actor")
            if not selected_text.isascii() or not selected_text.isdecimal():
                raise BootstrapEnrollmentPending("workflow choice must be a printed row number")
            selected_index = int(selected_text) - 1
            if not 0 <= selected_index < len(_APPLICATION_QUALIFICATION_WORKFLOWS):
                raise BootstrapEnrollmentPending("workflow choice is outside the printed fixed list")
            workflow_id, application_id, workload_id = _APPLICATION_QUALIFICATION_WORKFLOWS[selected_index]
            live = self._factory.session_store._live(self._handle)
            if live.record.get("actor_observation_receipt_handle") is None:
                raise BootstrapEnrollmentPending("workflow choice has no retained root actor observation")
            _verify_root_tty_proof(proof)
            self._check_live()
            if self._last_receipt is not prepared:
                raise BootstrapEnrollmentPending("prepared setup changed during workflow selection")
            now = time.monotonic()
            deadline = self._factory.session_store.current_deadline(self._handle)
            expiry = min(now + 30.0, prepared.expires_monotonic, deadline)
            if expiry <= now:
                raise BootstrapEnrollmentPending("workflow selection lease expired")
            handle = secrets.token_urlsafe(36)
            values = {
                "schema": 1, "selection_handle": handle,
                "setup_session_id": self._handle.session_id,
                "transaction_handle": self._authorization.transaction_handle,
                "plan_sha256": self._authorization.plan_digest,
                "prepared_generation_id": prepared.generation_id,
                "workflow_id": workflow_id, "application_id": application_id,
                "workload_id": workload_id,
                "choice_observation_id": secrets.token_hex(16),
                "issued_monotonic": now, "expires_monotonic": expiry,
            }
            signature = hmac.new(self._seal.encode("ascii"), _canonical(values), hashlib.sha256).hexdigest()
            choice = RootSelectedApplicationQualificationChoice(
                **values, signature=signature, _session_seal=self._seal)
            proof_record = {
                "pid": proof.controller_pid, "start_ticks": proof.controller_start_ticks,
                "uid": proof.controller_uid, "gid": proof.controller_gid,
                "session_id": proof.session_id, "process_group_id": proof.process_group_id,
                "device": proof.tty_device, "inode": proof.tty_inode,
                "rdevice": proof.tty_rdevice,
            }
            journal = self._factory.resolver.journal_root / "application-qualification-choices"
            _ensure_root_directory(journal)
            raw = _canonical({**values, "signature": signature, "tty": proof_record})
            fd = os.open(journal / f"{handle}.json",
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), 0o600)
            try:
                offset = 0
                while offset < len(raw):
                    offset += os.write(fd, raw[offset:])
                os.fsync(fd)
            finally:
                os.close(fd)
            journal_fd = os.open(journal, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                 | getattr(os, "O_CLOEXEC", 0))
            try:
                os.fsync(journal_fd)
            finally:
                os.close(journal_fd)
            self._application_setup_choices[handle] = choice
            self._application_choice_tty_proofs[handle] = proof
            proof = None
            return handle
        finally:
            if proof is not None:
                proof.close()

    def resolve_application_setup_choice(
            self, selection_handle: str) -> RootSelectedApplicationQualificationChoice:
        self._check_live()
        choice = self._application_setup_choices.get(selection_handle)
        proof = self._application_choice_tty_proofs.get(selection_handle)
        prepared = self._last_receipt
        if (not isinstance(choice, RootSelectedApplicationQualificationChoice)
                or proof is None or choice._session_seal != self._seal
                or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or choice.setup_session_id != self._handle.session_id
                or choice.transaction_handle != self._authorization.transaction_handle
                or choice.plan_sha256 != self._authorization.plan_digest
                or choice.prepared_generation_id != prepared.generation_id
                or choice.expires_monotonic <= time.monotonic()
                or (choice.workflow_id, choice.application_id, choice.workload_id)
                   not in _APPLICATION_QUALIFICATION_WORKFLOWS):
            raise BootstrapEnrollmentPending("application qualification choice is stale or unrecognized")
        from ..root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        self._factory.session_store.current_deadline(self._handle)
        self._refresh_authorization()
        expected = hmac.new(self._seal.encode("ascii"), _canonical({
            "schema": choice.schema, "selection_handle": choice.selection_handle,
            "setup_session_id": choice.setup_session_id,
            "transaction_handle": choice.transaction_handle,
            "plan_sha256": choice.plan_sha256,
            "prepared_generation_id": choice.prepared_generation_id,
            "workflow_id": choice.workflow_id, "application_id": choice.application_id,
            "workload_id": choice.workload_id,
            "choice_observation_id": choice.choice_observation_id,
            "issued_monotonic": choice.issued_monotonic,
            "expires_monotonic": choice.expires_monotonic,
        }), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, choice.signature):
            raise BootstrapEnrollmentPending("application qualification choice signature differs")
        return choice

    def observe_selected_resource_profile(self) -> str:
        """Mint a current resource-profile choice from the verified bundle and root TTY.

        The source archive, profile IDs and profile member identities are read
        from the verified release and pinned Resources catalog. The only user
        input is a one-based row number printed by this root process.
        """
        self._check_live()
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise BootstrapEnrollmentPending("Resources profile selection requires the root controlling TTY")
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("Resources profile selection requires the current empty prepared generation")
        proof = self._authorization
        self._refresh_authorization()
        if (proof.setup_session_id != self._authorization.setup_session_id
                or proof.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("root setup identity changed before resource profile selection")

        from .native_output_receipts import RootMaterializationReceiptRegistry
        from ..registry.native import NativeRegistry
        from ..registry.source import BundledRegistrySource, PinnedSource
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        output_registry = self._root_native_output_receipts()
        source_handle = output_registry.mint_packaged_resources_source(
            prepared.provision_receipt_handle, self._factory._release)
        source_receipt = output_registry._receipt_from_id(source_handle)
        if (source_receipt.artifact_role != "resources-source-bundle"
                or source_receipt.sha256 != "b09459b609676cff30f151ac7db1fc405039b8871486b483af563ba7f63e7cd1"
                or source_receipt.setup_session_id != self._handle.session_id
                or source_receipt.prepared_generation_id != prepared.generation_id):
            raise BootstrapEnrollmentPending("Resources source receipt is not current for this prepared session")
        archive = self._factory._release.open_file(source_receipt.artifact_id)
        try:
            payload = bytearray()
            while len(payload) <= source_receipt.size_bytes:
                block = os.read(archive, min(64 * 1024, source_receipt.size_bytes + 1 - len(payload)))
                if not block:
                    break
                payload.extend(block)
        finally:
            os.close(archive)
        if len(payload) != source_receipt.size_bytes or hashlib.sha256(payload).hexdigest() != source_receipt.sha256:
            raise BootstrapEnrollmentPending("verified Resources source changed before profile selection")
        try:
            pin_rows = [row for row in self._factory._release.files
                        if row.relative_path == "src/hermes_installer/registry/bundle_data/hermes-agent-resources.pin.json"]
            if len(pin_rows) != 1 or "module" not in pin_rows[0].roles:
                raise ValueError("pinned Resources source descriptor is not in the held release")
            pin_fd = self._factory._release.open_file(pin_rows[0].artifact_id)
            try:
                pin_raw = bytearray()
                while len(pin_raw) <= 64 * 1024:
                    block = os.read(pin_fd, min(16 * 1024, 64 * 1024 + 1 - len(pin_raw)))
                    if not block:
                        break
                    pin_raw.extend(block)
            finally:
                os.close(pin_fd)
            if len(pin_raw) > 64 * 1024:
                raise ValueError("Resources source descriptor exceeds its bound")
            pin = PinnedSource.from_mapping(json.loads(bytes(pin_raw).decode("utf-8")))
            if (pin.commit != "113f42d33be9e0c8f0f47f5ca998e687323dec83"
                    or pin.archive_sha256 != source_receipt.sha256
                    or pin.archive_size != source_receipt.size_bytes):
                raise ValueError("Resources pin mismatch")
            verified_source = BundledRegistrySource(pin).load(bytes(payload))
            registry = NativeRegistry.from_verified_source(verified_source)
        except Exception:
            raise BootstrapEnrollmentPending("verified Resources bundle could not be parsed for profile selection") from None
        profiles = []
        for key, raw in sorted(registry.resolver.raw.items()):
            if raw.kind != "profiles":
                continue
            member_path = registry.paths.get(key)
            member = verified_source.files.get(member_path) if isinstance(member_path, str) else None
            if (not isinstance(member, bytes) or raw.identity not in key
                    or not member_path.startswith("profiles/") or not member_path.endswith(".yaml")):
                raise BootstrapEnrollmentPending("Resources profile declaration is outside its verified source manifest")
            profiles.append((raw.identity, member_path, hashlib.sha256(member).hexdigest()))
        if not profiles or len(profiles) > 256 or len({row[0] for row in profiles}) != len(profiles):
            raise BootstrapEnrollmentPending("verified Resources bundle has no bounded unique profile list")
        if self._resource_profiles:
            raise BootstrapEnrollmentPending("this root setup session already has a Resources TTY selection")

        tty_proof = _capture_root_tty_proof()
        try:
            print("\nVerified Hermes Resources profiles:")
            for index, (profile_id, _path, _digest) in enumerate(profiles, 1):
                print(f"  {index}. {profile_id}")
            selected_text = input("Select a profile number: ").strip()
            _verify_root_tty_proof(tty_proof)
            if not selected_text.isascii() or not selected_text.isdecimal():
                raise BootstrapEnrollmentPending("Resources profile selection must be a printed row number")
            selected_index = int(selected_text) - 1
            if not 0 <= selected_index < len(profiles):
                raise BootstrapEnrollmentPending("Resources profile selection is outside the printed list")
            profile_id, member_path, member_sha = profiles[selected_index]
            live = self._factory.session_store._live(self._handle)
            if (tty_proof.controller_uid != 0 or tty_proof.controller_gid != 0
                    or tty_proof.controller_pid != os.getpid()
                    or live.record.get("actor_observation_receipt_handle") is None):
                raise BootstrapEnrollmentPending("root TTY selection is not joined to the live setup actor")
            _verify_root_tty_proof(tty_proof)
            current = self._last_receipt
            self._check_live()
            if current is not prepared or current.generation_id != prepared.generation_id:
                raise BootstrapEnrollmentPending("prepared generation changed during resource profile selection")
            now = time.monotonic()
            lease_expiry = min(prepared.expires_monotonic, source_receipt.expires_monotonic,
                               now + 30.0)
            if lease_expiry <= now:
                raise BootstrapEnrollmentPending("Resources source or setup selection expired")
            receipt_handle = secrets.token_urlsafe(36)
            observation_id = secrets.token_hex(16)
            values = {
                "schema": 1, "receipt_handle": receipt_handle,
                "setup_session_id": self._handle.session_id,
                "transaction_handle": self._authorization.transaction_handle,
                "plan_sha256": self._authorization.plan_digest,
                "prepared_generation_id": prepared.generation_id,
                "prepared_generation_digest": prepared.generation_digest,
                "resources_source_receipt_handle": source_handle,
                "resources_source_artifact_id": source_receipt.artifact_id,
                "resources_source_sha256": source_receipt.sha256,
                "resources_revision": verified_source.revision,
                "profile_id": profile_id,
                "profile_member_path": member_path,
                "profile_member_sha256": member_sha,
                "choice_observation_id": observation_id,
                "issued_monotonic": now, "expires_monotonic": lease_expiry,
            }
            signature = hmac.new(self._seal.encode("ascii"), _canonical(values), hashlib.sha256).hexdigest()
            receipt = RootSelectedResourceProfile(**values, signature=signature,
                                                  _session_seal=self._seal)
            self._persist_resource_profile_choice(receipt, tty_proof)
            self._resource_profiles[receipt_handle] = receipt
            self._resource_profile_tty_proofs[receipt_handle] = tty_proof
            self._verified_resources[source_handle] = (verified_source, registry)
            tty_proof = None
            return receipt_handle
        finally:
            if tty_proof is not None:
                tty_proof.close()

    def resolve_selected_resource_profile(self, receipt_handle: str) -> RootSelectedResourceProfile:
        self._check_live()
        receipt = self._resource_profiles.get(receipt_handle)
        proof = self._resource_profile_tty_proofs.get(receipt_handle)
        prepared = self._last_receipt
        if (not isinstance(receipt, RootSelectedResourceProfile) or proof is None
                or receipt._session_seal != self._seal or prepared is None
                or receipt.setup_session_id != self._handle.session_id
                or receipt.transaction_handle != self._authorization.transaction_handle
                or receipt.plan_sha256 != self._authorization.plan_digest
                or receipt.prepared_generation_id != prepared.generation_id
                or receipt.prepared_generation_digest != prepared.generation_digest
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("root-selected Resources profile receipt is stale or belongs to another setup")
        unsigned = {name: getattr(receipt, name) for name in (
            "schema", "receipt_handle", "setup_session_id", "transaction_handle", "plan_sha256",
            "prepared_generation_id", "prepared_generation_digest", "resources_source_receipt_handle",
            "resources_source_artifact_id", "resources_source_sha256", "resources_revision", "profile_id",
            "profile_member_path", "profile_member_sha256", "choice_observation_id", "issued_monotonic",
            "expires_monotonic")}
        expected_sig = hmac.new(self._seal.encode("ascii"), _canonical(unsigned), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(receipt.signature, expected_sig):
            raise BootstrapEnrollmentPending("root-selected Resources profile receipt signature is invalid")
        from ..root_setup import _verify_root_tty_proof
        try:
            _verify_root_tty_proof(proof)
            source = self._root_native_output_receipts()._receipt_from_id(
                receipt.resources_source_receipt_handle)
            if (source.artifact_id != receipt.resources_source_artifact_id
                    or source.sha256 != receipt.resources_source_sha256
                    or source.prepared_generation_id != prepared.generation_id
                    or source.setup_session_id != self._handle.session_id):
                raise BootstrapEnrollmentPending("selected Resources source receipt changed")
            self._factory._release.verify_current()
            self._factory._actor.verify_current(self._factory._release)
            return receipt
        except Exception:
            raise BootstrapEnrollmentPending("root-selected Resources profile proof is no longer current") from None

    def provision_official_pm_runtime(self) -> str:
        """Provision the pinned PM Python from the current source and lock receipts."""
        self._check_live()
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("official PM runtime requires the current empty prepared generation")
        self._refresh_authorization()
        source_handle = self._source_receipt(self._authorization)
        from .bootstrap_enrollment import RootLocalCatalogArtifactFetcher
        from .pm_runtime import RootPMRuntimeProvisioner, RootPMRuntimeReceiptRegistry, SOURCE_ID
        fetcher = RootLocalCatalogArtifactFetcher(
            catalog=self._factory._catalog,
            artifact_root=self._factory._receipt_registry.artifact_root,
            session_store=self._factory.session_store,
            session_handle=self._handle,
        )
        lock_handle = fetcher.fetch_selected_artifact(self._handle, "hermes-pm-lock")
        runtime_root = self._factory.resolver.journal_root / "pm-runtimes"
        if self._pm_runtime_registry is None:
            _ensure_root_directory(runtime_root)

            def current_guard(transaction_handle: str, generation_id: str) -> bool:
                try:
                    self._check_live()
                    self._refresh_authorization()
                    current = self._last_receipt
                    return (current is prepared and current.state == "prepared"
                            and current.transaction_handle == transaction_handle
                            and current.generation_id == generation_id
                            and self._authorization.transaction_handle == transaction_handle)
                except Exception:
                    return False

            registry = RootPMRuntimeReceiptRegistry(
                runtime_root=runtime_root, setup_session=self,
                current_guard=current_guard,
            )
            provisioner = RootPMRuntimeProvisioner(
                setup_session=self, artifact_fetcher=fetcher,
                receipt_registry=self._factory._receipt_registry,
                catalog=self._factory._catalog,
                artifact_root=self._factory._receipt_registry.artifact_root,
                runtime_root=runtime_root,
            )
            handle = provisioner.provision_selected(
                prepared_setup_receipt_handle=prepared.provision_receipt_handle,
                source_receipt_handle=source_handle,
                pm_lock_receipt_handle=lock_handle,
            )
            self._pm_runtime_registry = registry
            self._pm_runtime_handle = handle
        else:
            raise BootstrapEnrollmentPending("the current session already has a PM runtime receipt")
        # The selected PM runtime is joined to native materialization only once
        # the current service enrollment and Resources-profile TTY receipt are
        # both available.
        if self._pm_runtime_registry is None or not self._pm_runtime_handle:
            raise BootstrapEnrollmentPending("official PM runtime receipt was not retained")
        if SOURCE_ID not in self._factory.resolver.resolve(_PLAN_ID).allowed_artifact_ids:
            raise BootstrapEnrollmentPending("current setup plan excludes the pinned Hermes source")
        return self._pm_runtime_handle

    def stage_selected_native_resources(self) -> Any:
        """Install only the root-selected Resources profile into its fixed roots."""
        self._check_live()
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("native resource staging requires the current empty prepared generation")
        if self._native_materializer is not None:
            raise BootstrapEnrollmentPending("native resource staging has already run for this setup session")
        if not self._pm_runtime_handle or self._pm_runtime_registry is None:
            raise BootstrapEnrollmentPending("native resource staging requires the official PM runtime receipt")
        selected = tuple(self.resolve_selected_resource_profile(handle)
                         for handle in tuple(self._resource_profiles))
        if len(selected) != 1:
            raise BootstrapEnrollmentPending("native resource staging requires one root-TTY Resources profile selection")
        profile = selected[0]
        bundle = self._verified_resources.get(profile.resources_source_receipt_handle)
        if bundle is None:
            raise BootstrapEnrollmentPending("the selected Resources source bundle is no longer retained")
        verified_source, registry = bundle
        profile_keys = [key for key, raw in registry.resolver.raw.items()
                        if raw.kind == "profiles" and raw.identity == profile.profile_id]
        if verified_source.revision != profile.resources_revision or len(profile_keys) != 1:
            raise BootstrapEnrollmentPending("selected Resources profile differs from the retained verified bundle")
        if self._source_handoff is None:
            self._source_receipt(self._authorization)
        if self._source_handoff is None:
            raise BootstrapEnrollmentPending("verified official Hermes source tree is unavailable")
        from .native_materialization import RootNativeMaterialization
        from .pm_runtime import SOURCE_ID
        from .bootstrap_enrollment import _create_service_root, _verify_service_root
        parent = Path(self._policy.root_policy["service_parent_root"])
        identity = self._identity.ensure()
        # Empty prepared custody still needs the reviewed target roots before
        # native profile staging. Existing directories are accepted only when
        # their exact selected service UID/GID and private mode already match.
        _ensure_root_directory(parent)
        for root in (parent / "home", parent / "work", parent / "data"):
            _create_service_root(root, identity)
            _verify_service_root(root, identity)
        materializer = RootNativeMaterialization(
            self._selected_installation, registry=registry,
            home_root=parent / "home", data_root=parent / "data",
            journal_root=self._factory.resolver.journal_root / "native-materialization",
            hermes_source=self._source_handoff.source.tree_path,
            pm_runtime_resolver=self._pm_runtime_registry,
            output_registry=self._root_native_output_receipts(),
            authority_uid=0,
        )
        # Keep the concrete objects root-private for runtime composition and
        # current receipt revalidation; only receipt handles cross the seam.
        self._resources_source_handle = profile.resources_source_receipt_handle
        self._resources_source_artifact_id = profile.resources_source_artifact_id
        self._resources_registry = registry
        self._native_materializer = materializer
        matches = [item["record"] for item in self._policy.service_record_templates
                   if isinstance(item.get("record"), Mapping)]
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("prepared setup does not select one native service template")
        record = matches[0]
        enrollment_id = record.get("enrollment_id")
        if not isinstance(enrollment_id, str):
            raise BootstrapEnrollmentPending("selected prepared service template has no fixed enrollment ID")
        receipt = materializer.stage_selected(
            enrollment_id=enrollment_id,
            service_generation=prepared.generation_id,
            resource_profile_id=profile.profile_id,
        )
        self._native_materialization_receipts[receipt.receipt_handle] = receipt
        return receipt

    def prepare_selected_native_bundle(self) -> RootPreparedNativeBundle:
        """Run the reviewed source, PM, TTY-profile and native-materialization steps.

        This helper keeps the order and joins inside the root factory. It does
        not activate a service or claim that its native tool schemas, actions,
        observers, or boundary overlay have been proven.
        """
        self._check_live()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("native bundle preparation requires the current empty prepared commit")
        source_handle = self._source_receipt(self._authorization)
        pm_handle = self.provision_official_pm_runtime()
        if not self._resource_profiles:
            resource_handle = self.observe_selected_resource_profile()
        elif len(self._resource_profiles) == 1:
            resource_handle = next(iter(self._resource_profiles))
            self.resolve_selected_resource_profile(resource_handle)
        else:
            raise BootstrapEnrollmentPending("native bundle has ambiguous Resources profile selections")
        materialized = self.stage_selected_native_resources()
        self._check_live()
        if self._last_receipt is not prepared or self._last_receipt.generation_id != prepared.generation_id:
            raise BootstrapEnrollmentPending("prepared generation changed while staging native resources")
        from .native_materialization import NativeMaterializationReceipt
        if (not isinstance(materialized, NativeMaterializationReceipt)
                or materialized.receipt_handle not in self._native_materialization_receipts
                or self._native_materialization_receipts[materialized.receipt_handle] is not materialized):
            raise BootstrapEnrollmentPending("native materialization did not return a retained root receipt")
        profile = self.resolve_selected_resource_profile(resource_handle)
        return RootPreparedNativeBundle(
            self._handle.session_id, self._authorization.transaction_handle,
            prepared.generation_id, prepared.generation_digest,
            source_handle, pm_handle, profile.resources_source_receipt_handle,
            resource_handle, materialized.receipt_handle, materialized, self._seal,
        )

    def _persist_resource_profile_choice(self, receipt: RootSelectedResourceProfile,
                                         tty_proof: Any) -> None:
        root = self._factory.resolver.journal_root / "resource-profile-choices"
        _ensure_root_directory(root)
        values = {name: getattr(receipt, name) for name in (
            "schema", "receipt_handle", "setup_session_id", "transaction_handle", "plan_sha256",
            "prepared_generation_id", "prepared_generation_digest", "resources_source_receipt_handle",
            "resources_source_artifact_id", "resources_source_sha256", "resources_revision", "profile_id",
            "profile_member_path", "profile_member_sha256", "choice_observation_id", "issued_monotonic",
            "expires_monotonic", "signature")}
        values["tty"] = {"pid": tty_proof.controller_pid, "start_ticks": tty_proof.controller_start_ticks,
                         "uid": tty_proof.controller_uid, "gid": tty_proof.controller_gid,
                         "session_id": tty_proof.session_id, "process_group_id": tty_proof.process_group_id,
                         "device": tty_proof.tty_device, "inode": tty_proof.tty_inode,
                         "rdevice": tty_proof.tty_rdevice}
        path = root / f"{receipt.receipt_handle}.json"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        fd = os.open(path, flags, 0o600)
        try:
            raw = _canonical(values)
            offset = 0
            while offset < len(raw):
                offset += os.write(fd, raw[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        directory_fd = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _root_native_output_receipts(self) -> Any:
        if self._native_output_receipts is None:
            from .native_output_receipts import RootMaterializationReceiptRegistry
            journal = self._factory.resolver.journal_root
            cas_root = self._factory.resolver.artifact_root / "native-output-cas"
            receipt_root = journal / "native-output-receipts"
            _ensure_root_directory(cas_root)
            _ensure_root_directory(receipt_root)
            self._native_output_receipts = RootMaterializationReceiptRegistry._from_root_factory(
                binding=self._selected_installation, cas_root=cas_root,
                journal_root=receipt_root)
        return self._native_output_receipts

    def resolve_runtime_receipt(self, role: str, receipt_handle: str,
                                generation: str) -> RootRuntimeArtifactReceipt:
        """Mint a runtime receipt only from a current transaction-scoped CAS handle."""
        self._check_live()
        rule = next((item for item in self._policy.receipt_binding_rules
                     if item["receipt_role"] == role), None)
        if rule is None or rule["required_phase"] != "runnable":
            raise BootstrapEnrollmentError("runtime receipt role is not a reviewed first-setup role")
        if not isinstance(generation, str) or generation != self._authorization.transaction_handle:
            raise BootstrapEnrollmentError("runtime receipt generation is not bound to this setup transaction")
        artifact_id, digest = self._factory._receipt_registry.lookup(receipt_handle, self._authorization)
        if artifact_id not in rule["allowed_artifact_ids"]:
            raise BootstrapEnrollmentError("runtime receipt artifact is outside its exact selected role")
        resolved = self._factory._catalog.resolve(artifact_id, digest,
                                                  self._factory._receipt_registry.artifact_root, expected_uid=0)
        receipt = RootRuntimeArtifactReceipt(role, artifact_id, digest, generation, receipt_handle,
                                             resolved.size_bytes, self._factory._seal)
        self._runtime_receipts[role] = receipt
        return receipt

    def activate_runnable(self, receipts: Mapping[str, RootRuntimeArtifactReceipt]) -> EnrollmentReceipt:
        self._check_live()
        self._refresh_authorization()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("runnable activation requires the committed prepared transaction")
        if set(receipts) != set(self._runtime_receipts) or any(
                receipts.get(role) is not self._runtime_receipts[role] for role in self._runtime_receipts):
            raise BootstrapEnrollmentError("activation receipts were not minted by this live root setup session")
        policy = self._factory.policy_factory.activate_runnable(
            self._authorization, self._identity.ensure(), receipts, seal=self._factory._seal)
        self._runtime_receipts = dict(receipts)
        # Root policy and record construction remain captured in this trusted
        # transaction. The phase switch occurs only after verified receipts.
        self._transaction.policy_resolver = lambda _request, proof: policy
        self._transaction.record_builder = None
        receipt = self._client.provision(tuple(item.receipt_handle for item in receipts.values()),
                                        self._authorization.transaction_handle)
        if receipt.state != "committed" or not receipt.enrollment_ids:
            raise BootstrapEnrollmentPending("root selected runtime receipts did not create a runnable generation")
        self._last_receipt = receipt
        self._refresh_authorization()
        return receipt

    def _authorize_native_materialization(
            self, *, enrollment_id: str, service_generation: str,
            resource_profile_id: str) -> _BoundNativeSelection:
        self._check_live()
        if self._last_receipt is None or self._last_receipt.state != "prepared":
            raise BootstrapEnrollmentPending("native materialization requires a committed prepared generation")
        if (not isinstance(enrollment_id, str) or not _ID.fullmatch(enrollment_id)
                or not isinstance(service_generation, str)
                or not isinstance(resource_profile_id, str) or not _ID.fullmatch(resource_profile_id)):
            raise BootstrapEnrollmentError("native materialization selection identifiers are malformed")
        if service_generation != self._last_receipt.generation_id:
            raise BootstrapEnrollmentError("native materialization does not match the current prepared policy")
        matches = [item["record"] for item in self._policy.service_record_templates
                   if item["record"].get("enrollment_id") == enrollment_id]
        if len(matches) != 1:
            raise BootstrapEnrollmentError("native materialization enrollment is not uniquely selected by policy")
        selected_profiles = [self.resolve_selected_resource_profile(handle)
                             for handle in tuple(self._resource_profiles)]
        selected_profiles = [row for row in selected_profiles if row.profile_id == resource_profile_id]
        if len(selected_profiles) != 1:
            raise BootstrapEnrollmentPending(
                "native materialization requires the unique live root-TTY Resources profile selection")
        if not self._pm_runtime_handle or self._pm_runtime_registry is None:
            raise BootstrapEnrollmentPending(
                "native materialization requires the current official PM-managed Python 3.14 receipt")
        selected_resource = selected_profiles[0]
        source_receipt = self._source_receipt(self._authorization)
        from .pm_runtime import SOURCE_ID
        pm_binding = (enrollment_id, service_generation, SOURCE_ID)
        if pm_binding not in self._native_pm_bindings:
            self._pm_runtime_registry.bind_native_selection(
                self._pm_runtime_handle, enrollment_id=enrollment_id,
                service_generation=service_generation, source_artifact_id=SOURCE_ID)
            self._native_pm_bindings.add(pm_binding)
        identity = self._identity.ensure()
        resource_source_receipt = selected_resource.resources_source_receipt_handle
        return _BoundNativeSelection(
            enrollment_id=enrollment_id, service_generation=self._last_receipt.generation_id,
            service_profile_id=self._policy.identity_policy["service_profile_id"],
            protected_enrollment_digest=self._last_receipt.generation_digest,
            service_uid=identity.uid, service_gid=identity.gid,
            home_root_id=self._policy.root_policy["service_home_root_id"],
            data_root_id=self._policy.root_policy["service_data_root_id"],
            source_artifact_id=SOURCE_ID,
            source_receipt_handle=source_receipt,
            pm_runtime_handle=self._pm_runtime_handle,
            resource_profile_selection_receipt_handle=selected_resource.receipt_handle,
            resources_source_receipt_handle=resource_source_receipt,
            _session_id=self._handle.session_id, _seal=self._seal,
        )

    def _resolve_private_installation_roots(
            self, selection: Any) -> _RootPrivateInstallationRoots:
        self._check_live()
        if (not isinstance(selection, _BoundNativeSelection)
                or selection._session_id != self._handle.session_id
                or not secrets.compare_digest(selection._seal, self._seal)
                or self._last_receipt is None
                or selection.protected_enrollment_digest != self._last_receipt.generation_digest
                or self._last_receipt.state != "prepared"
                or selection.service_generation != self._last_receipt.generation_id
                or selection.service_profile_id != self._policy.identity_policy["service_profile_id"]
                or selection.home_root_id != self._policy.root_policy["service_home_root_id"]
                or selection.data_root_id != self._policy.root_policy["service_data_root_id"]):
            raise BootstrapEnrollmentError("native materialization authorization is stale or belongs to another session")
        try:
            profile = self.resolve_selected_resource_profile(
                selection.resource_profile_selection_receipt_handle)
            pm_runtime = self._pm_runtime_registry.resolve_runtime(
                selection.pm_runtime_handle, self._authorization.transaction_handle,
                self._last_receipt.generation_id)
        except Exception:
            raise BootstrapEnrollmentError("native materialization source/profile/runtime receipts are stale") from None
        identity = self._identity.ensure()
        if (profile.resources_source_receipt_handle != selection.resources_source_receipt_handle
                or self._resource_profiles.get(profile.receipt_handle) is not profile
                or pm_runtime.source_artifact_id != selection.source_artifact_id
                or pm_runtime.uid != 0
                or selection.service_uid != identity.uid or selection.service_gid != identity.gid
                or selection.source_receipt_handle != self._source_receipt(self._authorization)):
            raise BootstrapEnrollmentError("native materialization binding does not match its selected current receipts")
        if self._source_handoff is None:
            raise BootstrapEnrollmentPending("verified Hermes source tree is not provisioned for this session")
        parent = Path(self._policy.root_policy["service_parent_root"])
        return _RootPrivateInstallationRoots(
            home_root=parent / "home", data_root=parent / "data",
            journal_root=self._factory.session_store.session_root.parent / "native-materialization",
            hermes_source_tree=self._source_handoff.source.tree_path,
        )

    def _resolve_release_member_receipt(
            self, selection_handle: str, artifact_id: str) -> RootReleaseModuleReceipt:
        """Issue a receipt for an actual loaded module in the held release.

        The caller supplies only the opaque assembly handle and release artifact
        ID. Membership is joined to the current PIDFD-bound actor import origins;
        arbitrary files from the release tree cannot be presented as loaded
        registration code.
        """
        self._check_live()
        if (not isinstance(selection_handle, str) or not _ID.fullmatch(selection_handle)
                or not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id)):
            raise BootstrapEnrollmentPending("release member selection identifiers are malformed")
        selection = self._native_assembly_selections.get(selection_handle)
        if (not isinstance(selection, RootNativeBootstrapAssemblySelection)
                or selection.selection_handle != selection_handle
                or selection.setup_session_id != self._handle.session_id
                or selection.transaction_handle != self._authorization.transaction_handle
                or self._last_receipt is None
                or selection.prepared_generation_id != self._last_receipt.generation_id
                or selection.protected_enrollment_digest != self._last_receipt.generation_digest
                or selection.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("release member requires a current root-selected assembly")
        self._revalidate_native_assembly_selection(selection)
        release = self._factory._release
        actor = self._factory._actor
        actor.verify_current(release)
        matches = [row for row in release.files if row.artifact_id == artifact_id]
        if len(matches) != 1 or "module" not in matches[0].roles:
            raise BootstrapEnrollmentPending("release member is not one unique installed module")
        descriptor = matches[0]
        origin_matches = [row for row in actor.module_origins
                          if row[1] == str(release.release_root / descriptor.relative_path)
                          and row[4] == descriptor.sha256]
        if len(origin_matches) != 1:
            raise BootstrapEnrollmentPending("release module is not in the current actor's verified import closure")
        receipt_handle = secrets.token_urlsafe(36)
        receipt = RootReleaseModuleReceipt(
            artifact_id=descriptor.artifact_id, relative_path=descriptor.relative_path,
            sha256=descriptor.sha256, size_bytes=descriptor.size_bytes,
            release_commit=release.release_commit,
            deployment_receipt_sha256=release.deployment_receipt_sha256,
            source_receipt_handle=receipt_handle, _session_id=self._handle.session_id,
            _session_seal=self._seal, _session=self,
        )
        self._release_member_receipts[receipt_handle] = receipt
        return receipt

    def _mint_native_registration_schema_receipt(
            self, artifact_id: str) -> RootNativeRegistrationSchemaReceipt:
        """Mint one of the fixed local-result schema receipts from the held root catalog.

        The receipt is bound to the current empty prepared generation. The
        catalog observation and CAS receipt prove packaged schema bytes only;
        they do not authorize an active schema row or native action.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle
                or prepared.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("native result schema receipts require current empty prepared custody")
        if not isinstance(artifact_id, str) or not _ID.fullmatch(artifact_id):
            raise BootstrapEnrollmentPending("native result schema artifact ID is malformed")
        from .native_registration_projection import (
            RootNativeRegistrationResultSchemaReceiptRegistry,
            reviewed_local_registration_result_schemas,
        )
        reviewed = reviewed_local_registration_result_schemas()
        matches = [row for row in reviewed if row.artifact_id == artifact_id]
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("native result schema is outside the exact reviewed local set")
        cached = self._native_schema_receipts_by_artifact.get(artifact_id)
        if cached is not None:
            try:
                self._resolve_native_registration_schema_receipt(
                    next(handle for handle, value in self._native_schema_receipts.items()
                         if value is cached))
                return cached
            except Exception:
                self._native_schema_receipts_by_artifact.pop(artifact_id, None)
        if self._native_schema_receipt_registry is None:
            from .source_artifact_receipts import RootSetupCatalogArtifactObserver
            observer = RootSetupCatalogArtifactObserver.from_root_setup(
                self._factory._catalog,
                self._factory._receipt_registry.artifact_root,
                self._authorization,
                expected_uid=0,
            )
            self._native_schema_receipt_registry = RootNativeRegistrationResultSchemaReceiptRegistry(
                observer, self._factory._receipt_registry, self._authorization)
        binding = (prepared.provision_receipt_handle, prepared.generation_id)
        if self._native_schema_receipt_registry_minted_for != binding:
            registry_receipts = self._native_schema_receipt_registry.mint(
                prepared_setup_receipt_handle=binding[0], prepared_generation_id=binding[1],
            )
            self._native_schema_receipts.clear()
            self._native_schema_receipts_by_artifact.clear()
            deadline = min(prepared.expires_monotonic,
                           self._factory.session_store.current_deadline(self._handle))
            for root_receipt in registry_receipts:
                schema = root_receipt.schema
                wrapper_handle = secrets.token_urlsafe(36)
                wrapper = RootNativeRegistrationSchemaReceipt(
                    artifact_id=schema.artifact_id, sha256=schema.sha256,
                    size_bytes=schema.size_bytes, relative_path=schema.relative_path,
                    artifact_receipt_handle=root_receipt.source_receipt_handle,
                    setup_session_id=self._handle.session_id,
                    transaction_handle=self._authorization.transaction_handle,
                    prepared_generation_id=prepared.generation_id,
                    expires_monotonic=deadline, _schema_receipt=root_receipt,
                    _session_seal=self._seal, _session=self,
                )
                self._native_schema_receipts[wrapper_handle] = wrapper
                self._native_schema_receipts_by_artifact[schema.artifact_id] = wrapper
            self._native_schema_receipt_registry_minted_for = binding
        wrapper = self._native_schema_receipts_by_artifact.get(artifact_id)
        if wrapper is None:
            raise BootstrapEnrollmentPending("native result schema receipt could not be retained")
        wrapper.read_current()
        return wrapper

    def _resolve_native_registration_schema_receipt(
            self, receipt_handle: str) -> RootNativeRegistrationSchemaReceipt:
        self._check_live()
        if not isinstance(receipt_handle, str) or not _ID.fullmatch(receipt_handle):
            raise BootstrapEnrollmentPending("native result schema receipt handle is malformed")
        receipt = self._native_schema_receipts.get(receipt_handle)
        prepared = self._last_receipt
        if (not isinstance(receipt, RootNativeRegistrationSchemaReceipt)
                or receipt._session is not self
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or receipt.setup_session_id != self._handle.session_id
                or receipt.transaction_handle != self._authorization.transaction_handle
                or receipt.prepared_generation_id != prepared.generation_id
                or receipt.expires_monotonic <= time.monotonic()
                or self._native_schema_receipt_registry is None):
            raise BootstrapEnrollmentPending("native result schema receipt is stale or not retained")
        try:
            self._native_schema_receipt_registry.resolve(
                receipt._schema_receipt,
                prepared_setup_receipt_handle=prepared.provision_receipt_handle,
                prepared_generation_id=prepared.generation_id,
                setup_authorization=self._authorization,
            )
        except Exception:
            raise BootstrapEnrollmentPending("native result schema receipt failed currentness verification") from None
        return receipt

    def _read_native_registration_schema_receipt(
            self, receipt: RootNativeRegistrationSchemaReceipt) -> bytes:
        if not isinstance(receipt, RootNativeRegistrationSchemaReceipt):
            raise BootstrapEnrollmentPending("native result schema receipt is not root-issued")
        current = self._resolve_native_registration_schema_receipt(
            next((handle for handle, item in self._native_schema_receipts.items()
                  if item is receipt), ""))
        assert current is receipt
        return self._native_schema_receipt_registry.resolve(
            receipt._schema_receipt,
            prepared_setup_receipt_handle=self._last_receipt.provision_receipt_handle,
            prepared_generation_id=self._last_receipt.generation_id,
            setup_authorization=self._authorization,
        )

    def _resolve_installed_xpra_transform_module(self) -> RootInstalledReleaseMemberReceipt:
        """Issue the fixed Xpra toolchain member receipt independently of native assembly."""
        self._check_live()
        self._refresh_authorization()
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, sha256, size_bytes, role = _XPRA_TRANSFORM_MODULE
        plan = self._factory.resolver.resolve(_PLAN_ID)
        if artifact_id not in plan.allowed_artifact_ids:
            raise BootstrapEnrollmentPending("selected setup plan excludes the pinned Xpra transform module")
        rows = [row for row in release.files if row.artifact_id == artifact_id]
        if (len(rows) != 1 or rows[0].relative_path != relative_path
                or rows[0].sha256 != sha256 or rows[0].size_bytes != size_bytes
                or role not in rows[0].roles):
            raise BootstrapEnrollmentPending("installed release lacks the exact pinned Xpra transform module")
        handle = secrets.token_urlsafe(36)
        receipt = RootInstalledReleaseMemberReceipt(
            artifact_id, relative_path, sha256, size_bytes, release.release_commit,
            release.deployment_receipt_sha256, handle, self._handle.session_id,
            self._seal, self,
        )
        self._installed_release_member_receipts[handle] = receipt
        # First read verifies the held release FD and digest before the receipt
        # can be passed to the build-selection producer.
        receipt.read_current()
        actor.verify_current(release)
        return receipt

    def _read_installed_release_member_receipt(
            self, receipt: RootInstalledReleaseMemberReceipt) -> bytes:
        self._check_live()
        if (not isinstance(receipt, RootInstalledReleaseMemberReceipt)
                or receipt._session is not self
                or receipt._session_id != self._handle.session_id
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or self._installed_release_member_receipts.get(receipt.receipt_handle) is not receipt):
            raise BootstrapEnrollmentPending("installed release member receipt is not retained by this setup session")
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, sha256, size_bytes, role = _XPRA_TRANSFORM_MODULE
        row = next((item for item in release.files if item.artifact_id == artifact_id), None)
        if (row is None or role not in row.roles or row.relative_path != relative_path
                or row.sha256 != sha256 or row.size_bytes != size_bytes
                or receipt.artifact_id != artifact_id or receipt.sha256 != sha256
                or receipt.size_bytes != size_bytes or receipt.release_commit != release.release_commit
                or receipt.deployment_receipt_sha256 != release.deployment_receipt_sha256):
            raise BootstrapEnrollmentPending("installed release member differs from its fixed receipt")
        fd = release.open_file(artifact_id)
        try:
            content = bytearray()
            while len(content) <= size_bytes:
                block = os.read(fd, min(64 * 1024, size_bytes + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
        finally:
            os.close(fd)
        if len(content) != size_bytes or hashlib.sha256(content).hexdigest() != sha256:
            raise BootstrapEnrollmentPending("installed release module bytes changed after verification")
        actor.verify_current(release)
        return bytes(content)

    def _read_release_member_receipt(self, receipt: RootReleaseModuleReceipt) -> bytes:
        self._check_live()
        if (not isinstance(receipt, RootReleaseModuleReceipt)
                or receipt._session is not self
                or receipt._session_id != self._handle.session_id
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or self._release_member_receipts.get(receipt.source_receipt_handle) is not receipt):
            raise BootstrapEnrollmentPending("release member receipt is not retained by this live setup session")
        selection = next((item for item in self._native_assembly_selections.values()
                          if item.setup_session_id == receipt._session_id
                          and item.expires_monotonic > time.monotonic()), None)
        if selection is None:
            raise BootstrapEnrollmentPending("release member receipt has no current native assembly selection")
        self._revalidate_native_assembly_selection(selection)
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        row = next((item for item in release.files if item.artifact_id == receipt.artifact_id), None)
        if (row is None or "module" not in row.roles
                or row.relative_path != receipt.relative_path
                or row.sha256 != receipt.sha256 or row.size_bytes != receipt.size_bytes
                or release.release_commit != receipt.release_commit
                or release.deployment_receipt_sha256 != receipt.deployment_receipt_sha256):
            raise BootstrapEnrollmentPending("release member differs from its root-issued receipt")
        if not any(origin[1] == str(release.release_root / row.relative_path)
                   and origin[4] == row.sha256 for origin in actor.module_origins):
            raise BootstrapEnrollmentPending("release member left the current actor's imported module closure")
        fd = release.open_file(receipt.artifact_id)
        try:
            content = bytearray()
            while len(content) <= receipt.size_bytes:
                block = os.read(fd, min(64 * 1024, receipt.size_bytes + 1 - len(content)))
                if not block:
                    break
                content.extend(block)
        finally:
            os.close(fd)
        if len(content) != receipt.size_bytes or hashlib.sha256(content).hexdigest() != receipt.sha256:
            raise BootstrapEnrollmentPending("release module bytes changed after receipt issuance")
        actor.verify_current(release)
        return bytes(content)

    def _revalidate_native_assembly_selection(
            self, selection: RootNativeBootstrapAssemblySelection) -> None:
        """Revalidate a retained selection; no caller-created DTO can pass."""
        if (not isinstance(selection, RootNativeBootstrapAssemblySelection)
                or self._native_assembly_selections.get(selection.selection_handle) is not selection
                or selection._registry_seal is not self._factory._native_assembly_seal
                or selection.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("native assembly selection is stale or unrecognized")
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared"
                or selection.setup_session_id != self._handle.session_id
                or selection.transaction_handle != self._authorization.transaction_handle
                or selection.plan_digest != self._authorization.plan_digest
                or selection.prepared_generation_id != prepared.generation_id
                or selection.protected_enrollment_digest != prepared.generation_digest
                or selection.service_generation != prepared.generation_id):
            raise BootstrapEnrollmentPending("native assembly selection no longer matches prepared setup custody")
        raise BootstrapEnrollmentPending(
            "native assembly source, runtime, materialization and protected definition joins are not yet available")

    def record_functional_health(self, _active_receipt: EnrollmentReceipt, _health_receipt: Any) -> None:
        self._check_live()
        raise BootstrapEnrollmentPending("functional health requires the root-native health observer receipt consumer")

    def _make_source_provisioner(self) -> Any:
        from ..hermes_source import PinnedHermesSourceProvisioner
        from .bootstrap_enrollment import RootLocalCatalogArtifactFetcher
        fetcher = RootLocalCatalogArtifactFetcher(
            catalog=self._factory._catalog,
            artifact_root=self._factory._receipt_registry.artifact_root,
            session_store=self._factory.session_store, session_handle=self._handle,
        )
        return PinnedHermesSourceProvisioner(
            fetcher=fetcher, catalog=self._factory._catalog,
            artifact_root=self._factory._receipt_registry.artifact_root,
            receipt_registry=self._factory._receipt_registry, expected_uid=0,
        )

    def _source_receipt(self, proof: VerifiedRootSetupAuthorization) -> str:
        self._check_live()
        if proof != self._authorization:
            raise BootstrapEnrollmentError("source request does not match this live root setup authorization")
        if self._source_receipt_handle is None:
            self._source_handoff = self._source_provisioner.provision(proof)
            self._source_receipt_handle = self._source_handoff.receipt_handle
        return self._source_receipt_handle

    def _refresh_authorization(self) -> None:
        live = self._factory.session_store._live(self._handle)
        self._authorization = self._factory.session_store._proof(live)

    def close(self) -> None:
        if self._closed:
            return
        for proof in self._resource_profile_tty_proofs.values():
            try:
                proof.close()
            except Exception:
                pass
        self._resource_profile_tty_proofs.clear()
        for proof in self._application_choice_tty_proofs.values():
            try:
                proof.close()
            except Exception:
                pass
        self._application_choice_tty_proofs.clear()
        self._factory.session_store.close_session(self._handle)
        self._factory._sessions.pop(self._handle.session_id, None)
        self._closed = True

    def _check_live(self) -> None:
        if self._closed:
            raise BootstrapEnrollmentPending("root setup session is closed")
        self._factory.session_store._live(self._handle)

    def __enter__(self) -> "RootBootstrapSession":
        self._check_live()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self.close()


# Public root setup composition surface. setup_principal uses local imports of
# this module for the typed stage-zero context, so the re-export is deliberately
# placed after the factory/session definitions to avoid an import cycle.
from .setup_principal import (  # noqa: E402
    AuthentikIdentityReceipt,
    RootSetupAuthentikIdentityObserver,
    RootSetupIdentityIntake,
    RootSetupPrincipalSelectionRegistry,
    VerifiedRootSetupPrincipalSelection,
)
from .initial_policy_compiler import RootFirstStagePolicyCompiler  # noqa: E402
from .active_policy_compiler import RootActivePolicyCompilationRegistry  # noqa: E402
from .setup_capabilities import ReviewedNativeCapabilitySelection  # noqa: E402
from .setup_policy_publication import RootSetupPolicyGenerationPublisher  # noqa: E402

__all__ = [
    "CompiledRootSetupPublication", "RootActivePolicyCompilationRegistry",
    "RootBootstrapRuntimeFactory", "RootBootstrapSession",
    "RootInitialCompilationRegistry", "RootInitialCompilationSession",
    "RootInitialPublicationHandoff", "RootInitialSetupAggregate",
    "RootNativeAssemblyDefinitions", "RootNativeAssemblyMember", "RootReleaseModuleReceipt",
    "RootInstalledReleaseMemberReceipt", "RootSelectedApplicationQualificationChoice",
    "RootNativeBootstrapAssemblySelection", "RootSelectedInstallationBinding",
    "RootSetupChoices", "RootSetupPolicyGenerationPublisher",
    "RootSetupPrincipalSelectionRegistry", "RootFirstStagePolicyCompiler",
    "RootPreparedNativeBundle",
    "ReviewedNativeCapabilitySelection", "VerifiedReviewedNativeCapabilityMap",
]
