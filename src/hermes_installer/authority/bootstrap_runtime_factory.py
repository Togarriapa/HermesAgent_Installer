"""Installed root setup assembly for the first Hermes service generation.

The selection file, release tree, artifact catalog and bootstrap-policy document
are all read from the root deployment trust source. This module deliberately
does not accept caller supplied policy rows, paths, hashes or ``EnrollmentPolicy``
objects. Runtime activation accepts only setup-scoped receipt handles that the
same root registry resolves to immutable CAS objects.
"""
from __future__ import annotations

import copy
import grp
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
from typing import TYPE_CHECKING, Any, Mapping

from ..artifacts import ArtifactCatalog, load_protected_catalog
from ..protected_enrollment import RootJournalSelection
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
    _validate_authority_base,
    _atomic_root_file,
    _canonical,
    _create_service_root,
    _ensure_root_directory,
    _read_json_if_owned,
    _secure_directory_identity,
    _open_immutable_release_root,
    _read_secure_root_bytes,
    _unique_pairs,
    _validate_sha256,
    _verify_release_file_at,
)
from .application_runtime_selection import (
    RootApplicationRuntimePreparationInputSelection,
    RootApplicationRuntimePreparationSelection,
)

if TYPE_CHECKING:
    from .native_materialization import NativeMaterializationSelection


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
_APPLICATION_QUALIFICATION_PHASES = (
    "stage-pinned-source-locks",
    "acquire-locked-runtime-packages",
    "prepare-locked-isolated-runtime",
    "observe-runtime-probe",
    "run-owned-local-fixture",
)
_APPLICATION_QUALIFICATION_NETWORK_SCOPE = (
    "Qualification process effects only deny or exact root owned fixture loopback receipt endpoint. "
    "Public pinned artifact/source acquisition uses existing fixed hash/TLS sourcefetch scope, "
    "not permission to contact arbitrary provider/account/URI. Consent forbids private/provider "
    "model egress, extraction/capture/background memory, trade/payment/messaging, browserarbitraryURLs "
    "or addedbudget."
)
_XPRA_TRANSFORM_MODULE = (
    "installer-xpra-root-xauthority-transform-module-v1",
    "src/hermes_installer/remote/xpra_root_xauthority.py",
    "3342afa5311fef5008a35317a526c75b3d1531d21e92d1f8aae87dba38b0a7d1",
    59_621,
    "xpra-root-xauthority-transform-module",
)
_PREPARED_BUILD_TEMPLATE = (
    "installer-prepared-build-service-template-v1",
    "plans/amendments/2026-10-10-prepared-build-service-selection-v115/prepared-build-service-template-v1.json",
    "0d98bdabf27185d769f55de12e9242d5286e07d11e5d62369c2eeedf1fa4b967",
    1235,
)
_PREPARED_APPLICATION_BUILD_TEMPLATE = (
    "installer-prepared-application-build-service-template-v1",
    "plans/amendments/2026-10-10-application-offline-runtime-build-v132/prepared-application-build-service-template-v1.json",
    "8cc3bbce52901c5f05bab99622d77d9d4d44f4a5fe27eb636e3fe8e23beab0d9",
    1498,
    "prepared-build-service-template",
)
_PREPARED_APPLICATION_BUILD_PROFILES = {
    "application-graphify-runtime-prepare-v1": (
        "graphify", "application-graphify-runtime-prepare-v1",
        "application-graphify-runtime-prepare:start"),
    "application-browser-use-runtime-prepare-v1": (
        "browser-use", "application-browser-use-runtime-prepare-v1",
        "application-browser-use-runtime-prepare:start"),
    "application-hyperframes-runtime-prepare-v1": (
        "hyperframes", "application-hyperframes-runtime-prepare-v1",
        "application-hyperframes-runtime-prepare:start"),
    "application-scrapegraph-ai-runtime-prepare-v1": (
        "scrapegraph-ai", "application-scrapegraph-ai-runtime-prepare-v1",
        "application-scrapegraph-ai-runtime-prepare:start"),
}
_NATIVE_ASSEMBLY_COMPILER_ARTIFACT = "installer-module:hermes_installer.authority.native_assembler"
_NATIVE_ASSEMBLY_SUPPORT_MODULES = (
    "installer-module:hermes_installer.authority.native_assembler",
    "installer-module:hermes_installer.authority.native_materialization",
    "installer-module:hermes_installer.authority.native_registration_projection",
    "installer-module:hermes_installer.authority.native_output_receipts",
)
_CAPABILITY_MAP_TEMPLATE_SHA256 = "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565"
_CAPABILITY_MAP_TEMPLATE_PATH = "templates/reviewed-native-capability-map-v1.json"
_CAPABILITY_MAP_TEMPLATE_SIZE = 2026
_EXISTING_MODEL_STORE_TEMPLATE = (
    "installer-existing-model-store-root-template-v1",
    "templates/existing-model-store-root-template-v1.json",
    "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f",
    712,
    "existing-model-store-root-template",
)
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
_PREPARED_RELEASE_MEMBER_SEAL = object()


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
    _prepared_generation_id: str | None = field(default=None, repr=False, compare=False)

    def read_current(self) -> bytes:
        """Read the exact installed module through the held release FD."""
        return self._session._read_release_member_receipt(self)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedReleaseMemberReceipt:
    """Held-release source membership for code loaded later by a managed worker.

    This proves release membership and bytes only. It deliberately does not
    claim that the current setup actor imported the module; worker loader
    evidence is a separate join.
    """

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    release_commit: str
    deployment_receipt_sha256: str
    source_receipt_handle: str
    setup_session_id: str = field(repr=False)
    prepared_generation_id: str = field(repr=False)
    _receipt_seal: object = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._receipt_seal is not _PREPARED_RELEASE_MEMBER_SEAL:
            raise TypeError("prepared release members are minted by the current root setup session")

    def read_current(self) -> bytes:
        return self._session._read_prepared_release_member(self)


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
class RootExistingModelStoreTemplateReceipt:
    """Held installed-release receipt for the fixed v139 model-store root policy."""

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    role: str
    release_commit: str
    deployment_receipt_sha256: str
    receipt_handle: str
    _session_id: str = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def read_current(self) -> bytes:
        return self._session._read_existing_model_store_template(self)

    def verify_current(self) -> "RootExistingModelStoreTemplateReceipt":
        # The held release member is re-opened and checked on every use.  A
        # successful read is the currentness proof; the receipt itself stays
        # bound to this exact live session object.
        self.read_current()
        return self


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
class RootPreparedBuildServiceSelection:
    """Transaction-private setup build subject backed by actual NSS and roots."""

    service_selection_handle: str
    id: str
    profile_id: str
    generation: str
    setup_session_id: str
    transaction_handle: str
    prepared_generation_id: str
    prepared_generation_digest: str
    template_artifact_id: str
    template_sha256: str
    service_uid: int
    service_gid: int
    nss_identity_receipt_handle: str
    root_selection_receipt_handle: str
    allowed_operation_ids: tuple[str, ...]
    allowed_targets: tuple[str, ...]
    expires_monotonic: float
    _signature: str = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)

    def verify_current(self) -> "RootPreparedBuildServiceSelection":
        return self._session._resolve_current_prepared_build_service(self.service_selection_handle)

    def create_output_root(self) -> "RootPreparedBuildOutputRoot":
        return self._session._create_prepared_build_output_root(self.service_selection_handle)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedBuildOutputRoot:
    """A fresh directory capability; no filesystem path crosses the factory API."""

    output_root_id: str
    service_selection_handle: str
    service_uid: int
    service_gid: int
    _directory_fd: int = field(repr=False, compare=False)
    _session: Any = field(repr=False, compare=False)
    _session_seal: str = field(repr=False, compare=False)

    def open_current(self) -> int:
        return self._session._open_prepared_build_output_root(self)

    def remove_contents_current(self) -> None:
        self._session._remove_prepared_build_output_contents(self)


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

    def resolve_application_source_preparation(self, choice_handle: str, application_id: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application source selection is not owned by this setup session")
        return self._session.resolve_application_source_preparation(choice_handle, application_id)

    def resolve_application_runtime_preparation_input(
            self, qualification_choice_handle: str, application_id: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application runtime inputs are not owned by this setup session")
        return self._session._resolve_application_runtime_preparation_input(
            qualification_choice_handle, application_id)

    def resolve_application_runtime_preparation_input_selection(self, selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application runtime input is not owned by this setup session")
        return self._session._resolve_application_runtime_preparation_input_selection(selection_handle)

    def resolve_application_runtime_preparation(
            self, qualification_choice_handle: str, application_id: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application runtime preparation is not owned by this setup session")
        return self._session._resolve_application_runtime_preparation(
            qualification_choice_handle, application_id)

    def resolve_application_runtime_preparation_selection(self, selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application runtime preparation is not owned by this setup session")
        return self._session._resolve_application_runtime_preparation_selection(selection_handle)

    def attach_application_source_preparation_registry(self, registry: Any) -> None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application source registry is not owned by this setup session")
        self._session._attach_application_source_preparation_registry(registry)

    def attach_application_runtime_preparation_selection_registry(self, registry: Any) -> None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application runtime selector is not owned by this setup session")
        self._session._attach_application_runtime_preparation_selection_registry(registry)

    def attach_application_package_closure_registry(self, registry: Any) -> None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application package registry is not owned by this setup session")
        self._session.attach_application_package_closure_registry(registry)

    def resolve_current_application_package_closure(self, source_preparation_selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application package registry is not owned by this setup session")
        return self._session.resolve_current_application_package_closure(
            source_preparation_selection_handle)

    def resolve_application_controller_binding(
        self, choice_handle: str,
    ) -> "RootApplicationSetupControllerBinding":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application controller binding is not owned by this setup session")
        return self._session.resolve_application_controller_binding(choice_handle)

    def resolve_application_controller_binding_by_handle(
        self, controller_binding_handle: str,
    ) -> "RootApplicationSetupControllerBinding":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application controller binding is not owned by this setup session")
        return self._session.resolve_application_controller_binding_by_handle(controller_binding_handle)

    def is_application_controller_binding_current(self, controller_binding_handle: str) -> bool:
        if not secrets.compare_digest(self._seal, self._session._seal):
            return False
        return self._session.is_application_controller_binding_current(controller_binding_handle)

    def verify_application_controller_binding(self, binding: "RootApplicationSetupControllerBinding") -> bool:
        if not secrets.compare_digest(self._seal, self._session._seal):
            return False
        return self._session.verify_application_controller_binding(binding)

    def resolve_current_active_enrollment(self) -> EnrollmentReceipt:
        """Return only the actual current committed enrollment from this live session."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active enrollment is not owned by this setup session")
        return self._session._resolve_current_active_enrollment()

    def resolve_current_prepared_enrollment(self) -> EnrollmentReceipt:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("prepared enrollment is not owned by this setup session")
        return self._session._resolve_current_prepared_enrollment()

    def resolve_current_active_policy_compilation_registry(self) -> Any:
        """Resolve the exact live-session active compiler and its typed inputs."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active policy compiler is not owned by this setup session")
        return self._session._resolve_current_active_policy_compilation_registry()

    def resolve_current_active_policy_publisher(self) -> Any:
        """Resolve the publisher composed from this session's current compiler."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active policy publisher is not owned by this setup session")
        return self._session._resolve_current_active_policy_publisher()

    def resolve_current_active_policy_publication(self) -> Any:
        """Read the root-selected active publication through its journal resolver."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active policy publication is not owned by this setup session")
        return self._session._resolve_current_active_policy_publication()

    def resolve_current_active_policy_predecessor(self, publication_handle: str) -> str:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("active policy claim is not owned by this setup session")
        return self._session._resolve_current_active_policy_predecessor(publication_handle)

    def resolve_adopted_principal_selector(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("principal selector is not owned by this setup session")
        return self._session.resolve_adopted_principal_selector()

    def resolve_adopted_namespace_selector(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("namespace selector is not owned by this setup session")
        return self._session.resolve_adopted_namespace_selector()

    def observe_public_web_permission_selection(self, native_policy_selection_handle: str) -> str | None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("public web choice is not owned by this setup session")
        return self._session.observe_public_web_permission_selection(native_policy_selection_handle)

    def resolve_current_public_web_permission_choice(self, choice_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("public web choice is not owned by this setup session")
        return self._session.resolve_current_public_web_permission_choice(choice_handle)

    def attach_public_input_disclosure_registry(self, registry: Any) -> None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("public input disclosure is not owned by this setup session")
        self._session.attach_public_input_disclosure_registry(registry)

    def observe_public_input_disclosure(self, selection_handle: str, input_handle: str,
                                        execution_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("public input disclosure is not owned by this setup session")
        return self._session.observe_public_input_disclosure(selection_handle, input_handle, execution_handle)

    def resolve_current_setup_identity(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("current setup identity is not owned by this setup session")
        return self._session.resolve_current_setup_identity()

    def resolve_current_setup_choice_signer(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable setup-choice signer is not owned by this session")
        return self._session.resolve_current_setup_choice_signer()

    def resolve_setup_choice_registry(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable setup-choice registry is not owned by this session")
        return self._session._root_setup_choice_registry()

    def resolve_current_setup_choice(self, selection_handle: str, expected_purpose: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable setup choice is not owned by this session")
        return self._session.resolve_current_setup_choice(selection_handle, expected_purpose)

    def record_durable_setup_choice(self, actual_root_tty_choice: Any) -> str | None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable setup choice is not owned by this session")
        return self._session.record_durable_setup_choice(actual_root_tty_choice)

    def revoke_durable_setup_choice_purpose(self, purpose: str, profile_id: str) -> int:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable setup choice is not owned by this session")
        return self._session.revoke_durable_setup_choice_purpose(purpose, profile_id)

    def resolve_current_release_receipt_handle(self) -> str:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("held installer release is not owned by this session")
        return self._session.resolve_current_release_receipt_handle()

    def resolve_current_setup_session_handle(self) -> RootSetupSessionHandle:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("setup session is not owned by this binding")
        return self._session.resolve_current_setup_session_handle()

    def resolve_durable_memory_enablement_choice_handle(self, choice_handle: str) -> str | None:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("durable memory choice is not owned by this session")
        return self._session.resolve_durable_memory_enablement_choice_handle(choice_handle)

    def observe_existing_model_selection(self, private_profile_selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("existing model selection is not owned by this setup session")
        return self._session.observe_existing_model_selection(private_profile_selection_handle)

    def observe_private_profile_selection(self, purpose: str) -> "RootPrivateProfileSelection":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("private profile selection is not owned by this setup session")
        return self._session.observe_private_profile_selection(purpose)

    def resolve_current_private_profile(
            self, selection_handle: str, purpose: str) -> "VerifiedRootPrivateProfileSelection":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("private profile selection is not owned by this setup session")
        return self._session.resolve_current_private_profile(selection_handle, purpose)

    def resolve_current_pm_runtime(self) -> Any:
        """Resolve the current official PM environment without accepting a path."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("PM runtime is not owned by this setup session")
        return self._session._resolve_current_pm_runtime()

    def resolve_current_pm_runtime_projection(self) -> Any:
        """Resolve held official PM base-runtime descriptors for the live setup."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("PM runtime projection is not owned by this setup session")
        return self._session._resolve_current_pm_runtime_projection()

    def resolve_current_pm_uv_tool(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("PM uv tool selection is not owned by this setup session")
        return self._session._resolve_current_pm_uv_tool()

    def resolve_current_pm_uv_tool_projection(self) -> Any:
        """Resolve the official PM uv executable as a held current receipt FD."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("PM uv tool projection is not owned by this setup session")
        return self._session._resolve_current_pm_uv_tool()

    def observe_memory_service_enablement(
            self, provider: str, backend_variant: str) -> "RootSelectedMemoryServiceEnablementChoice":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("memory service choice is not owned by this setup session")
        return self._session.observe_memory_service_enablement(provider, backend_variant)

    def resolve_current_memory_service_enablement_choice(
            self, selection_handle: str) -> "RootSelectedMemoryServiceEnablementChoice":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("memory service choice is not owned by this setup session")
        return self._session.resolve_current_memory_service_enablement_choice(selection_handle)

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

    def resolve_existing_model_store_template(self) -> "RootExistingModelStoreTemplateReceipt":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("model-store root template is not owned by this setup session")
        return self._session.resolve_existing_model_store_template()

    def resolve_held_installer_release_receipt(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("held installer release is not owned by this setup session")
        return self._session.resolve_held_installer_release_receipt()

    def resolve_prepared_build_service(self, build_profile_id: str) -> RootPreparedBuildServiceSelection:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("prepared build service is not owned by this setup session")
        return self._session._resolve_prepared_build_service(build_profile_id)

    def resolve_prepared_application_build_service(
            self, build_profile_id: str) -> RootPreparedBuildServiceSelection:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application build service is not owned by this setup session")
        return self._session._resolve_prepared_application_build_service(build_profile_id)

    def resolve_application_runtime_probe_artifact(self, application_id: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("application probe artifact is not owned by this setup session")
        return self._session._resolve_application_runtime_probe_artifact(application_id)

    def verify_current_setup_controller(self) -> VerifiedRootSetupAuthorization:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("setup controller proof is not owned by this session")
        return self._session._verify_current_setup_controller()

    def prepare_selected_native_bundle(self) -> "RootPreparedNativeBundle":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native prepared bundle is not owned by this setup session")
        return self._session.prepare_selected_native_bundle()

    def resolve_current_prepared_native_bundle(
            self, bundle: "RootPreparedNativeBundle") -> "RootPreparedNativeBundle":
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native prepared bundle is not owned by this setup session")
        return self._session._resolve_current_prepared_native_bundle(bundle)

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

    def resolve_prepared_release_module_receipts(self) -> tuple[RootReleaseModuleReceipt, ...]:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("prepared release modules are not owned by this setup session")
        return self._session._resolve_prepared_release_module_receipts()

    def resolve_prepared_native_target_module_receipts(self) -> tuple[RootReleaseModuleReceipt, ...]:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native target source modules are not owned by this setup session")
        return self._session._resolve_prepared_native_target_module_receipts()

    def resolve_prepared_worker_role_module_receipts(self) -> tuple[RootPreparedReleaseMemberReceipt, ...]:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("worker role source receipts are not owned by this setup session")
        return self._session._resolve_prepared_worker_role_module_receipts()

    def resolve_prepared_native_source_definition_module_receipt(self) -> RootReleaseModuleReceipt:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native source definition receipt is not owned by this setup session")
        return self._session._resolve_prepared_native_source_definition_module_receipt()

    def mint_native_registration_schema_receipt(self, artifact_id: str) -> RootNativeRegistrationSchemaReceipt:
        """Fetch and receipt only one of the exact reviewed local result schemas."""
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native schema receipt is not owned by this setup session")
        return self._session._mint_native_registration_schema_receipt(artifact_id)

    def resolve_current_native_policy_registry(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native policy registry is not owned by this setup session")
        return self._session._resolve_current_native_policy_registry()

    def observe_native_policy_configuration(self) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native policy choice is not owned by this setup session")
        return self._session.observe_native_policy_configuration()

    def resolve_current_native_policy_configuration_choice(self, choice_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native policy choice is not owned by this setup session")
        return self._session.resolve_current_native_policy_configuration_choice(choice_handle)

    def resolve_current_native_policy_selection(self, selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native policy selection is not owned by this setup session")
        return self._session.resolve_current_native_policy_selection(selection_handle)

    def resolve_current_native_policy_targets(self, selection_handle: str) -> tuple[Any, ...]:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("native policy targets are not owned by this setup session")
        return self._session.resolve_current_native_policy_targets(selection_handle)

    def resolve_current_prepared_native_policy_records(self, selection_handle: str) -> Any:
        if not secrets.compare_digest(self._seal, self._session._seal):
            raise BootstrapEnrollmentPending("prepared native policy records are not owned by this setup session")
        return self._session.resolve_current_prepared_native_policy_records(selection_handle)

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
    """Root-TTY workflow selection plus bounded local qualification consent."""

    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    workflow_id: str
    application_id: str
    workload_id: str
    target_profile_id: str
    namespace_selection_receipt_handle: str
    principal_selection_receipt_handle: str
    principal_selection_handle: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    controller_binding_handle: str
    qualification_consent_receipt_handle: str
    choice_observation_id: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationQualificationConsent:
    """Short-lived setup consent for one finite local qualification phase."""

    schema: int
    receipt_handle: str
    consent_id: str
    purpose: str
    choice_observation_id: str
    qualification_choice_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    application_id: str
    workflow_id: str
    target_profile_id: str
    namespace_selection_receipt_handle: str
    principal_selection_handle: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    controller_binding_handle: str
    allowed_phase_ids: tuple[str, ...]
    network_scope: str
    additional_metered_budget_usd: float
    revocation_epoch: int
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationSetupControllerBinding:
    """Opaque root-TTY controller proof bound to one current setup choice."""

    handle: str
    setup_session_id: str
    qualification_choice_handle: str
    principal_id: str
    issued_monotonic: float
    expires_monotonic: float
    _session_seal: str = field(repr=False, compare=False)
    _proof: Any = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootSelectedMemoryServiceEnablementChoice:
    """Durable setup preference; it does not authorize process or memory effects."""

    schema: int
    choice_handle: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_receipt_handle: str
    principal_selection_handle: str
    principal_binding_sha256: str
    private_profile_selection_receipt_handle: str
    private_profile_selection_handle: str
    namespace_selection_receipt_handle: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    principal_id: str
    profile_id: str
    namespace_id: str
    provider: str
    backend_variant: str
    enabled: bool
    controller_binding_handle: str
    policy_revision: str
    selection_digest: str
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootPrivateProfileSelection:
    """Stable, purpose-limited private profile intent; it grants no dispatch authority."""

    selection_handle: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    principal_id: str
    profile_id: str
    namespace_id: str
    namespace_policy: str
    purpose: str
    privacy_classification: str
    public_egress_allowed: bool
    additional_metered_budget_usd: float
    source_template_receipt_handles: tuple[str, ...]
    reviewed_capability_map_sha256: str
    controller_binding_handle: str
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _session_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedRootPrivateProfileSelection:
    receipt_handle: str
    selection_handle: str
    purpose: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_selection_receipt_handle: str
    namespace_selection_receipt_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    namespace_policy: str
    privacy_classification: str
    public_egress_allowed: bool
    additional_metered_budget_usd: float
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _selection: RootPrivateProfileSelection = field(repr=False, compare=False)

    @property
    def controller_binding_handle(self) -> str:
        """Opaque handle joined to the retained root TTY proof for this choice."""
        return self._selection.controller_binding_handle


_PRIVATE_PROFILE_PURPOSES = frozenset({
    "memory-service-enablement", "existing-model-selection",
})
_PRIVATE_PROFILE_SEAL = object()


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
    process_role_records: tuple[Mapping[str, Any], ...]
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
        self._validate_authority_base_template(base, compilation_phase=compilation_phase)
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
                            "channel_delivery_bindings", "selected_resource_executions",
                            "selected_application_runtimes"}
        catalogs = doc["catalog_selections"]
        if not isinstance(catalogs, dict) or set(catalogs) != selection_fields:
            _fail("bootstrap catalog selections do not cover the exact enrollment schema")
        clean_catalogs = {}
        for name, rows in catalogs.items():
            if not isinstance(rows, list) or len(rows) > 1024 or any(not isinstance(row, dict) for row in rows):
                _fail("bootstrap catalog selection rows are malformed")
            clean_catalogs[name] = tuple(copy.deepcopy(rows))
        active_catalog_names = selection_fields - {"root_journal_roots"}
        if compilation_phase == "prepared":
            if any(clean_catalogs[name] for name in active_catalog_names):
                _fail("prepared bootstrap policy cannot preselect active catalogs")
        else:
            self._validate_active_catalog_selections(clean_catalogs, base)
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
    def _validate_authority_base_template(value: Any, *, compilation_phase: str = "prepared") -> None:
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
            "selected_resource_executions", "selected_application_runtimes",
        )
        if len(normalized["root_journal_roots"]) != 1:
            _fail("authority base must bind the exact root-journal identity")
        if compilation_phase == "prepared" and (
                normalized["service_records"]
                or any(normalized[name] for name in empty_snapshot_catalogs)):
            _fail("prepared authority base must bind the exact empty service snapshot")

    @staticmethod
    def _validate_active_catalog_selections(catalogs: Mapping[str, tuple[Mapping[str, Any], ...]],
                                            base: Mapping[str, Any]) -> None:
        """Require active catalog selections to equal strict, digest-bound rows.

        The policy parser proves structure and joins only. The active compiler
        and publisher additionally prove the source receipts/current selection
        before these rows can be published.
        """
        from .enrollment import _validate_service_generations
        generation = base.get("service_generations")
        if (not isinstance(generation, dict)
                or generation == {"root_binding": "prepared_service_generation.exact_empty_snapshot"}):
            _fail("active bootstrap policy requires a complete digest-bound service generation")
        try:
            normalized = _validate_service_generations(generation)
        except Exception:
            _fail("active bootstrap policy service generation is malformed or has broken joins")
        joins = {
            "protected_devices": "protected_devices",
            "protected_build_records": "protected_build_records",
            "native_packages": "native_packages",
            "memory_enrollments": "memory_enrollments",
            "operation_parameter_schemas": "operation_parameter_schemas",
            "source_issuers": "source_issuers",
            "resource_jobs": "resource_jobs",
            "remote_session_enrollments": "remote_session_enrollments",
            "resource_backend_enrollments": "resource_backend_enrollments",
            "resource_body_recipes": "resource_body_recipes",
            "resource_scope_bindings": "resource_scope_bindings",
            "resource_validators": "resource_validators",
            "root_journal_roots": "root_journal_roots",
            "resource_controller_roles": "resource_controller_roles",
            "native_mcp_tool_bindings": "native_mcp_tool_bindings",
            "remote_observation_enrollments": "remote_observation_enrollments",
            "native_schema_artifacts": "native_schema_artifacts",
            "composio_channel_enrollments": "composio_channel_enrollments",
            "channel_delivery_bindings": "channel_delivery_bindings",
            "selected_resource_executions": "selected_resource_executions",
            "selected_application_runtimes": "selected_application_runtimes",
        }
        for selected_name, generation_name in joins.items():
            selected = tuple(_plain_json(row) for row in catalogs[selected_name])
            actual = tuple(_plain_json(row) for row in normalized[generation_name])
            if selected != actual:
                _fail("active catalog selection differs from its digest-bound service-generation rows")

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
        self._verify_reader_policy(verified_release)
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
            _initial_compilation_registry=self.initial_registry,
            _authority_key_registry=self.key_registry,
            _initial_principal_registry=self.principal_registry,
            _initial_identity_observer=self.identity_observer,
            _initial_identity_intake=self.identity_intake)
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
                 _initial_compilation_registry: "RootInitialCompilationRegistry | None" = None,
                 _authority_key_registry: Any | None = None,
                 _initial_principal_registry: Any | None = None,
                 _initial_identity_observer: Any | None = None,
                 _initial_identity_intake: Any | None = None,
                 _authority_service: Any | None = None):
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
        if _authority_service is not None:
            from .service import AuthorityService
            if type(_authority_service) is not AuthorityService:
                raise BootstrapEnrollmentPending("model-store authority binding must be the actual root AuthorityService")
        self._authority_service = _authority_service
        if (_initial_compilation_registry is not None
                and (not isinstance(_initial_compilation_registry, RootInitialCompilationRegistry)
                     or _initial_compilation_registry.release is not _release
                     or _initial_compilation_registry.actor is not _actor)):
            raise BootstrapEnrollmentPending("initial publication registry is not bound to this held release actor")
        self._initial_compilation_registry = _initial_compilation_registry
        self._authority_key_registry = _authority_key_registry
        if _authority_key_registry is not None:
            if (_initial_compilation_registry is None
                    or getattr(_authority_key_registry, "initial_compilation_registry", None)
                       is not _initial_compilation_registry
                    or getattr(_authority_key_registry, "release", None) is not _release
                    or not callable(getattr(_authority_key_registry,
                                            "resolve_normal_setup_choice_signer", None))):
                raise BootstrapEnrollmentPending(
                    "authority-key signer registry is not bound to the transferred release and initial setup")
        if ((_initial_principal_registry is None)
                != (_initial_identity_observer is None)
                or (_initial_principal_registry is None)
                != (_initial_identity_intake is None)):
            raise BootstrapEnrollmentPending(
                "initial principal registry, identity observer, and intake must transfer together")
        self._initial_principal_registry = _initial_principal_registry
        self._initial_identity_observer = _initial_identity_observer
        self._initial_identity_intake = _initial_identity_intake
        self.resolver = InstalledBootstrapPolicyResolver(_SELECTION_PATH)
        if _initial_principal_registry is not None:
            from .setup_principal import (
                RootSetupAuthentikIdentityObserver, RootSetupIdentityIntake,
                RootSetupPrincipalSelectionRegistry,
            )
            if (not isinstance(_initial_principal_registry, RootSetupPrincipalSelectionRegistry)
                    or not isinstance(_initial_identity_observer, RootSetupAuthentikIdentityObserver)
                    or not isinstance(_initial_identity_intake, RootSetupIdentityIntake)
                    or _initial_principal_registry.identity_resolver is not _initial_identity_observer
                    or _initial_identity_observer.policy_resolver is not _initial_identity_intake
                    or _initial_principal_registry.setup_session_store is not _initial_compilation_registry
                    or _initial_identity_observer.setup_session_store is not _initial_compilation_registry
                    or _initial_identity_intake.initial_registry is not _initial_compilation_registry
                    or _initial_identity_intake.actor_verifier is not _initial_compilation_registry.actor_verifier
                    or _initial_identity_intake.vault is not _initial_identity_observer.vault
                    or _initial_principal_registry.root_journal != self.resolver.journal_root
                    or _initial_identity_observer.root_journal != self.resolver.journal_root):
                raise BootstrapEnrollmentPending(
                    "transferred principal registry and identity observer do not match the held initial setup")
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
        self._setup_choice_signers: dict[str, Any] = {}

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
        session = self._wrap_live_session(handle)
        if mode == "resume":
            try:
                session._restore_current_prepared_checkpoint()
            except Exception:
                session.close()
                raise
        return session

    def begin_from_initial_publication(self, handoff_handle: str) -> "RootBootstrapSession":
        """Adopt the same-process stage-zero publication into a normal session."""
        if self._initial_compilation_registry is None:
            raise BootstrapEnrollmentPending("fresh setup has no retained stage-zero publication registry")
        handle = self.session_store.begin_from_initial_publication(handoff_handle)
        try:
            session = self._wrap_live_session(handle)
            if (self._initial_principal_registry is None
                    or self._initial_identity_observer is None
                    or self._initial_identity_intake is None):
                raise BootstrapEnrollmentPending(
                    "published setup lacks retained principal and identity adoption dependencies")
            normal_observer, identity_receipt_handle = self._initial_identity_intake.rebind_published_policy(
                normal_session_store=self.session_store,
                normal_session_handle=handle,
                initial_principal_registry=self._initial_principal_registry,
                initial_identity_observer=self._initial_identity_observer,
            )
            normal_principal_registry, principal_selection_handle = (
                self._initial_principal_registry.adopt_initial_publication(
                    normal_session_store=self.session_store,
                    normal_session_handle=handle,
                    authenticated_identity_receipt_handle=identity_receipt_handle,
                    normal_identity_resolver=normal_observer,
                )
            )
            session._adopted_identity_observer = normal_observer
            session._adopted_identity_receipt_handle = identity_receipt_handle
            session._adopted_principal_registry = normal_principal_registry
            session._adopted_principal_selection_handle = principal_selection_handle
            # Re-open the exact stage-zero key receipt and adopt it against the
            # consumed publication handoff. Durable setup choices never use the
            # process-local session seal as a signer.
            key_registry = self._authority_key_registry
            if key_registry is None:
                raise BootstrapEnrollmentPending(
                    "normal setup lacks the transferred stage-zero authority-key registry")
            adopted_handoff = self._initial_compilation_registry.resolve_adopted_handoff(handle)
            key_receipt = key_registry.resolve_selected_key_for_compilation_session(
                adopted_handoff.compilation_session_handle)
            signer = key_registry.adopt_for_normal_setup(
                key_receipt.receipt_handle,
                adopted_handoff.compilation_session_handle,
                handle,
                adopted_handoff.handoff_handle,
            )
            session._setup_choice_signer = signer
            self._setup_choice_signers[handle.session_id] = signer
            return session
        except Exception:
            self.session_store.close_session(handle)
            self._sessions.pop(handle.session_id, None)
            raise

    def _wrap_live_session(self, handle: RootSetupSessionHandle) -> "RootBootstrapSession":
        try:
            live = self.session_store._live(handle)
            authorization = self.session_store._proof(live)
            policy = self.resolver.resolve_policy(
                authorization.plan_artifact_id,
                compilation_phase="prepared" if authorization.mode in {"install", "resume"} else "active")
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
        self._adopted_identity_observer: Any | None = None
        self._adopted_identity_receipt_handle: str | None = None
        self._adopted_principal_registry: Any | None = None
        self._adopted_principal_selection_handle: str | None = None
        self._setup_choice_signer: Any | None = None
        self._setup_choice_registry: Any | None = None
        self._public_input_disclosure_registry: Any | None = None
        self._public_web_selection_registry: Any | None = None
        self._durable_memory_choice_handles: dict[str, str] = {}
        self._release_receipt_handle: str | None = None
        self._native_output_receipts: Any | None = None
        self._active_policy_compilation_registry: Any | None = None
        self._active_policy_publisher: Any | None = None
        self._pm_runtime_registry: Any | None = None
        self._pm_runtime_handle: str | None = None
        self._native_pm_bindings: set[tuple[str, str, str]] = set()
        self._resource_profiles: dict[str, RootSelectedResourceProfile] = {}
        self._resource_profile_tty_proofs: dict[str, Any] = {}
        self._application_setup_choices: dict[str, RootSelectedApplicationQualificationChoice] = {}
        self._application_source_preparations: dict[str, Any] = {}
        self._application_source_preparation_handles: dict[tuple[str, str], str] = {}
        self._application_source_preparation_registry: Any | None = None
        self._application_runtime_preparation_selection_registry: Any | None = None
        self._application_package_closure_registry: Any | None = None
        self._application_node_bun_toolchain_registry: Any | None = None
        self._application_choice_tty_proofs: dict[str, Any] = {}
        self._application_controller_tty_proofs: dict[str, Any] = {}
        self._application_controller_bindings: dict[str, RootApplicationSetupControllerBinding] = {}
        self._application_qualification_consents: dict[str, RootApplicationQualificationConsent] = {}
        self._application_package_closure_registry: Any | None = None
        self._private_profile_registry: RootPrivateProfileSelectionRegistry | None = None
        self._private_profile_proofs: dict[str, Any] = {}
        self._model_store_filesystem_registry: Any | None = None
        self._existing_model_selection_registry: Any | None = None
        self._existing_model_store_template_receipt: RootExistingModelStoreTemplateReceipt | None = None
        self._memory_enablement_choices: dict[str, RootSelectedMemoryServiceEnablementChoice] = {}
        self._memory_enablement_tty_proofs: dict[str, Any] = {}
        self._verified_resources: dict[str, tuple[Any, Any]] = {}
        self._native_materializer: Any | None = None
        self._native_materialization_receipts: dict[str, Any] = {}
        self._prepared_native_bundle: RootPreparedNativeBundle | None = None
        self._native_assembly_selections: dict[str, RootNativeBootstrapAssemblySelection] = {}
        self._native_assembly_definitions: dict[str, RootNativeAssemblyDefinitions] = {}
        self._release_member_receipts: dict[str, RootReleaseModuleReceipt] = {}
        self._prepared_release_member_receipts: dict[str, RootReleaseModuleReceipt] = {}
        self._prepared_release_file_receipts: dict[str, RootPreparedReleaseMemberReceipt] = {}
        self._installed_release_member_receipts: dict[str, RootInstalledReleaseMemberReceipt] = {}
        self._native_schema_receipts: dict[str, RootNativeRegistrationSchemaReceipt] = {}
        self._native_schema_receipts_by_artifact: dict[str, RootNativeRegistrationSchemaReceipt] = {}
        self._native_schema_receipt_registry: Any | None = None
        self._native_schema_receipt_registry_minted_for: tuple[str, str] | None = None
        self._native_policy_preparation_registry: Any | None = None
        self._native_component_target_registry: Any | None = None
        self._native_registration_projection_registry: Any | None = None
        self._native_source_definition_registry: Any | None = None
        self._native_schema_derivation_registry: Any | None = None
        self._native_policy_choices: dict[str, Any] = {}
        self._native_policy_tty_proofs: dict[str, Any] = {}
        self._native_policy_records_by_selection: dict[str, Any] = {}
        self._prepared_build_identity: SystemIdentityAdapter | None = None
        self._prepared_build_selections: dict[str, RootPreparedBuildServiceSelection] = {}
        self._prepared_application_build_selections: dict[str, RootPreparedBuildServiceSelection] = {}
        self._prepared_build_output_roots: dict[str, RootPreparedBuildOutputRoot] = {}
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

    def resolve_current_setup_choice_signer(self) -> Any:
        self._check_live()
        registry = self._factory._authority_key_registry
        if registry is None:
            raise BootstrapEnrollmentPending("normal setup has no adopted authority-key signer registry")
        try:
            signer = registry.resolve_normal_setup_choice_signer(self._handle)
        except Exception:
            raise BootstrapEnrollmentPending("durable root setup-choice signer is stale or unavailable") from None
        if (self._setup_choice_signer is not None
                and getattr(self._setup_choice_signer, "key_id", None) != getattr(signer, "key_id", None)):
            raise BootstrapEnrollmentPending("normal setup-choice signer key changed after adoption")
        self._setup_choice_signer = signer
        return signer

    def _root_setup_choice_registry(self) -> Any:
        self._check_live()
        self.resolve_current_setup_choice_signer()
        if self._setup_choice_registry is None:
            try:
                from .root_setup_choices import RootSetupChoiceRegistry
                self._setup_choice_registry = RootSetupChoiceRegistry.from_root_setup(
                    self._factory._release, self._factory._actor, self._factory.session_store,
                    self._current_root_journal_selection(), self._setup_choice_signer)
            except Exception:
                raise BootstrapEnrollmentPending("durable root setup-choice registry is not composed") from None
        return self._setup_choice_registry

    def resolve_current_setup_choice(self, selection_handle: str, expected_purpose: str) -> Any:
        registry = self._root_setup_choice_registry()
        try:
            return registry.resolve_current_setup_choice(selection_handle, expected_purpose)
        except Exception:
            raise BootstrapEnrollmentPending("durable setup choice is absent, stale, or has another purpose") from None

    def record_durable_setup_choice(self, actual_root_tty_choice: Any) -> str | None:
        registry = self._root_setup_choice_registry()
        try:
            return registry.record_observed_choice(actual_root_tty_choice, self._selected_installation)
        except Exception:
            raise BootstrapEnrollmentPending("root TTY choice could not be durably signed and retained") from None

    def revoke_durable_setup_choice_purpose(self, purpose: str, profile_id: str) -> int:
        registry = self._root_setup_choice_registry()
        try:
            return registry.revoke_current_profile_purpose(
                self._selected_installation, purpose, profile_id)
        except Exception:
            raise BootstrapEnrollmentPending("current durable setup choice could not be revoked") from None

    def attach_public_web_selection_registry(self, registry: Any) -> None:
        """Attach the public-specific configuration producer during root composition."""
        self._check_live()
        from .public_web_selection import RootPublicWebSelectionRegistry
        targets = getattr(self, "_native_component_target_registry", None)
        if (type(registry) is not RootPublicWebSelectionRegistry
                or registry._session is not self or targets is None
                or registry._targets is not targets
                or self._public_web_selection_registry is not None):
            raise BootstrapEnrollmentPending("public web selector is not the exact retained native-target composition")
        self._public_web_selection_registry = registry

    def observe_public_web_permission_selection(
            self, native_policy_selection_handle: str,
    ) -> str | None:
        """Ask the root TTY to select finite source-derived public scope intent."""
        self._check_live()
        from .public_web_selection import RootPublicWebSelectionRegistry
        registry = self._public_web_selection_registry
        if (type(registry) is not RootPublicWebSelectionRegistry
                or registry._session is not self
                or registry._targets is not getattr(self, "_native_component_target_registry", None)):
            raise BootstrapEnrollmentPending("public web configuration producer is not composed")
        try:
            return registry.observe_public_web_permission_selection(native_policy_selection_handle)
        except Exception:
            raise BootstrapEnrollmentPending("root TTY public web choice is unavailable or was declined") from None

    def resolve_current_public_web_permission_choice(self, choice_handle: str) -> Any:
        self._check_live()
        registry = self._public_web_selection_registry
        if registry is None:
            raise BootstrapEnrollmentPending("public web choice resolver is not composed")
        try:
            return registry.resolve_current_public_web_permission_choice(choice_handle)
        except Exception:
            raise BootstrapEnrollmentPending("root TTY public web choice is absent or no longer current") from None

    def attach_public_input_disclosure_registry(self, registry: Any) -> None:
        """Attach the single public-specific TTY proof registry during root composition."""
        self._check_live()
        from .public_web_selection import RootPublicInputDisclosureRegistry
        source = (getattr(self, "_source_observer_registry", None)
                  or getattr(self._factory, "_source_observer_registry", None))
        if (type(registry) is not RootPublicInputDisclosureRegistry
                or source is None or registry._session is not self
                or registry._source is not source
                or self._public_input_disclosure_registry is not None):
            raise BootstrapEnrollmentPending("public input disclosure registry is not the exact root source composition")
        attach = getattr(source, "attach_public_input_disclosure_registry", None)
        if not callable(attach):
            raise BootstrapEnrollmentPending("source observer cannot retain the exact TTY disclosure registry")
        attach(registry)
        self._public_input_disclosure_registry = registry

    def resolve_current_public_input_disclosure_registry(self) -> Any:
        self._check_live()
        from .public_web_selection import RootPublicInputDisclosureRegistry
        registry = self._public_input_disclosure_registry
        source = (getattr(self, "_source_observer_registry", None)
                  or getattr(self._factory, "_source_observer_registry", None))
        if (type(registry) is not RootPublicInputDisclosureRegistry
                or registry._session is not self or source is None or registry._source is not source):
            raise BootstrapEnrollmentPending("root public input disclosure is not composed with the current source observer")
        return registry

    def observe_public_input_disclosure(
            self, public_permission_selection_handle: str,
            retained_observed_input_handle: str, selected_execution_handle: str,
    ) -> Any:
        """Review one exact retained input at the root TTY before public issuance."""
        self._check_live()
        registry = self.resolve_current_public_input_disclosure_registry()
        try:
            return registry.observe_public_input_disclosure(
                public_permission_selection_handle, retained_observed_input_handle,
                selected_execution_handle)
        except Exception:
            raise BootstrapEnrollmentPending("exact public input disclosure is unavailable or was declined") from None
    def _resolve_current_native_policy_registry(self) -> Any:
        """Compose the retained preactive native-policy registries once per session."""
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("native policy configuration requires current empty prepared custody")
        principal = self._adopted_principal_registry
        if principal is None:
            raise BootstrapEnrollmentPending("native policy configuration requires the adopted root principal registry")
        if self._native_policy_preparation_registry is None:
            from .native_component_targets import RootNativeComponentTargetRegistry
            from .native_registration_projection import RootNativeRegistrationProjectionRegistry
            from .native_policy_preparation import RootNativePolicyPreparationRegistry
            from .native_source_definitions import RootNativeSourceDefinitionRegistry
            from .native_schema_derivation import RootNativeSchemaDerivationRegistry
            journal = self._current_root_journal_selection().path
            binding = self._selected_installation
            targets = RootNativeComponentTargetRegistry.from_root_setup(binding, principal, journal)
            projections = RootNativeRegistrationProjectionRegistry.from_root_setup(binding, journal)
            source_definitions = RootNativeSourceDefinitionRegistry.from_selected_installation(binding)
            schema_derivations = RootNativeSchemaDerivationRegistry.from_root_setup(binding, journal)
            registry = RootNativePolicyPreparationRegistry.from_root_setup(
                binding, principal, targets, binding, projections, binding, journal)
            registry.attach_source_definition_registry(source_definitions)
            registry.attach_schema_derivation_registry(schema_derivations)
            self._native_component_target_registry = targets
            self._native_registration_projection_registry = projections
            self._native_source_definition_registry = source_definitions
            self._native_schema_derivation_registry = schema_derivations
            self._native_policy_preparation_registry = registry
        self._verify_current_setup_controller()
        return self._native_policy_preparation_registry

    def observe_native_policy_configuration(self) -> Any:
        """Capture root-TTY intent for finite native component families.

        The choice selects source families only. The registry separately
        resolves targets and reports any absent action, role, schema, observer,
        account or permission evidence as pending.
        """
        self._check_live()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("native policy choice requires current empty prepared custody")
        registry = self._resolve_current_native_policy_registry()
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise BootstrapEnrollmentPending("native policy configuration requires the root controlling TTY")
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        choice_handle: str | None = None
        try:
            _verify_root_tty_proof(proof)
            if (proof.controller_uid != 0 or proof.controller_gid != 0
                    or proof.controller_pid != os.getpid()):
                raise BootstrapEnrollmentPending("native policy choice is not joined to the current root TTY")
            current = self.resolve_current_setup_identity()
            principal_selector = self.resolve_adopted_principal_selector()
            namespace_selector = self.resolve_adopted_namespace_selector()
            if (current.principal_selection_handle != principal_selector.selection_handle
                    or current.namespace_selection_handle != namespace_selector.selection_handle):
                raise BootstrapEnrollmentPending("native policy choice identity selectors changed")
            from .native_registration_projection import (
                capture_actual_hermes_registrations, reviewed_native_registration_definitions,
            )
            captured = capture_actual_hermes_registrations()
            definitions = reviewed_native_registration_definitions(captured)
            component_ids = tuple(sorted({row.family for row in definitions}))
            print("\nNative component source configuration (intent only):")
            for index, component_id in enumerate(component_ids, 1):
                print(f"  {index}. {component_id}")
            print("Choose component family numbers separated by commas; blank selects none.")
            answer = input("Native component families: ").strip()
            _verify_root_tty_proof(proof)
            selected: tuple[str, ...]
            if not answer:
                selected = ()
            else:
                try:
                    numbers = tuple(int(item.strip(), 10) for item in answer.split(","))
                except ValueError:
                    raise BootstrapEnrollmentPending("native selection must use listed numbers or blank") from None
                if (not numbers or len(set(numbers)) != len(numbers)
                        or any(number < 1 or number > len(component_ids) for number in numbers)):
                    raise BootstrapEnrollmentPending("native selection contains a duplicate or unknown component")
                selected = tuple(component_ids[number - 1] for number in numbers)
            selected_set = set(selected)
            selected_registrations: list[str] = []
            selected_actions: list[str] = []
            for row in definitions:
                if row.family not in selected_set:
                    continue
                selected_registrations.append(f"{row.adapter_id}:tool:{row.native_tool_name}")
                selected_actions.extend(binding.action_id for binding in row.action_bindings)
            selected_registrations = sorted(set(selected_registrations))
            selected_actions = sorted(set(selected_actions))
            if len(captured) != 42 or len(component_ids) != 18:
                raise BootstrapEnrollmentPending("native source capture differs from the reviewed 18/42 set")
            profile_rows = [self.resolve_selected_resource_profile(handle)
                            for handle in tuple(self._resource_profiles)]
            if len(profile_rows) > 1:
                raise BootstrapEnrollmentPending("native policy choice has ambiguous Resources profiles")
            resource_handle = profile_rows[0].receipt_handle if profile_rows else None
            service_profile_id = self._policy.identity_policy.get("service_profile_id")
            if not isinstance(service_profile_id, str) or not service_profile_id:
                raise BootstrapEnrollmentPending("native policy choice lacks its selected service profile")
            now = time.monotonic()
            deadline = self._factory.session_store.current_deadline(self._handle)
            expires = min(deadline, current.expires_monotonic, now + 300.0)
            if expires <= now:
                raise BootstrapEnrollmentPending("native policy choice lease is already expired")
            choice_handle = secrets.token_urlsafe(36)
            controller_handle = secrets.token_urlsafe(36)
            from .native_policy_preparation import _issue_root_native_policy_configuration_choice
            choice = _issue_root_native_policy_configuration_choice(
                choice_handle=choice_handle, choice_observation_id=secrets.token_hex(16),
                setup_session_id=self._handle.session_id,
                transaction_handle=self._authorization.transaction_handle,
                plan_sha256=self._authorization.plan_digest,
                prepared_generation_id=prepared.generation_id,
                prepared_generation_digest=prepared.generation_digest,
                principal_selection_handle=principal_selector.selection_handle,
                principal_binding_sha256=principal_selector.binding_sha256,
                namespace_selection_handle=namespace_selector.selection_handle,
                namespace_binding_sha256=namespace_selector.binding_sha256,
                service_profile_id=service_profile_id,
                service_generation=prepared.generation_id,
                resource_profile_selection_handle=resource_handle,
                package_id="hermes-agent-native-package-v1",
                native_package_generation=None,
                selected_component_ids=tuple(selected),
                selected_registration_ids=tuple(selected_registrations),
                selected_action_binding_ids=tuple(selected_actions),
                controller_binding_handle=controller_handle,
                private_input_consent_selection_handle=None,
                issued_monotonic=now, expires_monotonic=expires, revocation_epoch=0,
            )
            self._native_policy_choices[choice_handle] = choice
            self._native_policy_tty_proofs[choice_handle] = proof
            selection = registry.record_configuration(choice)
            records = registry.prepare_selected_policy(selection.selection_handle)
            self._native_policy_records_by_selection[selection.selection_handle] = records
            self._current_native_policy_selection_handle = selection.selection_handle
            proof = None
            return registry.resolve_selection_current(selection.selection_handle)
        except BootstrapEnrollmentPending:
            if choice_handle is not None:
                self._native_policy_choices.pop(choice_handle, None)
                self._native_policy_tty_proofs.pop(choice_handle, None)
            raise
        except Exception:
            if choice_handle is not None:
                self._native_policy_choices.pop(choice_handle, None)
                self._native_policy_tty_proofs.pop(choice_handle, None)
            raise BootstrapEnrollmentPending("native policy configuration could not be retained from root TTY") from None
        finally:
            if proof is not None:
                proof.close()

    def resolve_current_native_policy_configuration_choice(self, choice_handle: str) -> Any:
        self._check_live()
        choice = self._native_policy_choices.get(choice_handle)
        proof = self._native_policy_tty_proofs.get(choice_handle)
        if choice is None or proof is None or choice.expires_monotonic <= time.monotonic():
            raise BootstrapEnrollmentPending("native policy TTY choice is absent, stale or revoked")
        from ..root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        current = self.resolve_current_setup_identity()
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        prepared = self._last_receipt
        resource_profile_current = None
        if choice.resource_profile_selection_handle is not None:
            resource_profile_current = self.resolve_selected_resource_profile(
                choice.resource_profile_selection_handle)
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or choice.setup_session_id != self._handle.session_id
                or choice.transaction_handle != self._authorization.transaction_handle
                or choice.plan_sha256 != self._authorization.plan_digest
                or choice.prepared_generation_id != prepared.generation_id
                or choice.prepared_generation_digest != prepared.generation_digest
                or choice.principal_selection_handle != principal_selector.selection_handle
                or choice.principal_binding_sha256 != principal_selector.binding_sha256
                or choice.namespace_selection_handle != namespace_selector.selection_handle
                or choice.namespace_binding_sha256 != namespace_selector.binding_sha256
                or current.principal_selection_handle != choice.principal_selection_handle
                or current.namespace_selection_handle != choice.namespace_selection_handle
                or self._policy.identity_policy.get("service_profile_id") != choice.service_profile_id
                or choice.service_generation != prepared.generation_id
                or (resource_profile_current is not None
                    and resource_profile_current.receipt_handle != choice.resource_profile_selection_handle)):
            raise BootstrapEnrollmentPending("native policy choice no longer matches current setup identity")
        self._verify_current_setup_controller()
        return choice

    def resolve_current_native_policy_selection(self, selection_handle: str) -> Any:
        registry = self._resolve_current_native_policy_registry()
        try:
            return registry.resolve_selection_current(selection_handle)
        except Exception:
            raise BootstrapEnrollmentPending("native policy selection is absent or stale") from None

    def resolve_current_native_policy_targets(self, selection_handle: str) -> tuple[Any, ...]:
        registry = self._resolve_current_native_policy_registry()
        selection = registry.resolve_selection_current(selection_handle)
        records = self._native_policy_records_by_selection.get(selection_handle)
        if records is None:
            try:
                records = registry.prepare_selected_policy(selection_handle)
            except Exception:
                raise BootstrapEnrollmentPending("native policy target preparation is unavailable") from None
            self._native_policy_records_by_selection[selection_handle] = records
        try:
            current_records = registry.resolve_prepared_policy(records.records_handle, self._selected_installation)
            if current_records is not records:
                raise ValueError
            targets = self._native_component_target_registry
            return tuple(targets.resolve_current_target(handle, selection_handle)
                         for handle in current_records.target_selection_handles)
        except Exception:
            raise BootstrapEnrollmentPending("current native policy targets are unavailable") from None

    def resolve_current_prepared_native_policy_records(self, selection_handle: str) -> Any:
        """Re-resolve the exact native policy/source/target record bundle.

        The bundle is intentionally not an executable permission projection;
        its typed rows and pending coverage are inputs to the later native
        assembly join, which still requires effect, schema and observer proofs.
        """
        registry = self._resolve_current_native_policy_registry()
        try:
            selection = registry.resolve_selection_current(selection_handle)
            records = self._native_policy_records_by_selection.get(selection_handle)
            if records is None:
                records = registry.prepare_selected_policy(selection_handle)
                self._native_policy_records_by_selection[selection_handle] = records
            current = registry.resolve_prepared_policy(records.records_handle, self._selected_installation)
            if (current is not records
                    or records.native_policy_selection_handle != selection.selection_handle
                    or records.selection_sha256 != selection.selection_sha256):
                raise ValueError("prepared policy record join changed")
            return records
        except Exception:
            raise BootstrapEnrollmentPending("current prepared native policy records are unavailable") from None

    def resolve_current_release_receipt_handle(self) -> str:
        self._check_live()
        self._factory._actor.verify_current(self._factory._release)
        self._factory._release.verify_current()
        initial = self._factory._initial_compilation_registry
        if initial is None:
            raise BootstrapEnrollmentPending("normal setup has no adopted release receipt lineage")
        try:
            handoff = initial.resolve_adopted_handoff(self._handle)
            source_session = handoff._initial_session
            if (not isinstance(source_session, RootInitialCompilationSession)
                    or source_session.compilation_session_handle != handoff.compilation_session_handle
                    or source_session.verified_release_receipt_handle == ""):
                raise ValueError("adopted handoff has no exact release receipt lineage")
            value = source_session.verified_release_receipt_handle
        except Exception:
            raise BootstrapEnrollmentPending("current normal session does not resolve its original held release receipt") from None
        if self._release_receipt_handle is not None and self._release_receipt_handle != value:
            raise BootstrapEnrollmentPending("adopted installer release receipt changed")
        self._release_receipt_handle = value
        return value

    def resolve_current_setup_session_handle(self) -> RootSetupSessionHandle:
        self._check_live()
        live = self._factory.session_store._live(self._handle)
        proof = self._factory.session_store._proof(live)
        if (proof.setup_session_id != self._handle.session_id
                or proof.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("current setup session binding changed")
        return self._handle

    def resolve_durable_memory_enablement_choice_handle(self, choice_handle: str) -> str | None:
        self._check_live()
        choice = self.resolve_current_memory_service_enablement_choice(choice_handle)
        durable = self._durable_memory_choice_handles.get(choice_handle)
        if choice.enabled and not durable:
            raise BootstrapEnrollmentPending("memory service choice has not been durably signed")
        return durable

    def resolve_adopted_principal_selection(self) -> Any:
        """Return the freshly re-observed principal bound to this normal session."""
        self._check_live()
        registry = self._adopted_principal_registry
        resolver = getattr(registry, "resolve_adopted_initial_principal", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending(
                "normal root setup session has no freshly adopted principal selection")
        return resolver(self._factory.session_store, self._handle)

    def resolve_adopted_namespace_selection(self) -> Any:
        """Resolve the distinct namespace receipt for the adopted normal principal."""
        self._check_live()
        registry = self._adopted_principal_registry
        resolver = getattr(registry, "resolve_adopted_namespace_selection", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending(
                "normal root setup session has no adopted namespace resolver")
        return resolver(self._factory.session_store, self._handle)

    def resolve_adopted_principal_selector(self) -> Any:
        """Resolve stable setup intent; this selector does not authorize effects."""
        self._check_live()
        resolver = getattr(self._adopted_principal_registry, "resolve_adopted_principal_selector", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending("normal setup session has no stable principal selector")
        return resolver(self._factory.session_store, self._handle)

    def resolve_adopted_namespace_selector(self) -> Any:
        """Resolve stable prepared namespace intent without reusing a short lease."""
        self._check_live()
        resolver = getattr(self._adopted_principal_registry, "resolve_adopted_namespace_selector", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending("normal setup session has no stable namespace selector")
        return resolver(self._factory.session_store, self._handle)

    def resolve_current_setup_identity(self) -> Any:
        """Freshly re-read Authentik and issue an atomic <=30s principal/namespace pair."""
        self._check_live()
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        resolver = getattr(self._adopted_principal_registry, "resolve_current_setup_identity", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending("normal setup session cannot refresh its identity snapshot")
        return resolver(principal_selector.selection_handle, namespace_selector.selection_handle,
                        self._handle)

    def _current_root_journal_selection(self) -> RootJournalSelection:
        prepared = self._last_receipt
        row = self._authorization.root_journal_root
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not isinstance(row, Mapping)):
            raise BootstrapEnrollmentPending("current root journal selection requires prepared custody")
        fields = {"root_id", "absolute_path", "device", "inode", "generation", "owner_uid",
                  "owner_gid", "mode", "purpose"}
        if (set(row) != fields or row.get("owner_uid") != 0 or row.get("owner_gid") != 0
                or row.get("mode") != 0o700):
            raise BootstrapEnrollmentPending("root setup journal selection is malformed")
        return RootJournalSelection(
            row["root_id"], Path(row["absolute_path"]), row["device"], row["inode"],
            row["generation"], prepared.generation_digest,
        )

    def _root_private_profile_registry(self) -> "RootPrivateProfileSelectionRegistry":
        if self._private_profile_registry is None:
            if self._adopted_principal_registry is None:
                raise BootstrapEnrollmentPending("normal setup session has no adopted principal registry")
            self._private_profile_registry = RootPrivateProfileSelectionRegistry.from_root_setup(
                self._selected_installation, self._adopted_principal_registry,
                self._current_root_journal_selection())
        return self._private_profile_registry

    def observe_private_profile_selection(self, purpose: str) -> RootPrivateProfileSelection:
        """Bind one purpose to the current principal/private namespace without another prompt."""
        self._check_live()
        if purpose not in _PRIVATE_PROFILE_PURPOSES:
            raise BootstrapEnrollmentPending("private profile purpose is outside the exact reviewed list")
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("private profile selection requires current prepared custody")
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise BootstrapEnrollmentPending("private profile selection requires the root controlling TTY")
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            if proof.controller_uid != 0 or proof.controller_pid != os.getpid():
                raise BootstrapEnrollmentPending("private profile selection is not joined to the live root TTY")
            current = self.resolve_current_setup_identity()
            selection = self._root_private_profile_registry().issue(
                purpose=purpose, identity=current, controller_proof=proof)
            self._private_profile_proofs[selection.selection_handle] = proof
            proof = None
            self._check_live()
            if self._last_receipt is not prepared:
                raise BootstrapEnrollmentPending("prepared setup changed during private profile selection")
            return selection
        finally:
            if proof is not None:
                proof.close()

    def resolve_current_private_profile(
            self, selection_handle: str, purpose: str) -> VerifiedRootPrivateProfileSelection:
        self._check_live()
        return self._root_private_profile_registry().resolve_current_private_profile(
            selection_handle, purpose)

    def observe_existing_model_selection(self, private_profile_selection_handle: str) -> Any:
        """Observe only the fixed v139 store, then ask the model owner for a child choice."""
        self._check_live()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or prepared.provision_receipt_handle is None):
            raise BootstrapEnrollmentPending("existing model selection requires the current empty prepared generation")
        if not isinstance(private_profile_selection_handle, str) or not private_profile_selection_handle:
            raise BootstrapEnrollmentPending("existing model selection requires a root-issued private-profile handle")
        profile = self.resolve_current_private_profile(
            private_profile_selection_handle, "existing-model-selection")
        if (profile.profile_id != "hermes-agent-native-v1"
                or profile.privacy_classification != "private"
                or profile.public_egress_allowed or profile.additional_metered_budget_usd != 0.0
                or not profile.controller_binding_handle):
            raise BootstrapEnrollmentPending("model-store selection is not joined to the current private profile/controller")
        self._refresh_authorization()
        from .filesystem_selection import RootOwnedFilesystemSelectionRegistry
        if self._model_store_filesystem_registry is None:
            self._model_store_filesystem_registry = RootOwnedFilesystemSelectionRegistry.from_root_setup(
                self._selected_installation, self._root_private_profile_registry(),
                self._selected_installation, self._current_root_journal_selection(),
                self._selected_installation.resolve_setup_choice_registry(),
                self._selected_installation.resolve_current_setup_choice_signer())
        root_selection = self._model_store_filesystem_registry.observe_existing_model_store(
            private_profile_selection_handle)
        try:
            from .source_artifact_receipts import RootSetupCatalogArtifactObserver
            observer = RootSetupCatalogArtifactObserver.from_root_setup(
                self._factory._catalog, self._factory._receipt_registry.artifact_root,
                self._authorization)
            from ..models.private_deployment import RootExistingModelSelectionRegistry
            if self._existing_model_selection_registry is None:
                self._existing_model_selection_registry = RootExistingModelSelectionRegistry.from_root_setup(
                    self._selected_installation, self._model_store_filesystem_registry,
                    self._current_root_journal_selection(), observer,
                    verified_installer_release_receipt=self.resolve_held_installer_release_receipt())
            return self._existing_model_selection_registry.observe_existing_model_directory(
                root_selection.selection_handle, private_profile_selection_handle)
        except (ImportError, AttributeError):
            raise BootstrapEnrollmentPending("root model source/tree observer is not composed in this release") from None

    def observe_memory_service_enablement(
            self, provider: str, backend_variant: str) -> RootSelectedMemoryServiceEnablementChoice:
        """Record an explicit, default-disabled memory service configuration choice."""
        self._check_live()
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("memory service choice requires current empty prepared custody")
        from ..memory.enrollment import ROUTES, SOURCE_PINS
        if provider not in SOURCE_PINS or backend_variant not in ROUTES.get(provider, {}):
            raise BootstrapEnrollmentPending("memory provider/backend is outside the reviewed finite source table")
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise BootstrapEnrollmentPending("memory service choice requires the root controlling TTY")
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            if proof.controller_uid != 0 or proof.controller_gid != 0 or proof.controller_pid != os.getpid():
                raise BootstrapEnrollmentPending("memory service choice is not joined to the current root TTY")
            current = self.resolve_current_setup_identity()
            private_choice = self.observe_private_profile_selection("memory-service-enablement")
            private = self.resolve_current_private_profile(
                private_choice.selection_handle, "memory-service-enablement")
            print("\nMemory service configuration (service lifecycle only):")
            print(f"Provider: {provider}; backend: {backend_variant}; profile: {private.profile_id}")
            print("This does not enable transcript capture, provider egress, extraction, embedding, or additional spend.")
            answer = input("Enable this selected memory service after its independent source/runtime checks? Type YES (default NO): ").strip()
            _verify_root_tty_proof(proof)
            enabled = answer == "YES"
            if answer not in {"", "NO", "YES"}:
                raise BootstrapEnrollmentPending("memory service choice must be YES, NO, or blank for disabled")
            principal_selector = self.resolve_adopted_principal_selector()
            namespace_selector = self.resolve_adopted_namespace_selector()
            if (private.profile_id != "hermes-agent-native-v1"
                    or private.principal_id != current.principal.principal_id
                    or private.namespace_id != current.namespace.namespace_id
                    or private.principal_selection_handle != principal_selector.selection_handle
                    or private.namespace_selection_handle != namespace_selector.selection_handle
                    or private.additional_metered_budget_usd != 0.0
                    or private.public_egress_allowed):
                raise BootstrapEnrollmentPending("memory choice is not joined to current private profile selection")
            route_ids = sorted(ROUTES[provider][backend_variant])
            policy_revision = hashlib.sha256(_canonical({
                "provider_source_revision": SOURCE_PINS[provider],
                "backend_variant": backend_variant,
                "routes": route_ids,
            })).hexdigest()
            now = time.monotonic()
            expiry = min(self._factory.session_store.current_deadline(self._handle),
                         private.expires_monotonic)
            if expiry <= now:
                raise BootstrapEnrollmentPending("memory service choice lease expired")
            handle, observation, controller = (secrets.token_urlsafe(36), secrets.token_hex(16),
                                               secrets.token_urlsafe(36))
            core = {
                "schema": 1, "choice_handle": handle, "choice_observation_id": observation,
                "setup_session_id": self._handle.session_id,
                "transaction_handle": self._authorization.transaction_handle,
                "plan_sha256": self._authorization.plan_digest,
                "prepared_generation_id": prepared.generation_id,
                "prepared_generation_digest": prepared.generation_digest,
                "principal_selection_receipt_handle": current.principal.receipt_id,
                "principal_selection_handle": principal_selector.selection_handle,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "private_profile_selection_receipt_handle": private.receipt_handle,
                "private_profile_selection_handle": private.selection_handle,
                "namespace_selection_receipt_handle": current.namespace.receipt_handle,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "principal_id": current.principal.principal_id,
                "profile_id": private.profile_id, "namespace_id": current.namespace.namespace_id,
                "provider": provider, "backend_variant": backend_variant, "enabled": enabled,
                "controller_binding_handle": controller, "policy_revision": policy_revision,
                "issued_monotonic": now, "expires_monotonic": expiry,
            }
            selection_digest = hashlib.sha256(_canonical(core)).hexdigest()
            signed = {**core, "selection_digest": selection_digest}
            signature = hmac.new(self._seal.encode("ascii"), _canonical(signed), hashlib.sha256).hexdigest()
            choice = RootSelectedMemoryServiceEnablementChoice(
                **signed, signature=signature, _session_seal=self._seal)
            self._memory_enablement_choices[handle] = choice
            self._memory_enablement_tty_proofs[handle] = proof
            durable_handle = self._selected_installation.record_durable_setup_choice(choice)
            if enabled and not durable_handle:
                self._memory_enablement_choices.pop(handle, None)
                self._memory_enablement_tty_proofs.pop(handle, None)
                raise BootstrapEnrollmentPending("enabled memory configuration was not durably signed")
            if durable_handle is not None:
                self._durable_memory_choice_handles[handle] = durable_handle
            proof = None
            return self.resolve_current_memory_service_enablement_choice(handle)
        finally:
            if proof is not None:
                proof.close()

    def resolve_current_memory_service_enablement_choice(
            self, selection_handle: str) -> RootSelectedMemoryServiceEnablementChoice:
        self._check_live()
        choice = self._memory_enablement_choices.get(selection_handle)
        if (type(choice) is not RootSelectedMemoryServiceEnablementChoice
                or choice._session_seal != self._seal
                or choice.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("memory enablement choice is absent, stale, or not root retained")
        current = self.resolve_current_setup_identity()
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        private = self.resolve_current_private_profile(
            choice.private_profile_selection_handle, "memory-service-enablement")
        proof = self._memory_enablement_tty_proofs.get(selection_handle)
        if proof is None:
            raise BootstrapEnrollmentPending("memory enablement choice lost its TTY proof")
        from ..root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        if (choice.setup_session_id != self._handle.session_id
                or choice.transaction_handle != self._authorization.transaction_handle
                or choice.plan_sha256 != self._authorization.plan_digest
                or choice.prepared_generation_id != self._last_receipt.generation_id
                or choice.principal_selection_handle != principal_selector.selection_handle
                or choice.principal_binding_sha256 != principal_selector.binding_sha256
                or choice.namespace_selection_handle != namespace_selector.selection_handle
                or choice.namespace_binding_sha256 != namespace_selector.binding_sha256
                or choice.principal_id != current.principal.principal_id
                or choice.namespace_id != current.namespace.namespace_id
                or private.selection_handle != choice.private_profile_selection_handle
                or private.profile_id != choice.profile_id):
            raise BootstrapEnrollmentPending("memory enablement choice no longer matches current setup identity")
        content = {name: getattr(choice, name) for name in (
            "schema", "choice_handle", "choice_observation_id", "setup_session_id",
            "transaction_handle", "plan_sha256", "prepared_generation_id", "prepared_generation_digest",
            "principal_selection_receipt_handle", "principal_selection_handle", "principal_binding_sha256",
            "private_profile_selection_receipt_handle", "private_profile_selection_handle",
            "namespace_selection_receipt_handle", "namespace_selection_handle", "namespace_binding_sha256",
            "principal_id", "profile_id", "namespace_id", "provider", "backend_variant", "enabled",
            "controller_binding_handle", "policy_revision", "selection_digest", "issued_monotonic",
            "expires_monotonic")}
        if _read_secure_root_bytes(self._factory.resolver.journal_root / "memory-service-enable-choices"
                                   / f"{selection_handle}.json", 32 * 1024, 0o600) != _canonical(
                                       {**content, "signature": choice.signature}):
            raise BootstrapEnrollmentPending("memory enablement choice journal differs")
        signed = hmac.new(self._seal.encode("ascii"), _canonical(content), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signed, choice.signature):
            raise BootstrapEnrollmentPending("memory enablement choice signature differs")
        return choice

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

    def _restore_current_prepared_checkpoint(self) -> EnrollmentReceipt:
        """Reissue a short-lived receipt from the current protected prepared snapshot.

        Resume never deserializes old in-memory capabilities. It accepts only a
        committed empty prepared generation that is still the exact authority
        snapshot, and verifies the matching root transaction and service identity
        without creating or changing host state.
        """
        self._check_live()
        self._refresh_authorization()
        auth = self._authorization
        if auth.mode != "resume":
            raise BootstrapEnrollmentPending("prepared checkpoint restore requires a live resume session")
        receipt = self._read_current_prepared_checkpoint_receipt()
        self._last_receipt = receipt
        return receipt

    def _read_current_prepared_checkpoint_receipt(self) -> EnrollmentReceipt:
        self._check_live()
        self._refresh_authorization()
        auth = self._authorization
        authority = self._factory.session_store.authority_loader_for_session()
        if not isinstance(authority, Mapping):
            raise BootstrapEnrollmentPending("resume has no current protected prepared authority snapshot")
        try:
            _validate_authority_base(authority)
            generation = authority.get("service_generations")
            from .enrollment import _validate_service_generations
            normalized = _validate_service_generations(generation)
        except Exception:
            raise BootstrapEnrollmentPending("resume authority snapshot is not strictly valid") from None
        if (not isinstance(generation, Mapping)
                or generation.get("service_records")
                or any(generation.get(name) for name in (
                    "protected_devices", "protected_build_records", "native_packages",
                    "memory_enrollments", "operation_parameter_schemas", "source_issuers",
                    "resource_jobs", "remote_session_enrollments", "resource_backend_enrollments",
                    "resource_body_recipes", "resource_scope_bindings", "resource_validators",
                    "resource_controller_roles", "native_mcp_tool_bindings",
                    "remote_observation_enrollments", "native_schema_artifacts",
                    "composio_channel_enrollments", "channel_delivery_bindings",
                    "remote_startup_enrollments", "private_loopback_networks",
                    "selected_resource_executions", "selected_application_runtimes",
                    "private_memory_endpoint_selections", "private_memory_model_selections",
                    "public_web_scopes"))):
            raise BootstrapEnrollmentPending("resume snapshot is not an empty prepared generation")
        digest = normalized.get("generation_digest")
        generation_id = normalized.get("generation_id")
        if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                or not isinstance(generation_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", generation_id)):
            raise BootstrapEnrollmentPending("resume prepared generation identity is malformed")
        matches: list[tuple[Path, Mapping[str, Any]]] = []
        for path in self._factory.session_store.transaction_root.glob("[0-9a-f]" * 32 + ".json"):
            row = _read_json_if_owned(path)
            setup = row.get("setup_authorization") if isinstance(row, Mapping) else None
            if (isinstance(row, Mapping) and isinstance(setup, Mapping)
                    and row.get("state") == "committed"
                    and setup.get("transaction_handle") == auth.transaction_handle
                    and setup.get("target_id") == auth.target_id
                    and setup.get("plan_artifact_id") == auth.plan_artifact_id
                    and setup.get("plan_digest") == auth.plan_digest
                    and row.get("generation_digest") == digest
                    and row.get("previous_generation_digest")
                        == setup.get("expected_previous_generation_digest")
                    and re.fullmatch(r"[0-9a-f]{48}", str(row.get("provision_receipt_handle", "")))):
                matches.append((path, row))
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("resume checkpoint does not identify one committed prepared transaction")
        journal_path, journal = matches[0]
        journal_id = journal_path.stem
        if journal.get("transaction_id") != journal_id or not re.fullmatch(r"[0-9a-f]{32}", journal_id):
            raise BootstrapEnrollmentPending("resume transaction journal identity is malformed")
        prior_setup = journal.get("setup_authorization")
        prior_session_id = prior_setup.get("setup_session_id") if isinstance(prior_setup, Mapping) else None
        if not isinstance(prior_session_id, str) or not re.fullmatch(r"setup-[0-9a-f]{32}", prior_session_id):
            raise BootstrapEnrollmentPending("resume checkpoint has no durable originating setup session")
        prior_session = _read_json_if_owned(
            self._factory.session_store.session_root / f"{prior_session_id}.json")
        if (not isinstance(prior_session, Mapping)
                or prior_session.get("schema") != 1
                or prior_session.get("setup_session_id") != prior_session_id
                or prior_session.get("target_id") != auth.target_id
                or prior_session.get("transaction_handle") != auth.transaction_handle
                or prior_session.get("plan_artifact_id") != auth.plan_artifact_id
                or prior_session.get("plan_digest") != auth.plan_digest
                or prior_session.get("mode") not in {"install", "repair", "resume"}):
            raise BootstrapEnrollmentPending("resume originating session record does not match the checkpoint")
        identity = journal.get("identity")
        if (not isinstance(identity, Mapping)
                or set(identity) != {"name", "uid", "gid", "created"}
                or identity.get("name") != self._identity.name
                or type(identity.get("uid")) is not int or identity["uid"] <= 0
                or type(identity.get("gid")) is not int or identity["gid"] <= 0
                or type(identity.get("created")) is not bool):
            raise BootstrapEnrollmentPending("resume checkpoint lacks the reviewed service identity receipt")
        try:
            account = pwd.getpwnam(identity["name"])
            group = grp.getgrnam(identity["name"])
            marker = _read_json_if_owned(self._identity.marker)
        except (KeyError, OSError):
            raise BootstrapEnrollmentPending("prepared service identity is no longer present") from None
        if (account.pw_uid != identity["uid"] or account.pw_gid != identity["gid"]
                or group.gr_gid != identity["gid"] or account.pw_dir not in {"/nonexistent", "/"}
                or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
                or marker != {"schema": 1, "name": identity["name"],
                              "uid": identity["uid"], "gid": identity["gid"]}):
            raise BootstrapEnrollmentPending("prepared service identity no longer matches its root marker")
        issued = time.monotonic()
        try:
            deadline = self._factory.session_store.current_deadline(self._handle)
        except Exception:
            raise BootstrapEnrollmentPending("resume setup session deadline is unavailable") from None
        expires = min(issued + 300.0, deadline)
        if expires <= issued:
            raise BootstrapEnrollmentPending("resume setup session expires before prepared receipt issuance")
        return EnrollmentReceipt(
            schema=1, transaction_handle=auth.transaction_handle,
            provision_receipt_handle=str(journal["provision_receipt_handle"]),
            generation_id=generation_id, generation_digest=digest,
            previous_generation_digest=journal.get("previous_generation_digest"),
            state="prepared", enrollment_ids=(), issued_monotonic=issued,
            expires_monotonic=expires)

    def _resolve_current_prepared_enrollment(self) -> EnrollmentReceipt:
        self._check_live()
        self._refresh_authorization()
        receipt = self._last_receipt
        current = self._read_current_prepared_checkpoint_receipt()
        if (not isinstance(receipt, EnrollmentReceipt)
                or receipt.state != "prepared" or receipt.enrollment_ids
                or receipt.transaction_handle != self._authorization.transaction_handle
                or receipt.generation_id != current.generation_id
                or receipt.generation_digest != current.generation_digest
                or receipt.provision_receipt_handle != current.provision_receipt_handle
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("current setup has no revalidated prepared enrollment receipt")
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

    def _resolve_current_pm_runtime_projection(self) -> Any:
        selected = self._resolve_current_pm_runtime()
        from .pm_runtime import RootPMRuntimeReceiptRegistry, VerifiedPMRuntimeProjection
        registry = self._pm_runtime_registry
        if not isinstance(registry, RootPMRuntimeReceiptRegistry):
            raise BootstrapEnrollmentPending("current PM runtime projection registry is unavailable")
        projection = registry.resolve_runtime_projection(
            selected.receipt_handle, self._authorization.transaction_handle,
            self._last_receipt.generation_id)
        if (not isinstance(projection, VerifiedPMRuntimeProjection)
                or projection.selection != selected
                or projection.selection.setup_session_id != self._handle.session_id
                or projection.selection.transaction_handle != self._authorization.transaction_handle
                or projection.selection.prepared_generation_id != self._last_receipt.generation_id):
            if isinstance(projection, VerifiedPMRuntimeProjection):
                projection.close()
            raise BootstrapEnrollmentPending("PM runtime projection differs from current setup custody")
        return projection

    def _resolve_current_pm_uv_tool(self) -> Any:
        """Resolve the sealed PM-managed uv executable selection for this setup."""
        runtime = self._resolve_current_pm_runtime()
        registry = self._pm_runtime_registry
        resolver = getattr(registry, "resolve_uv_tool", None)
        verifier = getattr(registry, "verify_current_uv_tool", None)
        if not callable(resolver) or not callable(verifier):
            raise BootstrapEnrollmentPending("current PM uv tool receipt is unavailable")
        selected = resolver(runtime.receipt_handle, self._authorization.transaction_handle,
                            self._last_receipt.generation_id)
        verifier(selected)
        if (getattr(selected, "transaction_handle", None) != self._authorization.transaction_handle
                or getattr(selected, "prepared_generation_id", None) != self._last_receipt.generation_id):
            raise BootstrapEnrollmentPending("PM uv tool receipt differs from current prepared setup")
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
            print("This stages only the selected pinned public source and lock, prepares its isolated runtime, observes its bounded probe, and runs its listed local fixture.")
            print("It grants no private/provider egress, background memory, trade, payment, messaging, arbitrary browser access, or additional metered budget. Network effects are denied except the root-owned loopback fixture endpoint.")
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
            acknowledgement = input(
                f"Authorize only {workflow_id} under the limits above? Type YES to continue: "
            ).strip()
            _verify_root_tty_proof(proof)
            if acknowledgement != "YES":
                raise BootstrapEnrollmentPending("application qualification consent was not explicitly granted")
            principal_selector = self.resolve_adopted_principal_selector()
            namespace_selector = self.resolve_adopted_namespace_selector()
            current_identity = self.resolve_current_setup_identity()
            principal, namespace = current_identity.principal, current_identity.namespace
            if (principal_selector.setup_session_id != self._handle.session_id
                    or principal_selector.transaction_handle != self._authorization.transaction_handle
                    or principal_selector.plan_sha256 != self._authorization.plan_digest
                    or namespace_selector.setup_session_id != self._handle.session_id
                    or namespace_selector.transaction_handle != self._authorization.transaction_handle
                    or namespace_selector.plan_sha256 != self._authorization.plan_digest
                    or current_identity.principal_selection_handle != principal_selector.selection_handle
                    or current_identity.namespace_selection_handle != namespace_selector.selection_handle
                    or current_identity.principal_binding_sha256 != principal_selector.binding_sha256
                    or current_identity.namespace_binding_sha256 != namespace_selector.binding_sha256
                    or namespace.principal_selection_receipt_id != principal.receipt_id
                    or namespace.target_profile_id != "hermes-agent-native-v1"):
                raise BootstrapEnrollmentPending(
                    "application workflow requires current principal and prepared namespace selections")
            live = self._factory.session_store._live(self._handle)
            if live.record.get("actor_observation_receipt_handle") is None:
                raise BootstrapEnrollmentPending("workflow choice has no retained root actor observation")
            _verify_root_tty_proof(proof)
            self._check_live()
            if self._last_receipt is not prepared:
                raise BootstrapEnrollmentPending("prepared setup changed during workflow selection")
            now = time.monotonic()
            deadline = self._factory.session_store.current_deadline(self._handle)
            # Retain the one explicit local-qualification choice for the live
            # setup session. Individual phase admissions below receive fresh
            # <=30 second snapshots, so slow source/runtime preparation does not
            # silently turn the user's single choice into a repeated prompt.
            expiry = min(prepared.expires_monotonic, deadline)
            if expiry <= now:
                raise BootstrapEnrollmentPending("workflow selection lease expired")
            handle = secrets.token_urlsafe(36)
            consent_handle = secrets.token_urlsafe(36)
            controller_handle = secrets.token_urlsafe(36)
            choice_observation_id = secrets.token_hex(16)
            consent_values = {
                "schema": 1,
                "receipt_handle": consent_handle,
                "consent_id": secrets.token_hex(16),
                "purpose": "installer-application-local-qualification",
                "choice_observation_id": choice_observation_id,
                "qualification_choice_handle": handle,
                "setup_session_id": self._handle.session_id,
                "transaction_handle": self._authorization.transaction_handle,
                "plan_sha256": self._authorization.plan_digest,
                "prepared_generation_id": prepared.generation_id,
                "prepared_generation_digest": prepared.generation_digest,
                "application_id": application_id,
                "workflow_id": workflow_id,
                "target_profile_id": namespace.target_profile_id,
                "namespace_selection_receipt_handle": namespace.receipt_handle,
                "principal_selection_handle": principal_selector.selection_handle,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "controller_binding_handle": controller_handle,
                "allowed_phase_ids": list(_APPLICATION_QUALIFICATION_PHASES),
                "network_scope": _APPLICATION_QUALIFICATION_NETWORK_SCOPE,
                "additional_metered_budget_usd": 0.0,
                "revocation_epoch": 0,
                "issued_monotonic": now,
                "expires_monotonic": expiry,
            }
            consent_signature = hmac.new(
                self._seal.encode("ascii"), _canonical(consent_values), hashlib.sha256,
            ).hexdigest()
            consent = RootApplicationQualificationConsent(
                **{
                    **consent_values,
                    "allowed_phase_ids": tuple(consent_values["allowed_phase_ids"]),
                    "signature": consent_signature,
                    "_session_seal": self._seal,
                }
            )
            values = {
                "schema": 1, "selection_handle": handle,
                "setup_session_id": self._handle.session_id,
                "transaction_handle": self._authorization.transaction_handle,
                "plan_sha256": self._authorization.plan_digest,
                "prepared_generation_id": prepared.generation_id,
                "prepared_generation_digest": prepared.generation_digest,
                "workflow_id": workflow_id, "application_id": application_id,
                "workload_id": workload_id,
                "target_profile_id": namespace.target_profile_id,
                "namespace_selection_receipt_handle": namespace.receipt_handle,
                "principal_selection_receipt_handle": principal.receipt_id,
                "principal_selection_handle": principal_selector.selection_handle,
                "principal_binding_sha256": principal_selector.binding_sha256,
                "namespace_selection_handle": namespace_selector.selection_handle,
                "namespace_binding_sha256": namespace_selector.binding_sha256,
                "controller_binding_handle": controller_handle,
                "qualification_consent_receipt_handle": consent_handle,
                "choice_observation_id": choice_observation_id,
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
            raw = _canonical({
                **values, "signature": signature, "tty": proof_record,
                "qualification_consent": {
                    **consent_values, "signature": consent_signature,
                },
            })
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
            self._application_controller_tty_proofs[controller_handle] = proof
            self._application_qualification_consents[handle] = consent
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
                or choice.prepared_generation_digest != prepared.generation_digest
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
            "prepared_generation_digest": choice.prepared_generation_digest,
            "workflow_id": choice.workflow_id, "application_id": choice.application_id,
            "workload_id": choice.workload_id,
            "target_profile_id": choice.target_profile_id,
            "namespace_selection_receipt_handle": choice.namespace_selection_receipt_handle,
            "principal_selection_receipt_handle": choice.principal_selection_receipt_handle,
            "principal_selection_handle": choice.principal_selection_handle,
            "principal_binding_sha256": choice.principal_binding_sha256,
            "namespace_selection_handle": choice.namespace_selection_handle,
            "namespace_binding_sha256": choice.namespace_binding_sha256,
            "controller_binding_handle": choice.controller_binding_handle,
            "qualification_consent_receipt_handle": choice.qualification_consent_receipt_handle,
            "choice_observation_id": choice.choice_observation_id,
            "issued_monotonic": choice.issued_monotonic,
            "expires_monotonic": choice.expires_monotonic,
        }), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, choice.signature):
            raise BootstrapEnrollmentPending("application qualification choice signature differs")
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        current_identity = self.resolve_current_setup_identity()
        principal, namespace = current_identity.principal, current_identity.namespace
        if (principal_selector.selection_handle != choice.principal_selection_handle
                or principal_selector.binding_sha256 != choice.principal_binding_sha256
                or namespace_selector.selection_handle != choice.namespace_selection_handle
                or namespace_selector.binding_sha256 != choice.namespace_binding_sha256
                or current_identity.principal_selection_handle != choice.principal_selection_handle
                or current_identity.namespace_selection_handle != choice.namespace_selection_handle
                or current_identity.principal_binding_sha256 != choice.principal_binding_sha256
                or current_identity.namespace_binding_sha256 != choice.namespace_binding_sha256
                or namespace.principal_selection_receipt_id != principal.receipt_id
                or namespace.target_profile_id != choice.target_profile_id
                or choice.target_profile_id != "hermes-agent-native-v1"):
            raise BootstrapEnrollmentPending(
                "application qualification choice no longer matches current principal and namespace selections")
        consent = self._application_qualification_consents.get(selection_handle)
        if (not isinstance(consent, RootApplicationQualificationConsent)
                or consent._session_seal != self._seal
                or consent.receipt_handle != choice.qualification_consent_receipt_handle
                or consent.qualification_choice_handle != choice.selection_handle
                or consent.choice_observation_id != choice.choice_observation_id
                or consent.controller_binding_handle != choice.controller_binding_handle):
            raise BootstrapEnrollmentPending("application qualification consent is missing or detached from its choice")
        consent_values = {
            "schema": consent.schema,
            "receipt_handle": consent.receipt_handle,
            "consent_id": consent.consent_id,
            "purpose": consent.purpose,
            "choice_observation_id": consent.choice_observation_id,
            "qualification_choice_handle": consent.qualification_choice_handle,
            "setup_session_id": consent.setup_session_id,
            "transaction_handle": consent.transaction_handle,
            "plan_sha256": consent.plan_sha256,
            "prepared_generation_id": consent.prepared_generation_id,
            "prepared_generation_digest": consent.prepared_generation_digest,
            "application_id": consent.application_id,
            "workflow_id": consent.workflow_id,
            "target_profile_id": consent.target_profile_id,
            "namespace_selection_receipt_handle": consent.namespace_selection_receipt_handle,
            "principal_selection_handle": consent.principal_selection_handle,
            "principal_binding_sha256": consent.principal_binding_sha256,
            "namespace_selection_handle": consent.namespace_selection_handle,
            "namespace_binding_sha256": consent.namespace_binding_sha256,
            "controller_binding_handle": consent.controller_binding_handle,
            "allowed_phase_ids": list(consent.allowed_phase_ids),
            "network_scope": consent.network_scope,
            "additional_metered_budget_usd": consent.additional_metered_budget_usd,
            "revocation_epoch": consent.revocation_epoch,
            "issued_monotonic": consent.issued_monotonic,
            "expires_monotonic": consent.expires_monotonic,
        }
        expected_consent_signature = hmac.new(
            self._seal.encode("ascii"), _canonical(consent_values), hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(expected_consent_signature, consent.signature):
            raise BootstrapEnrollmentPending("application qualification consent signature differs")
        journal_path = (self._factory.resolver.journal_root / "application-qualification-choices"
                        / f"{selection_handle}.json")
        try:
            stored = json.loads(_read_secure_root_bytes(journal_path, 32 * 1024, 0o600))
        except Exception:
            raise BootstrapEnrollmentPending("application qualification journal record is unavailable") from None
        stored_consent = stored.get("qualification_consent") if isinstance(stored, dict) else None
        if (not isinstance(stored, dict)
                or stored.get("signature") != choice.signature
                or stored.get("selection_handle") != choice.selection_handle
                or stored.get("setup_session_id") != choice.setup_session_id
                or stored.get("transaction_handle") != choice.transaction_handle
                or stored.get("qualification_consent_receipt_handle") != consent.receipt_handle
                or not isinstance(stored_consent, dict)
                or stored_consent != {**consent_values, "signature": consent.signature}):
            raise BootstrapEnrollmentPending("application qualification choice or consent journal record changed")
        return choice

    def resolve_application_qualification_consent(
        self, choice_handle: str, phase_id: str,
    ) -> RootApplicationQualificationConsent:
        """Issue a fresh, phase-limited snapshot of the same explicit TTY consent."""
        self._check_live()
        if phase_id not in _APPLICATION_QUALIFICATION_PHASES:
            raise BootstrapEnrollmentPending("application qualification phase is not in the reviewed finite list")
        choice = self.resolve_application_setup_choice(choice_handle)
        base = self._application_qualification_consents.get(choice_handle)
        controller_proof = self._application_controller_tty_proofs.get(
            choice.controller_binding_handle)
        if (not isinstance(base, RootApplicationQualificationConsent)
                or controller_proof is None
                or base.allowed_phase_ids != _APPLICATION_QUALIFICATION_PHASES
                or phase_id not in base.allowed_phase_ids
                or base.purpose != "installer-application-local-qualification"
                or base.additional_metered_budget_usd != 0.0
                or base.network_scope != _APPLICATION_QUALIFICATION_NETWORK_SCOPE
                or base.revocation_epoch != 0
                or base.setup_session_id != self._handle.session_id
                or base.transaction_handle != self._authorization.transaction_handle
                or base.plan_sha256 != self._authorization.plan_digest
                or base.prepared_generation_id != choice.prepared_generation_id
                or base.application_id != choice.application_id
                or base.workflow_id != choice.workflow_id
                or base.target_profile_id != choice.target_profile_id
                or base.namespace_selection_receipt_handle != choice.namespace_selection_receipt_handle
                or base.principal_selection_handle != choice.principal_selection_handle
                or base.principal_binding_sha256 != choice.principal_binding_sha256
                or base.namespace_selection_handle != choice.namespace_selection_handle
                or base.namespace_binding_sha256 != choice.namespace_binding_sha256
                or base.controller_binding_handle != choice.controller_binding_handle
                or base.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("application qualification consent is stale or revoked")
        from ..root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(controller_proof)
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or prepared.generation_id != base.prepared_generation_id
                or prepared.generation_digest != base.prepared_generation_digest):
            raise BootstrapEnrollmentPending("application qualification consent no longer matches prepared custody")
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        current_identity = self.resolve_current_setup_identity()
        principal, namespace = current_identity.principal, current_identity.namespace
        if (principal_selector.selection_handle != base.principal_selection_handle
                or principal_selector.binding_sha256 != base.principal_binding_sha256
                or namespace_selector.selection_handle != base.namespace_selection_handle
                or namespace_selector.binding_sha256 != base.namespace_binding_sha256
                or current_identity.principal_selection_handle != base.principal_selection_handle
                or current_identity.namespace_selection_handle != base.namespace_selection_handle
                or current_identity.principal_binding_sha256 != base.principal_binding_sha256
                or current_identity.namespace_binding_sha256 != base.namespace_binding_sha256
                or namespace.principal_selection_receipt_id != principal.receipt_id
                or namespace.target_profile_id != base.target_profile_id):
            raise BootstrapEnrollmentPending("qualification consent no longer matches current identity and namespace")
        now = time.monotonic()
        expiry = min(now + 30.0, base.expires_monotonic,
                     self._factory.session_store.current_deadline(self._handle))
        if expiry <= now:
            raise BootstrapEnrollmentPending("application qualification phase lease expired")
        snapshot_values = {
            "schema": base.schema,
            "receipt_handle": secrets.token_urlsafe(36),
            "consent_id": base.consent_id,
            "purpose": base.purpose,
            "choice_observation_id": base.choice_observation_id,
            "qualification_choice_handle": base.qualification_choice_handle,
            "setup_session_id": base.setup_session_id,
            "transaction_handle": base.transaction_handle,
            "plan_sha256": base.plan_sha256,
            "prepared_generation_id": base.prepared_generation_id,
            "prepared_generation_digest": base.prepared_generation_digest,
            "application_id": base.application_id,
            "workflow_id": base.workflow_id,
            "target_profile_id": base.target_profile_id,
            "namespace_selection_receipt_handle": base.namespace_selection_receipt_handle,
            "principal_selection_handle": base.principal_selection_handle,
            "principal_binding_sha256": base.principal_binding_sha256,
            "namespace_selection_handle": base.namespace_selection_handle,
            "namespace_binding_sha256": base.namespace_binding_sha256,
            "controller_binding_handle": base.controller_binding_handle,
            "allowed_phase_ids": [phase_id],
            "network_scope": base.network_scope,
            "additional_metered_budget_usd": 0.0,
            "revocation_epoch": base.revocation_epoch,
            "issued_monotonic": now,
            "expires_monotonic": expiry,
        }
        signature = hmac.new(
            self._seal.encode("ascii"), _canonical(snapshot_values), hashlib.sha256,
        ).hexdigest()
        snapshot = RootApplicationQualificationConsent(
            **{
                **snapshot_values,
                "allowed_phase_ids": (phase_id,),
                "signature": signature,
                "_session_seal": self._seal,
            }
        )
        self._check_live()
        if self._last_receipt is not prepared:
            raise BootstrapEnrollmentPending("prepared setup changed while issuing phase consent")
        return snapshot

    def resolve_application_controller_binding(
        self, choice_handle: str,
    ) -> RootApplicationSetupControllerBinding:
        choice = self.resolve_application_setup_choice(choice_handle)
        proof = self._application_controller_tty_proofs.get(choice.controller_binding_handle)
        consent = self._application_qualification_consents.get(choice_handle)
        if proof is None or not isinstance(consent, RootApplicationQualificationConsent):
            raise BootstrapEnrollmentPending("application controller proof is unavailable")
        from ..root_setup import _verify_root_tty_proof
        _verify_root_tty_proof(proof)
        principal = self.resolve_adopted_principal_selection()
        principal_selector = self.resolve_adopted_principal_selector()
        current_identity = self.resolve_current_setup_identity()
        if (principal.principal_id != current_identity.principal.principal_id
                or principal_selector.selection_handle != choice.principal_selection_handle
                or principal_selector.binding_sha256 != choice.principal_binding_sha256
                or current_identity.principal_selection_handle != choice.principal_selection_handle
                or current_identity.principal_binding_sha256 != choice.principal_binding_sha256):
            raise BootstrapEnrollmentPending("application controller no longer matches current principal selector")
        binding = self._application_controller_bindings.get(choice.controller_binding_handle)
        if binding is None:
            binding = RootApplicationSetupControllerBinding(
                handle=choice.controller_binding_handle,
                setup_session_id=self._handle.session_id,
                qualification_choice_handle=choice_handle,
                principal_id=principal.principal_id,
                issued_monotonic=consent.issued_monotonic,
                expires_monotonic=consent.expires_monotonic,
                _session_seal=self._seal,
                _proof=proof,
            )
            self._application_controller_bindings[choice.controller_binding_handle] = binding
        if (binding._session_seal != self._seal or binding._proof is not proof
                or binding.qualification_choice_handle != choice_handle
                or binding.principal_id != principal.principal_id):
            raise BootstrapEnrollmentPending("application controller binding changed")
        return binding

    def resolve_application_controller_binding_by_handle(
        self, controller_binding_handle: str,
    ) -> RootApplicationSetupControllerBinding:
        if not isinstance(controller_binding_handle, str):
            raise BootstrapEnrollmentPending("application controller handle is malformed")
        for choice_handle, choice in tuple(self._application_setup_choices.items()):
            if choice.controller_binding_handle == controller_binding_handle:
                binding = self.resolve_application_controller_binding(choice_handle)
                if binding.handle != controller_binding_handle:
                    break
                return binding
        raise BootstrapEnrollmentPending("application controller handle is not current")

    def is_application_controller_binding_current(self, controller_binding_handle: str) -> bool:
        try:
            self.resolve_application_controller_binding_by_handle(controller_binding_handle)
            return True
        except (BootstrapEnrollmentError, BootstrapEnrollmentPending, OSError, ValueError):
            return False

    def verify_application_controller_binding(
            self, binding: RootApplicationSetupControllerBinding,
    ) -> bool:
        if not isinstance(binding, RootApplicationSetupControllerBinding):
            return False
        try:
            current = self.resolve_application_controller_binding_by_handle(binding.handle)
            return (current is binding and current._session_seal == self._seal
                    and current._proof is binding._proof
                    and current.setup_session_id == self._handle.session_id
                    and current.qualification_choice_handle == binding.qualification_choice_handle
                    and current.principal_id == binding.principal_id
                    and current.expires_monotonic > time.monotonic())
        except (BootstrapEnrollmentError, BootstrapEnrollmentPending, OSError, ValueError):
            return False

    def resolve_application_source_preparation(self, choice_handle: str, application_id: str) -> Any:
        """Mint a finite v117 source/lock selection from the current root TTY choice."""
        self._check_live()
        from .application_source_preparation import (
            RootApplicationSourcePreparationSelection,
            reviewed_application_source_profile,
        )
        choice = self.resolve_application_setup_choice(choice_handle)
        profile = reviewed_application_source_profile(application_id)
        if (choice.application_id != application_id
                or choice.workflow_id != profile.workflow_id
                or choice.target_profile_id != "hermes-agent-native-v1"):
            raise BootstrapEnrollmentPending("application choice differs from the reviewed source profile")
        prepared = self._last_receipt
        if prepared is None or prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("source preparation requires the current empty prepared generation")
        # Re-resolve the durable base consent and its short phase snapshot. The
        # selection retains the durable handle; the source producer must obtain
        # a fresh phase snapshot immediately before each bounded operation.
        base_consent = self._application_qualification_consents.get(choice_handle)
        phase = self.resolve_application_qualification_consent(
            choice_handle, "stage-pinned-source-locks")
        if (not isinstance(base_consent, RootApplicationQualificationConsent)
                or phase.qualification_choice_handle != choice_handle
                or phase.application_id != application_id
                or phase.workflow_id != profile.workflow_id
                or base_consent.receipt_handle != choice.qualification_consent_receipt_handle):
            raise BootstrapEnrollmentPending("application source staging has no current scoped consent")
        controller = self.resolve_application_controller_binding(choice_handle)
        principal_selector = self.resolve_adopted_principal_selector()
        namespace_selector = self.resolve_adopted_namespace_selector()
        current_identity = self.resolve_current_setup_identity()
        namespace = current_identity.namespace
        principal = current_identity.principal
        if (namespace_selector.selection_handle != choice.namespace_selection_handle
                or namespace_selector.binding_sha256 != choice.namespace_binding_sha256
                or principal_selector.selection_handle != choice.principal_selection_handle
                or principal_selector.binding_sha256 != choice.principal_binding_sha256
                or current_identity.namespace_selection_handle != choice.namespace_selection_handle
                or current_identity.namespace_binding_sha256 != choice.namespace_binding_sha256
                or current_identity.principal_selection_handle != choice.principal_selection_handle
                or current_identity.principal_binding_sha256 != choice.principal_binding_sha256
                or namespace.prepared_generation_id != prepared.generation_id
                or namespace.prepared_generation_digest != prepared.generation_digest
                or namespace.target_profile_id != choice.target_profile_id
                or namespace.principal_selection_receipt_id != principal.receipt_id
                or controller.handle != choice.controller_binding_handle):
            raise BootstrapEnrollmentPending("application source selection lost its current setup joins")
        now = time.monotonic()
        expiry = min(prepared.expires_monotonic, base_consent.expires_monotonic,
                     self._factory.session_store.current_deadline(self._handle),
                     choice.expires_monotonic)
        if expiry <= now:
            raise BootstrapEnrollmentPending("application source selection lease expired")
        selection_key = (choice_handle, application_id)
        selection_handle = self._application_source_preparation_handles.get(selection_key)
        if selection_handle is None:
            selection_handle = secrets.token_urlsafe(36)
        selection = RootApplicationSourcePreparationSelection._mint(
            schema=1,
            selection_handle=selection_handle,
            setup_session_id=self._handle.session_id,
            transaction_handle=self._authorization.transaction_handle,
            plan_sha256=self._authorization.plan_digest,
            prepared_generation_id=prepared.generation_id,
            prepared_generation_digest=prepared.generation_digest,
            qualification_choice_handle=choice_handle,
            qualification_consent_receipt_handle=base_consent.receipt_handle,
            application_id=profile.application_id,
            workflow_id=profile.workflow_id,
            source_identity=profile.source_identity,
            source_revision=profile.source_revision,
            source_catalog_artifact_id=profile.source_catalog_artifact_id,
            source_catalog_sha256=profile.source_catalog_sha256,
            manifest_paths=profile.manifest_paths,
            lock_paths=profile.lock_paths,
            target_profile_id=choice.target_profile_id,
            namespace_selection_receipt_handle=namespace.receipt_handle,
            principal_selection_receipt_handle=principal.receipt_id,
            controller_binding_handle=controller.handle,
            expires_monotonic=expiry,
        )
        self._check_live()
        if (self._last_receipt is not prepared
                or self._application_setup_choices.get(choice_handle) is not choice
                or not self.verify_application_controller_binding(controller)):
            raise BootstrapEnrollmentPending("application source selection changed while being issued")
        prior = self._application_source_preparations.get(selection_handle)
        if prior is not None and prior != selection:
            raise BootstrapEnrollmentPending("retained application source selection changed")
        self._application_source_preparations[selection_handle] = selection
        self._application_source_preparation_handles[selection_key] = selection_handle
        return selection

    def _attach_application_source_preparation_registry(self, registry: Any) -> None:
        self._check_live()
        from .application_source_preparation import RootApplicationSourcePreparationRegistry
        if (type(registry) is not RootApplicationSourcePreparationRegistry
                or getattr(registry, "binding", None) is not self._selected_installation):
            raise BootstrapEnrollmentPending("application source registry is not owned by this setup binding")
        if (self._application_source_preparation_registry is not None
                and self._application_source_preparation_registry is not registry):
            raise BootstrapEnrollmentPending("another application source registry is already attached")
        self._application_source_preparation_registry = registry

    def _attach_application_runtime_preparation_selection_registry(self, registry: Any) -> None:
        self._check_live()
        from .application_runtime_selection import RootApplicationRuntimePreparationSelectionRegistry
        if (type(registry) is not RootApplicationRuntimePreparationSelectionRegistry
                or getattr(registry, "binding", None) is not self._selected_installation
                or getattr(registry, "source_registry", None)
                   is not self._application_source_preparation_registry):
            raise BootstrapEnrollmentPending("application runtime selector does not match the attached source registry")
        if (self._application_runtime_preparation_selection_registry is not None
                and self._application_runtime_preparation_selection_registry is not registry):
            raise BootstrapEnrollmentPending("another application runtime selector is already attached")
        self._application_runtime_preparation_selection_registry = registry

    def _attach_application_package_closure_registry(self, registry: Any) -> None:
        self._check_live()
        from .application_runtime_preparation import RootApplicationOfflinePackageClosureRegistry
        if (type(registry) is not RootApplicationOfflinePackageClosureRegistry
                or getattr(registry, "binding", None) is not self._selected_installation
                or getattr(registry, "source_registry", None)
                   is not self._application_source_preparation_registry
                or not callable(getattr(registry, "resolve_current_package_closure_for_selection", None))):
            raise BootstrapEnrollmentPending("application package registry does not match this setup/source binding")
        selector = self._application_runtime_preparation_selection_registry
        if selector is None:
            raise BootstrapEnrollmentPending("root application runtime selector must be attached before package closure")
        if (self._application_package_closure_registry is not None
                and self._application_package_closure_registry is not registry):
            raise BootstrapEnrollmentPending("another application package registry is already attached")
        selector.attach_package_registry(registry)
        self._application_package_closure_registry = registry

    def attach_application_package_closure_registry(self, registry: Any) -> None:
        self._attach_application_package_closure_registry(registry)

    def resolve_current_application_package_closure(self, source_preparation_selection_handle: str) -> Any:
        self._check_live()
        registry = self._application_package_closure_registry
        if registry is None:
            raise BootstrapEnrollmentPending("application package closure registry is not attached")
        try:
            closure = registry.resolve_current_package_closure_for_selection(
                source_preparation_selection_handle)
        except Exception as exc:
            from .application_runtime_preparation import ApplicationRuntimePreparationDenied
            if isinstance(exc, ApplicationRuntimePreparationDenied):
                raise BootstrapEnrollmentPending(str(exc)) from None
            raise BootstrapEnrollmentPending("current application package closure is unavailable") from None
        if getattr(closure, "source_preparation_selection_handle", None) != source_preparation_selection_handle:
            raise BootstrapEnrollmentPending("application package closure belongs to another source selection")
        return closure

    def _attach_application_node_bun_toolchain_registry(self, registry: Any) -> None:
        self._check_live()
        selector = self._application_runtime_preparation_selection_registry
        if (selector is None or getattr(registry, "choices", None) is not self._selected_installation):
            raise BootstrapEnrollmentPending("Node/Bun toolchain registry does not match the current setup selector")
        if (self._application_node_bun_toolchain_registry is not None
                and self._application_node_bun_toolchain_registry is not registry):
            raise BootstrapEnrollmentPending("another Node/Bun toolchain registry is already attached")
        selector.attach_node_toolchain_registry(registry)
        self._application_node_bun_toolchain_registry = registry

    def _application_runtime_selection_registry(self) -> Any:
        self._check_live()
        registry = self._application_runtime_preparation_selection_registry
        if registry is None:
            raise BootstrapEnrollmentPending("root application runtime-preparation selector is unavailable")
        return registry

    def _resolve_application_runtime_preparation_input(
            self, qualification_choice_handle: str,
            application_id: str) -> RootApplicationRuntimePreparationInputSelection:
        registry = self._application_runtime_selection_registry()
        try:
            selected = registry.resolve_application_runtime_preparation_input(
                qualification_choice_handle, application_id)
        except Exception as exc:
            from .application_runtime_selection import ApplicationRuntimeSelectionDenied
            if isinstance(exc, ApplicationRuntimeSelectionDenied):
                raise BootstrapEnrollmentPending(str(exc)) from None
            raise
        if type(selected) is not RootApplicationRuntimePreparationInputSelection:
            raise BootstrapEnrollmentPending("root app selector returned no sealed source/lock input")
        return selected

    def _resolve_application_runtime_preparation_input_selection(
            self, selection_handle: str) -> RootApplicationRuntimePreparationInputSelection:
        registry = self._application_runtime_selection_registry()
        try:
            selected = registry.resolve_application_runtime_preparation_input_selection(selection_handle)
        except Exception as exc:
            from .application_runtime_selection import ApplicationRuntimeSelectionDenied
            if isinstance(exc, ApplicationRuntimeSelectionDenied):
                raise BootstrapEnrollmentPending(str(exc)) from None
            raise
        if type(selected) is not RootApplicationRuntimePreparationInputSelection:
            raise BootstrapEnrollmentPending("root app selector returned no current source/lock input")
        return selected

    def _resolve_application_runtime_preparation(
            self, qualification_choice_handle: str,
            application_id: str) -> RootApplicationRuntimePreparationSelection:
        registry = self._application_runtime_selection_registry()
        try:
            selected = registry.resolve_application_runtime_preparation(
                qualification_choice_handle, application_id)
        except Exception as exc:
            from .application_runtime_selection import ApplicationRuntimeSelectionDenied
            if isinstance(exc, ApplicationRuntimeSelectionDenied):
                raise BootstrapEnrollmentPending(str(exc)) from None
            raise
        if type(selected) is not RootApplicationRuntimePreparationSelection:
            raise BootstrapEnrollmentPending("root app selector returned no sealed runtime preparation selection")
        return selected

    def _resolve_application_runtime_preparation_selection(
            self, selection_handle: str) -> RootApplicationRuntimePreparationSelection:
        registry = self._application_runtime_selection_registry()
        try:
            selected = registry.resolve_application_runtime_preparation_selection(selection_handle)
        except Exception as exc:
            from .application_runtime_selection import ApplicationRuntimeSelectionDenied
            if isinstance(exc, ApplicationRuntimeSelectionDenied):
                raise BootstrapEnrollmentPending(str(exc)) from None
            raise
        if type(selected) is not RootApplicationRuntimePreparationSelection:
            raise BootstrapEnrollmentPending("root app selector returned no current runtime preparation selection")
        return selected

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
                catalog=self._factory._catalog,
                artifact_root=self._factory._receipt_registry.artifact_root,
                artifact_receipts=self._factory._receipt_registry,
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
        if self._prepared_native_bundle is not None:
            return self._resolve_current_prepared_native_bundle(self._prepared_native_bundle)
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
        bundle = RootPreparedNativeBundle(
            self._handle.session_id, self._authorization.transaction_handle,
            prepared.generation_id, prepared.generation_digest,
            source_handle, pm_handle, profile.resources_source_receipt_handle,
            resource_handle, materialized.receipt_handle, materialized, self._seal,
        )
        self._prepared_native_bundle = bundle
        return bundle

    def _resolve_current_prepared_native_bundle(
            self, bundle: RootPreparedNativeBundle) -> RootPreparedNativeBundle:
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (not isinstance(bundle, RootPreparedNativeBundle)
                or bundle is not self._prepared_native_bundle
                or not secrets.compare_digest(bundle._session_seal, self._seal)
                or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or bundle.setup_session_id != self._handle.session_id
                or bundle.transaction_handle != self._authorization.transaction_handle
                or bundle.prepared_generation_id != prepared.generation_id
                or bundle.prepared_generation_digest != prepared.generation_digest
                or self._native_materialization_receipts.get(bundle.materialization_receipt_handle)
                   is not bundle.materialization_receipt):
            raise BootstrapEnrollmentPending("prepared native bundle is stale or not retained by this setup session")
        source = self._resolve_current_hermes_source()
        pm_runtime = self._resolve_current_pm_runtime()
        profile = self.resolve_selected_resource_profile(bundle.resource_profile_selection_receipt_handle)
        enrollment_ids = [row["record"].get("enrollment_id")
                          for row in self._policy.service_record_templates
                          if isinstance(row.get("record"), Mapping)]
        if (source.receipt_handle != bundle.hermes_source_receipt_handle
                or pm_runtime.receipt_handle != bundle.pm_runtime_receipt_handle
                or profile.resources_source_receipt_handle != bundle.resources_source_receipt_handle
                or profile.profile_id != bundle.materialization_receipt.resource_profile_id
                or len(enrollment_ids) != 1
                or bundle.materialization_receipt.enrollment_id != enrollment_ids[0]
                or bundle.materialization_receipt.service_generation != prepared.generation_id
                or bundle.materialization_receipt.protected_enrollment_digest != prepared.generation_digest
                or bundle.materialization_receipt.service_profile_id != self._policy.identity_policy["service_profile_id"]):
            raise BootstrapEnrollmentPending("prepared native bundle source, profile, runtime or materialization join changed")
        self._verify_current_setup_controller()
        return bundle

    def _resolve_native_bootstrap_assembly(
            self, prepared_setup_receipt_handle: str,
            native_materialization_receipt_handle: str) -> RootNativeBootstrapAssemblySelection:
        self._check_live()
        self._refresh_authorization()
        prepared = self.resolve_prepared_receipt(prepared_setup_receipt_handle)
        bundle = self.prepare_selected_native_bundle()
        self._resolve_current_prepared_native_bundle(bundle)
        policy_selection_handle = self._current_native_policy_selection_handle
        if not isinstance(policy_selection_handle, str) or not policy_selection_handle:
            raise BootstrapEnrollmentPending(
                "native assembly requires a current root-TTY native policy configuration choice")
        policy_selection = self.resolve_current_native_policy_selection(policy_selection_handle)
        policy_records = self.resolve_current_prepared_native_policy_records(policy_selection_handle)
        if (policy_selection.setup_session_id != self._handle.session_id
                or policy_selection.transaction_handle != self._authorization.transaction_handle
                or policy_selection.prepared_generation_id != prepared.generation_id
                or policy_selection.prepared_generation_digest != prepared.generation_digest
                or policy_records.native_policy_selection_handle != policy_selection_handle):
            raise BootstrapEnrollmentPending(
                "native policy selection or source records do not match current prepared custody")
        if (bundle.materialization_receipt_handle != native_materialization_receipt_handle
                or self._native_materialization_receipts.get(native_materialization_receipt_handle)
                   is not bundle.materialization_receipt):
            raise BootstrapEnrollmentPending("native assembly requires the exact current materialization receipt")
        template_rows = [row.get("record") for row in self._policy.service_record_templates
                         if isinstance(row.get("record"), Mapping)]
        if len(template_rows) != 1 or not isinstance(template_rows[0].get("enrollment_id"), str):
            raise BootstrapEnrollmentPending("prepared policy has no unique fixed native enrollment subject")
        enrollment_id = template_rows[0]["enrollment_id"]
        service_profile_id = self._policy.identity_policy.get("service_profile_id")
        if service_profile_id != "hermes-agent-native-v1":
            raise BootstrapEnrollmentPending("prepared policy does not select the fixed native service profile")
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        compiler_rows = [row for row in release.files
                         if row.artifact_id == _NATIVE_ASSEMBLY_COMPILER_ARTIFACT]
        if (len(compiler_rows) != 1 or "module" not in compiler_rows[0].roles
                or compiler_rows[0].artifact_id not in plan.allowed_artifact_ids):
            raise BootstrapEnrollmentPending("selected release lacks the native compiler module role")
        support_receipts = []
        for module_id in _NATIVE_ASSEMBLY_SUPPORT_MODULES:
            rows = [row for row in release.files if row.artifact_id == module_id]
            if (len(rows) != 1 or "module" not in rows[0].roles
                    or module_id not in plan.allowed_artifact_ids):
                raise BootstrapEnrollmentPending("native assembler support module is outside the installed plan")
            row = rows[0]
            origins = [origin for origin in actor.module_origins
                       if origin[1] == str(release.release_root / row.relative_path)
                       and origin[4] == row.sha256]
            if len(origins) != 1:
                raise BootstrapEnrollmentPending("native assembler module is not in the current actor import closure")
            prior = next((item for item in self._prepared_release_member_receipts.values()
                          if item.artifact_id == module_id
                          and item._prepared_generation_id == prepared.generation_id), None)
            if prior is None:
                handle = secrets.token_urlsafe(36)
                prior = RootReleaseModuleReceipt(
                    row.artifact_id, row.relative_path, row.sha256, row.size_bytes,
                    release.release_commit, release.deployment_receipt_sha256,
                    handle, self._handle.session_id, self._seal, self, prepared.generation_id)
                self._prepared_release_member_receipts[handle] = prior
            prior.read_current()
            support_receipts.append(prior)
        compiler = next(item for item in support_receipts
                        if item.artifact_id == _NATIVE_ASSEMBLY_COMPILER_ARTIFACT)
        capture_rows = __import__(
            "hermes_installer.authority.native_registration_projection",
            fromlist=["capture_actual_hermes_registrations"],
        ).capture_actual_hermes_registrations()
        registration_sources = self._resolve_prepared_release_module_receipts()
        source_digest = hashlib.sha256(_canonical([
            {"artifact_id": item.artifact_id, "sha256": item.sha256,
             "size_bytes": item.size_bytes, "source_receipt_handle": item.source_receipt_handle}
            for item in registration_sources
        ])).hexdigest()
        closure_digest = hashlib.sha256(_canonical([
            {"artifact_id": item.artifact_id, "sha256": item.sha256,
             "size_bytes": item.size_bytes, "source_receipt_handle": item.source_receipt_handle}
            for item in sorted(support_receipts, key=lambda value: value.artifact_id)
        ])).hexdigest()
        materialization = bundle.materialization_receipt
        package_generation = hashlib.sha256(_canonical({
            "package_id": "hermes-agent-native-package-v1",
            "profile_id": service_profile_id,
            "service_generation": prepared.generation_id,
            "service_digest": prepared.generation_digest,
            "resource_profile_id": materialization.resource_profile_id,
            "resource_closure_digest": materialization.selected_closure_digest,
            "hermes_revision": materialization.hermes_revision,
            "compiler_sha256": compiler.sha256,
            "compiler_closure_sha256": closure_digest,
        })).hexdigest()
        now = time.monotonic()
        expires = min(prepared.expires_monotonic,
                      self._factory.session_store.current_deadline(self._handle), now + 300.0)
        handle = secrets.token_urlsafe(36)
        seed = {
            "selection_handle": handle, "setup_session_id": self._handle.session_id,
            "transaction_handle": self._authorization.transaction_handle,
            "plan_digest": self._authorization.plan_digest,
            "prepared_generation_id": prepared.generation_id,
            "protected_enrollment_digest": prepared.generation_digest,
            "enrollment_id": enrollment_id, "service_profile_id": service_profile_id,
            "service_generation": prepared.generation_id,
            "resource_profile_id": materialization.resource_profile_id,
            "package_id": "hermes-agent-native-package-v1",
            "native_package_generation": package_generation,
            "compiler_artifact_id": compiler.artifact_id,
            "compiler_sha256": compiler.sha256,
            "compiler_release_receipt_handle": compiler.source_receipt_handle,
            "compiler_module_closure_sha256": closure_digest,
            "pm_runtime_receipt_handle": bundle.pm_runtime_receipt_handle,
            "materialization_receipt_handle": bundle.materialization_receipt_handle,
            "hermes_source_receipt_handle": bundle.hermes_source_receipt_handle,
            "resources_source_receipt_handle": bundle.resources_source_receipt_handle,
            "native_policy_preparation_handle": policy_selection_handle,
            "definitions_handle": secrets.token_urlsafe(36),
            "definitions_sha256": hashlib.sha256(_canonical({
                "registrations": [{"name": row.native_tool_name,
                                   "adapter": row.adapter_id,
                                   "argument_sha256": row.native_schema_sha256,
                                   "source_sha256": row.registration_source_sha256}
                                  for row in capture_rows],
                "source_receipt_closure_sha256": source_digest,
            })).hexdigest(),
            "issued_monotonic": now, "expires_monotonic": expires,
        }
        if expires <= now:
            raise BootstrapEnrollmentPending("native assembly selection lease expired")
        selection = RootNativeBootstrapAssemblySelection(
            schema=1, selection_handle=handle, setup_session_id=seed["setup_session_id"],
            transaction_handle=seed["transaction_handle"], plan_digest=seed["plan_digest"],
            prepared_generation_id=prepared.generation_id,
            protected_enrollment_digest=prepared.generation_digest,
            enrollment_id=enrollment_id, service_profile_id=service_profile_id,
            service_generation=prepared.generation_id,
            resource_profile_id=materialization.resource_profile_id,
            package_id=seed["package_id"], native_package_generation=package_generation,
            compiler_artifact_id=compiler.artifact_id, compiler_sha256=compiler.sha256,
            compiler_release_receipt_handle=compiler.source_receipt_handle,
            compiler_module_closure_sha256=closure_digest,
            pm_runtime_receipt_handle=bundle.pm_runtime_receipt_handle,
            materialization_receipt_handle=bundle.materialization_receipt_handle,
            hermes_source_receipt_handle=bundle.hermes_source_receipt_handle,
            resources_source_receipt_handle=bundle.resources_source_receipt_handle,
            native_policy_preparation_handle=policy_selection_handle,
            definitions_handle=seed["definitions_handle"], definitions_sha256=seed["definitions_sha256"],
            issued_monotonic=now, expires_monotonic=expires,
            _registry_seal=self._factory._native_assembly_seal,
        )
        self._native_assembly_selections[handle] = selection
        actor.verify_current(release)
        return selection

    def _resolve_current_native_bootstrap_assembly(
            self, selection_handle: str) -> RootNativeBootstrapAssemblySelection:
        if not isinstance(selection_handle, str) or not _GEN.fullmatch(selection_handle):
            raise BootstrapEnrollmentPending("native assembly selection handle is malformed")
        selection = self._native_assembly_selections.get(selection_handle)
        if not isinstance(selection, RootNativeBootstrapAssemblySelection):
            raise BootstrapEnrollmentPending("native assembly selection is not retained by this session")
        self._revalidate_native_assembly_selection(selection)
        return selection

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

    def _resolve_current_active_policy_compilation_registry(self) -> Any:
        """Compose the active compiler from this session's retained authorities.

        This is deliberately a resolver, not a constructor accepting registries:
        the PM runtime, principal selection, output receipt store, release and
        journal must all be the objects already owned by this live root session.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._resolve_current_prepared_enrollment()
        if prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("active compilation requires the current empty prepared generation")
        if self._adopted_principal_registry is None:
            raise BootstrapEnrollmentPending("active compilation has no adopted normal-session principal registry")
        if self._pm_runtime_registry is None or not self._pm_runtime_handle:
            raise BootstrapEnrollmentPending("active compilation requires the retained official PM runtime registry")
        # Refresh short-lived identity and process evidence on every access. The
        # compiler retains the stable registry, never this short-lived snapshot.
        self.resolve_current_setup_identity()
        self._resolve_current_pm_runtime()
        self._factory._actor.verify_current(self._factory._release)
        self._factory._release.verify_current()
        journal = self._current_root_journal_selection()
        if journal.path != Path("/var/lib/hermes-installer/authority-journal"):
            raise BootstrapEnrollmentPending("active compiler journal is not the fixed root authority journal")
        from .active_policy_compiler import (
            RootActivePolicyCompilationRegistry,
            RootActivePolicyTemplateResolver,
        )
        from .native_output_receipts import RootMaterializationReceiptRegistry
        from .pm_runtime import RootPMRuntimeReceiptRegistry
        if not isinstance(self._pm_runtime_registry, RootPMRuntimeReceiptRegistry):
            raise BootstrapEnrollmentPending("current PM runtime registry has an unsupported concrete type")
        outputs = self._root_native_output_receipts()
        if (not isinstance(outputs, RootMaterializationReceiptRegistry)
                or getattr(outputs, "_binding", None) is not self._selected_installation
                or getattr(getattr(outputs, "_binding", None), "_session", None) is not self):
            raise BootstrapEnrollmentPending("native output receipt registry is outside this exact setup session")
        if self._active_policy_compilation_registry is None:
            resolver = RootActivePolicyTemplateResolver(
                self._factory.resolver, self._adopted_principal_registry)
            self._active_policy_compilation_registry = RootActivePolicyCompilationRegistry.from_root_setup(
                self._factory, resolver, self._pm_runtime_registry, outputs, journal.path)
        registry = self._active_policy_compilation_registry
        if (not isinstance(registry, RootActivePolicyCompilationRegistry)
                or registry.factory is not self._factory
                or registry.sessions is not self._factory.session_store
                or registry.principal_registry is not self._adopted_principal_registry
                or registry.runtime_receipts is not self._pm_runtime_registry
                or registry.materialization_receipts is not outputs
                or registry.root_journal != journal.path):
            raise BootstrapEnrollmentPending("retained active compiler dependencies changed")
        return registry

    def _resolve_current_active_policy_publisher(self) -> Any:
        self._check_live()
        compiler = self._resolve_current_active_policy_compilation_registry()
        from .setup_policy_publication import RootSetupPolicyGenerationPublisher
        if self._active_policy_publisher is None:
            self._active_policy_publisher = RootSetupPolicyGenerationPublisher.from_root_setup(
                self._factory._release, self._factory.session_store,
                self._current_root_journal_selection().path, compiler)
        publisher = self._active_policy_publisher
        if (not isinstance(publisher, RootSetupPolicyGenerationPublisher)
                or publisher.release is not self._factory._release
                or publisher.session_store is not self._factory.session_store
                or publisher.registry is not compiler
                or publisher.root_journal != self._current_root_journal_selection().path):
            raise BootstrapEnrollmentPending("retained active publisher dependencies changed")
        self._factory._release.verify_current()
        self._factory._actor.verify_current(self._factory._release)
        return publisher

    def _resolve_current_active_policy_publication(self) -> Any:
        """Reopen the durable active selection; never infer it from a session receipt."""
        self._check_live()
        self._factory._release.verify_current()
        self._factory._actor.verify_current(self._factory._release)
        try:
            from .setup_policy_publication import PolicyPublicationReceiptResolver
            receipt = PolicyPublicationReceiptResolver.resolve_current()
        except Exception:
            raise BootstrapEnrollmentPending("there is no revalidated current active publication") from None
        if receipt.state != "active-committed":
            raise BootstrapEnrollmentPending("current root publication is not active")
        return receipt

    def _resolve_current_active_policy_predecessor(self, publication_handle: str) -> str:
        registry = self._resolve_current_active_policy_compilation_registry()
        try:
            return registry.resolve_current_active_policy_predecessor(publication_handle)
        except Exception:
            raise BootstrapEnrollmentPending(
                "active publication handle has no current root-verified predecessor") from None

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

    def _resolve_prepared_release_module_receipts(self) -> tuple[RootReleaseModuleReceipt, ...]:
        """Mint held module receipts for the actual 42 captured tool registrations.

        This API is available before a native assembly selection exists, which
        breaks the source-receipt/selection cycle without widening membership:
        the source module paths come only from actual `register_tool` captures.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("release registration modules require current empty prepared custody")
        from .native_registration_projection import capture_actual_hermes_registrations
        captured = capture_actual_hermes_registrations()
        if len(captured) != 42:
            raise BootstrapEnrollmentPending("installed native source did not yield the exact 42 registrations")
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        by_path: dict[str, list[tuple[str, str, int]]] = {}
        for captured_row in captured:
            path = "src/" + captured_row.registration_source_path
            rows = [row for row in release.files
                    if row.relative_path == path and "module" in row.roles]
            if (len(rows) != 1 or rows[0].sha256 != captured_row.registration_source_sha256
                    or rows[0].artifact_id not in plan.allowed_artifact_ids):
                raise BootstrapEnrollmentPending("actual registration source module is not pinned by selected release")
            by_path[path] = [(rows[0].artifact_id, rows[0].sha256, rows[0].size_bytes)]
        output: list[RootReleaseModuleReceipt] = []
        for path, choices in sorted(by_path.items()):
            if len(choices) != 1:
                raise BootstrapEnrollmentPending("captured registration module path is ambiguous")
            artifact_id, digest, size = choices[0]
            matches = [row for row in actor.module_origins
                       if row[1] == str(release.release_root / path) and row[4] == digest]
            if len(matches) != 1:
                raise BootstrapEnrollmentPending("registration module is outside current root actor import closure")
            handle = secrets.token_urlsafe(36)
            receipt = RootReleaseModuleReceipt(
                artifact_id, path, digest, size,
                release.release_commit, release.deployment_receipt_sha256,
                handle, self._handle.session_id, self._seal, self,
                prepared.generation_id,
            )
            self._prepared_release_member_receipts[handle] = receipt
            receipt.read_current()
            output.append(receipt)
        actor.verify_current(release)
        return tuple(output)

    def _resolve_prepared_native_target_module_receipts(self) -> tuple[RootReleaseModuleReceipt, ...]:
        """Issue current member receipts for fixed native target source modules."""
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("native target modules require current empty prepared custody")
        pins = (
            ("src/hermes_installer/components/native_plugins.py",
             "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7"),
            ("src/hermes_installer/components/public_registries.py",
             "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f"),
            ("src/hermes_installer/components/plugin_public_https.py",
             "63e4a128f0a48f0bfcbd3c0f6c7313d94f4a3e79f83c2655dde32a339b91ff0d"),
        )
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        output: list[RootReleaseModuleReceipt] = []
        for relative_path, digest in pins:
            rows = [row for row in release.files if row.relative_path == relative_path
                    and row.sha256 == digest and "module" in row.roles
                    and row.artifact_id in plan.allowed_artifact_ids]
            if len(rows) != 1:
                raise BootstrapEnrollmentPending("native target source module is not uniquely pinned in the installed release")
            row = rows[0]
            if not any(origin[1] == str(release.release_root / relative_path)
                       and origin[4] == digest for origin in actor.module_origins):
                raise BootstrapEnrollmentPending("native target source module is outside the current root actor import closure")
            prior = next((item for item in self._prepared_release_member_receipts.values()
                          if item.artifact_id == row.artifact_id
                          and item._prepared_generation_id == prepared.generation_id), None)
            if prior is None:
                handle = secrets.token_urlsafe(36)
                prior = RootReleaseModuleReceipt(
                    row.artifact_id, relative_path, digest, row.size_bytes,
                    release.release_commit, release.deployment_receipt_sha256,
                    handle, self._handle.session_id, self._seal, self,
                    prepared.generation_id)
                self._release_member_receipts[handle] = prior
                self._prepared_release_member_receipts[handle] = prior
            prior.read_current()
            output.append(prior)
        actor.verify_current(release)
        return tuple(output)

    def _resolve_current_runtime_receipt(
            self, role: str, receipt_handle: str) -> RootRuntimeArtifactReceipt:
        """Derive generation from current root authorization, never from the caller."""
        self._check_live()
        self._refresh_authorization()
        prepared = self._resolve_current_prepared_enrollment()
        if prepared.state != "prepared" or prepared.enrollment_ids:
            raise BootstrapEnrollmentPending("runnable receipt selection requires current prepared custody")
        receipt = self.resolve_runtime_receipt(
            role, receipt_handle, self._authorization.transaction_handle)
        rule = next((row for row in self._policy.receipt_binding_rules
                     if row.get("receipt_role") == role), None)
        if (rule is None or rule.get("required_phase") != "runnable"
                or receipt.generation != prepared.transaction_handle):
            raise BootstrapEnrollmentPending("runtime receipt is not bound to the current runnable role")
        self._factory._actor.verify_current(self._factory._release)
        self._factory._release.verify_current()
        return receipt

    def _resolve_prepared_native_action_schema_module_receipts(
            self) -> tuple[RootReleaseModuleReceipt, ...]:
        """Resolve the five code-reviewed action-schema modules from the release.

        The artifact IDs are read from the selected release inventory rather
        than guessed from module names.  Path, bytes, plan membership and the
        current root actor's actual import origin are all fixed and checked.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending(
                "native action schema modules require current empty prepared custody")
        pins = (
            ("src/hermes_installer/components/plugin_accounts_schemas.py",
             "7608bddb4206156f179f18dd5418cea7e5807003295017a26acbb4a6c7d9d9c4", 6766),
            ("src/hermes_installer/components/plugin_document_schemas.py",
             "710d2f1877d2e5a40ddbf0e5ce83f2b14243bf1a459183065143a18aa55c2d25", 7281),
            ("src/hermes_installer/components/plugin_finance_schemas.py",
             "e379719b684d85bb467b567ac9f69664db8028688e131e9ba3401c80b277a8a6", 8687),
            ("src/hermes_installer/components/plugin_homelab_schemas.py",
             "c8438dac1ca54dfddbee8d9d3140466e8c075a6a46084edd0385438b82188111", 8932),
            ("src/hermes_installer/components/plugin_local_voice_web_schemas.py",
             "35ed72ffbc516c20d447685481cc4b49850a71c11b892ce085e57bb0e946ee84", 10880),
        )
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        output: list[RootReleaseModuleReceipt] = []
        for relative_path, digest, size_bytes in pins:
            rows = [row for row in release.files if row.relative_path == relative_path
                    and row.sha256 == digest and row.size_bytes == size_bytes
                    and "module" in row.roles and row.artifact_id in plan.allowed_artifact_ids]
            if len(rows) != 1:
                raise BootstrapEnrollmentPending(
                    "native action schema module is not uniquely pinned in the selected release")
            row = rows[0]
            origins = [origin for origin in actor.module_origins
                       if origin[1] == str(release.release_root / relative_path)
                       and origin[4] == digest]
            if len(origins) != 1:
                raise BootstrapEnrollmentPending(
                    "native action schema module is outside the current root actor import closure")
            prior = next((item for item in self._prepared_release_member_receipts.values()
                          if item.artifact_id == row.artifact_id
                          and item._prepared_generation_id == prepared.generation_id), None)
            if prior is None:
                handle = secrets.token_urlsafe(36)
                prior = RootReleaseModuleReceipt(
                    row.artifact_id, relative_path, digest, size_bytes,
                    release.release_commit, release.deployment_receipt_sha256,
                    handle, self._handle.session_id, self._seal, self,
                    prepared.generation_id)
                self._release_member_receipts[handle] = prior
                self._prepared_release_member_receipts[handle] = prior
            prior.read_current()
            output.append(prior)
        actor.verify_current(release)
        return tuple(output)

    def _resolve_prepared_native_capture_profile_receipts(
            self) -> tuple[RootPreparedReleaseMemberReceipt, ...]:
        """Read the three exact v158 capture profiles from the held release.

        These amendment files define capture validation limits and source IDs;
        the receipts prove only their selected-release bytes. They do not
        create action, observer, or process-role authority.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending(
                "native capture profiles require current empty prepared custody")
        pins = (
            ("installer-native-input-capture-profile-v1",
             "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-input-capture-profile-v1.json",
             "bfdf7175ee1df681b60ab4b707ffe9d314d8cc7fdc5a30a56e19d2cb1372c1d0", 837),
            ("installer-native-tool-result-capture-profile-v1",
             "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-tool-result-capture-profile-v1.json",
             "470fcc43b3d268a6594e0d6bdf2c635ba3bf4e6cd0cfe2dfcd57840d7bee105a", 984),
            ("installer-native-provider-result-capture-profile-v1",
             "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-provider-result-capture-profile-v1.json",
             "a2c6ae9243a7854f114ed492afd395d867f02ed58d50a3f1692fe0ea7efbd8eb", 993),
        )
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        output: list[RootPreparedReleaseMemberReceipt] = []
        for artifact_id, relative_path, digest, size_bytes in pins:
            rows = [row for row in release.files if row.artifact_id == artifact_id]
            if (artifact_id not in plan.allowed_artifact_ids or len(rows) != 1
                    or rows[0].relative_path != relative_path or rows[0].sha256 != digest
                    or rows[0].size_bytes != size_bytes or "amendment" not in rows[0].roles):
                raise BootstrapEnrollmentPending(
                    "native capture profile is not uniquely pinned as a v158 release amendment")
            prior = next((item for item in self._prepared_release_file_receipts.values()
                          if item.artifact_id == artifact_id
                          and item.prepared_generation_id == prepared.generation_id), None)
            if prior is None:
                handle = secrets.token_urlsafe(36)
                prior = RootPreparedReleaseMemberReceipt(
                    artifact_id, relative_path, digest, size_bytes,
                    release.release_commit, release.deployment_receipt_sha256,
                    handle, self._handle.session_id, prepared.generation_id,
                    _PREPARED_RELEASE_MEMBER_SEAL, self._seal, self, "amendment")
                self._prepared_release_file_receipts[handle] = prior
            if prior.role != "amendment":
                raise BootstrapEnrollmentPending("capture profile receipt has a different release role")
            prior.read_current()
            output.append(prior)
        actor.verify_current(release)
        return tuple(output)

    def _resolve_prepared_worker_role_module_receipts(
            self) -> tuple[RootPreparedReleaseMemberReceipt, ...]:
        """Retain release-pinned worker role modules without claiming actor imports.

        The role modules are loaded in their eventual managed worker. Their
        membership is checked here; a later worker-start receipt must prove the
        actual loader closure before any role becomes executable.
        """
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending("worker role modules require current empty prepared custody")
        pins = (
            ("src/hermes_installer/native_invocations.py",
             "78a3452289df5b7343e5c650ea8620d51b3aa1056e2eedea02cc3a0bff7b8226"),
            ("src/hermes_installer/native_boundary.py",
             "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb"),
        )
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        output: list[RootPreparedReleaseMemberReceipt] = []
        for relative_path, digest in pins:
            rows = [row for row in release.files
                    if row.relative_path == relative_path and row.sha256 == digest
                    and "module" in row.roles and row.artifact_id in plan.allowed_artifact_ids]
            if len(rows) != 1:
                raise BootstrapEnrollmentPending(
                    "worker role module is not uniquely pinned in the selected installed release")
            row = rows[0]
            prior = next((item for item in self._prepared_release_file_receipts.values()
                          if item.artifact_id == row.artifact_id
                          and item.prepared_generation_id == prepared.generation_id), None)
            if prior is None:
                handle = secrets.token_urlsafe(36)
                prior = RootPreparedReleaseMemberReceipt(
                    row.artifact_id, row.relative_path, row.sha256, row.size_bytes,
                    release.release_commit, release.deployment_receipt_sha256,
                    handle, self._handle.session_id, prepared.generation_id,
                    _PREPARED_RELEASE_MEMBER_SEAL, self._seal, self)
                self._prepared_release_file_receipts[handle] = prior
            prior.read_current()
            output.append(prior)
        actor.verify_current(release)
        return tuple(output)

    def _resolve_prepared_native_source_definition_module_receipt(self) -> RootReleaseModuleReceipt:
        """Resolve the root-imported source adapter with module-origin proof."""
        self._check_live()
        self._refresh_authorization()
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle):
            raise BootstrapEnrollmentPending(
                "native source definition adapter requires current empty prepared custody")
        relative_path = "lib/python/hermes_installer/authority/native_source_definitions.py"
        digest = "190c471b721ee03edb6fb731bd2b86ca335f00fb00adcc2fd20060424a417c9c"
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        rows = [row for row in release.files if row.relative_path == relative_path
                and row.sha256 == digest and row.size_bytes == 10_311 and "module" in row.roles
                and row.artifact_id in plan.allowed_artifact_ids]
        if len(rows) != 1:
            raise BootstrapEnrollmentPending(
                "native source definition adapter is not uniquely pinned in the installed release")
        row = rows[0]
        origins = [origin for origin in actor.module_origins
                   if origin[1] == str(release.release_root / relative_path)
                   and origin[4] == digest]
        if len(origins) != 1:
            raise BootstrapEnrollmentPending(
                "native source definition adapter is outside the current root actor import closure")
        prior = next((item for item in self._prepared_release_member_receipts.values()
                      if item.artifact_id == row.artifact_id
                      and item._prepared_generation_id == prepared.generation_id), None)
        if prior is None:
            handle = secrets.token_urlsafe(36)
            prior = RootReleaseModuleReceipt(
                row.artifact_id, relative_path, digest, row.size_bytes,
                release.release_commit, release.deployment_receipt_sha256,
                handle, self._handle.session_id, self._seal, self,
                prepared.generation_id)
            self._prepared_release_member_receipts[handle] = prior
        prior.read_current()
        actor.verify_current(release)
        return prior

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
            reviewed_packaged_registration_result_schemas,
        )
        reviewed = reviewed_packaged_registration_result_schemas()
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
                observer, self._factory._receipt_registry, self._authorization,
                release=self._factory._release, actor=self._factory._actor)
        binding = (prepared.provision_receipt_handle, prepared.generation_id)
        if self._native_schema_receipt_registry_minted_for not in {None, binding}:
            self._native_schema_receipts.clear()
            self._native_schema_receipts_by_artifact.clear()
        (root_receipt,) = self._native_schema_receipt_registry.mint(
            prepared_setup_receipt_handle=binding[0], prepared_generation_id=binding[1],
            artifact_id=artifact_id,
        )
        schema = root_receipt.schema
        deadline = min(prepared.expires_monotonic,
                       self._factory.session_store.current_deadline(self._handle))
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

    def resolve_existing_model_store_template(self) -> RootExistingModelStoreTemplateReceipt:
        """Issue only the exact v139 root-store template from the held release."""
        self._check_live()
        self._refresh_authorization()
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, digest, size_bytes, role = _EXISTING_MODEL_STORE_TEMPLATE
        plan = self._factory.resolver.resolve(_PLAN_ID)
        if artifact_id not in plan.allowed_artifact_ids:
            raise BootstrapEnrollmentPending("selected setup plan does not include the fixed model-store root template")
        rows = [row for row in release.files if row.artifact_id == artifact_id]
        if (len(rows) != 1 or rows[0].relative_path != relative_path
                or rows[0].sha256 != digest or rows[0].size_bytes != size_bytes
                or role not in rows[0].roles):
            raise BootstrapEnrollmentPending("installed release lacks the exact v139 model-store root template role")
        receipt = RootExistingModelStoreTemplateReceipt(
            artifact_id, relative_path, digest, size_bytes, role,
            release.release_commit, release.deployment_receipt_sha256,
            secrets.token_urlsafe(36), self._handle.session_id, self._seal, self)
        if self._existing_model_store_template_receipt is not None:
            previous = self._existing_model_store_template_receipt
            if previous != receipt:
                receipt = previous
        else:
            self._existing_model_store_template_receipt = receipt
        receipt.read_current()
        actor.verify_current(release)
        return receipt

    def _read_existing_model_store_template(
            self, receipt: RootExistingModelStoreTemplateReceipt) -> bytes:
        self._check_live()
        if (type(receipt) is not RootExistingModelStoreTemplateReceipt
                or receipt._session is not self or receipt._session_id != self._handle.session_id
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or self._existing_model_store_template_receipt is not receipt):
            raise BootstrapEnrollmentPending("model-store root template receipt is not retained by this session")
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, digest, size_bytes, role = _EXISTING_MODEL_STORE_TEMPLATE
        plan = self._factory.resolver.resolve(_PLAN_ID)
        rows = [row for row in release.files if row.artifact_id == artifact_id]
        if (artifact_id not in plan.allowed_artifact_ids or len(rows) != 1
                or role not in rows[0].roles or rows[0].relative_path != relative_path
                or rows[0].sha256 != digest or rows[0].size_bytes != size_bytes
                or receipt.artifact_id != artifact_id or receipt.relative_path != relative_path
                or receipt.sha256 != digest or receipt.size_bytes != size_bytes
                or receipt.role != role or receipt.release_commit != release.release_commit
                or receipt.deployment_receipt_sha256 != release.deployment_receipt_sha256):
            raise BootstrapEnrollmentPending("model-store template no longer matches fixed release pin")
        fd = release.open_file(artifact_id)
        try:
            raw = bytearray()
            while len(raw) <= size_bytes:
                block = os.read(fd, min(64 * 1024, size_bytes + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
        finally:
            os.close(fd)
        if len(raw) != size_bytes or hashlib.sha256(raw).hexdigest() != digest:
            raise BootstrapEnrollmentPending("model-store root template bytes differ from fixed source")
        document = self._factory.resolver._json(bytes(raw), "existing model-store root template")
        expected = {
            "id": artifact_id,
            "root_id": "installer-existing-model-store-v1",
            "absolute_path": "/var/lib/hermes-installer/model-store",
            "owner_uid": 0,
            "directory_mode": 0o700,
            "selection_kind": "existing-model-store",
            "public_egress_allowed": False,
            "additional_metered_budget_usd": 0,
        }
        if not isinstance(document, dict) or any(document.get(key) != value for key, value in expected.items()):
            raise BootstrapEnrollmentPending("installed model-store root policy differs from v139")
        actor.verify_current(release)
        return bytes(raw)

    def resolve_held_installer_release_receipt(self) -> Any:
        """Return the same held release only after rechecking actor and session."""
        self._check_live()
        self._refresh_authorization()
        self._factory._actor.verify_current(self._factory._release)
        return self._factory._release

    def _resolve_prepared_build_service(self, build_profile_id: str) -> RootPreparedBuildServiceSelection:
        """Resolve the fixed setup-only Xpra builder against actual NSS/root custody."""
        self._check_live()
        self._refresh_authorization()
        if build_profile_id != "xpra-root-xauthority-transform-v1":
            raise BootstrapEnrollmentPending("prepared build profile is outside the fixed Xpra operation")
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle
                or prepared.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("prepared build service requires current empty prepared custody")
        prior = self._prepared_build_selections.get(build_profile_id)
        if prior is not None:
            return self._resolve_current_prepared_build_service(prior.service_selection_handle)
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, digest, size = _PREPARED_BUILD_TEMPLATE
        plan = self._factory.resolver.resolve(_PLAN_ID)
        rows = [item for item in release.files if item.artifact_id == artifact_id]
        if (artifact_id not in plan.allowed_artifact_ids or len(rows) != 1
                or rows[0].relative_path != relative_path or rows[0].sha256 != digest
                or rows[0].size_bytes != size or "template" not in rows[0].roles):
            raise BootstrapEnrollmentPending("installed release lacks the exact reviewed prepared build template")
        fd = release.open_file(artifact_id)
        try:
            raw = bytearray()
            while len(raw) <= size:
                block = os.read(fd, min(64 * 1024, size + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
        finally:
            os.close(fd)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise BootstrapEnrollmentPending("prepared build template changed after release verification")
        try:
            template = json.loads(raw)
        except Exception:
            raise BootstrapEnrollmentPending("prepared build template is malformed") from None
        if (not isinstance(template, dict) or template.get("id") != artifact_id
                or template.get("profile_id") != "hermes-installer-build-v1"
                or template.get("service_account_name") != "hermes-installer-build"
                or template.get("exclusive_group_name") != "hermes-installer-build"
                or template.get("allowed_operation_ids") != ["xpra-root-xauthority-transform-v1"]
                or template.get("allowed_targets") != ["xpra-root-xauthority-transform:start"]):
            raise BootstrapEnrollmentPending("prepared build template does not match its fixed Xpra scope")
        if self._prepared_build_identity is None:
            self._prepared_build_identity = SystemIdentityAdapter(
                Path("/var/lib/hermes-installer/identities/hermes-installer-build.json"),
                name="hermes-installer-build")
        identity = self._prepared_build_identity.ensure()
        if identity.uid == 0 or identity.gid == 0:
            raise BootstrapEnrollmentPending("prepared build identity must be a dedicated non-root account")
        transaction_digest = hashlib.sha256(self._authorization.transaction_handle.encode("ascii")).hexdigest()
        root = self._factory.resolver.journal_root / "prepared-build-services" / transaction_digest
        _ensure_root_directory(root.parent)
        _ensure_root_directory(root)
        work = root / "work"
        if not work.exists():
            _create_service_root(work, identity)
        work_info = work.lstat()
        if (work_info.st_uid != identity.uid or work_info.st_gid != identity.gid
                or not stat.S_ISDIR(work_info.st_mode) or stat.S_IMODE(work_info.st_mode) != 0o700):
            raise BootstrapEnrollmentPending("prepared build work root conflicts with the selected NSS identity")
        now = time.monotonic()
        expires = min(now + min(300.0, float(template.get("limits", {}).get("max_lifetime_seconds", 300))),
                      prepared.expires_monotonic,
                      self._factory.session_store.current_deadline(self._handle))
        if expires <= now:
            raise BootstrapEnrollmentPending("prepared build service selection lease expired")
        selection_handle = secrets.token_urlsafe(36)
        nss_handle, root_handle = secrets.token_urlsafe(36), secrets.token_urlsafe(36)
        immutable = {
            "schema": 1,
            "id": f"setup-build:{self._authorization.transaction_handle}:hermes-installer-build-v1",
            "profile_id": "hermes-installer-build-v1",
            "setup_session_id": self._handle.session_id,
            "transaction_handle": self._authorization.transaction_handle,
            "prepared_generation_id": prepared.generation_id,
            "prepared_generation_digest": prepared.generation_digest,
            "template_artifact_id": artifact_id, "template_sha256": digest,
            "service_uid": identity.uid, "service_gid": identity.gid,
            "nss_identity_receipt_handle": nss_handle,
            "root_selection_receipt_handle": root_handle,
            "allowed_operation_ids": ["xpra-root-xauthority-transform-v1"],
            "allowed_targets": ["xpra-root-xauthority-transform:start"],
            "root_device": root.stat().st_dev, "root_inode": root.stat().st_ino,
            "work_device": work_info.st_dev, "work_inode": work_info.st_ino,
        }
        generation = hashlib.sha256(_canonical(immutable)).hexdigest()
        signature = hmac.new(self._seal.encode("ascii"), _canonical({**immutable,
                    "generation": generation, "expires_monotonic": expires}), hashlib.sha256).hexdigest()
        record = {**immutable, "generation": generation, "expires_monotonic": expires,
                  "selection_handle": selection_handle, "signature": signature}
        _atomic_root_file(root / f"{selection_handle}.json", _canonical(record), 0o600)
        selected = RootPreparedBuildServiceSelection(
            selection_handle, immutable["id"], immutable["profile_id"], generation,
            self._handle.session_id, self._authorization.transaction_handle,
            prepared.generation_id, prepared.generation_digest, artifact_id, digest,
            identity.uid, identity.gid, nss_handle, root_handle,
            tuple(immutable["allowed_operation_ids"]), tuple(immutable["allowed_targets"]),
            expires, signature, self._seal, self)
        self._prepared_build_selections[selection_handle] = selected
        self._prepared_build_selections[build_profile_id] = selected
        actor.verify_current(release)
        return selected

    def _resolve_current_prepared_build_service(self, selection_handle: str) -> RootPreparedBuildServiceSelection:
        if selection_handle in self._prepared_application_build_selections:
            return self._resolve_current_prepared_application_build_service(selection_handle)
        self._check_live()
        self._refresh_authorization()
        selected = self._prepared_build_selections.get(selection_handle)
        prepared = self._last_receipt
        if (not isinstance(selected, RootPreparedBuildServiceSelection)
                or selected.service_selection_handle != selection_handle
                or selected._session is not self
                or not secrets.compare_digest(selected._session_seal, self._seal)
                or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or selected.setup_session_id != self._handle.session_id
                or selected.transaction_handle != self._authorization.transaction_handle
                or selected.prepared_generation_id != prepared.generation_id
                or selected.prepared_generation_digest != prepared.generation_digest
                or selected.expires_monotonic <= time.monotonic()
                or self._prepared_build_identity is None):
            raise BootstrapEnrollmentPending("prepared build service selection is stale or not retained")
        identity = self._prepared_build_identity.ensure()
        if (identity.uid != selected.service_uid or identity.gid != selected.service_gid
                or identity.name != "hermes-installer-build"):
            raise BootstrapEnrollmentPending("prepared build NSS identity changed after selection")
        if selected.template_artifact_id == _PREPARED_APPLICATION_BUILD_TEMPLATE[0]:
            app_profile = next((row for row in _PREPARED_APPLICATION_BUILD_PROFILES.values()
                                if selected.allowed_operation_ids == (row[1],)
                                and selected.allowed_targets == (row[2],)), None)
            if app_profile is None:
                raise BootstrapEnrollmentPending("application output root has no fixed operation profile")
            root = (self._factory.resolver.journal_root / "prepared-application-build-services"
                    / hashlib.sha256(selected.transaction_handle.encode("ascii")).hexdigest()
                    / app_profile[0])
        else:
            root = (self._factory.resolver.journal_root / "prepared-build-services"
                    / hashlib.sha256(selected.transaction_handle.encode("ascii")).hexdigest())
        path = root / f"{selection_handle}.json"
        record = _read_json_if_owned(path)
        if (not isinstance(record, dict) or record.get("selection_handle") != selection_handle
                or record.get("signature") != selected._signature
                or record.get("prepared_generation_digest") != prepared.generation_digest
                or record.get("service_uid") != identity.uid or record.get("service_gid") != identity.gid):
            raise BootstrapEnrollmentPending("prepared build service journal no longer matches current setup")
        unsigned = dict(record)
        unsigned.pop("signature", None)
        unsigned.pop("selection_handle", None)
        check = hmac.new(self._seal.encode("ascii"), _canonical(unsigned), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(check, selected._signature):
            raise BootstrapEnrollmentPending("prepared build service journal signature is invalid")
        work_info = (root / "work").lstat()
        if (work_info.st_uid != identity.uid or work_info.st_gid != identity.gid
                or not stat.S_ISDIR(work_info.st_mode) or stat.S_IMODE(work_info.st_mode) != 0o700
                or root.stat().st_ino != record.get("root_inode")
                or work_info.st_ino != record.get("work_inode")):
            raise BootstrapEnrollmentPending("prepared build roots changed after selection")
        self._factory._actor.verify_current(self._factory._release)
        return selected

    def _resolve_prepared_application_build_service(
            self, build_profile_id: str) -> RootPreparedBuildServiceSelection:
        """Select one v132 offline application-build operation under the distinct template."""
        self._check_live()
        self._refresh_authorization()
        profile = _PREPARED_APPLICATION_BUILD_PROFILES.get(build_profile_id)
        if profile is None:
            raise BootstrapEnrollmentPending("application build profile is outside the fixed v132 set")
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or not prepared.provision_receipt_handle
                or prepared.transaction_handle != self._authorization.transaction_handle):
            raise BootstrapEnrollmentPending("application build service requires current empty prepared custody")
        prior = self._prepared_build_selections.get(build_profile_id)
        if prior is not None:
            return self._resolve_current_prepared_application_build_service(prior.service_selection_handle)
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        artifact_id, relative_path, digest, size, role = _PREPARED_APPLICATION_BUILD_TEMPLATE
        plan = self._factory.resolver.resolve(_PLAN_ID)
        rows = [row for row in release.files if row.artifact_id == artifact_id]
        if (artifact_id not in plan.allowed_artifact_ids or len(rows) != 1
                or rows[0].relative_path != relative_path or rows[0].sha256 != digest
                or rows[0].size_bytes != size or role not in rows[0].roles):
            raise BootstrapEnrollmentPending("installed release lacks the exact reviewed v132 application template")
        fd = release.open_file(artifact_id)
        try:
            raw = bytearray()
            while len(raw) <= size:
                block = os.read(fd, min(64 * 1024, size + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
        finally:
            os.close(fd)
        if len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
            raise BootstrapEnrollmentPending("v132 application template bytes changed after release verification")
        try:
            template = json.loads(raw)
        except Exception:
            raise BootstrapEnrollmentPending("v132 application template is malformed") from None
        app_id, operation_id, target_id = profile
        expected_operations = [row[1] for row in _PREPARED_APPLICATION_BUILD_PROFILES.values()]
        expected_targets = [row[2] for row in _PREPARED_APPLICATION_BUILD_PROFILES.values()]
        if (not isinstance(template, dict) or template.get("schema") != 1
                or template.get("id") != artifact_id
                or template.get("profile_id") != "hermes-installer-build-v1"
                or template.get("service_account_name") != "hermes-installer-build"
                or template.get("exclusive_group_name") != "hermes-installer-build"
                or template.get("allowed_operation_ids") != expected_operations
                or template.get("allowed_targets") != expected_targets
                or operation_id not in template["allowed_operation_ids"]
                or target_id not in template["allowed_targets"]):
            raise BootstrapEnrollmentPending("v132 application template does not match its fixed four-operation scope")
        if self._prepared_build_identity is None:
            self._prepared_build_identity = SystemIdentityAdapter(
                Path("/var/lib/hermes-installer/identities/hermes-installer-build.json"),
                name="hermes-installer-build")
        identity = self._prepared_build_identity.ensure()
        if identity.uid == 0 or identity.gid == 0:
            raise BootstrapEnrollmentPending("application build identity must be a dedicated non-root account")
        transaction_digest = hashlib.sha256(self._authorization.transaction_handle.encode("ascii")).hexdigest()
        root = (self._factory.resolver.journal_root / "prepared-application-build-services"
                / transaction_digest / app_id)
        _ensure_root_directory(root.parent)
        _ensure_root_directory(root)
        work = root / "work"
        if not work.exists():
            _create_service_root(work, identity)
        work_info = work.lstat()
        if (work_info.st_uid != identity.uid or work_info.st_gid != identity.gid
                or not stat.S_ISDIR(work_info.st_mode) or stat.S_IMODE(work_info.st_mode) != 0o700):
            raise BootstrapEnrollmentPending("application build work root conflicts with the selected NSS identity")
        now = time.monotonic()
        expires = min(now + min(600.0, float(template.get("limits", {}).get("max_lifetime_seconds", 600))),
                      prepared.expires_monotonic,
                      self._factory.session_store.current_deadline(self._handle))
        if expires <= now:
            raise BootstrapEnrollmentPending("application build service selection lease expired")
        selection_handle = secrets.token_urlsafe(36)
        nss_handle, root_handle = secrets.token_urlsafe(36), secrets.token_urlsafe(36)
        immutable = {
            "schema": 1,
            "id": f"setup-app-build:{self._authorization.transaction_handle}:{operation_id}",
            "profile_id": "hermes-installer-build-v1",
            "application_id": app_id,
            "setup_session_id": self._handle.session_id,
            "transaction_handle": self._authorization.transaction_handle,
            "prepared_generation_id": prepared.generation_id,
            "prepared_generation_digest": prepared.generation_digest,
            "template_artifact_id": artifact_id, "template_sha256": digest,
            "service_uid": identity.uid, "service_gid": identity.gid,
            "nss_identity_receipt_handle": nss_handle,
            "root_selection_receipt_handle": root_handle,
            "allowed_operation_ids": [operation_id],
            "allowed_targets": [target_id],
            "root_device": root.stat().st_dev, "root_inode": root.stat().st_ino,
            "work_device": work_info.st_dev, "work_inode": work_info.st_ino,
        }
        generation = hashlib.sha256(_canonical(immutable)).hexdigest()
        signature = hmac.new(self._seal.encode("ascii"), _canonical({**immutable,
                    "generation": generation, "expires_monotonic": expires}), hashlib.sha256).hexdigest()
        record = {**immutable, "generation": generation, "expires_monotonic": expires,
                  "selection_handle": selection_handle, "signature": signature}
        _atomic_root_file(root / f"{selection_handle}.json", _canonical(record), 0o600)
        selected = RootPreparedBuildServiceSelection(
            selection_handle, immutable["id"], immutable["profile_id"], generation,
            self._handle.session_id, self._authorization.transaction_handle,
            prepared.generation_id, prepared.generation_digest, artifact_id, digest,
            identity.uid, identity.gid, nss_handle, root_handle,
            (operation_id,), (target_id,), expires, signature, self._seal, self)
        self._prepared_application_build_selections[selection_handle] = selected
        self._prepared_build_selections[selection_handle] = selected
        self._prepared_build_selections[build_profile_id] = selected
        actor.verify_current(release)
        return selected

    def _resolve_current_prepared_application_build_service(
            self, selection_handle: str) -> RootPreparedBuildServiceSelection:
        self._check_live()
        self._refresh_authorization()
        selected = self._prepared_application_build_selections.get(selection_handle)
        prepared = self._last_receipt
        if (not isinstance(selected, RootPreparedBuildServiceSelection)
                or selected.service_selection_handle != selection_handle
                or selected._session is not self
                or not secrets.compare_digest(selected._session_seal, self._seal)
                or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or selected.setup_session_id != self._handle.session_id
                or selected.transaction_handle != self._authorization.transaction_handle
                or selected.prepared_generation_id != prepared.generation_id
                or selected.prepared_generation_digest != prepared.generation_digest
                or selected.expires_monotonic <= time.monotonic()
                or self._prepared_build_identity is None):
            raise BootstrapEnrollmentPending("application build selection is stale or not retained")
        app_id = selected.id.rsplit(":", 1)[-1].removesuffix("-runtime-prepare-v1")
        # The operation suffix alone is not an app identity for hyphenated IDs;
        # derive it only from the exact operation/target pair retained in the row.
        profile = next((value for value in _PREPARED_APPLICATION_BUILD_PROFILES.values()
                        if selected.allowed_operation_ids == (value[1],)
                        and selected.allowed_targets == (value[2],)), None)
        if profile is None:
            raise BootstrapEnrollmentPending("application build selection has an unknown operation")
        app_id = profile[0]
        artifact_id, relative_path, digest, size, role = _PREPARED_APPLICATION_BUILD_TEMPLATE
        if selected.template_artifact_id != artifact_id or selected.template_sha256 != digest:
            raise BootstrapEnrollmentPending("application build selection template pin changed")
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        template_rows = [row for row in release.files if row.artifact_id == artifact_id]
        if (len(template_rows) != 1 or template_rows[0].relative_path != relative_path
                or template_rows[0].sha256 != digest or template_rows[0].size_bytes != size
                or role not in template_rows[0].roles):
            raise BootstrapEnrollmentPending("installed v132 template membership changed")
        template_fd = release.open_file(artifact_id)
        try:
            template_bytes = bytearray()
            while len(template_bytes) <= size:
                block = os.read(template_fd, min(64 * 1024, size + 1 - len(template_bytes)))
                if not block:
                    break
                template_bytes.extend(block)
        finally:
            os.close(template_fd)
        if len(template_bytes) != size or hashlib.sha256(template_bytes).hexdigest() != digest:
            raise BootstrapEnrollmentPending("installed v132 template bytes changed")
        identity = self._prepared_build_identity.ensure()
        if (identity.uid != selected.service_uid or identity.gid != selected.service_gid
                or identity.name != "hermes-installer-build"):
            raise BootstrapEnrollmentPending("application build NSS identity changed after selection")
        root = (self._factory.resolver.journal_root / "prepared-application-build-services"
                / hashlib.sha256(selected.transaction_handle.encode("ascii")).hexdigest() / app_id)
        record = _read_json_if_owned(root / f"{selection_handle}.json")
        if (not isinstance(record, dict) or record.get("selection_handle") != selection_handle
                or record.get("signature") != selected._signature
                or record.get("prepared_generation_digest") != prepared.generation_digest
                or record.get("service_uid") != identity.uid or record.get("service_gid") != identity.gid
                or record.get("allowed_operation_ids") != list(selected.allowed_operation_ids)
                or record.get("allowed_targets") != list(selected.allowed_targets)
                or record.get("template_artifact_id") != artifact_id
                or record.get("template_sha256") != digest):
            raise BootstrapEnrollmentPending("application build selection journal changed")
        unsigned = dict(record)
        unsigned.pop("signature", None)
        unsigned.pop("selection_handle", None)
        check = hmac.new(self._seal.encode("ascii"), _canonical(unsigned), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(check, selected._signature):
            raise BootstrapEnrollmentPending("application build selection journal signature is invalid")
        work_info = (root / "work").lstat()
        if (not stat.S_ISDIR(work_info.st_mode) or work_info.st_uid != identity.uid
                or work_info.st_gid != identity.gid or stat.S_IMODE(work_info.st_mode) != 0o700
                or root.stat().st_ino != record.get("root_inode")
                or work_info.st_ino != record.get("work_inode")):
            raise BootstrapEnrollmentPending("application build roots changed after selection")
        actor.verify_current(release)
        return selected

    def _resolve_application_runtime_probe_artifact(self, application_id: str) -> Any:
        if application_id not in {row[0] for row in _PREPARED_APPLICATION_BUILD_PROFILES.values()}:
            raise BootstrapEnrollmentPending("application probe request is outside the fixed application set")
        raise BootstrapEnrollmentPending(
            "installed application ABI/origin probe artifact receipt is unavailable in this release")

    def _verify_current_setup_controller(self) -> VerifiedRootSetupAuthorization:
        self._check_live()
        self._refresh_authorization()
        self._factory._actor.verify_current(self._factory._release)
        live = self._factory.session_store._live(self._handle)
        proof = self._factory.session_store._proof(live)
        if (proof != self._authorization or proof.setup_session_id != self._handle.session_id
                or proof.transaction_handle != self._transaction.transaction_handle):
            raise BootstrapEnrollmentPending("setup controller proof is no longer current")
        return proof

    def _create_prepared_build_output_root(self, selection_handle: str) -> RootPreparedBuildOutputRoot:
        selected = self._resolve_current_prepared_build_service(selection_handle)
        if selected._session is not self:
            raise BootstrapEnrollmentPending("prepared build output request is not owned by this session")
        prior = next((row for row in self._prepared_build_output_roots.values()
                      if row.service_selection_handle == selection_handle), None)
        if prior is not None:
            check_fd = prior.open_current()
            os.close(check_fd)
            return prior
        if selected.template_artifact_id == _PREPARED_APPLICATION_BUILD_TEMPLATE[0]:
            app_profile = next((row for row in _PREPARED_APPLICATION_BUILD_PROFILES.values()
                                if selected.allowed_operation_ids == (row[1],)
                                and selected.allowed_targets == (row[2],)), None)
            if app_profile is None:
                raise BootstrapEnrollmentPending("application output root has no fixed operation profile")
            root = (self._factory.resolver.journal_root / "prepared-application-build-services"
                    / hashlib.sha256(selected.transaction_handle.encode("ascii")).hexdigest()
                    / app_profile[0])
        else:
            root = (self._factory.resolver.journal_root / "prepared-build-services"
                    / hashlib.sha256(selected.transaction_handle.encode("ascii")).hexdigest())
        output_parent = root / "outputs"
        if not output_parent.exists():
            _ensure_root_directory(output_parent)
        else:
            info = output_parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                    or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
                raise BootstrapEnrollmentPending("prepared build output parent is unsafe")
        output_root_id = secrets.token_hex(24)
        output = output_parent / output_root_id
        try:
            os.mkdir(output, 0o700)
            os.chown(output, selected.service_uid, selected.service_gid)
            os.chmod(output, 0o700)
            fd = os.open(output, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        except Exception:
            try:
                output.rmdir()
            except OSError:
                pass
            raise BootstrapEnrollmentPending("fresh prepared build output root could not be allocated safely") from None
        info = os.fstat(fd)
        if (info.st_uid != selected.service_uid or info.st_gid != selected.service_gid
                or stat.S_IMODE(info.st_mode) != 0o700):
            os.close(fd)
            raise BootstrapEnrollmentPending("prepared build output root ownership is invalid")
        receipt = RootPreparedBuildOutputRoot(
            output_root_id, selection_handle, selected.service_uid, selected.service_gid,
            fd, self, self._seal)
        self._prepared_build_output_roots[output_root_id] = receipt
        self._verify_current_setup_controller()
        return receipt

    def _open_prepared_build_output_root(self, receipt: RootPreparedBuildOutputRoot) -> int:
        selected = self._resolve_current_prepared_build_service(receipt.service_selection_handle)
        if (not isinstance(receipt, RootPreparedBuildOutputRoot) or receipt._session is not self
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or self._prepared_build_output_roots.get(receipt.output_root_id) is not receipt
                or selected.service_uid != receipt.service_uid or selected.service_gid != receipt.service_gid):
            raise BootstrapEnrollmentPending("prepared build output capability is stale or foreign")
        try:
            info = os.fstat(receipt._directory_fd)
        except OSError:
            raise BootstrapEnrollmentPending("prepared build output descriptor is closed") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != selected.service_uid
                or info.st_gid != selected.service_gid or stat.S_IMODE(info.st_mode) != 0o700):
            raise BootstrapEnrollmentPending("prepared build output descriptor identity changed")
        self._verify_current_setup_controller()
        return os.dup(receipt._directory_fd)

    def _remove_prepared_build_output_contents(self, receipt: RootPreparedBuildOutputRoot) -> None:
        fd = self._open_prepared_build_output_root(receipt)

        def remove_children(directory_fd: int) -> None:
            for name in os.listdir(directory_fd):
                if name in {".", ".."} or "/" in name or "\\" in name:
                    raise BootstrapEnrollmentPending("prepared build output contains an invalid entry name")
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    child_fd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                       | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                                       dir_fd=directory_fd)
                    try:
                        child_info = os.fstat(child_fd)
                        if (child_info.st_dev != info.st_dev or child_info.st_ino != info.st_ino
                                or child_info.st_uid != receipt.service_uid
                                or child_info.st_gid != receipt.service_gid):
                            raise BootstrapEnrollmentPending("prepared build output directory changed during cleanup")
                        remove_children(child_fd)
                    finally:
                        os.close(child_fd)
                    os.rmdir(name, dir_fd=directory_fd)
                elif stat.S_ISREG(info.st_mode):
                    if info.st_uid != receipt.service_uid or info.st_gid != receipt.service_gid:
                        raise BootstrapEnrollmentPending("prepared build output file has unexpected ownership")
                    os.unlink(name, dir_fd=directory_fd)
                else:
                    raise BootstrapEnrollmentPending("prepared build output contains a link or special file")
            os.fsync(directory_fd)

        try:
            remove_children(fd)
            self._verify_current_setup_controller()
        finally:
            os.close(fd)

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
        if receipt._prepared_generation_id is not None:
            prepared = self._last_receipt
            if (self._prepared_release_member_receipts.get(receipt.source_receipt_handle) is not receipt
                    or prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                    or prepared.generation_id != receipt._prepared_generation_id):
                raise BootstrapEnrollmentPending("prepared release module receipt is stale")
        else:
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

    def _read_prepared_release_member(
            self, receipt: RootPreparedReleaseMemberReceipt) -> bytes:
        self._check_live()
        if (type(receipt) is not RootPreparedReleaseMemberReceipt
                or receipt._session is not self
                or receipt.setup_session_id != self._handle.session_id
                or not secrets.compare_digest(receipt._session_seal, self._seal)
                or self._prepared_release_file_receipts.get(receipt.source_receipt_handle) is not receipt):
            raise BootstrapEnrollmentPending("prepared release member is not retained by this live setup session")
        prepared = self._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or prepared.generation_id != receipt.prepared_generation_id):
            raise BootstrapEnrollmentPending("prepared release member is stale for current custody")
        release, actor = self._factory._release, self._factory._actor
        actor.verify_current(release)
        plan = self._factory.resolver.resolve(self._authorization.plan_artifact_id)
        row = next((item for item in release.files if item.artifact_id == receipt.artifact_id), None)
        if (row is None or row.artifact_id not in plan.allowed_artifact_ids
                or "module" not in row.roles or row.relative_path != receipt.relative_path
                or row.sha256 != receipt.sha256 or row.size_bytes != receipt.size_bytes
                or release.release_commit != receipt.release_commit
                or release.deployment_receipt_sha256 != receipt.deployment_receipt_sha256):
            raise BootstrapEnrollmentPending("prepared release member differs from its fixed receipt")
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
            raise BootstrapEnrollmentPending("prepared release member bytes changed")
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
        bundle = self._prepared_native_bundle
        if bundle is None:
            raise BootstrapEnrollmentPending("current prepared native bundle is unavailable")
        self._resolve_current_prepared_native_bundle(bundle)
        if (selection.materialization_receipt_handle != bundle.materialization_receipt_handle
                or selection.hermes_source_receipt_handle != bundle.hermes_source_receipt_handle
                or selection.pm_runtime_receipt_handle != bundle.pm_runtime_receipt_handle
                or selection.resources_source_receipt_handle != bundle.resources_source_receipt_handle
                or selection.resource_profile_id != bundle.materialization_receipt.resource_profile_id
                or selection.package_id != "hermes-agent-native-package-v1"
                or selection.service_profile_id != "hermes-agent-native-v1"):
            raise BootstrapEnrollmentPending("native assembly selection differs from its retained prepared bundle")
        compiler = self._prepared_release_member_receipts.get(
            selection.compiler_release_receipt_handle)
        if (not isinstance(compiler, RootReleaseModuleReceipt)
                or compiler.artifact_id != selection.compiler_artifact_id
                or compiler.sha256 != selection.compiler_sha256
                or compiler._prepared_generation_id != prepared.generation_id):
            raise BootstrapEnrollmentPending("native compiler source receipt is absent or stale")
        compiler.read_current()
        source_receipts = self._resolve_prepared_release_module_receipts()
        if not source_receipts:
            raise BootstrapEnrollmentPending("actual Hermes registration module receipts are unavailable")
        self._factory._actor.verify_current(self._factory._release)

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
        for output_root in self._prepared_build_output_roots.values():
            try:
                os.close(output_root._directory_fd)
            except OSError:
                pass
        self._prepared_build_output_roots.clear()
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
        self._application_controller_tty_proofs.clear()
        self._application_controller_bindings.clear()
        self._application_source_preparations.clear()
        self._application_source_preparation_handles.clear()
        self._application_qualification_consents.clear()
        for proof in self._private_profile_proofs.values():
            try:
                proof.close()
            except Exception:
                pass
        self._private_profile_proofs.clear()
        if self._model_store_filesystem_registry is not None:
            try:
                self._model_store_filesystem_registry.close()
            except Exception:
                pass
            self._model_store_filesystem_registry = None
        if self._existing_model_selection_registry is not None:
            try:
                self._existing_model_selection_registry.close()
            except Exception:
                pass
            self._existing_model_selection_registry = None
        self._private_profile_registry = None
        for proof in self._memory_enablement_tty_proofs.values():
            try:
                proof.close()
            except Exception:
                pass
        self._memory_enablement_tty_proofs.clear()
        self._memory_enablement_choices.clear()
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


class RootPrivateProfileSelectionRegistry:
    """Retain purpose-limited private profile intent and refresh short evidence."""

    def __init__(self, selected_installation_binding: RootSelectedInstallationBinding,
                 root_principal_selection_registry: Any,
                 root_journal: RootJournalSelection):
        session = selected_installation_binding._session
        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or selected_installation_binding._seal != session._seal
                or root_principal_selection_registry is not session._adopted_principal_registry
                or not isinstance(root_journal, RootJournalSelection)):
            raise BootstrapEnrollmentPending("private profile registry requires the current root setup and journal bindings")
        session._check_live()
        row = session._authorization.root_journal_root
        if (root_journal.root_id != row.get("root_id")
                or root_journal.path != Path(row.get("absolute_path", ""))
                or (root_journal.device, root_journal.inode, root_journal.generation)
                   != (row.get("device"), row.get("inode"), row.get("generation"))):
            raise BootstrapEnrollmentPending("private profile journal differs from the held setup journal")
        self._binding = selected_installation_binding
        self._session = session
        self._principal_registry = root_principal_selection_registry
        self.root_journal = root_journal
        self._records: dict[str, RootPrivateProfileSelection] = {}
        self._sources: dict[str, tuple[tuple[str, str, str, str, int], ...]] = {}
        self._seal = session._seal
        self._journal_root = root_journal.path / "private-profile-selections"

    @classmethod
    def from_root_setup(cls, selected_installation_binding: RootSelectedInstallationBinding,
                        root_principal_selection_registry: Any,
                        root_journal: RootJournalSelection) -> "RootPrivateProfileSelectionRegistry":
        return cls(selected_installation_binding, root_principal_selection_registry, root_journal)

    def issue(self, *, purpose: str, identity: Any, controller_proof: Any) -> RootPrivateProfileSelection:
        session = self._session
        session._check_live()
        if purpose not in _PRIVATE_PROFILE_PURPOSES:
            raise BootstrapEnrollmentPending("private profile purpose is outside the reviewed finite list")
        current = session.resolve_current_setup_identity()
        principal_selector = session.resolve_adopted_principal_selector()
        namespace_selector = session.resolve_adopted_namespace_selector()
        if (not hasattr(identity, "principal") or not hasattr(identity, "namespace")
                or identity.principal_selection_handle != current.principal_selection_handle
                or identity.namespace_selection_handle != current.namespace_selection_handle
                or identity.principal_binding_sha256 != current.principal_binding_sha256
                or identity.namespace_binding_sha256 != current.namespace_binding_sha256
                or identity.principal.principal_id != current.principal.principal_id
                or identity.namespace.namespace_id != current.namespace.namespace_id
                or current.principal_selection_handle != principal_selector.selection_handle
                or current.namespace_selection_handle != namespace_selector.selection_handle
                or current.principal_binding_sha256 != principal_selector.binding_sha256
                or current.namespace_binding_sha256 != namespace_selector.binding_sha256
                or current.namespace.principal_selection_receipt_id != current.principal.receipt_id
                or current.namespace.target_profile_id != "hermes-agent-native-v1"):
            raise BootstrapEnrollmentPending("private profile requires the actual fresh principal and namespace pair")
        template_rows = self._read_reviewed_sources()
        now = time.monotonic()
        expiry = min(session._factory.session_store.current_deadline(session._handle), now + 1800.0)
        if expiry <= now:
            raise BootstrapEnrollmentPending("private profile selection lease has expired")
        controller_handle = secrets.token_urlsafe(36)
        handle = secrets.token_urlsafe(36)
        observation_id = secrets.token_hex(16)
        core = {
            "selection_handle": handle,
            "choice_observation_id": observation_id,
            "setup_session_id": session._handle.session_id,
            "transaction_handle": session._authorization.transaction_handle,
            "plan_sha256": session._authorization.plan_digest,
            "prepared_generation_id": session._last_receipt.generation_id,
            "prepared_generation_digest": session._last_receipt.generation_digest,
            "principal_selection_handle": principal_selector.selection_handle,
            "namespace_selection_handle": namespace_selector.selection_handle,
            "principal_binding_sha256": principal_selector.binding_sha256,
            "namespace_binding_sha256": namespace_selector.binding_sha256,
            "principal_id": current.principal.principal_id,
            "profile_id": "hermes-agent-native-v1",
            "namespace_id": current.namespace.namespace_id,
            "namespace_policy": "per-selected-principal-native-profile-v1",
            "purpose": purpose,
            "privacy_classification": "private",
            "public_egress_allowed": False,
            "additional_metered_budget_usd": 0.0,
            "source_template_receipt_handles": [row[0] for row in template_rows],
            "reviewed_capability_map_sha256": _CAPABILITY_MAP_TEMPLATE_SHA256,
            "controller_binding_handle": controller_handle,
            "issued_monotonic": now,
            "expires_monotonic": expiry,
            "revocation_epoch": 0,
        }
        selection_sha = hashlib.sha256(_canonical(core)).hexdigest()
        selection = RootPrivateProfileSelection(
            **{**core, "source_template_receipt_handles": tuple(core["source_template_receipt_handles"]),
               "selection_sha256": selection_sha,
               "_session_seal": self._seal})
        _ensure_root_directory(self._journal_root)
        journal = {
            **core, "source_template_receipt_handles": list(selection.source_template_receipt_handles),
            "selection_sha256": selection.selection_sha256,
            "source_templates": [
                {"artifact_id": row[1], "relative_path": row[2], "sha256": row[3], "size_bytes": row[4]}
                for row in template_rows
            ],
        }
        _atomic_root_file(self._journal_root / f"{handle}.json", _canonical(journal), 0o600)
        self._records[handle] = selection
        self._sources[handle] = template_rows
        return selection

    def resolve_current_private_profile(self, selection_handle: str,
                                        purpose: str) -> VerifiedRootPrivateProfileSelection:
        session = self._session
        session._check_live()
        selection = self._records.get(selection_handle)
        if (type(selection) is not RootPrivateProfileSelection
                or selection._session_seal != self._seal
                or selection.purpose != purpose or purpose not in _PRIVATE_PROFILE_PURPOSES
                or selection.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("private profile selection is absent, expired, or has another purpose")
        prepared = session._last_receipt
        if (prepared is None or prepared.state != "prepared" or prepared.enrollment_ids
                or selection.setup_session_id != session._handle.session_id
                or selection.transaction_handle != session._authorization.transaction_handle
                or selection.plan_sha256 != session._authorization.plan_digest
                or selection.prepared_generation_id != prepared.generation_id
                or selection.prepared_generation_digest != prepared.generation_digest):
            raise BootstrapEnrollmentPending("private profile selection no longer matches current prepared custody")
        principal_selector = session.resolve_adopted_principal_selector()
        namespace_selector = session.resolve_adopted_namespace_selector()
        current = session.resolve_current_setup_identity()
        if (principal_selector.selection_handle != selection.principal_selection_handle
                or principal_selector.binding_sha256 != selection.principal_binding_sha256
                or namespace_selector.selection_handle != selection.namespace_selection_handle
                or namespace_selector.binding_sha256 != selection.namespace_binding_sha256
                or current.principal_selection_handle != selection.principal_selection_handle
                or current.namespace_selection_handle != selection.namespace_selection_handle
                or current.principal_binding_sha256 != selection.principal_binding_sha256
                or current.namespace_binding_sha256 != selection.namespace_binding_sha256
                or current.principal.principal_id != selection.principal_id
                or current.namespace.namespace_id != selection.namespace_id
                or current.namespace.principal_selection_receipt_id != current.principal.receipt_id
                or current.namespace.target_profile_id != selection.profile_id):
            raise BootstrapEnrollmentPending("private profile no longer matches current identity and namespace")
        self._verify_sources(selection, self._sources[selection_handle])
        from ..root_setup import _verify_root_tty_proof
        proof = session._private_profile_proofs.get(selection_handle)
        if proof is None:
            raise BootstrapEnrollmentPending("private profile selection lost its root TTY proof")
        _verify_root_tty_proof(proof)
        journal_path = self._journal_root / f"{selection_handle}.json"
        if _read_secure_root_bytes(journal_path, 64 * 1024, 0o600) != _canonical(self._journal_document(selection, self._sources[selection_handle])):
            raise BootstrapEnrollmentPending("private profile journal record changed")
        now = time.monotonic()
        expiry = min(now + 30.0, selection.expires_monotonic,
                     session._factory.session_store.current_deadline(session._handle),
                     current.expires_monotonic)
        if expiry <= now:
            raise BootstrapEnrollmentPending("private profile evidence lease expired")
        return VerifiedRootPrivateProfileSelection(
            secrets.token_urlsafe(36), selection_handle, purpose,
            selection.principal_selection_handle, selection.namespace_selection_handle,
            current.principal.receipt_id, current.namespace.receipt_handle,
            selection.principal_id, selection.profile_id, selection.namespace_id,
            selection.namespace_policy, selection.privacy_classification,
            selection.public_egress_allowed, selection.additional_metered_budget_usd,
            selection.selection_sha256, now, expiry, selection)

    def resolve_current(self, selection_handle: str, *, purpose: str
                        ) -> VerifiedRootPrivateProfileSelection:
        """Typed registry API used by root-owned filesystem/model selectors."""
        if self._session is not self._binding._session:
            raise BootstrapEnrollmentPending("private profile registry lost its setup binding")
        return self.resolve_current_private_profile(selection_handle, purpose)

    def _read_reviewed_sources(self) -> tuple[tuple[str, str, str, str, int], ...]:
        session = self._session
        release, actor = session._factory._release, session._factory._actor
        actor.verify_current(release)
        rows = []
        for artifact_id, relative_path, expected_sha in (
            (_TEMPLATE_ID, "templates/bootstrap-compiler-template-v1.json", None),
            (_CAPABILITY_MAP_TEMPLATE_ID, _CAPABILITY_MAP_TEMPLATE_PATH,
             _CAPABILITY_MAP_TEMPLATE_SHA256),
        ):
            matches = [item for item in release.files if item.artifact_id == artifact_id]
            if (len(matches) != 1 or matches[0].relative_path != relative_path
                    or "template" not in matches[0].roles
                    or expected_sha is not None and matches[0].sha256 != expected_sha):
                raise BootstrapEnrollmentPending("installed release lacks an exact private profile source template")
            descriptor = matches[0]
            fd = release.open_file(artifact_id)
            try:
                raw = bytearray()
                while len(raw) <= descriptor.size_bytes:
                    block = os.read(fd, min(65536, descriptor.size_bytes + 1 - len(raw)))
                    if not block:
                        break
                    raw.extend(block)
            finally:
                os.close(fd)
            if len(raw) != descriptor.size_bytes or hashlib.sha256(raw).hexdigest() != descriptor.sha256:
                raise BootstrapEnrollmentPending("private profile source template bytes changed")
            document = InstalledBootstrapPolicyResolver._json(bytes(raw), "private profile source template")
            if artifact_id == _TEMPLATE_ID and (
                    not isinstance(document, dict) or document.get("id") != _TEMPLATE_ID
                    or document.get("identity", {}).get("service_profile_id") != "hermes-agent-native-v1"):
                raise BootstrapEnrollmentPending("installed v30 service profile template differs")
            if artifact_id == _CAPABILITY_MAP_TEMPLATE_ID:
                if (not isinstance(document, dict) or document.get("id") != _CAPABILITY_MAP_TEMPLATE_ID
                        or document.get("namespace_policy") != "per-selected-principal-native-profile-v1"
                        or document.get("profile_id") != "hermes-agent-native-v1"):
                    raise BootstrapEnrollmentPending("installed v91 private namespace template differs")
            rows.append((secrets.token_urlsafe(32), artifact_id, relative_path,
                         descriptor.sha256, descriptor.size_bytes))
        mapped = session._factory._initial_compilation_registry.resolve_adopted_reviewed_capability_map(
            session._handle)
        if (not isinstance(mapped, VerifiedReviewedNativeCapabilityMap)
                or mapped.sha256 != _CAPABILITY_MAP_TEMPLATE_SHA256
                or mapped._session_handle != session._handle.session_id
                or mapped._registry_seal != session._factory._initial_compilation_registry._seal):
            raise BootstrapEnrollmentPending("current setup reviewed capability map receipt differs")
        actor.verify_current(release)
        return tuple(rows)

    def _verify_sources(self, selection: RootPrivateProfileSelection,
                        sources: tuple[tuple[str, str, str, str, int], ...]) -> None:
        current = self._read_reviewed_sources()
        by_id = {row[1]: row for row in current}
        for handle, artifact_id, relative_path, sha256, size_bytes in sources:
            row = by_id.get(artifact_id)
            if (row is None or row[2:] != (relative_path, sha256, size_bytes)
                    or handle not in selection.source_template_receipt_handles):
                raise BootstrapEnrollmentPending("private profile source template receipt changed")
        if (selection.reviewed_capability_map_sha256 != _CAPABILITY_MAP_TEMPLATE_SHA256
                or len(sources) != 2):
            raise BootstrapEnrollmentPending("private profile source closure is incomplete")

    @staticmethod
    def _journal_document(selection: RootPrivateProfileSelection,
                          sources: tuple[tuple[str, str, str, str, int], ...]) -> dict[str, Any]:
        core = {
            "selection_handle": selection.selection_handle,
            "choice_observation_id": selection.choice_observation_id,
            "setup_session_id": selection.setup_session_id,
            "transaction_handle": selection.transaction_handle,
            "plan_sha256": selection.plan_sha256,
            "prepared_generation_id": selection.prepared_generation_id,
            "prepared_generation_digest": selection.prepared_generation_digest,
            "principal_selection_handle": selection.principal_selection_handle,
            "namespace_selection_handle": selection.namespace_selection_handle,
            "principal_binding_sha256": selection.principal_binding_sha256,
            "namespace_binding_sha256": selection.namespace_binding_sha256,
            "principal_id": selection.principal_id,
            "profile_id": selection.profile_id,
            "namespace_id": selection.namespace_id,
            "namespace_policy": selection.namespace_policy,
            "purpose": selection.purpose,
            "privacy_classification": selection.privacy_classification,
            "public_egress_allowed": selection.public_egress_allowed,
            "additional_metered_budget_usd": selection.additional_metered_budget_usd,
            "source_template_receipt_handles": list(selection.source_template_receipt_handles),
            "reviewed_capability_map_sha256": selection.reviewed_capability_map_sha256,
            "controller_binding_handle": selection.controller_binding_handle,
            "issued_monotonic": selection.issued_monotonic,
            "expires_monotonic": selection.expires_monotonic,
            "revocation_epoch": selection.revocation_epoch,
        }
        return {**core, "selection_sha256": selection.selection_sha256,
                "source_templates": [
                    {"artifact_id": row[1], "relative_path": row[2],
                     "sha256": row[3], "size_bytes": row[4]} for row in sources]}


# Public root setup composition surface. setup_principal uses local imports of
# this module for the typed stage-zero context, so the re-export is deliberately
# placed after the factory/session definitions to avoid an import cycle.
from .setup_principal import (  # noqa: E402
    AuthentikIdentityReceipt,
    RootCurrentSetupIdentitySnapshot,
    RootSetupNamespaceSelector,
    RootSetupPrincipalSelector,
    RootSetupAuthentikIdentityObserver,
    RootSetupIdentityIntake,
    RootSetupPrincipalSelectionRegistry,
    VerifiedRootSetupPrincipalSelection,
)
from .initial_policy_compiler import RootFirstStagePolicyCompiler  # noqa: E402
from .active_policy_compiler import RootActivePolicyCompilationRegistry  # noqa: E402
from .setup_capabilities import ReviewedNativeCapabilitySelection  # noqa: E402
from .setup_policy_publication import RootSetupPolicyGenerationPublisher  # noqa: E402
from .filesystem_selection import (  # noqa: E402
    RootHeldFilesystemDirectory,
    RootOwnedFilesystemSelection,
    RootOwnedFilesystemSelectionRegistry,
)

__all__ = [
    "CompiledRootSetupPublication", "RootActivePolicyCompilationRegistry",
    "RootBootstrapRuntimeFactory", "RootBootstrapSession",
    "RootInitialCompilationRegistry", "RootInitialCompilationSession",
    "RootInitialPublicationHandoff", "RootInitialSetupAggregate",
    "RootNativeAssemblyDefinitions", "RootNativeAssemblyMember", "RootReleaseModuleReceipt",
    "RootPreparedReleaseMemberReceipt", "RootInstalledReleaseMemberReceipt",
    "RootSelectedApplicationQualificationChoice",
    "RootApplicationQualificationConsent",
    "RootApplicationSetupControllerBinding",
    "RootNativeBootstrapAssemblySelection", "RootSelectedInstallationBinding",
    "RootSetupChoices", "RootSetupPolicyGenerationPublisher",
    "RootSetupPrincipalSelectionRegistry", "RootFirstStagePolicyCompiler",
    "RootSetupPrincipalSelector", "RootSetupNamespaceSelector",
    "RootCurrentSetupIdentitySnapshot", "RootExistingModelStoreTemplateReceipt",
    "RootPreparedNativeBundle",
    "RootPrivateProfileSelection", "VerifiedRootPrivateProfileSelection",
    "RootPrivateProfileSelectionRegistry",
    "RootSelectedMemoryServiceEnablementChoice",
    "RootOwnedFilesystemSelection", "RootHeldFilesystemDirectory",
    "RootOwnedFilesystemSelectionRegistry",
    "ReviewedNativeCapabilitySelection", "VerifiedReviewedNativeCapabilityMap",
]
