"""Finite source-role declarations for the pinned native invocation boundary.

These declarations describe reviewed call sites; they do not mint active role,
observer, package, or process evidence. A definition becomes usable only after
the selected installed release supplies exact held receipts for the definition
module and both role modules, and the remaining selected schema/action joins
are available.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Any
from types import MappingProxyType


class NativeSourceDefinitionUnavailable(PermissionError):
    """The source-role declaration lacks current held-release evidence."""


_REGISTRY_SEAL = object()


@dataclass(frozen=True, slots=True)
class NativeSourceRoleDeclaration:
    role_id: str
    module_name: str
    closure_member_path: str
    release_member_path: str
    module_sha256: str
    call_sites: tuple[str, ...]
    source_kinds: tuple[str, ...]
    capture_schema_ids: tuple[str, ...]
    source_action_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class NativeCaptureProfileDeclaration:
    """Exact v158 capture contract, separate from a loaded process role.

    ``source_action_ids`` are the fixed action keys only. Tool-result actions
    are deliberately selected later from the protected action/registration
    graph after its result-schema receipt has been verified.
    """

    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    capture_schema_id: str
    source_kind: str
    source_action_ids: tuple[str, ...]
    max_payload_bytes: int
    role_id: str
    call_site: str


_CAPTURE_PROFILES = (
    NativeCaptureProfileDeclaration(
        "installer-native-input-capture-profile-v1",
        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-input-capture-profile-v1.json",
        "bfdf7175ee1df681b60ab4b707ffe9d314d8cc7fdc5a30a56e19d2cb1372c1d0",
        837, "native-authenticated-input-v1", "native-input",
        ("authenticated-input",), 1_048_576,
        "hermes-native-invocations-v1", "read_selected_native_input",
    ),
    NativeCaptureProfileDeclaration(
        "installer-native-tool-result-capture-profile-v1",
        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-tool-result-capture-profile-v1.json",
        "470fcc43b3d268a6594e0d6bdf2c635ba3bf4e6cd0cfe2dfcd57840d7bee105a",
        984, "native-registered-tool-result-v1", "tool-result",
        (), 1_048_576, "hermes-native-invocations-v1",
        "record_native_tool_result",
    ),
    NativeCaptureProfileDeclaration(
        "installer-native-provider-result-capture-profile-v1",
        "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-provider-result-capture-profile-v1.json",
        "a2c6ae9243a7854f114ed492afd395d867f02ed58d50a3f1692fe0ea7efbd8eb",
        993, "native-root-provider-response-v1", "tool-result",
        ("root-provider-response-v1",), 4_194_304,
        "hermes-native-boundary-v1", "register_provider_response",
    ),
    NativeCaptureProfileDeclaration(
        "installer-native-mcp-discovery-capture-profile-v171",
        "plans/amendments/2026-10-10-mcp-discovery-capture-v171/mcp-discovery-capture-v1.json",
        "bf9b3b649bf995d5743a38597415ef003928e1d67dc337ab5c7f3e7ec9643e8a",
        4601, "native-root-mcp-discovery-response-v1", "tool-result",
        ("root-mcp-tools-list-discovery-v1",), 1_048_576,
        "hermes-native-invocations-v1", "dispatch_native_mcp_tool_call",
    ),
)


# These are code facts from the pinned installer hooks. The fixed input and
# provider action keys come from the held capture-profile artifacts below;
# tool-result actions remain selected dynamically from protected rows.
_ROLE_DECLARATIONS = (
    NativeSourceRoleDeclaration(
        role_id="hermes-native-invocations-v1",
        module_name="hermes_installer.native_invocations",
        closure_member_path="hermes_installer/native_invocations.py",
        release_member_path="src/hermes_installer/native_invocations.py",
        module_sha256="78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226",
        call_sites=(
            "read_selected_native_input",
            "prepare_native_provider_request",
            "dispatch_native_mcp_tool_call",
            "record_native_tool_result",
            "finish_selected_native_turn",
        ),
        source_kinds=("native-input", "tool-result"),
        capture_schema_ids=("native-authenticated-input-v1", "native-registered-tool-result-v1",
                            "native-root-mcp-discovery-response-v1"),
        source_action_ids=("authenticated-input", "root-mcp-tools-list-discovery-v1"),
    ),
    NativeSourceRoleDeclaration(
        role_id="hermes-native-boundary-v1",
        module_name="hermes_installer.native_boundary",
        closure_member_path="hermes_installer/native_boundary.py",
        release_member_path="src/hermes_installer/native_boundary.py",
        module_sha256="ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb",
        call_sites=("prepare_provider_request", "capture_provider_response"),
        source_kinds=("tool-result",),
        capture_schema_ids=("native-root-provider-response-v1",),
        source_action_ids=("root-provider-response-v1",),
    ),
)


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedSourceDefinitionBundle:
    selection_handle: str
    selection_sha256: str
    definition_source_receipt: Any = field(repr=False, compare=False)
    role_module_receipts: tuple[Any, ...] = field(repr=False, compare=False)
    capture_profile_receipts: tuple[Any, ...] = field(repr=False, compare=False)
    owner_overlay_capture_schema_receipt: Any = field(repr=False, compare=False)
    capture_profiles: tuple[NativeCaptureProfileDeclaration, ...]
    declarations: tuple[NativeSourceRoleDeclaration, ...]
    missing_prerequisite_ids: tuple[str, ...]
    issued_monotonic: float
    expires_monotonic: float
    _registry_token: object = field(repr=False, compare=False)


class RootNativeSourceDefinitionRegistry:
    """Reads only exact current module receipts from a selected installation.

    ``receipt_resolver`` is a root assembly dependency. It must resolve a
    previously held RootPreparedReleaseMemberReceipt by artifact ID; arbitrary
    paths, bytes, and caller-created receipt-shaped objects are rejected.
    Worker modules are release members, not root-actor imports, so they must
    not be represented by RootReleaseModuleReceipt.
    """

    def __init__(self, installation_binding: Any, worker_receipt_provider: Any,
                 definition_receipt_provider: Any,
                 *, capture_profile_receipt_provider: Any | None = None,
                 owner_overlay_capture_schema_receipt_provider: Any | None = None,
                 monotonic=time.monotonic, _seal: object | None = None):
        if (installation_binding is None or not callable(worker_receipt_provider)
                or not callable(definition_receipt_provider)
                or not callable(monotonic) or _seal is not _REGISTRY_SEAL):
            raise TypeError("root source definition registry dependencies are invalid")
        self._binding = installation_binding
        self._worker_receipt_provider = worker_receipt_provider
        self._definition_receipt_provider = definition_receipt_provider
        self._capture_profile_receipt_provider = capture_profile_receipt_provider
        self._owner_overlay_capture_schema_receipt_provider = owner_overlay_capture_schema_receipt_provider
        self._monotonic = monotonic
        self._token = object()
        self._bundles: dict[str, RootPreparedSourceDefinitionBundle] = {}
        self._selected_roles: dict[tuple[str, str], tuple[Any, ...]] = {}

    @classmethod
    def from_selected_installation(cls, binding: Any, *, monotonic=time.monotonic):
        from hermes_installer.authority.bootstrap_runtime_factory import RootSelectedInstallationBinding

        worker_provider = getattr(binding, "resolve_prepared_worker_role_module_receipts", None)
        definition_provider = getattr(binding, "resolve_prepared_native_source_definition_module_receipt", None)
        profile_provider = getattr(binding, "resolve_prepared_native_capture_profile_receipts", None)
        overlay_schema_provider = getattr(
            binding, "resolve_prepared_owner_overlay_capture_schema_module_receipt", None)
        if (type(binding) is not RootSelectedInstallationBinding
                or not callable(worker_provider) or not callable(definition_provider)):
            raise NativeSourceDefinitionUnavailable(
                "selected installation cannot resolve the fixed native source module set",
            )
        # Calling the exact guarded resolver here proves that this binding is
        # still attached to its live selected setup session.
        worker_provider()
        definition_provider()
        return cls(binding, worker_provider, definition_provider,
                   capture_profile_receipt_provider=profile_provider,
                   owner_overlay_capture_schema_receipt_provider=overlay_schema_provider,
                   monotonic=monotonic, _seal=_REGISTRY_SEAL)

    def prepare_for_policy(self, selection: Any) -> RootPreparedSourceDefinitionBundle:
        from hermes_installer.authority.bootstrap_runtime_factory import (
            RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt,
        )
        selection_handle = getattr(selection, "selection_handle", None)
        selection_digest = getattr(selection, "selection_sha256", None)
        if (not isinstance(selection_handle, str) or not selection_handle
                or not isinstance(selection_digest, str) or len(selection_digest) != 64
                or getattr(selection, "package_id", None) is None):
            raise NativeSourceDefinitionUnavailable("native policy selection is malformed")

        try:
            receipts = self._worker_receipt_provider()
        except Exception:
            receipts = ()
        try:
            definition_receipt = self._definition_receipt_provider()
        except Exception:
            definition_receipt = None
        try:
            profile_receipts = (self._capture_profile_receipt_provider()
                                if callable(self._capture_profile_receipt_provider) else ())
        except Exception:
            profile_receipts = ()
        try:
            overlay_schema_receipt = (
                self._owner_overlay_capture_schema_receipt_provider()
                if callable(self._owner_overlay_capture_schema_receipt_provider) else None)
        except Exception:
            overlay_schema_receipt = None
        if not isinstance(receipts, tuple) or any(
                type(item) is not RootPreparedReleaseMemberReceipt for item in receipts):
            raise NativeSourceDefinitionUnavailable("release resolver returned non-held module evidence")
        if len({item.relative_path for item in receipts}) != len(receipts):
            raise NativeSourceDefinitionUnavailable("release resolver returned duplicate worker module receipts")
        by_path = {item.relative_path: item for item in receipts}
        missing: list[str] = []
        if (type(definition_receipt) is not RootReleaseModuleReceipt
                or definition_receipt.relative_path !=
                   "lib/python/hermes_installer/authority/native_source_definitions.py"):
            missing.append("hermes-installer.native-source-definitions.v1")
        elif not self._check_receipt(
                definition_receipt,
                "lib/python/hermes_installer/authority/native_source_definitions.py"):
            raise NativeSourceDefinitionUnavailable("source definition release-member receipt is stale or mismatched")
        if (type(overlay_schema_receipt) is not RootReleaseModuleReceipt
                or overlay_schema_receipt.artifact_id !=
                   "installer-module:hermes_installer.authority.owner_overlay_capture_schemas"
                or overlay_schema_receipt.relative_path !=
                   "lib/python/hermes_installer/authority/owner_overlay_capture_schemas.py"):
            missing.append("hermes-installer.owner-overlay-capture-schemas.v185")
        else:
            try:
                from .owner_overlay_capture_schemas import (
                    INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID, verify_held_capture_schema,
                )
                verify_held_capture_schema(overlay_schema_receipt, INVOCATION_SCHEMA_ID)
                verify_held_capture_schema(overlay_schema_receipt, RESULT_SCHEMA_ID)
            except Exception:
                missing.append("hermes-installer.owner-overlay-capture-schemas.v185")
        role_receipts = []
        for declaration in _ROLE_DECLARATIONS:
            receipt = by_path.get(declaration.release_member_path)
            if receipt is None:
                missing.append(declaration.module_name)
                continue
            if not self._check_receipt(receipt, declaration.release_member_path,
                                       declaration.module_sha256):
                raise NativeSourceDefinitionUnavailable("native source role release member differs from reviewed bytes")
            role_receipts.append(receipt)
        if not isinstance(profile_receipts, tuple) or any(
                type(row) not in {RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt}
                for row in profile_receipts):
            raise NativeSourceDefinitionUnavailable("capture profile resolver returned invalid held evidence")
        profiles_by_id = {getattr(row, "artifact_id", None): row for row in profile_receipts}
        if len(profiles_by_id) != len(profile_receipts):
            raise NativeSourceDefinitionUnavailable("capture profile resolver returned duplicate receipts")
        retained_profiles: list[Any] = []
        available_profiles: list[NativeCaptureProfileDeclaration] = []
        for profile in _CAPTURE_PROFILES:
            receipt = profiles_by_id.get(profile.artifact_id)
            if receipt is None:
                missing.append(profile.artifact_id)
                continue
            if not self._check_receipt(receipt, profile.relative_path, profile.sha256,
                                       profile.artifact_id, profile.size_bytes):
                raise NativeSourceDefinitionUnavailable("capture profile receipt differs from the pinned v158 bytes")
            raw = receipt.read_current()
            try:
                parsed = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError):
                raise NativeSourceDefinitionUnavailable("capture profile JSON is invalid") from None
            # v171 is an append-only amendment describing a dedicated
            # discovery event, so its reviewed profile lives under `profile`
            # and intentionally has no self-referential artifact_id.
            declaration = (parsed.get("profile") if type(parsed) is dict
                           and profile.artifact_id == "installer-native-mcp-discovery-capture-profile-v171"
                           else parsed)
            if (type(parsed) is not dict or parsed.get("schema") != 1
                    or type(declaration) is not dict
                    or (profile.artifact_id != "installer-native-mcp-discovery-capture-profile-v171"
                        and parsed.get("artifact_id") != profile.artifact_id)
                    or declaration.get("capture_schema_id") != profile.capture_schema_id
                    or declaration.get("source_kind") != profile.source_kind
                    or declaration.get("max_payload_bytes") != profile.max_payload_bytes):
                raise NativeSourceDefinitionUnavailable("capture profile fields differ from the reviewed declaration")
            if profile.source_action_ids and declaration.get("source_action_id") not in profile.source_action_ids:
                raise NativeSourceDefinitionUnavailable("capture profile source action differs from its reviewed declaration")
            retained_profiles.append(receipt)
            available_profiles.append(profile)
        # Dynamic tool-result actions require a selected action result schema
        # receipt and validator, never merely the profile's existence.
        if not any(row.artifact_id == "installer-native-tool-result-capture-profile-v1"
                   for row in available_profiles):
            missing.append("selected-tool-result-profile")
        missing.append("selected-tool-result-schema-action-join")
        now = self._monotonic()
        bundle = RootPreparedSourceDefinitionBundle(
            selection_handle, selection_digest, definition_receipt,
            tuple(role_receipts), tuple(retained_profiles), overlay_schema_receipt,
            tuple(available_profiles),
            _ROLE_DECLARATIONS, tuple(dict.fromkeys(missing)),
            now, min(now + 30.0, getattr(selection, "expires_monotonic", now)), self._token,
        )
        if bundle.expires_monotonic <= now:
            raise NativeSourceDefinitionUnavailable("native source-definition selection expired")
        self._bundles[selection_handle] = bundle
        return bundle

    def resolve_current(self, bundle: RootPreparedSourceDefinitionBundle) -> RootPreparedSourceDefinitionBundle:
        if (type(bundle) is not RootPreparedSourceDefinitionBundle
                or bundle._registry_token is not self._token
                or self._bundles.get(bundle.selection_handle) is not bundle
                or bundle.expires_monotonic <= self._monotonic()):
            raise NativeSourceDefinitionUnavailable("prepared source-definition bundle is stale")
        for receipt in ((bundle.definition_source_receipt,) + bundle.role_module_receipts
                        + (bundle.owner_overlay_capture_schema_receipt,)):
            if receipt is None:
                continue
            receipt.read_current()
        profiles = {row.artifact_id: row for row in bundle.capture_profiles}
        if len(profiles) != len(bundle.capture_profiles) or len(bundle.capture_profile_receipts) != len(profiles):
            raise NativeSourceDefinitionUnavailable("capture profile bundle membership is inconsistent")
        receipts = {row.artifact_id: row for row in bundle.capture_profile_receipts}
        if set(receipts) != set(profiles):
            raise NativeSourceDefinitionUnavailable("capture profile receipt set changed")
        for artifact_id, profile in profiles.items():
            receipt = receipts[artifact_id]
            if not self._check_receipt(receipt, profile.relative_path, profile.sha256,
                                       profile.artifact_id, profile.size_bytes):
                raise NativeSourceDefinitionUnavailable("capture profile receipt is no longer current")
        return bundle

    def resolve_current_owner_overlay_role(self, selection_handle: str,
                                           registration_id: str) -> tuple[Any, ...]:
        """Retain source-only declarations; never assert a loaded process.

        The observer key is a preactivation foreign key whose runtime observer
        still needs the separate publication and loaded-worker proof.
        """
        selection = self._binding.resolve_current_native_policy_selection(selection_handle)
        bundle = self._bundles.get(selection_handle)
        if (bundle is None or bundle.selection_sha256 != selection.selection_sha256
                or registration_id not in selection.selected_owner_overlay_registration_ids):
            raise NativeSourceDefinitionUnavailable("owner-overlay role is not selected")
        self.resolve_current(bundle)
        role = next((row for row in bundle.declarations
                     if row.role_id == "hermes-native-invocations-v1"), None)
        profile = next((row for row in bundle.capture_profiles
                        if row.capture_schema_id == "native-root-provider-response-v1"), None)
        receipts = {row.relative_path: row for row in bundle.role_module_receipts}
        if (role is None or profile is None or role.release_member_path not in receipts
                or bundle.owner_overlay_capture_schema_receipt is None):
            raise NativeSourceDefinitionUnavailable("owner-overlay source role/profile is unavailable")
        receipt = receipts[role.release_member_path]
        key = (selection_handle, registration_id)
        identity = hashlib.sha256(json.dumps({
            "selection": selection.selection_sha256, "registration": registration_id,
            "role": receipt.source_receipt_handle, "profile": profile.sha256,
            "capture_schemas": bundle.owner_overlay_capture_schema_receipt.sha256,
        }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        # Distinct root-selected issuer and enrollment handles bind the
        # provider-response invocation schema to the root-handler result
        # schema.  The selection, held module receipt and selected registration
        # are all in the identity; no runtime observer scan can mint either.
        row = ("native-source-selection:" + identity,
               ("native-source-observer:" + identity + ":package",
                "native-source-observer:" + identity + ":invocation",
                "native-source-observer:" + identity + ":result"), role.role_id,
               "native-source-issuer:" + identity + ":invocation")
        prior = self._selected_roles.get(key)
        if prior is not None and prior != row:
            raise NativeSourceDefinitionUnavailable("owner-overlay source declaration changed")
        self._selected_roles[key] = row
        return row

    def selected_owner_overlay_source_rows(self, selection: Any) -> tuple[Any, ...]:
        """Source-receipted role/issuer rows for only the guarded selected set."""
        bundle = self._bundles.get(selection.selection_handle)
        if bundle is None:
            raise NativeSourceDefinitionUnavailable("selected source declarations are absent")
        self.resolve_current(bundle)
        role = next(row for row in bundle.declarations
                    if row.role_id == "hermes-native-invocations-v1")
        receipt = next(row for row in bundle.role_module_receipts
                       if row.relative_path == role.release_member_path)
        handles, observer_ids, issuer_rows, observer_rows = [], [], [], []
        profile = next(row for row in bundle.capture_profiles
                       if row.capture_schema_id == "native-registered-tool-result-v1")
        for registration_id in sorted(selection.selected_owner_overlay_registration_ids):
            handle, ids, role_id, issuer_id = self.resolve_current_owner_overlay_role(
                selection.selection_handle, registration_id)
            handles.append(handle)
            package_observer_id, invocation_observer_id, result_observer_id = ids
            observer_ids.extend(ids)
            package_identity = hashlib.sha256(json.dumps({
                "selection": bundle.selection_sha256, "registration": registration_id,
                "role": receipt.source_receipt_handle, "profile": profile.sha256,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            package_issuer_id = "native-source-issuer:" + package_identity
            issuer_rows.append(MappingProxyType({
                "issuer_channel_id": package_issuer_id,
                "producer_profile_id": selection.service_profile_id,
                "producer_role_artifact_id": receipt.artifact_id,
                "producer_role_sha256": receipt.sha256,
                "capture_schema_id": profile.capture_schema_id,
                "allowed_parent_channels": (), "generation": selection.service_generation,
                "observer_enrollment_id": package_observer_id,
                "source_action_ids": (registration_id,),
            }))
            observer_rows.append(MappingProxyType({
                "observer_enrollment_id": package_observer_id,
                "source_role_selection_handle": handle,
                "role_id": role_id, "issuer_channel_id": package_issuer_id,
                "source_kind": profile.source_kind,
                "capture_schema_id": profile.capture_schema_id,
                "source_action_ids": (registration_id,),
                "generation": selection.service_generation,
                "source_receipt_handle": receipt.source_receipt_handle,
                "evidence_kind": "preactive-source-declaration",
            }))
        role_rows = ()
        if observer_ids:
            role_rows = (MappingProxyType({
                "role_id": role.role_id, "package_id": selection.package_id,
                "native_package_generation": selection.native_package_generation,
                "profile_id": selection.service_profile_id, "profile_generation": selection.service_generation,
                "role_artifact_id": receipt.artifact_id, "role_sha256": receipt.sha256,
                "role_source_receipt_handle": receipt.source_receipt_handle,
                "module_name": role.module_name, "closure_member_path": role.closure_member_path,
                "role_source_revision": receipt.release_commit,
                "role_source_tree_sha256": receipt.deployment_receipt_sha256,
                "observer_enrollment_ids": tuple(sorted(observer_ids)),
                "registration_ids": tuple(sorted(selection.selected_owner_overlay_registration_ids)),
                "action_binding_ids": (), "workflow_ids": (),
            }),)
        # Owner-overlay source selectors live in the separate signed local
        # owner catalog. Never coerce them into native package SourceIssuer or
        # backend action records, whose schemas/actions are unrelated.
        return role_rows, tuple(issuer_rows), tuple(observer_rows), tuple(handles)

    def selected_owner_overlay_source_records(self, selection: Any) -> tuple[Any, ...]:
        """Return source-selector facts for the signed local-owner catalog.

        These records are deliberately not NativePackage source issuers:
        ``registered-tool-result`` is a typed local effect result discriminator
        and never a generic backend action.
        """
        from .owner_overlay_capture_schemas import INVOCATION_SCHEMA_ID, RESULT_SCHEMA_ID
        bundle = self._bundles.get(selection.selection_handle)
        if bundle is None:
            raise NativeSourceDefinitionUnavailable("selected source declarations are absent")
        self.resolve_current(bundle)
        role = next(row for row in bundle.declarations
                    if row.role_id == "hermes-native-invocations-v1")
        role_receipt = next(row for row in bundle.role_module_receipts
                            if row.relative_path == role.release_member_path)
        schema_receipt = bundle.owner_overlay_capture_schema_receipt
        if schema_receipt is None:
            raise NativeSourceDefinitionUnavailable("held owner-overlay capture schema module is unavailable")
        handler_receipt_provider = getattr(
            self._binding, "resolve_prepared_owner_overlay_result_handler_module_receipt", None)
        if not callable(handler_receipt_provider):
            raise NativeSourceDefinitionUnavailable("held root overlay-result handler source is unavailable")
        handler_id = "installer-module:hermes_installer.authority.local_resource_effects"
        handler_path = "lib/python/hermes_installer/authority/local_resource_effects.py"
        handler_receipt = handler_receipt_provider()
        from hermes_installer.authority.bootstrap_runtime_factory import RootReleaseModuleReceipt
        if (type(handler_receipt) is not RootReleaseModuleReceipt
                or handler_receipt.artifact_id != handler_id
                or handler_receipt.relative_path != handler_path):
            raise NativeSourceDefinitionUnavailable("exact held owner-overlay result handler is unavailable")
        handler_bytes = handler_receipt.read_current()
        if (not handler_bytes or len(handler_bytes) != handler_receipt.size_bytes
                or hashlib.sha256(handler_bytes).hexdigest() != handler_receipt.sha256):
            raise NativeSourceDefinitionUnavailable("held owner-overlay result handler changed")
        records = []
        for registration_id in sorted(selection.selected_owner_overlay_registration_ids):
            handle, ids, role_id, invocation_issuer_id = self.resolve_current_owner_overlay_role(
                selection.selection_handle, registration_id)
            _package_observer_id, invocation_id, result_id = ids
            result_issuer_id = "native-source-issuer:" + hashlib.sha256(json.dumps({
                "selection": bundle.selection_sha256, "registration": registration_id,
                "schema_source": schema_receipt.sha256,
                "handler_source": handler_receipt.source_receipt_handle,
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest() + ":result"
            role_row = MappingProxyType({
                "role_id": role_id, "role_artifact_id": role_receipt.artifact_id,
                "role_sha256": role_receipt.sha256,
                "role_source_receipt_handle": role_receipt.source_receipt_handle,
                "role_module_name": role.module_name,
                "role_closure_member_path": role.closure_member_path,
                "role_source_revision": role_receipt.release_commit,
                "role_source_tree_sha256": role_receipt.deployment_receipt_sha256,
            })
            records.append(MappingProxyType({
                "registration_id": registration_id,
                "package_observer_enrollment_id": _package_observer_id,
                "source_role_selection_handle": handle,
                "invocation": MappingProxyType({
                    "observer_enrollment_id": invocation_id,
                    "issuer_channel_id": invocation_issuer_id,
                    "source_kind": "provider-result",
                    "capture_schema_id": INVOCATION_SCHEMA_ID,
                    "source_action_id": "root-provider-response-v1",
                    "source_registration_ids": (registration_id,),
                    "allowed_parent_channels": (),
                }),
                "result": MappingProxyType({
                    "observer_enrollment_id": result_id,
                    "issuer_channel_id": result_issuer_id,
                    "source_kind": "tool-result",
                    "capture_schema_id": RESULT_SCHEMA_ID,
                    "source_action_id": "registered-tool-result",
                    "source_registration_ids": (registration_id,),
                    "allowed_parent_channels": (invocation_issuer_id,),
                }),
                "role": role_row,
                "handler": MappingProxyType({
                    "artifact_id": handler_id, "sha256": handler_receipt.sha256,
                    "source_receipt_handle": handler_receipt.source_receipt_handle,
                    "module_name": "hermes_installer.authority.local_resource_effects",
                    "closure_member_path": handler_path,
                    "size_bytes": handler_receipt.size_bytes,
                }),
                "capture_schema_source": MappingProxyType({
                    "artifact_id": schema_receipt.artifact_id,
                    "sha256": schema_receipt.sha256,
                    "source_receipt_handle": schema_receipt.source_receipt_handle,
                    "relative_path": schema_receipt.relative_path,
                    "size_bytes": schema_receipt.size_bytes,
                }),
            }))
        return tuple(records)

    @staticmethod
    def _check_receipt(receipt: Any, path: str, expected_digest: str | None = None,
                       expected_artifact_id: str | None = None,
                       expected_size: int | None = None) -> bool:
        raw = receipt.read_current()
        digest = hashlib.sha256(raw).hexdigest()
        return (receipt.relative_path == path and receipt.sha256 == digest
                and receipt.size_bytes == len(raw)
                and (expected_artifact_id is None or receipt.artifact_id == expected_artifact_id)
                and (expected_size is None or len(raw) == expected_size)
                and (expected_digest is None or digest == expected_digest))


__all__ = [
    "NativeSourceDefinitionUnavailable", "NativeSourceRoleDeclaration",
    "NativeCaptureProfileDeclaration",
    "RootPreparedSourceDefinitionBundle", "RootNativeSourceDefinitionRegistry",
]
