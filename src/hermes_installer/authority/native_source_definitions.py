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
                 monotonic=time.monotonic, _seal: object | None = None):
        if (installation_binding is None or not callable(worker_receipt_provider)
                or not callable(definition_receipt_provider)
                or not callable(monotonic) or _seal is not _REGISTRY_SEAL):
            raise TypeError("root source definition registry dependencies are invalid")
        self._binding = installation_binding
        self._worker_receipt_provider = worker_receipt_provider
        self._definition_receipt_provider = definition_receipt_provider
        self._capture_profile_receipt_provider = capture_profile_receipt_provider
        self._monotonic = monotonic
        self._token = object()
        self._bundles: dict[str, RootPreparedSourceDefinitionBundle] = {}

    @classmethod
    def from_selected_installation(cls, binding: Any, *, monotonic=time.monotonic):
        from hermes_installer.authority.bootstrap_runtime_factory import RootSelectedInstallationBinding

        worker_provider = getattr(binding, "resolve_prepared_worker_role_module_receipts", None)
        definition_provider = getattr(binding, "resolve_prepared_native_source_definition_module_receipt", None)
        profile_provider = getattr(binding, "resolve_prepared_native_capture_profile_receipts", None)
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
            tuple(role_receipts), tuple(retained_profiles), tuple(available_profiles),
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
        for receipt in ((bundle.definition_source_receipt,) + bundle.role_module_receipts):
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
