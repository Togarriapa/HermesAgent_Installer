"""Root-reviewed projection of native principal capabilities.

This module turns the separately pinned finite capability map and the current
root-enrolled effect policy into a principal selection. Authentik group facts
are accepted only from the typed, freshly observed root identity receipt that
the principal-selection registry passes here.
"""
from __future__ import annotations

import hashlib
import re
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending
from .setup_principal import ReviewedPrincipalCapabilities


MAP_ARTIFACT_ID = "installer-reviewed-native-capability-map-v1"
MAP_SOURCE_PATH = "templates/reviewed-native-capability-map-v1.json"
MAP_SHA256 = "41b00c5d949ae6e460cc28ffc1136d729b15f7d5f61c4618e6fb60b132733565"
MAP_SIZE = 2026
_PROFILE_ID = "hermes-agent-native-v1"
_ORDINARY_CAPABILITIES = frozenset({
    "provider-dispatch", "memory-retrieval", "memory-capture", "memory-extraction",
    "memory-embedding", "memory-export", "memory-backup", "memory-restore", "memory-delete",
})
_ORDINARY_CAPABILITY_ORDER = (
    "provider-dispatch", "memory-retrieval", "memory-capture", "memory-extraction",
    "memory-embedding", "memory-export", "memory-backup", "memory-restore", "memory-delete",
)
_SYSTEM_ROW_SOURCES = (
    "selected_native_adapter_records",       # optional strict-loader extension
    "resource_job_records",
    "native_mcp_tool_binding_records",
    "service_records",                       # selected application runtime rows
)
_SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")


@dataclass(frozen=True, slots=True, repr=False)
class RootReviewedCapabilitySelection(ReviewedPrincipalCapabilities):
    """Opaque root-only capability projection bound to identity and policy."""

    principal_id: str
    identity_receipt_handle: str
    effect_policy_receipt_handle: str
    map_artifact_id: str
    map_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_seal: str = field(repr=False)

    @property
    def profile_id(self) -> str:
        return self.service_profile_id


class ReviewedNativeCapabilitySelection:
    """Concrete HI-T03 selector backed by the held installed-release map.

    Stage zero can select identity and the fixed private namespace, but has no
    active effect policy; its capability tuple is therefore intentionally
    empty. Normal setup intersects the map's finite candidates with the exact
    current authority binding and its enrolled effect rules.
    """

    def __init__(self, initial_compilation_registry: Any, *, monotonic=time.monotonic):
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        if (not isinstance(initial_compilation_registry, RootInitialCompilationRegistry)
                or not callable(monotonic)):
            raise ValueError("capability selection requires the installed root stage-zero registry")
        self.initial_registry = initial_compilation_registry
        self.root_journal = initial_compilation_registry.root_journal
        self._clock = monotonic
        self._seal = secrets.token_hex(32)
        self._issued: dict[tuple[str, str], RootReviewedCapabilitySelection] = {}
        self._policy_digests: dict[tuple[str, str], str] = {}
        self._identity_receipts: dict[tuple[str, str], Any] = {}
        self._map_documents: dict[tuple[str, str], Mapping[str, Any]] = {}

    @classmethod
    def from_initial_compilation(
        cls, initial_compilation_registry: Any, *, monotonic=time.monotonic,
    ) -> "ReviewedNativeCapabilitySelection":
        return cls(initial_compilation_registry, monotonic=monotonic)

    def select_for_identity(self, identity: Any, setup_authorization: Any) -> RootReviewedCapabilitySelection:
        from .bootstrap_runtime_factory import RootInitialCompilationSession
        from .setup_principal import AuthentikIdentityReceipt, _PrincipalSetupContext

        if (not isinstance(identity, AuthentikIdentityReceipt)
                or not isinstance(setup_authorization, _PrincipalSetupContext)
                or type(identity.system_member) is not bool
                or identity.expires_monotonic <= self._clock()
                or identity.setup_session_id != setup_authorization.session_id
                or identity.transaction_handle != setup_authorization.transaction_handle
                or identity.plan_digest != setup_authorization.plan_digest):
            raise BootstrapEnrollmentPending("native capability selection requires current root Authentik identity evidence")
        map_doc = self._resolve_map(setup_authorization)
        namespace_id = _namespace_id(identity, map_doc)
        if setup_authorization.phase == "initial-compilation":
            session = setup_authorization.resolver_handle
            if (not isinstance(session, RootInitialCompilationSession)
                    or session.compilation_session_handle != setup_authorization.session_id):
                raise BootstrapEnrollmentPending("stage-zero capability selection has no live compilation session")
            capabilities: tuple[str, ...] = tuple(map_doc["prepared_capabilities"])
            effect_digest = "prepared-empty"
        elif setup_authorization.phase == "root-setup":
            capabilities, effect_digest = self._project_current_enrollment(
                identity, setup_authorization, map_doc)
        else:
            raise BootstrapEnrollmentPending("native capability selection has an unsupported setup phase")
        issued = self._clock()
        expires = min(issued + 30.0, identity.expires_monotonic,
                      setup_authorization.expires_monotonic)
        if expires <= issued:
            raise BootstrapEnrollmentPending("native capability selection lease expired")
        effect_handle = secrets.token_hex(32)
        selection = RootReviewedCapabilitySelection(
            _PROFILE_ID, namespace_id, capabilities,
            _principal_id(identity.authentik_subject_id), identity.receipt_id,
            effect_handle, MAP_ARTIFACT_ID, MAP_SHA256, issued, expires, self._seal,
        )
        # The opaque effect handle is tied to this selector instance and the
        # exact current policy digest; it cannot be supplied as a capability.
        self._issued[(identity.receipt_id, effect_handle)] = selection
        self._policy_digests[(identity.receipt_id, effect_handle)] = effect_digest
        self._identity_receipts[(identity.receipt_id, effect_handle)] = identity
        self._map_documents[(identity.receipt_id, effect_handle)] = map_doc
        if len(self._issued) > 4096:
            raise BootstrapEnrollmentPending("root native capability selection registry reached its bound")
        return selection

    def resolve_reviewed_capability_selection(
        self, current_identity_receipt_handle: str,
        selected_effect_policy_receipt_handle: str,
    ) -> RootReviewedCapabilitySelection:
        key = (current_identity_receipt_handle, selected_effect_policy_receipt_handle)
        selection = self._issued.get(key)
        identity = self._identity_receipts.get(key)
        if (selection is None or selection._issuer_seal != self._seal
                or selection.expires_monotonic <= self._clock()
                or key not in self._policy_digests
                or identity is None or identity.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("root reviewed capability selection is absent or stale")
        if type(identity.system_member) is not bool:
            raise BootstrapEnrollmentPending("root reviewed capability identity is malformed")
        if getattr(selection, "_issuer_seal", None) != self._seal:
            raise BootstrapEnrollmentPending("root reviewed capability selection seal is invalid")
        if self._policy_digests[key] != "prepared-empty":
            current_capabilities, current_digest = self._project_current_enrollment(
                identity, None, self._map_documents[key])
            if (current_digest != self._policy_digests[key]
                    or current_capabilities != selection.capabilities):
                raise BootstrapEnrollmentPending("current root effect policy changed after capability selection")
        return selection

    def _resolve_map(self, setup_authorization: Any) -> Mapping[str, Any]:
        handle = getattr(setup_authorization, "session_id", None)
        if getattr(setup_authorization, "phase", None) == "root-setup":
            try:
                verified = self.initial_registry.resolve_adopted_reviewed_capability_map(
                    setup_authorization.resolver_handle)
            except Exception:
                raise BootstrapEnrollmentPending(
                    "current setup has no verified stage-zero release handoff for capability policy") from None
        else:
            verified = self.initial_registry.resolve_reviewed_capability_map(handle)
        from .bootstrap_runtime_factory import VerifiedReviewedNativeCapabilityMap
        if (not isinstance(verified, VerifiedReviewedNativeCapabilityMap)
                or verified.artifact_id != MAP_ARTIFACT_ID
                or verified.relative_path != MAP_SOURCE_PATH
                or verified.sha256 != MAP_SHA256 or verified.size_bytes != MAP_SIZE):
            raise BootstrapEnrollmentPending("installed native capability map differs from its selected pin")
        expected_session_handle = (setup_authorization.session_id
                                   if setup_authorization.phase == "root-setup" else handle)
        if (verified._session_handle != expected_session_handle
                or verified._registry_seal != self.initial_registry._seal):
            raise BootstrapEnrollmentPending("installed native capability map is not sealed to this root release session")
        document = verified.document
        if not isinstance(document, Mapping) or _plain(document) != _expected_map_document():
            raise BootstrapEnrollmentPending("installed native capability map has unsupported policy fields")
        return MappingProxyType(dict(document))

    def _project_current_enrollment(self, identity: Any, authorization: Any,
                                    map_doc: Mapping[str, Any]) -> tuple[tuple[str, ...], str]:
        from .enrollment import load_protected_enrollment
        from .types import AuthorityDenied
        try:
            current = load_protected_enrollment()
        except Exception:
            raise BootstrapEnrollmentPending("current root-selected effect policy is unavailable") from None
        principal_id = _principal_id(identity.authentik_subject_id)
        binding = next((row for row in current.bindings_by_uid.values()
                        if row.principal_id == principal_id), None)
        if (binding is None or binding.profile_id != map_doc["profile_id"]
                or binding.namespace_id != _namespace_id(identity, map_doc)):
            raise BootstrapEnrollmentPending("current effect policy has no exact selected principal/profile/namespace join")
        current_identity = current.policy.enrollment.principal_identities.get(principal_id)
        if (current_identity is None or current_identity.subject_id != identity.authentik_subject_id
                or current_identity.username.casefold() != identity.username.casefold()
                or current_identity.email.casefold() != identity.email.casefold()):
            raise BootstrapEnrollmentPending("current effect policy identity no longer matches the live Authentik observation")

        candidate_caps = set(map_doc["ordinary_member_capability_candidates"])
        if identity.system_member:
            for source in _SYSTEM_ROW_SOURCES:
                rows = getattr(current, source, ())
                for row in rows:
                    if isinstance(row, Mapping):
                        capability = row.get("capability")
                        row_profile = (row.get("profile_id") or row.get("service_profile_id")
                                       or row.get("native_profile_id"))
                    else:
                        capability = getattr(row, "capability", None)
                        row_profile = (getattr(row, "profile_id", None)
                                       or getattr(row, "service_profile_id", None))
                    operation = _row_value(row, "operation", "operation_id", "effect_operation")
                    target = _row_value(row, "target", "target_id", "effect_target")
                    if (isinstance(capability, str) and row_profile == binding.profile_id
                            and _SAFE_ID.fullmatch(capability)
                            and isinstance(operation, str) and isinstance(target, str)
                            and (capability, operation, target) in current.rules):
                        candidate_caps.add(capability)
        # Only exact rules that remain selected in the current parsed policy
        # may project a candidate. Rules for unrelated profiles or unknown
        # targets never enter the tuple.
        # The active catalog loader has already joined every profile's fixed
        # operation targets to its service generation. Keep the candidate
        # decision tied to that current root snapshot and the selected
        # principal's binding; do not infer capabilities from group labels.
        rule_caps = {rule.capability for rule in current.rules.values()
                     if rule.capability in binding.capabilities}
        projected = tuple(sorted(candidate_caps & rule_caps & set(binding.capabilities)))
        if not projected:
            raise BootstrapEnrollmentPending("current selected effect policy grants no reviewed native capabilities")
        return projected, current.protected_enrollment_digest


def _principal_id(subject_id: str) -> str:
    if not isinstance(subject_id, str) or not subject_id or len(subject_id) > 512:
        raise BootstrapEnrollmentPending("Authentik subject is invalid for native capability selection")
    return "authentik:" + hashlib.sha256(subject_id.encode("utf-8")).hexdigest()


def _namespace_id(identity: Any, document: Mapping[str, Any]) -> str:
    principal_id = _principal_id(identity.authentik_subject_id)
    profile_id = document["profile_id"]
    digest = hashlib.sha256((principal_id + "\0" + profile_id).encode("utf-8")).hexdigest()[:32]
    return "hermes-native-" + digest


def _expected_map_document() -> dict[str, Any]:
    return {
        "id": MAP_ARTIFACT_ID,
        "namespace_id_recipe": "hermes-native-<first32hex(SHA256(UTF8(principal_id + NUL + profile_id)))>",
        "namespace_policy": "per-selected-principal-native-profile-v1",
        "normal_selection_rule": "Candidates become principal capabilities only when exact current root reviewed selected effect rule matches principal/profile/namespace and actual selected enrolled action/target. No group alone grants an action; grants still require exact operation/payload/source/sensitivity/recipient/consent/account/budget and destructive confirmations. Ordinary memory candidates are owner-private data only, background extraction/embedding still separately consented. No installer/service bootstrap infrastructure capability enters worker principal map.",
        "ordinary_member_capability_candidates": list(_ORDINARY_CAPABILITY_ORDER),
        "prepared_capabilities": [],
        "profile_id": _PROFILE_ID,
        "projection": "Sorted unique finite tuple intersection of candidate set/projected selected row capabilities with current protected effect-rule capabilities. Max1024; reject unknown wildcard/generic HTTP/argv/infrastructure capabilities and unmatched rows. Namespace binds exact verified principal+fixed native profile and per-profile owner data; not system filesystem/network sandbox proof.",
        "schema": 1,
        "system_gate": "Only current root verified Authentik system_group_id membership permits protected host/write action selection. Group label string System or caller membership claim is never proof. Nonmember receives no protected host-write capabilities. User task/explicit selected account permission remains required even for System member.",
        "system_member_additional_capability_sources": [
            "selected-native-adapter-records.capability",
            "selected-resource-execution-records.capability",
            "selected-mcp-binding-records.capability",
            "selected-application-runtime-records.capability",
        ],
    }


def _plain(value: Any) -> Any:
    """Normalize the immutable parsed map without changing its semantics."""
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _row_value(row: Any, *names: str) -> Any:
    if isinstance(row, Mapping):
        return next((row[name] for name in names if isinstance(row.get(name), str)), None)
    return next((getattr(row, name, None) for name in names
                 if isinstance(getattr(row, name, None), str)), None)
