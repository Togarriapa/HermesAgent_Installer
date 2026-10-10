"""Root-owned, preactive native component target observations (HI-T137.2).

This module records only selected target facts backed by live setup selections
and source-specific root receipts. A fixed source map is used to report precise
configuration gaps; it never grants an account, target, network permission, or
runtime effect by itself.
"""
from __future__ import annotations

import secrets
import time
import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_TARGET_SEAL = object()
_PUBLIC_CANDIDATE_SEAL = object()
_TARGET_TTL_SECONDS = 300.0
_WEB_REGISTRATION_SOURCE_PATH = "hermes_installer/components/plugin_local_voice_web.py"
_WEB_REGISTRATION_SOURCE_SHA256 = "f46733a6e59788c94360187bb4d24369c5f3298984b6a351b190b1dca4feea84"
_WEB_TARGET_CONTRACT_PATH = "src/hermes_installer/components/plugin_public_https.py"
_WEB_TARGET_CONTRACT_SHA256 = "63e4a128f0a48f0bfcbd3c0f6c7313d94f4a3e79f83c2655dde32a339b91ff0d"
_OWNER_OVERLAY_VIEW_SCHEMA = {
    "schema": 1,
    "parent": "selected-private-service-data-root",
    "directory_mode": 0o700,
    "root_owned": True,
    "resource_profile_receipt": True,
}
_OWNER_OVERLAY_VIEW_SCHEMA_SHA256 = hashlib.sha256(json.dumps(
    _OWNER_OVERLAY_VIEW_SCHEMA, sort_keys=True, separators=(",", ":"),
).encode("ascii")).hexdigest()


class NativeComponentTargetDenied(PermissionError):
    """A component target request was malformed, stale, or not selected."""


class NativeComponentTargetPending(PermissionError):
    """A selected component lacks one or more source-specific target proofs."""

    def __init__(self, component_id: str, missing_prerequisite_ids: tuple[str, ...]):
        missing = tuple(missing_prerequisite_ids)
        if (not isinstance(component_id, str) or not component_id
                or not missing or any(not isinstance(value, str) or not value for value in missing)):
            raise ValueError("pending component target requires exact prerequisite identifiers")
        self.component_id = component_id
        self.missing_prerequisite_ids = missing
        super().__init__(f"native component {component_id} is pending target evidence")


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeTargetSelection:
    """Root-issued, current target/source/account/permission observation."""

    selection_handle: str
    native_policy_selection_handle: str
    component_id: str
    adapter_id: str
    target_contract_artifact_id: str
    target_contract_sha256: str
    target_contract_source_receipt_handle: str
    configuration_schema_id: str
    configuration_schema_sha256: str
    configuration_observation_handle: str
    principal_selection_handle: str
    namespace_selection_handle: str
    profile_id: str
    profile_generation: str
    target_id: str
    recipient: str | None
    credential_reference_ids: tuple[str, ...]
    account_observation_handle: str | None
    owned_target_observation_handle: str | None
    permission_observation_handle: str | None
    backend_generation: str
    configuration_sha256: str
    # Present only when the root TTY target-config producer retained the exact
    # v142 scope payload. Hashes of arbitrary/config files are not substitutes.
    scope_payload: bytes | None
    scope_payload_sha256: str | None
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _TARGET_SEAL:
            raise TypeError("native target selections are issued by the root target registry")
        if (self.scope_payload is None) != (self.scope_payload_sha256 is None):
            raise TypeError("public web scope payload and digest must be retained together")
        if self.scope_payload is not None:
            _validate_scope_payload(self, self.scope_payload, self.scope_payload_sha256)


@dataclass(frozen=True, slots=True)
class NativeComponentTargetSourceContract:
    """Finite source contract used to report a selected component's gaps.

    These rows are descriptive only. They contain no target IDs, recipient,
    credentials, permission, account, ownership, or target receipt.
    """

    component_id: str
    adapter_id: str
    source_module_path: str
    prerequisite_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RootNativeTargetSourceObservation:
    """Current source-derived constants from held release module receipts.

    This proves only the finite handler/source contract. It is never a target
    selection or permission receipt.
    """

    adapter_id: str
    source_module_path: str
    source_artifact_id: str
    source_sha256: str
    source_receipt_handle: str
    fixed_targets: tuple[tuple[str, str, str], ...]
    contract_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class RootNativePublicWebTargetCandidate:
    """Source-backed preconfiguration candidate; carries no scope or permission."""

    candidate_handle: str
    native_policy_selection_handle: str
    component_id: str
    enrollment_id: str
    target_id: str
    profile_id: str
    profile_generation: str
    recipient: str
    principal_selection_handle: str
    namespace_selection_handle: str
    target_contract_artifact_id: str
    target_contract_sha256: str
    target_contract_source_receipt_handle: str
    registration_source_artifact_id: str
    registration_source_sha256: str
    registration_source_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        strings = (
            self.candidate_handle, self.native_policy_selection_handle, self.component_id,
            self.enrollment_id, self.target_id, self.profile_id, self.profile_generation,
            self.recipient, self.principal_selection_handle, self.namespace_selection_handle,
            self.target_contract_artifact_id, self.target_contract_source_receipt_handle,
            self.registration_source_artifact_id, self.registration_source_receipt_handle,
        )
        hashes = (self.target_contract_sha256, self.registration_source_sha256)
        if (self._seal is not _PUBLIC_CANDIDATE_SEAL or any(not isinstance(item, str) or not item for item in strings)
                or any(not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item) for item in hashes)
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or self.expires_monotonic <= self.issued_monotonic):
            raise TypeError("public web candidates are issued by the root target registry")

    @property
    def backend_generation(self) -> str:
        return self.profile_generation

    def __repr__(self) -> str:
        return "RootNativePublicWebTargetCandidate(<root-private>)"


# Deliberately limited to the three source families with concrete bounded
# implementations reviewed in this checkout. Other source components receive
# a precise pending result from their own future adapters; no cartesian target
# or effect table is synthesized here.
_SOURCE_CONTRACTS = {
    "agent37-discovery": NativeComponentTargetSourceContract(
        "agent37-discovery", "agent37-discovery",
        "src/hermes_installer/components/native_plugins.py",
        ("root-target-source-receipt:native_plugins", "selected-public-registry-scope",
         "public-registry-egress-permission"),
    ),
    "mcp-registry": NativeComponentTargetSourceContract(
        "mcp-registry", "mcp-registry",
        "src/hermes_installer/components/native_plugins.py",
        ("root-target-source-receipt:native_plugins", "selected-public-registry-scope",
         "public-registry-egress-permission"),
    ),
    "resource-overlay-store": NativeComponentTargetSourceContract(
        "resource-overlay-store", "resource-overlay-store",
        "src/hermes_installer/components/native_plugins.py",
        ("root-target-source-receipt:native_plugins", "current-native-profile-generation",
         "root-owned-overlay-view-receipt"),
    ),
}


class RootNativeComponentTargetRegistry:
    """Bind root TTY policy selections to finite component target adapters.

    The registry intentionally returns pending for components whose required
    root source/target/account/permission receipt producer has not been wired.
    It never treats fixed source constants or a selected component name as a
    successful target observation.
    """

    def __init__(self, selected_installation_binding: Any,
                 root_principal_selection_registry: Any, root_journal: Path,
                 ) -> None:
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or root_principal_selection_registry is None
                or not callable(getattr(selected_installation_binding, "resolve_current_setup_choice", None))):
            raise ValueError("native target registry requires root installation, signed setup-choice and principal services")
        self._binding = selected_installation_binding
        self._principal_registry = root_principal_selection_registry
        self._journal = root_journal
        self._seal = secrets.token_bytes(32)
        self._policy_selections: dict[str, Any] = {}
        self._targets: dict[str, RootPreparedNativeTargetSelection] = {}
        self._target_by_policy_component: dict[tuple[str, str], str] = {}
        self._source_observations: dict[tuple[str, str], RootNativeTargetSourceObservation] = {}
        self._public_candidates: dict[str, RootNativePublicWebTargetCandidate] = {}
        self._configured_candidates: dict[str, tuple[RootNativePublicWebTargetCandidate, Any, RootPreparedNativeTargetSelection]] = {}
        self._candidate_by_policy: dict[str, tuple[str, ...]] = {}
        self._candidate_evidence: dict[str, tuple[Any, Any]] = {}
        self._owner_overlay_targets: dict[str, tuple[Any, RootPreparedNativeTargetSelection, Any]] = {}
        self._owner_overlay_target_by_policy: dict[str, str] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_principal_selection_registry: Any,
                        root_journal: Path
                        ) -> "RootNativeComponentTargetRegistry":
        return cls(selected_installation_binding, root_principal_selection_registry,
                   root_journal)

    def bind_policy_selection(self, selection: Any) -> None:
        """Retain the actual policy-registry selection before resolving targets."""
        from .native_policy_preparation import (
            RootNativePolicyPreparationSelection, _SELECTION_SEAL,
        )
        if (type(selection) is not RootNativePolicyPreparationSelection
                or selection._seal is not _SELECTION_SEAL
                or not selection.selection_handle
                or selection.expires_monotonic <= time.monotonic()):
            raise NativeComponentTargetDenied("target binding requires a live root policy selection")
        self._assert_binding_matches_selection(selection)
        prior = self._policy_selections.get(selection.selection_handle)
        if prior is not None and prior is not selection:
            prior_handles = tuple(
                handle for (policy_handle, _component), handle in self._target_by_policy_component.items()
                if policy_handle == selection.selection_handle
            )
            unchanged = all(
                getattr(prior, name) == getattr(selection, name)
                for name in (
                    "choice_observation_id", "setup_session_id", "transaction_handle", "plan_sha256",
                    "prepared_generation_id", "prepared_generation_digest", "principal_selection_handle",
                    "namespace_selection_handle", "principal_binding_sha256", "namespace_binding_sha256",
                    "service_profile_id", "service_generation", "resource_profile_selection_handle",
                    "package_id", "native_package_generation", "selected_component_ids",
                    "selected_registration_ids", "selected_action_binding_ids",
                    "private_input_consent_selection_handle", "controller_binding_handle",
                    "revocation_epoch",
                )
            )
            if (not unchanged or prior.target_selection_handles
                    or tuple(selection.target_selection_handles) != prior_handles):
                raise NativeComponentTargetDenied("policy selection handle was rebound outside target resolution")
        self._policy_selections[selection.selection_handle] = selection

    def source_contract(self, component_id: str) -> NativeComponentTargetSourceContract:
        """Return a finite descriptive contract, never an executable target."""
        row = _SOURCE_CONTRACTS.get(component_id)
        if row is None:
            raise NativeComponentTargetPending(component_id, ("component-specific-target-adapter",))
        return row

    def observe_source_contract(self, component_id: str) -> RootNativeTargetSourceObservation:
        """Re-read exact imported module bytes through root-held release receipts."""
        contract = self.source_contract(component_id)
        expected_paths = {contract.source_module_path}
        if component_id in {"agent37-discovery", "mcp-registry"}:
            expected_paths.add("src/hermes_installer/components/public_registries.py")
        resolver = getattr(self._binding, "resolve_prepared_native_target_module_receipts", None)
        if not callable(resolver):
            raise NativeComponentTargetPending(
                component_id,
                ("root-held-target-source-module-receipts",),
            )
        try:
            from .bootstrap_runtime_factory import RootReleaseModuleReceipt
            receipts = resolver()
            if not isinstance(receipts, tuple):
                raise ValueError
            by_path: dict[str, Any] = {}
            for receipt in receipts:
                if (type(receipt) is not RootReleaseModuleReceipt
                        or receipt.relative_path not in expected_paths
                        or receipt.relative_path in by_path):
                    raise ValueError
                raw = receipt.read_current()
                if (not isinstance(raw, bytes) or len(raw) != receipt.size_bytes
                        or hashlib.sha256(raw).hexdigest() != receipt.sha256):
                    raise ValueError
                by_path[receipt.relative_path] = (receipt, raw)
            if set(by_path) != expected_paths:
                raise ValueError
            plugin_receipt, plugin_bytes = by_path[contract.source_module_path]
            self._verify_plugin_target_source(component_id, plugin_bytes)
            targets: tuple[tuple[str, str, str], ...] = ()
            evidence = [(plugin_receipt.artifact_id, plugin_receipt.sha256,
                        plugin_receipt.source_receipt_handle)]
            if component_id in {"agent37-discovery", "mcp-registry"}:
                public_receipt, public_bytes = by_path[
                    "src/hermes_installer/components/public_registries.py"]
                targets = self._verify_public_registry_target_source(component_id, public_bytes)
                evidence.append((public_receipt.artifact_id, public_receipt.sha256,
                                 public_receipt.source_receipt_handle))
            contract_digest = hashlib.sha256(_canonical_target_source({
                "component_id": component_id, "targets": targets, "evidence": evidence,
            })).hexdigest()
            observation = RootNativeTargetSourceObservation(
                component_id, contract.source_module_path, plugin_receipt.artifact_id,
                plugin_receipt.sha256, plugin_receipt.source_receipt_handle,
                targets, contract_digest,
            )
            self._source_observations[(component_id, plugin_receipt.source_receipt_handle)] = observation
            return observation
        except NativeComponentTargetPending:
            raise
        except Exception:
            raise NativeComponentTargetPending(
                component_id,
                ("current-root-target-source-observation",),
            ) from None

    @staticmethod
    def _verify_plugin_target_source(component_id: str, source: bytes) -> None:
        try:
            module = ast.parse(source)
            classes = {node.name: node for node in module.body if isinstance(node, ast.ClassDef)}
            if component_id == "resource-overlay-store":
                node = classes["ResourceOverlayStoreImplementation"]
                literals = {item.value for item in ast.walk(node)
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                if ("register" not in {item.name for item in node.body if isinstance(item, ast.FunctionDef)}
                        or not {"local_overlay_store", "resource_overlay_", "read", "write", "history",
                                "delete", "expected_revision"} <= literals):
                    raise ValueError
            elif component_id == "mcp-registry":
                node = classes["MCPRegistryImplementation"]
                literals = {item.value for item in ast.walk(node)
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                if ("register" not in {item.name for item in node.body if isinstance(item, ast.FunctionDef)}
                        or not {"registry:modelcontextprotocol", "mcp_registry_discover",
                                "mcp_registry_inspect", "discover-servers",
                                "inspect-server-metadata"} <= literals):
                    raise ValueError
            elif component_id == "agent37-discovery":
                node = classes["Agent37DiscoveryImplementation"]
                literals = {item.value for item in ast.walk(node)
                            if isinstance(item, ast.Constant) and isinstance(item.value, str)}
                if ("register" not in {item.name for item in node.body if isinstance(item, ast.FunctionDef)}
                        or not {"registry:agent37", "agent37_discover_skills",
                                "agent37_inspect_skill", "discover-skill-candidates",
                                "inspect-public-metadata"} <= literals):
                    raise ValueError
        except Exception:
            raise NativeComponentTargetPending(
                component_id, ("reviewed-source-target-handler-contract",),
            ) from None

    @staticmethod
    def _verify_public_registry_target_source(
            component_id: str, source: bytes
    ) -> tuple[tuple[str, str, str], ...]:
        try:
            module = ast.parse(source)
            assigned: dict[str, Any] = {}
            for node in module.body:
                if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                    name = node.targets[0].id
                    if name in {"_CAPABILITIES", "_RECIPIENTS"}:
                        assigned[name] = ast.literal_eval(node.value)
            if set(assigned) != {"_CAPABILITIES", "_RECIPIENTS"}:
                raise ValueError
            expected = {
                "mcp-registry": ("registry:modelcontextprotocol", "registry-read",
                                 "https://registry.modelcontextprotocol.io"),
                "agent37-discovery": ("registry:agent37", "registry-agent37-read",
                                      "https://www.agent37.com"),
            }[component_id]
            target, capability, recipient = expected
            if assigned["_CAPABILITIES"].get(target) != capability or assigned["_RECIPIENTS"].get(target) != recipient:
                raise ValueError
            # Reject broadened or omitted target catalogs: these modules
            # currently declare exactly the two reviewed finite registry
            # services, each with one matching recipient and capability.
            expected_targets = {"registry:modelcontextprotocol", "registry:agent37"}
            if (set(assigned["_CAPABILITIES"]) != expected_targets
                    or set(assigned["_RECIPIENTS"]) != expected_targets):
                raise ValueError
            return ((target, capability, recipient),)
        except Exception:
            raise NativeComponentTargetPending(
                component_id, ("reviewed-finite-public-registry-source-contract",),
            ) from None

    def observe_selected_component_target(
            self, native_policy_selection_handle: str, component_id: str
    ) -> RootPreparedNativeTargetSelection:
        selection = self._resolve_policy_selection(native_policy_selection_handle)
        if component_id not in selection.selected_component_ids:
            raise NativeComponentTargetDenied("component is not in the root TTY policy selection")
        contract = self.source_contract(component_id)
        source_observation = self.observe_source_contract(component_id)
        if component_id == "resource-overlay-store":
            return self._observe_selected_owner_overlay_target(
                selection, contract, source_observation)
        # The policy selection is intent, while target configuration, ownership,
        # account eligibility and permission require independent root receipts.
        # Current setup has no public issuer for native_plugins.py target-source
        # membership, an owned overlay view, or finite public-registry egress.
        # Until those exact issuers are composed, return named prerequisites.
        missing = [value for value in contract.prerequisite_ids
                   if value not in {"root-target-source-receipt:native_plugins"}]
        if not source_observation.source_receipt_handle:
            missing.append("current-root-target-source-receipt")
        if component_id in {"agent37-discovery", "mcp-registry"}:
            missing.extend(("current-public-source-policy", "selected-public-read-target"))
        else:
            missing.extend(("selected-profile-overlay-view", "overlay-root-owner-receipt"))
        raise NativeComponentTargetPending(component_id, tuple(dict.fromkeys(missing)))

    def _observe_selected_owner_overlay_target(
            self, selection: Any, contract: NativeComponentTargetSourceContract,
            source_observation: RootNativeTargetSourceObservation,
    ) -> RootPreparedNativeTargetSelection:
        """Turn the actual selected root view into its separate local target.

        The target is the root-owned profile view, not a user directory or a
        guessed path.  The factory is the only view issuer; this registry
        retains a typed target selection tied to the receipt and source bytes.
        """
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        from .local_resource_effects import (
            RootPreparedOwnedProfileOverlayView, _VIEW_SEAL,
        )

        if type(self._binding) is not RootSelectedInstallationBinding:
            raise NativeComponentTargetPending(
                "resource-overlay-store", ("root-owned-overlay-view-issuer",),)
        try:
            selected_ids = tuple(getattr(selection, "selected_owner_overlay_registration_ids", ()))
            expected_registrations = {
                "resource-overlay-store:tool:resource_overlay_read",
                "resource-overlay-store:tool:resource_overlay_write",
                "resource-overlay-store:tool:resource_overlay_history",
                "resource-overlay-store:tool:resource_overlay_delete",
            }
            if (not selected_ids or len(selected_ids) > 4 or len(set(selected_ids)) != len(selected_ids)
                    or not set(selected_ids) <= expected_registrations
                    or selection.resource_profile_selection_handle is None):
                raise ValueError
            factory_receipt = self._binding.prepare_selected_profile_overlay_view(
                selection.selection_handle, selection.resource_profile_selection_handle)
            if (type(factory_receipt) is not RootPreparedOwnedProfileOverlayView
                    or factory_receipt._seal is not _VIEW_SEAL
                    or factory_receipt.native_policy_selection_handle != selection.selection_handle
                    or factory_receipt.resource_profile_receipt_handle
                        != selection.resource_profile_selection_handle
                    or factory_receipt.prepared_generation_id != selection.prepared_generation_id
                    or factory_receipt.service_profile_id != selection.service_profile_id
                    or factory_receipt.service_generation != selection.service_generation
                    or factory_receipt.principal_selection_handle != selection.principal_selection_handle
                    or factory_receipt.namespace_selection_handle != selection.namespace_selection_handle
                    or factory_receipt.target_id == ""):
                raise ValueError
            current = self._binding.resolve_current_profile_overlay_view(
                factory_receipt.profile_view_selection_handle, selection.selection_handle)
            if current is not factory_receipt:
                raise ValueError
            expected_component_target = self._owner_overlay_target_by_policy.get(selection.selection_handle)
            if expected_component_target is not None:
                retained = self._owner_overlay_targets.get(expected_component_target)
                if retained is None:
                    raise ValueError
                old_view, target, old_source = retained
                if old_view is not factory_receipt or old_source != source_observation:
                    raise ValueError
                return self.resolve_current_target(target.selection_handle, selection.selection_handle)

            current_identity = self._binding.resolve_current_setup_identity()
            if (current_identity.principal_selection_handle != selection.principal_selection_handle
                    or current_identity.namespace_selection_handle != selection.namespace_selection_handle
                    or current_identity.principal.principal_id != factory_receipt.principal_id
                    or current_identity.namespace.namespace_id != factory_receipt.namespace_id):
                raise ValueError
            now = time.monotonic()
            target = RootPreparedNativeTargetSelection(
                selection_handle=factory_receipt.target_selection_handle,
                native_policy_selection_handle=selection.selection_handle,
                component_id="resource-overlay-store", adapter_id=contract.adapter_id,
                target_contract_artifact_id=source_observation.source_artifact_id,
                target_contract_sha256=source_observation.contract_sha256,
                target_contract_source_receipt_handle=source_observation.source_receipt_handle,
                configuration_schema_id="root-owned-profile-overlay-view-v1",
                configuration_schema_sha256=_OWNER_OVERLAY_VIEW_SCHEMA_SHA256,
                configuration_observation_handle=factory_receipt.profile_view_selection_handle,
                principal_selection_handle=factory_receipt.principal_selection_handle,
                namespace_selection_handle=factory_receipt.namespace_selection_handle,
                profile_id=factory_receipt.service_profile_id,
                profile_generation=factory_receipt.service_generation,
                target_id=factory_receipt.target_id, recipient=None,
                credential_reference_ids=(), account_observation_handle=None,
                owned_target_observation_handle=factory_receipt.view_selection_handle,
                permission_observation_handle=factory_receipt.target_receipt_handle,
                backend_generation=factory_receipt.service_generation,
                configuration_sha256=_owner_overlay_configuration_digest(factory_receipt),
                scope_payload=None, scope_payload_sha256=None,
                issued_monotonic=now,
                expires_monotonic=min(now + _TARGET_TTL_SECONDS,
                                      selection.expires_monotonic,
                                      factory_receipt.expires_monotonic),
                revocation_epoch=selection.revocation_epoch,
                _seal=_TARGET_SEAL,
            )
            self._targets[target.selection_handle] = target
            self._owner_overlay_targets[factory_receipt.target_selection_handle] = (
                factory_receipt, target, source_observation)
            self._owner_overlay_target_by_policy[selection.selection_handle] = (
                factory_receipt.target_selection_handle)
            self._target_by_policy_component[(selection.selection_handle, "resource-overlay-store")] = (
                target.selection_handle)
            return target
        except NativeComponentTargetPending:
            raise
        except Exception:
            raise NativeComponentTargetPending(
                "resource-overlay-store",
                ("current-selected-root-owned-profile-overlay-view",),
            ) from None

    def resolve_current_owner_overlay_target(
            self, native_policy_selection_handle: str, view: Any,
            operation: str,
    ) -> tuple[RootPreparedNativeTargetSelection, str]:
        """Revalidate one operation rule against the retained typed target."""
        from .local_resource_effects import (
            RootPreparedOwnedProfileOverlayView, _VIEW_SEAL,
        )

        selection = self._resolve_policy_selection(native_policy_selection_handle)
        retained = self._owner_overlay_targets.get(getattr(view, "target_selection_handle", ""))
        if (type(view) is not RootPreparedOwnedProfileOverlayView or view._seal is not _VIEW_SEAL
                or retained is None or retained[0] is not view
                or view.native_policy_selection_handle != selection.selection_handle
                or operation not in {"plugin.resource-overlay-store.read",
                                     "plugin.resource-overlay-store.write"}):
            raise NativeComponentTargetDenied("owner-overlay target is not retained for the current selection")
        target = self.resolve_current_target(retained[1].selection_handle, selection.selection_handle)
        current = self._binding.resolve_current_profile_overlay_view(
            view.profile_view_selection_handle, selection.selection_handle)
        if current is not view or _owner_overlay_configuration_digest(current) != target.configuration_sha256:
            raise NativeComponentTargetDenied("owner-overlay target view changed")
        rules = [row for row in view._effect_rules
                 if row.operation == operation and row.target_id == target.target_id]
        if (len(rules) != 1 or rules[0].expires_monotonic <= time.monotonic()
                or rules[0].principal_id != self._binding.resolve_current_setup_identity().principal.principal_id
                or rules[0].profile_id != selection.service_profile_id
                or rules[0].namespace_id != selection.namespace_id
                or rules[0].generation != selection.service_generation):
            raise NativeComponentTargetPending(
                "resource-overlay-store", ("current-selected-owner-overlay-effect-rule",),)
        return target, rules[0].effect_enrollment_id

    def resolve_current_public_web_target_candidates(
            self, native_policy_selection_handle: str
    ) -> tuple[RootNativePublicWebTargetCandidate, ...]:
        """Resolve source-derived web target candidates before any scope exists."""
        selection = self._resolve_policy_selection(native_policy_selection_handle)
        if ("web" not in selection.selected_component_ids
                or "web:tool:web_retrieve" not in selection.selected_registration_ids):
            return ()
        candidate_handles = self._candidate_by_policy.get(native_policy_selection_handle)
        if candidate_handles is None:
            candidates = self._mint_public_web_candidates(selection)
            candidate_handles = tuple(row.candidate_handle for row in candidates)
            self._candidate_by_policy[native_policy_selection_handle] = candidate_handles
        output = []
        for handle in candidate_handles:
            candidate = self._public_candidates.get(handle)
            evidence = self._candidate_evidence.get(handle)
            if (candidate is None or evidence is None or candidate._seal is not _PUBLIC_CANDIDATE_SEAL
                    or candidate.expires_monotonic <= time.monotonic()
                    or candidate.native_policy_selection_handle != native_policy_selection_handle):
                raise NativeComponentTargetDenied("public web target candidate is stale or not retained")
            registration_receipt, contract_receipt = evidence
            registration_raw = registration_receipt.read_current()
            contract_raw = contract_receipt.read_current()
            if (hashlib.sha256(registration_raw).hexdigest() != candidate.registration_source_sha256
                    or hashlib.sha256(contract_raw).hexdigest() != candidate.target_contract_sha256):
                raise NativeComponentTargetDenied("public web source candidate receipts changed")
            self._verify_public_web_contract_source(contract_raw)
            output.append(candidate)
        return tuple(output)

    def observe_configured_public_web_scope(
            self, native_policy_selection_handle: str, target_candidate_handle: str,
            typed_configuration: Any,
    ) -> RootPreparedNativeTargetSelection:
        """Retain exact TTY-selected scope after candidate/source/policy joins."""
        from .public_web_selection import RootPublicWebScopeConfiguration, _CONFIGURATION_SEAL

        candidates = self.resolve_current_public_web_target_candidates(native_policy_selection_handle)
        candidate = self._public_candidates.get(target_candidate_handle)
        if (type(typed_configuration) is not RootPublicWebScopeConfiguration
                or typed_configuration._issuer_token is not _CONFIGURATION_SEAL
                or candidate is None or candidate not in candidates
                or typed_configuration.native_policy_selection_handle != native_policy_selection_handle
                or typed_configuration.target_candidate_handle != target_candidate_handle
                or typed_configuration.component_id != candidate.component_id
                or typed_configuration.target_id != candidate.target_id
                or typed_configuration.profile_id != candidate.profile_id
                or typed_configuration.profile_generation != candidate.profile_generation
                or typed_configuration.recipient != candidate.recipient):
            raise NativeComponentTargetDenied("public scope configuration does not join the current source candidate")
        _validate_scope_configuration_bytes(typed_configuration.scope_payload,
                                            typed_configuration.scope_payload_sha256,
                                            candidate)
        existing = self._configured_candidates.get(target_candidate_handle)
        if existing is not None:
            old_candidate, old_configuration, old_target = existing
            if (old_candidate is not candidate
                    or old_configuration is not typed_configuration
                    or old_target.scope_payload != typed_configuration.scope_payload):
                raise NativeComponentTargetDenied("public scope candidate was rebound")
            return self.resolve_current_target(old_target.selection_handle, native_policy_selection_handle)

        now = time.monotonic()
        registration_receipt, contract_receipt = self._candidate_evidence[target_candidate_handle]
        raw_source = contract_receipt.read_current()
        self._verify_public_web_contract_source(raw_source)
        observation_handle = secrets.token_urlsafe(36)
        target = RootPreparedNativeTargetSelection(
            selection_handle=secrets.token_urlsafe(36),
            native_policy_selection_handle=native_policy_selection_handle,
            component_id=candidate.component_id,
            adapter_id="web",
            target_contract_artifact_id=contract_receipt.artifact_id,
            target_contract_sha256=contract_receipt.sha256,
            target_contract_source_receipt_handle=contract_receipt.source_receipt_handle,
            configuration_schema_id=contract_receipt.artifact_id,
            configuration_schema_sha256=contract_receipt.sha256,
            configuration_observation_handle=observation_handle,
            principal_selection_handle=candidate.principal_selection_handle,
            namespace_selection_handle=candidate.namespace_selection_handle,
            profile_id=candidate.profile_id,
            profile_generation=candidate.profile_generation,
            target_id=candidate.target_id,
            recipient=candidate.recipient,
            credential_reference_ids=(),
            account_observation_handle=None,
            owned_target_observation_handle=None,
            permission_observation_handle=None,
            backend_generation=candidate.profile_generation,
            configuration_sha256=typed_configuration.tty_configuration_sha256,
            scope_payload=typed_configuration.scope_payload,
            scope_payload_sha256=typed_configuration.scope_payload_sha256,
            issued_monotonic=now,
            expires_monotonic=min(now + _TARGET_TTL_SECONDS, typed_configuration.expires_monotonic),
            revocation_epoch=self._resolve_policy_selection(native_policy_selection_handle).revocation_epoch,
            _seal=_TARGET_SEAL,
        )
        self._targets[target.selection_handle] = target
        self._target_by_policy_component[(native_policy_selection_handle, candidate.component_id)] = target.selection_handle
        self._configured_candidates[target_candidate_handle] = (candidate, typed_configuration, target)
        return target

    def _mint_public_web_candidates(self, selection: Any) -> tuple[RootNativePublicWebTargetCandidate, ...]:
        """Join one actual selected web registration to current held source receipts."""
        try:
            from .bootstrap_runtime_factory import RootReleaseModuleReceipt
            from .native_registration_projection import capture_actual_hermes_registrations

            registrations = [row for row in capture_actual_hermes_registrations()
                             if row.adapter_id == "web" and row.native_tool_name == "web_retrieve"]
            if len(registrations) != 1:
                raise ValueError
            registration = registrations[0]
            if (registration.registration_source_path != _WEB_REGISTRATION_SOURCE_PATH
                    or registration.registration_source_sha256 != _WEB_REGISTRATION_SOURCE_SHA256):
                raise ValueError
            receipt_rows = self._binding.resolve_prepared_release_module_receipts()
            registration_receipts = [row for row in receipt_rows
                                      if type(row) is RootReleaseModuleReceipt
                                      and row.relative_path == "src/" + _WEB_REGISTRATION_SOURCE_PATH
                                      and row.sha256 == _WEB_REGISTRATION_SOURCE_SHA256]
            target_receipts = self._binding.resolve_prepared_native_target_module_receipts()
            contract_receipts = [row for row in target_receipts
                                 if type(row) is RootReleaseModuleReceipt
                                 and row.relative_path == _WEB_TARGET_CONTRACT_PATH
                                 and row.sha256 == _WEB_TARGET_CONTRACT_SHA256]
            if len(registration_receipts) != 1 or len(contract_receipts) != 1:
                raise ValueError
            registration_receipt, contract_receipt = registration_receipts[0], contract_receipts[0]
            registration_raw, contract_raw = registration_receipt.read_current(), contract_receipt.read_current()
            if (hashlib.sha256(registration_raw).hexdigest() != _WEB_REGISTRATION_SOURCE_SHA256
                    or hashlib.sha256(contract_raw).hexdigest() != contract_receipt.sha256):
                raise ValueError
            self._verify_public_web_contract_source(contract_raw)
            now = time.monotonic()
            candidate = RootNativePublicWebTargetCandidate(
                candidate_handle=secrets.token_urlsafe(36),
                native_policy_selection_handle=selection.selection_handle,
                component_id="web",
                enrollment_id="scope-" + secrets.token_hex(16),
                target_id="public-web-" + secrets.token_hex(16),
                profile_id=selection.service_profile_id,
                profile_generation=selection.service_generation,
                recipient="public-web",
                principal_selection_handle=selection.principal_selection_handle,
                namespace_selection_handle=selection.namespace_selection_handle,
                target_contract_artifact_id=contract_receipt.artifact_id,
                target_contract_sha256=contract_receipt.sha256,
                target_contract_source_receipt_handle=contract_receipt.source_receipt_handle,
                registration_source_artifact_id=registration_receipt.artifact_id,
                registration_source_sha256=registration_receipt.sha256,
                registration_source_receipt_handle=registration_receipt.source_receipt_handle,
                issued_monotonic=now,
                expires_monotonic=min(now + _TARGET_TTL_SECONDS, selection.expires_monotonic),
                _seal=_PUBLIC_CANDIDATE_SEAL,
            )
            self._public_candidates[candidate.candidate_handle] = candidate
            self._candidate_evidence[candidate.candidate_handle] = (registration_receipt, contract_receipt)
            return (candidate,)
        except NativeComponentTargetPending:
            raise
        except Exception:
            raise NativeComponentTargetPending(
                "web", ("current-web-registration-and-target-contract-receipts",),
            ) from None

    @staticmethod
    def _verify_public_web_contract_source(source: bytes) -> None:
        try:
            module = ast.parse(source)
            classes = {node.name: node for node in module.body if isinstance(node, ast.ClassDef)}
            target = classes["PublicReadTarget"]
            scope = classes["EnrolledPublicWebScope"]
            target_fields = {node.target.id for node in target.body if isinstance(node, ast.AnnAssign)
                             and isinstance(node.target, ast.Name)}
            scope_fields = {node.target.id for node in scope.body if isinstance(node, ast.AnnAssign)
                            and isinstance(node.target, ast.Name)}
            limits = {item.value for item in ast.walk(scope)
                      if isinstance(item, ast.Constant) and type(item.value) is int}
            if (target_fields != {"hostname", "path_prefixes", "query_keys"}
                    or not {"target_id", "generation", "principal_id", "profile_id", "recipient",
                            "targets", "request_bytes_limit", "response_bytes_limit", "deadline_seconds"} <= scope_fields
                    or not {262144, 2_097_152, 30} <= limits):
                raise ValueError
        except Exception:
            raise NativeComponentTargetPending(
                "web", ("reviewed-public-web-target-contract",),
            ) from None

    def resolve_current_target(self, target_selection_handle: str,
                               native_policy_selection_handle: str
                               ) -> RootPreparedNativeTargetSelection:
        target = self._targets.get(target_selection_handle)
        selection = self._resolve_policy_selection(native_policy_selection_handle)
        if (target is None or target.native_policy_selection_handle != selection.selection_handle
                or target.expires_monotonic <= time.monotonic()
                or target._seal is not _TARGET_SEAL):
            raise NativeComponentTargetDenied("native target selection is absent, stale or belongs to another policy")
        self._assert_binding_matches_selection(selection)
        if target.component_id == "web":
            self._validate_configured_target(target, selection)
        return target

    def resolve_current_target_handle(
            self, target_selection_handle: str
    ) -> RootPreparedNativeTargetSelection:
        """Resolve a target by handle using its retained policy binding.

        Scope consumers hold the target receipt handle, not the policy
        selection handle. Resolve that second handle only from this registry's
        retained target row; never accept caller-supplied target metadata or a
        caller-selected policy handle as proof.
        """
        target = self._targets.get(target_selection_handle)
        if target is None or target._seal is not _TARGET_SEAL:
            raise NativeComponentTargetDenied("native target selection handle is absent or unissued")
        selection = self._policy_selections.get(target.native_policy_selection_handle)
        if selection is None:
            raise NativeComponentTargetDenied("native target has no retained root policy selection")
        return self.resolve_current_target(target_selection_handle, selection.selection_handle)

    def resolve_current_scope_payload(self, target_selection_handle: str) -> bytes:
        """Return exact canonical v142 configuration after revalidating its roots."""
        target = self.resolve_current_target_handle(target_selection_handle)
        if target.scope_payload is None:
            raise NativeComponentTargetPending(
                target.component_id, ("root-tty-public-web-scope-configuration",),
            )
        _validate_scope_payload(target, target.scope_payload, target.scope_payload_sha256)
        return target.scope_payload

    def resolve_current_public_web_scope(
            self, target_selection_handle: str
    ) -> RootPreparedNativeTargetSelection:
        """Return the current retained scope and its exact source/config joins."""
        target = self.resolve_current_target_handle(target_selection_handle)
        if target.component_id != "web" or target.scope_payload is None:
            raise NativeComponentTargetPending(
                getattr(target, "component_id", "web"), ("retained-public-web-scope-configuration",),
            )
        _validate_scope_payload(target, target.scope_payload, target.scope_payload_sha256)
        return target

    def _resolve_policy_selection(self, selection_handle: str) -> Any:
        if not isinstance(selection_handle, str) or not selection_handle:
            raise NativeComponentTargetDenied("native policy selection handle is malformed")
        selection = self._policy_selections.get(selection_handle)
        if selection is None or selection.expires_monotonic <= time.monotonic():
            raise NativeComponentTargetDenied("native policy selection is absent or expired")
        self._assert_binding_matches_selection(selection)
        current_resolver = getattr(self._binding, "resolve_current_native_policy_selection", None)
        if callable(current_resolver):
            try:
                current = current_resolver(selection_handle)
            except Exception:
                raise NativeComponentTargetDenied("current signed native policy selection is unavailable") from None
            if (current is not selection or current.selection_sha256 != selection.selection_sha256
                    or current.choice_payload_sha256 != selection.choice_payload_sha256):
                raise NativeComponentTargetDenied("native policy selection changed after target selection")
        return selection

    def _validate_configured_target(self, target: RootPreparedNativeTargetSelection,
                                    selection: Any) -> None:
        matches = [row for row in self._configured_candidates.values() if row[2] is target]
        if len(matches) != 1:
            raise NativeComponentTargetDenied("web target is not retained from a TTY scope configuration")
        candidate, configuration, _ = matches[0]
        from .public_web_selection import RootPublicWebScopeConfiguration, _CONFIGURATION_SEAL
        if (type(configuration) is not RootPublicWebScopeConfiguration
                or configuration._issuer_token is not _CONFIGURATION_SEAL
                or configuration.expires_monotonic <= time.monotonic()
                or candidate.native_policy_selection_handle != selection.selection_handle
                or configuration.native_policy_selection_handle != selection.selection_handle
                or configuration.scope_payload != target.scope_payload
                or configuration.scope_payload_sha256 != target.scope_payload_sha256
                or configuration.tty_configuration_sha256 != target.configuration_sha256):
            raise NativeComponentTargetDenied("public TTY configuration is stale or detached from its target")
        self.resolve_current_public_web_target_candidates(selection.selection_handle)
        _validate_scope_payload(target, target.scope_payload, target.scope_payload_sha256)

    def _assert_binding_matches_selection(self, selection: Any) -> None:
        try:
            durable_handle = getattr(selection, "setup_choice_selection_handle", None)
            choice_epoch = getattr(selection, "choice_epoch", None)
            choice_digest = getattr(selection, "choice_payload_sha256", None)
            if (not isinstance(durable_handle, str) or not durable_handle
                    or type(choice_epoch) is not int or choice_epoch < 0
                    or not isinstance(choice_digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", choice_digest)):
                raise ValueError
            choice = self._binding.resolve_current_setup_choice(
                durable_handle, "native-policy-preparation",
            )
            if (choice.selection_handle != durable_handle
                    or choice.purpose != "native-policy-preparation"
                    or choice.choice_epoch != choice_epoch
                    or choice.choice_payload_sha256 != choice_digest
                    or choice.revocation_epoch != selection.revocation_epoch
                    or choice.principal_selection_handle != selection.principal_selection_handle
                    or choice.namespace_selection_handle != selection.namespace_selection_handle
                    or choice.prepared_generation != selection.prepared_generation_id):
                raise ValueError
            authorization = self._binding.verify_current_setup_controller()
            current = self._binding.resolve_current_setup_identity()
            principal = current.principal
            namespace = current.namespace
        except Exception:
            raise NativeComponentTargetDenied("signed setup choice, root identity or controller proof is unavailable") from None
        if (selection.setup_session_id != authorization.setup_session_id
                or selection.transaction_handle != authorization.transaction_handle
                or selection.plan_sha256 != authorization.plan_digest
                or selection.principal_selection_handle != current.principal_selection_handle
                or selection.namespace_selection_handle != current.namespace_selection_handle
                or selection.prepared_generation_id != namespace.prepared_generation_id
                or selection.service_profile_id != principal.service_profile_id
                or selection.principal_binding_sha256 != current.principal_binding_sha256
                or selection.namespace_binding_sha256 != current.namespace_binding_sha256
                or selection.service_generation != namespace.prepared_generation_id
                or selection.revocation_epoch < 0):
            raise NativeComponentTargetDenied("native policy selection no longer matches current root setup identity")


__all__ = [
    "NativeComponentTargetDenied", "NativeComponentTargetPending",
    "NativeComponentTargetSourceContract", "RootNativeComponentTargetRegistry",
    "RootNativePublicWebTargetCandidate", "RootNativeTargetSourceObservation",
    "RootPreparedNativeTargetSelection",
]


def _canonical_target_source(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _owner_overlay_configuration_digest(view: Any) -> str:
    """Hash only the retained actual root view/data-root observation fields."""
    from .local_resource_effects import RootPreparedOwnedProfileOverlayView, _VIEW_SEAL

    if type(view) is not RootPreparedOwnedProfileOverlayView or view._seal is not _VIEW_SEAL:
        raise NativeComponentTargetDenied("owner-overlay view is not a root-issued receipt")
    payload = {
        "schema": view.schema,
        "native_policy_selection_handle": view.native_policy_selection_handle,
        "profile_view_selection_handle": view.profile_view_selection_handle,
        "setup_session_id": view.setup_session_id,
        "transaction_handle": view.transaction_handle,
        "prepared_generation_id": view.prepared_generation_id,
        "prepared_generation_digest": view.prepared_generation_digest,
        "service_profile_id": view.service_profile_id,
        "service_generation": view.service_generation,
        "resource_profile_id": view.resource_profile_id,
        "resource_profile_receipt_handle": view.resource_profile_receipt_handle,
        "resources_source_receipt_handle": view.resources_source_receipt_handle,
        "resources_source_artifact_id": view.resources_source_artifact_id,
        "resources_source_sha256": view.resources_source_sha256,
        "principal_selection_handle": view.principal_selection_handle,
        "namespace_selection_handle": view.namespace_selection_handle,
        "principal_id": view.principal_id,
        "namespace_id": view.namespace_id,
        "data_root_selection_handle": view.data_root_selection_handle,
        "data_root_receipt_handle": view.data_root_receipt_handle,
        "data_root_id": view.data_root_id,
        "data_root_device": view.data_root_device,
        "data_root_inode": view.data_root_inode,
        "data_root_owner_uid": view.data_root_owner_uid,
        "data_root_owner_gid": view.data_root_owner_gid,
        "target_id": view.target_id,
        "view_device": view.view_device,
        "view_inode": view.view_inode,
        "view_owner_uid": view.view_owner_uid,
        "view_owner_gid": view.view_owner_gid,
        "view_mode": view.view_mode,
        "ownership_marker_sha256": view.ownership_marker_sha256,
    }
    return hashlib.sha256(_canonical_target_source(payload)).hexdigest()


def _validate_scope_payload(target: RootPreparedNativeTargetSelection,
                            raw: bytes, digest: str | None) -> None:
    """Validate the exact canonical first-ten-field v142 scope payload."""
    if (not isinstance(raw, bytes) or len(raw) > 256 * 1024
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or hashlib.sha256(raw).hexdigest() != digest):
        raise TypeError("public scope payload bytes or digest are invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
        required = {
            "enrollment_id", "target_id", "generation", "principal_id", "profile_id",
            "recipient", "targets", "request_bytes_limit", "response_bytes_limit",
            "deadline_seconds",
        }
        if not isinstance(value, dict) or set(value) != required or _canonical_target_source(value) != raw:
            raise ValueError
        if (value["target_id"] != target.target_id
                or value["profile_id"] != target.profile_id
                or value["generation"] != target.backend_generation
                or value["recipient"] != target.recipient):
            raise ValueError
        if (not isinstance(value["targets"], list) or not 1 <= len(value["targets"]) <= 32
                or type(value["request_bytes_limit"]) is not int
                or not 1 <= value["request_bytes_limit"] <= 262144
                or type(value["response_bytes_limit"]) is not int
                or not 1 <= value["response_bytes_limit"] <= 2097152
                or type(value["deadline_seconds"]) not in (int, float)
                or not 0 < value["deadline_seconds"] <= 30):
            raise ValueError
        from ..protected_enrollment import RootSelectedPublicWebScope
        # Reuse the production parser's exact hostname/path/query validation.
        receipt_fields = {
            "enrollment_id": value["enrollment_id"], "target_id": value["target_id"],
            "generation": value["generation"], "principal_id": value["principal_id"],
            "profile_id": value["profile_id"], "recipient": value["recipient"],
            "targets": value["targets"], "request_bytes_limit": value["request_bytes_limit"],
            "response_bytes_limit": value["response_bytes_limit"],
            "deadline_seconds": value["deadline_seconds"],
            "target_selection_handle": target.selection_handle,
            "configuration_observation_handle": target.configuration_observation_handle,
            "configuration_sha256": target.configuration_sha256,
            "target_contract_artifact_id": target.target_contract_artifact_id,
            "target_contract_sha256": target.target_contract_sha256,
            "target_contract_source_receipt_handle": target.target_contract_source_receipt_handle,
        }
        parsed = RootSelectedPublicWebScope.from_protected_record(
            receipt_fields, service_generation_digest="0" * 64,
        )
        if parsed.scope_payload_sha256 != digest:
            raise ValueError
    except Exception:
        raise TypeError("public scope payload is not a canonical, bounded selected scope") from None


def _validate_scope_configuration_bytes(raw: bytes, digest: str,
                                        candidate: RootNativePublicWebTargetCandidate) -> None:
    if (not isinstance(raw, bytes) or not isinstance(digest, str)
            or hashlib.sha256(raw).hexdigest() != digest):
        raise NativeComponentTargetDenied("public scope configuration digest is invalid")
    try:
        value = json.loads(raw.decode("utf-8"))
        if _canonical_target_source(value) != raw:
            raise ValueError
        if (value.get("target_id") != candidate.target_id
                or value.get("enrollment_id") != candidate.enrollment_id
                or value.get("profile_id") != candidate.profile_id
                or value.get("generation") != candidate.profile_generation
                or value.get("recipient") != candidate.recipient):
            raise ValueError
        # Full schema and dangerous-target checks are performed by the typed
        # TTY constructor; invoke the same production scope parser here too.
        from .public_web_selection import canonical_scope_payload
        canonical, expected = canonical_scope_payload(value)
        if canonical != raw or expected != digest:
            raise ValueError
    except Exception:
        raise NativeComponentTargetDenied("public scope is not the exact canonical candidate configuration") from None
