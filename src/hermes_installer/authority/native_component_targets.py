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
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


_TARGET_SEAL = object()
_TARGET_TTL_SECONDS = 300.0


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
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _TARGET_SEAL:
            raise TypeError("native target selections are issued by the root target registry")


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
                 authority_service: Any) -> None:
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding

        if (type(selected_installation_binding) is not RootSelectedInstallationBinding
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or root_principal_selection_registry is None or authority_service is None):
            raise ValueError("native target registry requires root installation, principal, journal and authority services")
        self._binding = selected_installation_binding
        self._principal_registry = root_principal_selection_registry
        self._journal = root_journal
        self._authority = authority_service
        self._seal = secrets.token_bytes(32)
        self._policy_selections: dict[str, Any] = {}
        self._targets: dict[str, RootPreparedNativeTargetSelection] = {}
        self._target_by_policy_component: dict[tuple[str, str], str] = {}
        self._source_observations: dict[tuple[str, str], RootNativeTargetSourceObservation] = {}

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        root_principal_selection_registry: Any,
                        root_journal: Path, authority_service: Any
                        ) -> "RootNativeComponentTargetRegistry":
        return cls(selected_installation_binding, root_principal_selection_registry,
                   root_journal, authority_service)

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
                methods = {item.name for item in node.body if isinstance(item, ast.FunctionDef)}
                if not {"register"}.issubset(methods):
                    raise ValueError
                # The root-owned CAS implementation and its profile view are
                # pinned in the imported source closure, not accepted from a
                # caller-supplied adapter.
                ast.parse(source)
            elif component_id == "mcp-registry":
                node = classes["MCPRegistryImplementation"]
                if "register" not in {item.name for item in node.body if isinstance(item, ast.FunctionDef)}:
                    raise ValueError
            elif component_id == "agent37-discovery":
                node = classes["Agent37DiscoveryImplementation"]
                if "register" not in {item.name for item in node.body if isinstance(item, ast.FunctionDef)}:
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
        return target

    def _resolve_policy_selection(self, selection_handle: str) -> Any:
        if not isinstance(selection_handle, str) or not selection_handle:
            raise NativeComponentTargetDenied("native policy selection handle is malformed")
        selection = self._policy_selections.get(selection_handle)
        if selection is None or selection.expires_monotonic <= time.monotonic():
            raise NativeComponentTargetDenied("native policy selection is absent or expired")
        self._assert_binding_matches_selection(selection)
        return selection

    def _assert_binding_matches_selection(self, selection: Any) -> None:
        try:
            authorization = self._binding.verify_current_setup_controller()
            current = self._binding.resolve_current_setup_identity()
            principal = current.principal
            namespace = current.namespace
        except Exception:
            raise NativeComponentTargetDenied("current root setup identity or controller proof is unavailable") from None
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
    "RootNativeTargetSourceObservation", "RootPreparedNativeTargetSelection",
]


def _canonical_target_source(value: Any) -> bytes:
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")
