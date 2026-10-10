"""Root-owned application build selections, kept separate from build outputs.

The input selection is a stable join of an actual setup TTY choice, current
source/lock receipts, and the current setup subject.  The final selection is
issued only when package/toolchain/build/probe inputs are already retained;
it contains no produced environment or active application-runtime receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Mapping


_SEAL = object()
_PROFILES: Mapping[str, tuple[str, str, str, str]] = {
    "graphify": ("qualify-graphify-v1", "python", ">=3.10",
                 "application-graphify-runtime-prepare-v1"),
    "browser-use": ("qualify-browser-use-v1", "python", ">=3.11,<4",
                    "application-browser-use-runtime-prepare-v1"),
    "hyperframes": ("qualify-hyperframes-v1", "node",
                    "Node>=22; actual Bun workspace builder separately pinned",
                    "application-hyperframes-runtime-prepare-v1"),
    "scrapegraph-ai": ("qualify-scrapegraph-v1", "python", ">=3.12,<4",
                       "application-scrapegraph-ai-runtime-prepare-v1"),
}
_TEMPLATE_ID = "installer-prepared-application-build-service-template-v1"
_TEMPLATE_SHA256 = "8cc3bbce52901c5f05bab99622d77d9d4d44f4a5fe27eb636e3fe8e23beab0d9"
_TEMPLATE_SIZE = 1498
_MAX_TTL = 1800.0


class ApplicationRuntimeSelectionDenied(PermissionError):
    """A selected app lacks current, root-retained pre-build inputs."""


def _opaque(value: Any, label: str) -> str:
    if (not isinstance(value, str) or not 32 <= len(value) <= 128
            or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                   for char in value)):
        raise ApplicationRuntimeSelectionDenied(f"{label} handle is malformed")
    return value


def _digest(value: Any, label: str) -> str:
    if (not isinstance(value, str) or len(value) != 64
            or any(char not in "0123456789abcdef" for char in value)):
        raise ApplicationRuntimeSelectionDenied(f"{label} digest is malformed")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationRuntimePreparationInputSelection:
    """Stable preclosure input used by source/toolchain/package producers."""

    schema: int
    selection_handle: str
    qualification_choice_handle: str
    application_id: str
    workflow_id: str
    runtime_kind: str
    source_runtime_constraint: str
    source_preparation_selection_handle: str
    prepared_source_receipt_handle: str
    selected_lock_receipt_handle: str
    source_generation_manifest_sha256: str
    lock_sha256: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    qualification_consent_receipt_handle: str
    namespace_selection_receipt_handle: str
    principal_selection_receipt_handle: str
    principal_selection_handle: str
    principal_binding_sha256: str
    namespace_selection_handle: str
    namespace_binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("runtime-preparation input selections are minted by the root factory")

    @classmethod
    def _mint(cls, **claims: Any) -> "RootApplicationRuntimePreparationInputSelection":
        return cls(**claims, _seal=_SEAL)


@dataclass(frozen=True, slots=True, repr=False)
class RootApplicationRuntimePreparationSelection:
    """Complete v132 selection; it authorizes preparation/probe only."""

    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    qualification_choice_handle: str
    qualification_consent_receipt_handle: str
    application_id: str
    workflow_id: str
    runtime_kind: str
    source_preparation_selection_handle: str
    prepared_source_receipt_handle: str
    selected_lock_receipt_handle: str
    source_generation_manifest_sha256: str
    lock_sha256: str
    source_runtime_constraint: str
    build_profile_id: str
    operation_id: str
    target_id: str
    prepared_build_service_selection_handle: str
    runtime_toolchain_receipt_handles: tuple[str, ...]
    package_closure_receipt_handle: str
    build_recipe_sha256: str
    output_root_receipt_handle: str
    probe_artifact_receipt_handle: str
    namespace_selection_receipt_handle: str
    principal_selection_receipt_handle: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("application runtime-preparation selections are minted by the root factory")

    @property
    def handle(self) -> str:
        """Compatibility spelling consumed by the existing probe authority."""
        return self.selection_handle

    @classmethod
    def _mint(cls, **claims: Any) -> "RootApplicationRuntimePreparationSelection":
        return cls(**claims, _seal=_SEAL)


class RootApplicationRuntimePreparationSelectionRegistry:
    """Resolve and retain pre-output app selections against actual registries."""

    def __init__(self, *, selected_installation_binding: Any,
                 source_preparation_registry: Any, monotonic=time.monotonic,
                 ttl_seconds: float = 900.0) -> None:
        if (not callable(getattr(selected_installation_binding,
                                 "resolve_application_setup_choice", None))
                or not callable(getattr(source_preparation_registry, "resolve_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_prepared_source_for_selection", None))
                or not callable(getattr(source_preparation_registry,
                                        "resolve_current_lock_for_selection", None))
                or not 0 < ttl_seconds <= _MAX_TTL):
            raise ValueError("application runtime-preparation selection inputs are unavailable")
        self.binding = selected_installation_binding
        self.source_registry = source_preparation_registry
        self.package_registry: Any | None = None
        self.node_toolchain_registry: Any | None = None
        self.monotonic = monotonic
        self.ttl_seconds = float(ttl_seconds)
        self._inputs: dict[str, RootApplicationRuntimePreparationInputSelection] = {}
        self._final: dict[str, RootApplicationRuntimePreparationSelection] = {}
        self._final_output_roots: dict[str, Any] = {}
        self._input_by_choice: dict[tuple[str, str], str] = {}
        self._final_by_choice: dict[tuple[str, str], str] = {}
        attach_source = getattr(selected_installation_binding,
                                "attach_application_source_preparation_registry", None)
        if callable(attach_source):
            attach_source(source_preparation_registry)

    @classmethod
    def from_root_setup(cls, selected_installation_binding: Any,
                        source_preparation_registry: Any, **kwargs: Any
                        ) -> "RootApplicationRuntimePreparationSelectionRegistry":
        registry = cls(selected_installation_binding=selected_installation_binding,
                       source_preparation_registry=source_preparation_registry, **kwargs)
        attach = getattr(selected_installation_binding,
                         "attach_application_runtime_preparation_selection_registry", None)
        if not callable(attach):
            raise ValueError("selected setup binding has no runtime-preparation selector attachment")
        attach(registry)
        return registry

    def attach_package_registry(self, registry: Any) -> None:
        if (self.package_registry is not None
                or getattr(registry, "binding", None) is not self.binding
                or getattr(registry, "source_registry", None) is not self.source_registry
                or not callable(getattr(registry, "resolve_current_package_closure_for_selection", None))):
            raise ApplicationRuntimeSelectionDenied("package-closure registry is not the current source-bound root registry")
        self.package_registry = registry

    def attach_node_toolchain_registry(self, registry: Any) -> None:
        if (self.node_toolchain_registry is not None
                or getattr(registry, "choices", None) is not self.binding
                or not callable(getattr(registry, "resolve_current_toolchain_for_selection", None))):
            raise ApplicationRuntimeSelectionDenied("Node/Bun toolchain registry is not bound to this setup")
        self.node_toolchain_registry = registry

    def resolve_application_runtime_preparation_input(
            self, qualification_choice_handle: str,
            application_id: str) -> RootApplicationRuntimePreparationInputSelection:
        _opaque(qualification_choice_handle, "qualification choice")
        profile = _PROFILES.get(application_id)
        if profile is None:
            raise ApplicationRuntimeSelectionDenied("application is outside the four reviewed runtime profiles")
        choice = self.binding.resolve_application_setup_choice(qualification_choice_handle)
        if (getattr(choice, "selection_handle", None) != qualification_choice_handle
                or getattr(choice, "application_id", None) != application_id
                or getattr(choice, "workflow_id", None) != profile[0]):
            raise ApplicationRuntimeSelectionDenied("current root TTY application choice differs from the finite profile")
        source_selection = self.binding.resolve_application_source_preparation(
            qualification_choice_handle, application_id)
        from .application_source_preparation import RootApplicationSourcePreparationSelection
        if (type(source_selection) is not RootApplicationSourcePreparationSelection
                or source_selection.qualification_choice_handle != qualification_choice_handle
                or source_selection.application_id != application_id
                or source_selection.workflow_id != profile[0]):
            raise ApplicationRuntimeSelectionDenied("current root factory returned no matching source selection")
        source_selection = self.source_registry.resolve_selection(source_selection.selection_handle)
        source = self.source_registry.resolve_current_prepared_source_for_selection(
            source_selection.selection_handle)
        lock = self.source_registry.resolve_current_lock_for_selection(
            source_selection.selection_handle, source.receipt_handle)
        self.source_registry.read_current_lock_bytes(
            lock.receipt_handle, source_selection.selection_handle, source.receipt_handle)
        consent = self.binding.resolve_application_qualification_consent(
            qualification_choice_handle, "stage-pinned-source-locks")
        controller = self.binding.resolve_application_controller_binding(qualification_choice_handle)
        principal_selector = self.binding.resolve_adopted_principal_selector()
        namespace_selector = self.binding.resolve_adopted_namespace_selector()
        current_identity = self.binding.resolve_current_setup_identity()
        now = self.monotonic()
        if (principal_selector.selection_handle != choice.principal_selection_handle
                or principal_selector.binding_sha256 != choice.principal_binding_sha256
                or namespace_selector.selection_handle != choice.namespace_selection_handle
                or namespace_selector.binding_sha256 != choice.namespace_binding_sha256
                or current_identity.principal_selection_handle != choice.principal_selection_handle
                or current_identity.principal_binding_sha256 != choice.principal_binding_sha256
                or current_identity.namespace_selection_handle != choice.namespace_selection_handle
                or current_identity.namespace_binding_sha256 != choice.namespace_binding_sha256
                or current_identity.expires_monotonic <= now
                or current_identity.expires_monotonic > now + 30.0
                or current_identity.namespace.target_profile_id != source_selection.target_profile_id
                or current_identity.namespace.prepared_generation_id != source_selection.prepared_generation_id
                or current_identity.namespace.prepared_generation_digest != source_selection.prepared_generation_digest
                or current_identity.namespace.principal_selection_receipt_id != current_identity.principal.receipt_id):
            raise ApplicationRuntimeSelectionDenied("current paired principal/namespace identity does not match stable selectors")
        if (source_selection != self.source_registry.resolve_selection(source_selection.selection_handle)
                or source.selection_handle != source_selection.selection_handle
                or source.application_id != application_id
                or lock.selection_handle != source_selection.selection_handle
                or lock.prepared_source_receipt_handle != source.receipt_handle
                or getattr(consent, "qualification_choice_handle", None) != qualification_choice_handle
                or getattr(consent, "application_id", None) != application_id
                or getattr(consent, "workflow_id", None) != profile[0]
                or getattr(consent, "purpose", None) != "installer-application-local-qualification"
                or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                or getattr(consent, "revocation_epoch", None) != 0
                or getattr(consent, "setup_session_id", None) != source_selection.setup_session_id
                or getattr(consent, "transaction_handle", None) != source_selection.transaction_handle
                or getattr(consent, "plan_sha256", None) != source_selection.plan_sha256
                or getattr(consent, "prepared_generation_id", None) != source_selection.prepared_generation_id
                or getattr(consent, "prepared_generation_digest", None) != source_selection.prepared_generation_digest
                or getattr(consent, "receipt_handle", None) == source_selection.qualification_consent_receipt_handle
                or getattr(consent, "controller_binding_handle", None) != source_selection.controller_binding_handle
                or getattr(consent, "principal_selection_handle", None) != choice.principal_selection_handle
                or getattr(consent, "principal_binding_sha256", None) != choice.principal_binding_sha256
                or getattr(consent, "namespace_selection_handle", None) != choice.namespace_selection_handle
                or getattr(consent, "namespace_binding_sha256", None) != choice.namespace_binding_sha256
                or "stage-pinned-source-locks" not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "expires_monotonic", 0) <= self.monotonic()
                or getattr(controller, "handle", None) != source_selection.controller_binding_handle
                or getattr(controller, "expires_monotonic", 0) <= self.monotonic()
                or not self.binding.verify_application_controller_binding(controller)
                or choice.namespace_selection_handle != source_selection.namespace_selection_handle
                or choice.namespace_binding_sha256 != source_selection.namespace_binding_sha256
                or choice.principal_selection_handle != source_selection.principal_selection_handle
                or choice.principal_binding_sha256 != source_selection.principal_binding_sha256
                or choice.setup_session_id != source_selection.setup_session_id
                or choice.transaction_handle != source_selection.transaction_handle
                or choice.plan_sha256 != source_selection.plan_sha256
                or choice.prepared_generation_id != source_selection.prepared_generation_id
                or choice.prepared_generation_digest != source_selection.prepared_generation_digest
                or choice.controller_binding_handle != source_selection.controller_binding_handle):
            raise ApplicationRuntimeSelectionDenied("current source/lock, controller or selector joins changed")
        key = (qualification_choice_handle, application_id)
        handle = self._input_by_choice.get(key)
        # Stable choice/source/controller handles govern the retained selection
        # lease. The current paired identity receipts above are checked on each
        # resolution; their short IDs are evidence of the issuance snapshot only.
        previous = self._inputs.get(handle) if handle is not None else None
        principal_receipt_handle = (
            previous.principal_selection_receipt_handle if previous is not None
            else current_identity.principal.receipt_id)
        namespace_receipt_handle = (
            previous.namespace_selection_receipt_handle if previous is not None
            else current_identity.namespace.receipt_handle)
        expiry = min(now + self.ttl_seconds, choice.expires_monotonic,
                     source_selection.expires_monotonic, source.expires_monotonic,
                     lock.expires_monotonic, controller.expires_monotonic)
        if expiry <= now:
            raise ApplicationRuntimeSelectionDenied("current source/lock setup selection lease is expired")
        if handle is None:
            handle = secrets.token_urlsafe(36)
        if previous is not None:
            if previous.expires_monotonic <= now or previous.expires_monotonic > expiry:
                raise ApplicationRuntimeSelectionDenied("retained source/lock input selection expired or lost currentness")
            expiry = previous.expires_monotonic
            now = previous.issued_monotonic
        selection = RootApplicationRuntimePreparationInputSelection._mint(
            schema=1, selection_handle=handle,
            qualification_choice_handle=qualification_choice_handle,
            application_id=application_id, workflow_id=profile[0],
            runtime_kind=profile[1], source_runtime_constraint=profile[2],
            source_preparation_selection_handle=source_selection.selection_handle,
            prepared_source_receipt_handle=source.receipt_handle,
            selected_lock_receipt_handle=lock.receipt_handle,
            source_generation_manifest_sha256=source.source_generation_manifest_sha256,
            lock_sha256=lock.lock_sha256,
            setup_session_id=source_selection.setup_session_id,
            transaction_handle=source_selection.transaction_handle,
            plan_sha256=source_selection.plan_sha256,
            prepared_generation_id=source_selection.prepared_generation_id,
            prepared_generation_digest=source_selection.prepared_generation_digest,
            qualification_consent_receipt_handle=source_selection.qualification_consent_receipt_handle,
            namespace_selection_receipt_handle=namespace_receipt_handle,
            principal_selection_receipt_handle=principal_receipt_handle,
            principal_selection_handle=choice.principal_selection_handle,
            principal_binding_sha256=choice.principal_binding_sha256,
            namespace_selection_handle=choice.namespace_selection_handle,
            namespace_binding_sha256=choice.namespace_binding_sha256,
            controller_binding_handle=source_selection.controller_binding_handle,
            issued_monotonic=now, expires_monotonic=expiry)
        if previous is not None and (previous._seal is not _SEAL or previous != selection):
            raise ApplicationRuntimeSelectionDenied("retained runtime input selection no longer matches its current source/lock joins")
        self._inputs[handle] = selection
        self._input_by_choice[key] = handle
        return selection

    def resolve_application_runtime_preparation_input_selection(
            self, selection_handle: str) -> RootApplicationRuntimePreparationInputSelection:
        _opaque(selection_handle, "runtime input selection")
        stored = self._inputs.get(selection_handle)
        if (stored is None or stored._seal is not _SEAL
                or stored.expires_monotonic <= self.monotonic()):
            raise ApplicationRuntimeSelectionDenied("runtime input selection is absent, stale or expired")
        current = self.resolve_application_runtime_preparation_input(
            stored.qualification_choice_handle, stored.application_id)
        if current != stored:
            raise ApplicationRuntimeSelectionDenied("runtime input source/lock selection changed")
        return stored

    def _resolve_current_package_closure(self, source_selection_handle: str) -> Any:
        resolver = getattr(self.binding, "resolve_current_application_package_closure", None)
        if not callable(resolver):
            raise ApplicationRuntimeSelectionDenied(
                "root setup binding has no current offline package-closure resolver")
        return resolver(source_selection_handle)

    def resolve_application_runtime_preparation(
            self, qualification_choice_handle: str,
            application_id: str) -> RootApplicationRuntimePreparationSelection:
        inputs = self.resolve_application_runtime_preparation_input(
            qualification_choice_handle, application_id)
        if self.package_registry is None:
            raise ApplicationRuntimeSelectionDenied(
                "current offline package-closure registry is unavailable; no runtime preparation was selected")
        if inputs.runtime_kind == "node":
            if self.node_toolchain_registry is None:
                raise ApplicationRuntimeSelectionDenied(
                    "current selected Node/Bun toolchain and package closure are unavailable for Hyperframes")
            toolchain = self.node_toolchain_registry.resolve_current_toolchain_for_selection(
                inputs.selection_handle)
            if not isinstance(toolchain, tuple) or len(toolchain) != 2:
                raise ApplicationRuntimeSelectionDenied("current Node/Bun toolchain resolver returned no typed receipt pair")
            from .application_toolchains import RootApplicationToolchainObservation
            if (any(type(row) is not RootApplicationToolchainObservation for row in toolchain)
                    or {row.tool_id for row in toolchain} != {
                        "application-node-26.7.0-linux-arm64",
                        "application-bun-1.4.3-linux-arm64",
                    }):
                raise ApplicationRuntimeSelectionDenied("current Node/Bun toolchain resolver returned unreviewed receipts")
            toolchain_handles = tuple(row.receipt_handle for row in toolchain)
            closure = self._resolve_current_package_closure(
                inputs.source_preparation_selection_handle)
        else:
            closure = self._resolve_current_package_closure(
                inputs.source_preparation_selection_handle)
            toolchain_handles = tuple(getattr(closure, "runtime_toolchain_receipt_handles", ()))
        from .application_runtime_preparation import RootApplicationOfflinePackageClosureReceipt
        if (type(closure) is not RootApplicationOfflinePackageClosureReceipt
                or closure.source_preparation_selection_handle != inputs.source_preparation_selection_handle
                or closure.source_receipt_handle != inputs.prepared_source_receipt_handle
                or closure.lock_receipt_handle != inputs.selected_lock_receipt_handle
                or closure.lock_sha256 != inputs.lock_sha256
                or closure.setup_session_id != inputs.setup_session_id
                or closure.transaction_handle != inputs.transaction_handle
                or closure.prepared_generation_digest != inputs.prepared_generation_digest
                or closure.application_id != application_id
                or not toolchain_handles or len(set(toolchain_handles)) != len(toolchain_handles)
                or any(not isinstance(handle, str) or len(handle) < 32 for handle in toolchain_handles)
                or closure.expires_monotonic <= self.monotonic()):
            raise ApplicationRuntimeSelectionDenied("current retained package closure does not match source/lock/toolchain")
        choice = self.binding.resolve_application_setup_choice(qualification_choice_handle)
        consent = self.binding.resolve_application_qualification_consent(
            qualification_choice_handle, "prepare-locked-isolated-runtime")
        if (getattr(consent, "qualification_choice_handle", None) != qualification_choice_handle
                or getattr(consent, "application_id", None) != application_id
                or getattr(consent, "workflow_id", None) != inputs.workflow_id
                or getattr(consent, "purpose", None) != "installer-application-local-qualification"
                or "prepare-locked-isolated-runtime" not in getattr(consent, "allowed_phase_ids", ())
                or getattr(consent, "additional_metered_budget_usd", None) != 0.0
                or getattr(consent, "revocation_epoch", None) != 0
                or getattr(consent, "expires_monotonic", 0) <= self.monotonic()):
            raise ApplicationRuntimeSelectionDenied("current runtime preparation consent is absent, revoked or mismatched")
        probe_resolver = getattr(self.binding, "resolve_application_runtime_probe_artifact", None)
        if not callable(probe_resolver):
            raise ApplicationRuntimeSelectionDenied(
                "independent installed application ABI/origin probe artifact receipt is unavailable")
        probe = probe_resolver(application_id)
        probe_handle = getattr(probe, "receipt_handle", None)
        _opaque(probe_handle, "runtime probe artifact")
        if getattr(probe, "application_id", application_id) != application_id:
            raise ApplicationRuntimeSelectionDenied("installed runtime probe artifact belongs to another application")
        build_profile = _PROFILES[application_id][3]
        build_resolver = getattr(self.binding, "resolve_prepared_application_build_service", None)
        if not callable(build_resolver):
            raise ApplicationRuntimeSelectionDenied("root v132 prepared application-build service selector is unavailable")
        build_service = build_resolver(build_profile)
        verifier = getattr(build_service, "verify_current", None)
        if not callable(verifier) or verifier() is not build_service:
            raise ApplicationRuntimeSelectionDenied("prepared application-build service selection is stale")
        target_id = build_profile.replace("-runtime-prepare-v1", "-runtime-prepare:start")
        if (getattr(build_service, "template_artifact_id", None) != _TEMPLATE_ID
                or getattr(build_service, "template_sha256", None) != _TEMPLATE_SHA256
                or getattr(build_service, "profile_id", None) != "hermes-installer-build-v1"
                or build_profile not in getattr(build_service, "allowed_operation_ids", ())
                or target_id not in getattr(build_service, "allowed_targets", ())
                or getattr(build_service, "setup_session_id", None) != inputs.setup_session_id
                or getattr(build_service, "transaction_handle", None) != inputs.transaction_handle
                or getattr(build_service, "prepared_generation_id", None) != inputs.prepared_generation_id
                or getattr(build_service, "prepared_generation_digest", None) != inputs.prepared_generation_digest):
            raise ApplicationRuntimeSelectionDenied("exact v132 app build subject/template is not held for this transaction")
        key = (qualification_choice_handle, application_id)
        handle = self._final_by_choice.get(key)
        if handle is None:
            handle = secrets.token_urlsafe(36)
        previous = self._final.get(handle)
        if previous is None:
            output = build_service.create_output_root()
            self._final_output_roots[handle] = output
        else:
            output = self._final_output_roots.get(handle)
            if (output is None
                    or getattr(output, "service_selection_handle", None)
                       != build_service.service_selection_handle):
                raise ApplicationRuntimeSelectionDenied("retained output root is unavailable for current build subject")
            fd = output.open_current()
            os.close(fd)
        output_handle = getattr(output, "output_root_id", None)
        _opaque(output_handle, "build output root")
        now = self.monotonic()
        expiry = min(now + self.ttl_seconds, inputs.expires_monotonic,
                     closure.expires_monotonic, consent.expires_monotonic,
                     build_service.expires_monotonic,
                     getattr(probe, "expires_monotonic", 0))
        if expiry <= now:
            raise ApplicationRuntimeSelectionDenied("application runtime-preparation inputs expired before selection")
        recipe = {
            "schema": 1,
            "build_profile_id": build_profile,
            "runtime_kind": inputs.runtime_kind,
            "python_lock_integrity_check": (
                ["uv", "lock", "--check", "--offline", "--no-progress"]
                if inputs.runtime_kind == "python" else None),
            "python_dependency_export": (
                ["uv", "export", "--locked", "--offline", "--no-dev",
                 "--no-default-groups", "--no-editable", "--no-emit-project",
                 "--format", "requirements-txt", "--output-file",
                 "<fixed-selected-work-requirements>"]
                if inputs.runtime_kind == "python" else None),
            "python_dependency_install": (
                ["uv", "pip", "sync", "--require-hashes", "--offline",
                 "--no-index", "--find-links", "<root-selected-wheelhouse>",
                 "--python", "<selected-environment-python>",
                 "<validated-target-requirements>"]
                if inputs.runtime_kind == "python" else None),
            "python_project_wheel_stage": (
                {"source": "<fixed-readonly-selected-source>",
                 "build_backend_closure": "<separate-reviewed-held-backend-closure-required>",
                 "network": "disabled", "editable": False,
                 "output": "<observed-source-bound-project-wheel>"}
                if inputs.runtime_kind == "python" else None),
            "python_project_install": (
                ["uv", "pip", "install", "--no-deps", "--require-hashes",
                 "--offline", "--no-index", "--find-links",
                 "<observed-project-wheelhouse>", "--python",
                 "<selected-environment-python>", "<observed-project-wheel>"]
                if inputs.runtime_kind == "python" else None),
            "node_install_stage": (
                ["bun", "install", "--frozen-lockfile", "--offline"]
                if inputs.runtime_kind == "node" else None),
            "network": "PrivateNetwork=yes; AF_UNIX only",
            "mounts": "source/package/toolchain readonly; selected work/output only writable",
            "bounds": {"MemoryMax": 2147483648, "TasksMax": 128,
                       "archive_bytes": 2147483648, "expanded_bytes": 2147483648,
                       "members": 131072, "lifetime_seconds": 600,
                       "output_bytes": 1048576},
        }
        claims = {
            "schema": 1,
            "application_id": application_id,
            "source_preparation_selection_handle": inputs.source_preparation_selection_handle,
            "prepared_source_receipt_handle": inputs.prepared_source_receipt_handle,
            "selected_lock_receipt_handle": inputs.selected_lock_receipt_handle,
            "source_generation_manifest_sha256": inputs.source_generation_manifest_sha256,
            "lock_sha256": inputs.lock_sha256,
            "runtime_toolchain_receipt_handles": list(toolchain_handles),
            "package_closure_receipt_handle": closure.receipt_handle,
            "build_profile_id": build_profile,
            "build_template_artifact_id": _TEMPLATE_ID,
            "build_template_sha256": _TEMPLATE_SHA256,
            "output_root_receipt_handle": output_handle,
            "probe_artifact_receipt_handle": probe_handle,
            "recipe": recipe,
            "package_closure_sha256": closure.package_closure_sha256,
            "package_records": [
                {name: getattr(row, name) for name in row.__dataclass_fields__}
                for row in closure.package_records
            ],
        }
        recipe_sha = hashlib.sha256(json.dumps(
            claims, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        if previous is not None:
            if previous._seal is not _SEAL or previous.expires_monotonic <= now:
                raise ApplicationRuntimeSelectionDenied("retained runtime-preparation selection expired or lost currentness")
            now = previous.issued_monotonic
            expiry = previous.expires_monotonic
        selection = RootApplicationRuntimePreparationSelection._mint(
            selection_handle=handle,
            setup_session_id=inputs.setup_session_id,
            transaction_handle=inputs.transaction_handle,
            plan_sha256=inputs.plan_sha256,
            prepared_generation_id=inputs.prepared_generation_id,
            prepared_generation_digest=inputs.prepared_generation_digest,
            qualification_choice_handle=qualification_choice_handle,
            qualification_consent_receipt_handle=inputs.qualification_consent_receipt_handle,
            application_id=application_id, workflow_id=inputs.workflow_id,
            runtime_kind=inputs.runtime_kind,
            source_preparation_selection_handle=inputs.source_preparation_selection_handle,
            prepared_source_receipt_handle=inputs.prepared_source_receipt_handle,
            selected_lock_receipt_handle=inputs.selected_lock_receipt_handle,
            source_generation_manifest_sha256=inputs.source_generation_manifest_sha256,
            lock_sha256=inputs.lock_sha256,
            source_runtime_constraint=inputs.source_runtime_constraint,
            build_profile_id=build_profile, operation_id=build_profile,
            target_id=target_id,
            prepared_build_service_selection_handle=build_service.service_selection_handle,
            runtime_toolchain_receipt_handles=toolchain_handles,
            package_closure_receipt_handle=closure.receipt_handle,
            build_recipe_sha256=recipe_sha,
            output_root_receipt_handle=output_handle,
            probe_artifact_receipt_handle=probe_handle,
            namespace_selection_receipt_handle=inputs.namespace_selection_receipt_handle,
            principal_selection_receipt_handle=inputs.principal_selection_receipt_handle,
            controller_binding_handle=inputs.controller_binding_handle,
            issued_monotonic=now, expires_monotonic=expiry)
        if previous is not None and previous != selection:
            raise ApplicationRuntimeSelectionDenied("retained build recipe or preparation inputs changed")
        self._final[handle] = selection
        self._final_by_choice[key] = handle
        return selection

    def resolve_application_runtime_preparation_selection(
            self, selection_handle: str) -> RootApplicationRuntimePreparationSelection:
        _opaque(selection_handle, "runtime preparation selection")
        stored = self._final.get(selection_handle)
        if (stored is None or stored._seal is not _SEAL
                or stored.expires_monotonic <= self.monotonic()):
            raise ApplicationRuntimeSelectionDenied("runtime preparation selection is absent, stale or expired")
        current = self.resolve_application_runtime_preparation(
            stored.qualification_choice_handle, stored.application_id)
        if current != stored:
            raise ApplicationRuntimeSelectionDenied("runtime preparation build recipe or source selection changed")
        return stored
