"""Join the protected active catalogs to concrete root authority components.

This module runs after the root enrollment loader and ``RootRuntimeBindings``
builder. It accepts those verified objects, never caller-selected factories,
capability flags, or paths from a worker. Components are returned as one
immutable epoch-scoped object so the daemon can install the exact instances it
serves and close them together at shutdown.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import math
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from hermes_installer.artifacts import ArtifactCatalog
from hermes_installer.authority.service import AuthorityService
from hermes_installer.authority.enrollment import ProtectedEnrollment, RootCredentialVault
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.authority.types import strict_json_loads
from hermes_installer.protected_enrollment import RootJournalSelection

_AUTHORITY_JOURNAL_ROOT_ID = "installer-authority-journal-v1"
_RESOURCE_JOB_LEDGER_FILENAME = "resource-jobs.sqlite3"


def _root_resource_job_ledger_path(bindings: RootRuntimeBindings,
                                   enrollment: ProtectedEnrollment) -> Path:
    resolver = getattr(bindings, "resolve_root_journal", None)
    if not callable(resolver):
        raise AuthorityDenied("journal.unavailable", "root bindings have no protected journal resolver")
    try:
        selection = resolver(
            _AUTHORITY_JOURNAL_ROOT_ID,
            expected_active_generation_digest=enrollment.protected_enrollment_digest,
        )
    except Exception:
        raise AuthorityDenied("journal.unavailable", "protected authority journal is unavailable") from None
    path = selection.path if isinstance(selection, RootJournalSelection) else None
    if (not isinstance(selection, RootJournalSelection)
            or selection.root_id != _AUTHORITY_JOURNAL_ROOT_ID
            or selection.service_generation_digest != enrollment.protected_enrollment_digest
            or not isinstance(path, Path) or not path.is_absolute()
            or not selection.generation or selection.device < 0 or selection.inode <= 0):
        raise AuthorityDenied("journal.unavailable", "protected authority journal selection is malformed")
    return path / _RESOURCE_JOB_LEDGER_FILENAME


def _native_json_schema_matches(value: Any, schema: Mapping[str, Any]) -> bool:
    """Validate one bounded JSON value against the finite pinned schema subset."""
    if ("enum" in schema and not any(type(value) is type(item) and value == item
                                     for item in schema["enum"])):
        return False
    kind = schema.get("type")
    if kind == "object":
        if not isinstance(value, dict):
            return False
        properties = schema.get("properties", {})
        required = schema.get("required", ())
        if (not isinstance(properties, Mapping)
                or any(name not in value for name in required)
                or schema.get("additionalProperties", False) is False
                and set(value) - set(properties)):
            return False
        return all(name not in properties or _native_json_schema_matches(child, properties[name])
                   for name, child in value.items())
    if kind == "array":
        if not isinstance(value, list):
            return False
        if len(value) < schema.get("minItems", 0) or len(value) > schema.get("maxItems", 2**31):
            return False
        item_schema = schema.get("items")
        return isinstance(item_schema, Mapping) and all(
            _native_json_schema_matches(child, item_schema) for child in value)
    if kind == "string":
        return (isinstance(value, str)
                and len(value) >= schema.get("minLength", 0)
                and len(value) <= schema.get("maxLength", 2**31))
    if kind == "integer":
        if type(value) is not int:
            return False
    elif kind == "number":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        if isinstance(value, float) and not math.isfinite(value):
            return False
    elif kind == "boolean":
        if type(value) is not bool:
            return False
    elif kind == "null":
        if value is not None:
            return False
    elif kind != "string":
        return False
    if kind in {"integer", "number"}:
        if "minimum" in schema and value < schema["minimum"]:
            return False
        if "maximum" in schema and value > schema["maximum"]:
            return False
    return True


class _ProtectedNativeActionResolver:
    """Resolve provider tool names through active native workflows and schemas."""

    def __init__(self, bindings: RootRuntimeBindings, schema_catalog: Any, *,
                 service_generation_digest: str):
        from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog

        if (not isinstance(bindings, RootRuntimeBindings)
                or not isinstance(schema_catalog, NativeMCPProtectedSchemaCatalog)
                or service_generation_digest != bindings.enrollment_catalog.digest):
            raise AuthorityDenied("native.action", "active package and source-verified schema catalog are required")
        self.bindings = bindings
        self.schema_catalog = schema_catalog
        self.service_generation_digest = service_generation_digest

    def __call__(self, bridge: Any, live_identity: Any, tool_name: str) -> Any:
        from .native_runtime_observer import NativeActionSelection

        if (not isinstance(tool_name, str) or not tool_name
                or getattr(bridge, "bridge_id", None) not in self.bindings.native_bridges
                or self.bindings.native_bridges.get(bridge.bridge_id) != bridge
                or getattr(bridge, "producer_profile_id", None) != getattr(live_identity, "profile_id", None)
                or getattr(bridge, "producer_generation", None) != getattr(live_identity, "generation", None)
                or self.service_generation_digest != self.bindings.enrollment_catalog.digest):
            raise AuthorityDenied("native.action", "provider tool call is outside its active protected bridge")
        try:
            package = self.bindings.enrollment_catalog.resolve_profile_native_package(
                bridge.producer_profile_id, bridge.producer_generation,
            )
            package = self.bindings.resolve_native_package(package.package_id, package.generation)
        except Exception:
            raise AuthorityDenied("native.action", "producer native package is no longer selected") from None
        candidates: list[tuple[Any, Mapping[str, Any]]] = []
        for adapter in package.adapter_records.values():
            for workflow in adapter.workflow_bindings:
                if workflow.get("external_tool_name") != tool_name:
                    continue
                try:
                    schema_id = workflow["external_argument_schema_id"]
                    protected_schema = self.bindings.resolve_native_schema_record(
                        schema_id, package.package_id, package.generation,
                        adapter.adapter_id, adapter.action_id, "arguments",
                    )
                    if (not isinstance(protected_schema, Mapping)
                            or protected_schema.get("id") != schema_id
                            or protected_schema.get("native_package_id") != package.package_id
                            or protected_schema.get("native_package_generation") != package.generation
                            or protected_schema.get("adapter_id") != adapter.adapter_id
                            or protected_schema.get("action_id") != adapter.action_id
                            or protected_schema.get("schema_kind") != "arguments"
                            or not isinstance(protected_schema.get("source_receipt_handle"), str)):
                        raise AuthorityDenied(
                            "native.action", "selected workflow schema metadata does not match its protected row",
                        )
                    schema = self.schema_catalog.resolve(
                        schema_id,
                        native_package_id=package.package_id,
                        native_package_generation=package.generation,
                        adapter_id=adapter.adapter_id,
                        action_id=adapter.action_id,
                        schema_kind="arguments",
                    )
                except Exception:
                    raise AuthorityDenied(
                        "native.action", "selected workflow argument schema is not source-verified",
                    ) from None
                candidates.append((adapter, schema))
        if len(candidates) != 1:
            raise AuthorityDenied("native.action", "provider tool name is absent or ambiguous in selected workflows")
        adapter, schema = candidates[0]

        def validate_arguments(raw: bytes) -> bool:
            if not isinstance(raw, bytes) or not 1 <= len(raw) <= 65_536:
                return False
            try:
                value = strict_json_loads(raw.decode("utf-8", errors="strict"))
                canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, UnicodeError, RecursionError):
                return False
            return canonical == raw and _native_json_schema_matches(value, schema)

        return NativeActionSelection(
            package_id=package.package_id, profile_id=package.profile_id,
            generation=package.generation, adapter_id=adapter.adapter_id,
            action_id=adapter.action_id, operation=adapter.operation,
            validate_arguments=validate_arguments,
        )


def _prepare_native_mcp_selection(
    *, service: AuthorityService, enrollment: ProtectedEnrollment,
    bindings: RootRuntimeBindings,
) -> tuple[Any, Mapping[str, Any], Mapping[str, str], tuple[Mapping[str, Any], ...],
           str, str, str, str, str]:
    """Prepare the exact MCP registration before schema receipt assembly.

    The discovery observer must exist before the derivation registry, while
    the invocation registry needs the verified schema catalog. This root-only
    prepare value breaks that cycle without attaching a partially ready
    dispatcher or reparsing the protected selection later.
    """
    from hermes_installer.mcp.broker import ProtectedMCPService
    from hermes_installer.mcp.native_dispatch import NativeMCPRegistrationIndex

    if not isinstance(enrollment.native_mcp_tool_binding_records, tuple):
        raise AuthorityDenied("native.mcp", "protected MCP action rows are malformed")
    grouped: dict[tuple[str, str, str, str, str], list[Mapping[str, Any]]] = {}
    for raw in enrollment.native_mcp_tool_binding_records:
        if not isinstance(raw, Mapping):
            raise AuthorityDenied("native.mcp", "protected MCP action row is malformed")
        key = tuple(raw.get(field) for field in (
            "profile_id", "process_generation", "native_package_id",
            "native_package_generation", "handler_artifact_sha256",
        ))
        if any(not isinstance(part, str) or not part for part in key):
            raise AuthorityDenied("native.mcp", "protected MCP package selector is malformed")
        if raw.get("effect_operation") == "mcp.request":
            grouped.setdefault(key, []).append(raw)
    if not grouped:
        raise AuthorityDenied("native.mcp", "no selected native MCP action has a fixed HTTP transport")
    if len(grouped) != 1:
        raise AuthorityDenied("native.mcp", "selected native MCP actions span multiple package dispatch generations")
    (profile_id, process_generation, package_id,
     package_generation, handler_sha), raw_rows = next(iter(grouped.items()))
    active = bindings.resolve_native_mcp_tool_bindings(
        profile_id, process_generation, service.service_generation_digest,
    )
    selected_rows = tuple(row for row in active if row.get("effect_operation") == "mcp.request")
    if ({row.get("id"): dict(row) for row in selected_rows}
            != {row.get("id"): dict(row) for row in raw_rows}):
        raise AuthorityDenied("native.mcp", "selected MCP action rows differ from active root bindings")

    services: dict[str, Any] = {}
    for service_id, raw in enrollment.mcp_services.items():
        fields = {key: value for key, value in raw.items() if key != "id"}
        fields["allowed_tools"] = frozenset(fields["allowed_tools"])
        fields["selection_arguments"] = {
            tool: tuple(arguments) for tool, arguments in fields["selection_arguments"].items()
        }
        try:
            services[service_id] = ProtectedMCPService(service_id=service_id, **fields)
        except Exception:
            raise AuthorityDenied("native.mcp", "protected MCP service record is invalid") from None
    generations: dict[str, str] = {}
    for row in selected_rows:
        service_id, generation = row["mcp_enrollment_id"], row["mcp_generation"]
        previous = generations.setdefault(service_id, generation)
        if previous != generation or service_id not in services:
            raise AuthorityDenied("native.mcp", "selected MCP service generations are ambiguous")
        target_key = (row["effect_operation"], row["effect_target"])
        if (target_key not in services[service_id].handlers
                or not any(rule.operation == target_key[0] and rule.target == target_key[1]
                           and rule.capability == row["capability"]
                           for rule in services[service_id].rules.values())):
            raise AuthorityDenied("native.mcp", "selected MCP row lacks its installed fixed effect handler")
    registration = NativeMCPRegistrationIndex.from_protected_records(
        tuple(raw_rows), services=services,
        mcp_generation_by_enrollment=generations,
        profile_id=profile_id, process_generation=process_generation,
        native_package_id=package_id, native_package_generation=package_generation,
        handler_artifact_sha256=handler_sha,
    )
    return (registration, MappingProxyType(services), MappingProxyType(generations),
            selected_rows, profile_id, process_generation, package_id,
            package_generation, handler_sha)


def _build_native_mcp_dispatcher(
    *, service: AuthorityService, enrollment: ProtectedEnrollment,
    bindings: RootRuntimeBindings, schema_catalog: Any,
    source_observers: Any, prepared: tuple[Any, ...],
    mcp_discovery_registry: Any,
) -> Any:
    """Construct the fixed MCP dispatcher from one exact active native package.

    This dispatcher accepts only one-use invocations already issued by the
    attached NativeInvocationRegistry. Multiple package generations are kept
    unroutable until the dispatcher/index contract supports a typed composite.
    """
    from .native_runtime_observer import NativeRuntimeObserver
    from hermes_installer.mcp.native_execution import NativeMCPDispatcher
    from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog

    if (not isinstance(schema_catalog, NativeMCPProtectedSchemaCatalog)
            or not isinstance(enrollment.native_mcp_tool_binding_records, tuple)
            or not enrollment.native_mcp_tool_binding_records
            or source_observers is None or service.source_observer_registry is not source_observers
            or service.native_invocation_registry is None
            or not getattr(mcp_discovery_registry, "ready", False)):
        raise AuthorityDenied("native.mcp", "active schema, source, or invocation bindings are unavailable")
    (registration, services, generations, selected_rows, profile_id,
     process_generation, package_id, package_generation, handler_sha) = prepared

    observers = getattr(source_observers, "observers", {})
    effect_observer_ids: dict[tuple[str, str, str], str] = {}
    for row in selected_rows:
        operation, target = row["effect_operation"], row["effect_target"]
        candidates = [observer_id for observer_id, observer in observers.items()
                      if getattr(observer, "source_kind", None) == "tool-result"
                      and getattr(observer, "source_action_id", None) == "registered-tool-result"
                      and getattr(observer, "profile_id", None) == profile_id
                      and getattr(observer, "generation", None) == process_generation
                      and getattr(observer, "target_id", None) == target
                      and getattr(observer, "recipient", None) == row["recipient"]]
        if len(candidates) != 1:
            raise AuthorityDenied("native.mcp", "selected MCP effect has no unique active tool-result observer")
        key = (row["capability"], operation, target)
        previous = effect_observer_ids.setdefault(key, candidates[0])
        if previous != candidates[0]:
            raise AuthorityDenied("native.mcp", "selected MCP effects resolve to conflicting result observers")
    current_observer = service.native_runtime_observer
    if current_observer is None:
        service.attach_native_runtime_observer(NativeRuntimeObserver(
            source_observers=source_observers,
            effect_observer_ids=effect_observer_ids,
        ))
    elif any(getattr(current_observer, "effect_observer_ids", {}).get(key) != observer_id
             for key, observer_id in effect_observer_ids.items()):
        raise AuthorityDenied("native.mcp", "active MCP result observers differ from the root observer")
    dispatcher = NativeMCPDispatcher(
        service, registration_index=registration, schema_catalog=schema_catalog,
        protected_services=services,
        current_mcp_generations=generations,
        invocation_resolver=service.native_invocation_registry,
        mcp_discovery_registry=mcp_discovery_registry,
        monotonic=service.monotonic,
    )
    service.attach_native_mcp_dispatcher(dispatcher)
    return dispatcher


def _build_native_bridge_candidate(
    *, service: AuthorityService, enrollment: ProtectedEnrollment,
    bindings: RootRuntimeBindings, vault: RootCredentialVault,
) -> tuple[Any, Any]:
    """Build the root broker from exact provider and bridge enrollments.

    The provider response registry is attached later, after the live source
    observer exists. The broker itself is a concrete cycle-breaking object;
    it is never attached to the service unless the response registry also
    passes the provider owner’s full validation.
    """
    from .native_bridge import NativeBridgeBroker, RootObserverDeliveryBinding
    from .provider_runtime_composition import build_provider_runtime_selection
    from hermes_installer.provider_effect_handlers import canonical_provider_request

    bridges = bindings.native_bridges
    if (not isinstance(bridges, Mapping) or not bridges
            or dict(bridges) != dict(enrollment.native_bridges)):
        raise AuthorityDenied("native.broker", "active bridge rows are absent or stale")
    selection = build_provider_runtime_selection(
        service=service, enrollment=enrollment, bindings=bindings,
        bridges=bridges, provider_handlers=service.handlers, vault=vault,
        source_observer_enrollments=bindings.source_observer_enrollments,
    )
    digests = {bridge.canonicalizer_sha256 for bridge in bridges.values()}
    if len(digests) != 1:
        raise AuthorityDenied("native.broker", "selected bridges do not share one reviewed canonicalizer")
    delivery_map: dict[str, tuple[Any, ...]] = {}
    for bridge_id, bridge in bridges.items():
        raw_rows = getattr(bridge, "observer_delivery_bindings", None)
        if not isinstance(raw_rows, tuple) or not raw_rows:
            raise AuthorityDenied("native.broker", "selected bridge has no protected delivery rows")
        rows = tuple(
            RootObserverDeliveryBinding(
                observer_enrollment_id=row.observer_enrollment_id,
                delivery_role=row.delivery_role,
            )
            for row in raw_rows
        )
        if (any(row.observer_enrollment_id not in bindings.source_observer_enrollments
                for row in rows)
                or len({row.observer_enrollment_id for row in rows}) != len(rows)):
            raise AuthorityDenied("native.broker", "bridge delivery rows do not join active observer records")
        delivery_map[bridge_id] = rows
    process_resolver = getattr(bindings.process_manager, "resolve_live_peer", None)
    role_resolver = getattr(bindings, "resolve_native_bridge_role_artifact", None)
    if not callable(process_resolver) or not callable(role_resolver):
        raise AuthorityDenied("native.broker", "selected bridge process or role resolver is unavailable")
    broker = NativeBridgeBroker(
        service=service, bridges=bridges, process_resolver=process_resolver,
        canonicalizer=canonical_provider_request,
        root_selected_enrollments=selection.root_selected_enrollments_by_bridge,
        canonicalizer_sha256=next(iter(digests)),
        observer_delivery_bindings=delivery_map,
        peer_role_artifact_resolver=role_resolver,
        monotonic=service.monotonic,
    )
    return broker, selection


@dataclass(frozen=True, slots=True)
class RootAuthorityRuntime:
    """Concrete root-owned catalog joins for one AuthorityService epoch."""

    service: AuthorityService
    enrollment: ProtectedEnrollment
    bindings: RootRuntimeBindings
    artifact_catalog: ArtifactCatalog
    vault: RootCredentialVault
    boot_epoch: str
    backend_enrollments: Mapping[str, Any]
    body_recipes: Mapping[str, Any]
    scope_bindings: Mapping[str, Any]
    validators: Mapping[str, Any]
    source_observer_unavailable_reason: str | None
    resource_task_unavailable_reason: str | None
    job_enrollments: Mapping[tuple[str, str], Any]
    memory_runtime: Any | None
    job_authority: Any | None
    build_execution_service: Any | None
    native_mcp_unavailable_reason: str | None = None
    native_mcp_discovery_registry: Any | None = None
    selected_resources: Any | None = None
    selected_resource_unavailable_reason: str | None = None

    @property
    def process_manager(self) -> Any:
        return self.bindings.process_manager

    @property
    def service_connector(self) -> Any:
        return self.bindings.service_connector

    @property
    def build_catalog(self) -> Any:
        return self.bindings.build_catalog

    @property
    def device_catalog(self) -> Any:
        return self.bindings.device_catalog

    @property
    def remote_session_enrollments(self) -> Mapping[str, Any]:
        return self.bindings.remote_session_enrollments

    @property
    def source_observer_registry(self) -> Any | None:
        return self.service.source_observer_registry

    @property
    def source_observer_enrollments(self) -> Mapping[str, Any]:
        """Typed candidates derived from exact active issuer/package joins.

        These are enrollment metadata, not proof that a package is currently
        loaded or that a receipt may be issued. Registry construction still
        requires the live loader and recipient PIDFD proof resolvers.
        """
        records = getattr(self.bindings, "source_observer_enrollments", {})
        return MappingProxyType(dict(records)) if isinstance(records, Mapping) else MappingProxyType({})

    @property
    def native_runtime_observer(self) -> Any | None:
        return getattr(self.service, "native_runtime_observer", None)

    @property
    def native_loader_observation_store(self) -> Any | None:
        return getattr(self.service, "native_loader_observation_store", None)

    @property
    def gateway_boundary_observer(self) -> Any | None:
        return getattr(self.service, "gateway_boundary_observer", None)

    @property
    def native_window_observer(self) -> Any | None:
        return getattr(self.service, "native_window_observer", None)

    @property
    def native_bridge_broker(self) -> Any | None:
        return getattr(self.service, "native_bridge_broker", None)

    @property
    def native_invocation_registry(self) -> Any | None:
        return getattr(self.service, "native_invocation_registry", None)

    @property
    def task_native_observations(self) -> Any | None:
        attached = getattr(self.service, "task_native_observations", None)
        if attached is not None:
            return attached
        runner = getattr(self.service, "resource_task_runner", None)
        return getattr(runner, "native_observations", None)

    @property
    def native_mcp_dispatcher(self) -> Any | None:
        return getattr(self.service, "native_mcp_dispatcher", None)

    @property
    def remote_session_authority(self) -> Any | None:
        return self.service.remote_session_authority

    def prune(self) -> None:
        """Prune root observer leases using the service's attached registry."""
        registry = self.source_observer_registry
        prune = getattr(registry, "prune", None)
        if callable(prune):
            prune()

    def revoke_native_process(self, process_id: str, generation: str | None = None) -> None:
        """Revoke loader proofs when the root process manager retires a process."""
        store = self.native_loader_observation_store
        revoke = getattr(store, "revoke_process", None)
        if callable(revoke):
            revoke(process_id, generation)

    def close(self) -> None:
        """Close attached root observers and stop the active remote lease worker."""
        errors: list[BaseException] = []
        # Dependents close before the registries they retain. These attributes
        # are populated only by the concrete one-time service attachment APIs;
        # the composer never installs capability flags or callback placeholders.
        components = (
            self.task_native_observations,
            getattr(self.service, "native_input_delivery_registry", None),
            getattr(self.process_manager, "task_input_coordinator", None),
            getattr(self.service, "native_turn_observation_registry", None),
            getattr(self.native_bridge_broker, "native_request_observer", None),
            getattr(self.native_bridge_broker, "native_turn_observer", None),
            self.native_mcp_dispatcher,
            self.native_mcp_discovery_registry,
            self.native_runtime_observer,
            self.native_invocation_registry,
            self.native_bridge_broker,
            self.source_observer_registry,
            self.native_loader_observation_store,
            self.gateway_boundary_observer,
            self.native_window_observer,
        )
        closed: set[int] = set()
        for component in components:
            if component is None or id(component) in closed:
                continue
            closed.add(id(component))
            close = getattr(component, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException as exc:
                    errors.append(exc)
        directories = (self.memory_runtime.get("state_directories", {})
                       if isinstance(self.memory_runtime, Mapping) else {})
        for directory in directories.values() if isinstance(directories, Mapping) else ():
            close = getattr(directory, "close", None)
            if callable(close):
                try:
                    close()
                except BaseException as exc:
                    errors.append(exc)
        stop = getattr(self.remote_session_authority, "stop_watchdog", None)
        if callable(stop):
            try:
                stop()
            except BaseException as exc:
                errors.append(exc)
        if errors:
            raise errors[0]

    def resolve_native_package(self, package_id: str, generation: str) -> Any:
        return self.bindings.resolve_native_package(package_id, generation)

    def resolve_selected_native_principal(
        self, profile_id: str, generation: str, service_generation_digest: str,
    ) -> Any:
        return self.bindings.resolve_selected_native_principal(
            profile_id, generation, service_generation_digest,
        )

    def resolve_device(self, enrollment_id: str, generation: str) -> Any:
        return self.bindings.resolve_device(enrollment_id, generation)

    def resolve_operation(self, enrollment_id: str, generation: str,
                          operation: str, operation_id: str) -> Any:
        return self.bindings.resolve_selected_operation(
            enrollment_id, generation, operation, operation_id,
        )

    def resolve_artifact_store_id(self, store_id: str) -> Any:
        resolver = getattr(self.artifact_catalog, "resolve_store_id", None)
        if not callable(resolver):
            raise AuthorityDenied("artifact.unavailable", "root artifact catalog has no protected store resolver")
        return resolver(store_id, self.enrollment.artifact_staging_directory,
                        expected_uid=self.vault.expected_uid)

    def resolve_live_peer(self, peer_pid: int, peer_pidfd: int, *,
                          profile_id: str, generation: str) -> Any:
        resolver = getattr(self.process_manager, "resolve_live_peer", None)
        if not callable(resolver):
            raise AuthorityDenied("process.unavailable", "root process custody has no live peer resolver")
        return resolver(peer_pid, peer_pidfd, profile_id=profile_id, generation=generation)

    def resolve_loaded_native_package(self, process_id: str, generation: str) -> Any:
        resolver = getattr(self.process_manager, "resolve_loaded_native_package", None)
        if not callable(resolver):
            raise AuthorityDenied("native.unavailable", "root process custody has no loaded package resolver")
        return resolver(process_id, generation)

    def resolve_root_journal(self, root_id: str, *,
                             expected_active_generation_digest: str) -> Any:
        """Resolve a journal only inside this exact active protected snapshot.

        The protected enrollment catalog revalidates its selected root row and
        filesystem identity. This wrapper prevents a caller from asking the
        catalog for a root under a stale or caller-selected generation.
        """
        if (not isinstance(root_id, str) or not root_id
                or expected_active_generation_digest
                != self.enrollment.protected_enrollment_digest):
            raise AuthorityDenied("journal.unavailable", "journal root is outside the active protected generation")
        resolver = getattr(self.bindings, "resolve_root_journal", None)
        if not callable(resolver):
            raise AuthorityDenied("journal.unavailable", "root bindings have no protected journal resolver")
        return resolver(
            root_id,
            expected_active_generation_digest=expected_active_generation_digest,
        )

    def resource_job_ledger_path(self) -> Path:
        """Return the fixed ledger child of the current protected authority journal.

        The active journal catalog revalidates its root path and inode. The
        database filename is an installer constant; neither setup nor a worker
        can select a filesystem location for the job ledger.
        """
        return _root_resource_job_ledger_path(self.bindings, self.enrollment)


def compose_root_authority_runtime(
    *,
    service: AuthorityService,
    enrollment: ProtectedEnrollment,
    bindings: RootRuntimeBindings,
    artifact_catalog: ArtifactCatalog,
    vault: RootCredentialVault,
) -> RootAuthorityRuntime:
    """Assemble selected runtime registries from the active verified snapshot.

    Active job state is placed only below the digest-bound protected authority
    journal. If active resource jobs exist, the root-installed source and
    native execution registries must already be attached to the real service;
    missing observer, artifact, backend, or effect joins leave jobs unroutable.
    """
    if (not isinstance(service, AuthorityService)
            or not isinstance(enrollment, ProtectedEnrollment)
            or not isinstance(bindings, RootRuntimeBindings)
            or not isinstance(artifact_catalog, ArtifactCatalog)
            or not isinstance(vault, RootCredentialVault)):
        raise AuthorityDenied("authority.composition", "root runtime inputs are not verified authority objects")
    if (bindings.artifact_catalog is not artifact_catalog
            or bindings.process_manager is not service.process_effect_handler
            or not isinstance(service.authority_epoch, str) or not service.authority_epoch
            or service.service_generation_digest != enrollment.protected_enrollment_digest):
        raise AuthorityDenied("authority.composition", "runtime bindings do not match this service epoch and catalog")

    source_observer_unavailable_reason: str | None = None
    source_receipt_runtime = None
    schema_catalog = None
    action_resolver = None
    prepared_native_mcp = None
    mcp_discovery_registry = None
    if enrollment.native_mcp_tool_binding_records:
        try:
            from .mcp_discovery_registry import MCPDiscoveryObservationRegistry

            prepared_native_mcp = _prepare_native_mcp_selection(
                service=service, enrollment=enrollment, bindings=bindings,
            )
            mcp_discovery_registry = MCPDiscoveryObservationRegistry(
                service=service, invocation_registry=None,
                runtime_bindings=bindings,
                registration_index=prepared_native_mcp[0],
                protected_services=prepared_native_mcp[1],
                current_mcp_generations=prepared_native_mcp[2],
                monotonic=service.monotonic,
            )
        except Exception:
            prepared_native_mcp = None
            mcp_discovery_registry = None

    def assemble_source_schema_runtime() -> None:
        """Build exactly one receipt/derivation registry for this startup."""
        nonlocal source_receipt_runtime, schema_catalog, action_resolver
        from .source_artifact_receipts import build_root_schema_receipt_runtime
        from hermes_installer.mcp.native_schema_catalog import NativeMCPProtectedSchemaCatalog

        if source_receipt_runtime is None:
            source_receipt_runtime = build_root_schema_receipt_runtime(
                bindings, enrollment, mcp_discovery_registry=mcp_discovery_registry,
            )
            if mcp_discovery_registry is not None:
                mcp_discovery_registry.attach_schema_derivation_registry(
                    source_receipt_runtime.derivations,
                )
        if schema_catalog is None:
            if mcp_discovery_registry is not None:
                from hermes_installer.mcp.native_execution import build_native_mcp_schema_catalog
                if prepared_native_mcp is None:
                    raise AuthorityDenied(
                        "native.mcp", "dynamic schema rows lack their protected registration index",
                    )
                schema_catalog = build_native_mcp_schema_catalog(
                    enrollment.native_schema_artifact_records,
                    authority_service=service,
                    artifact_catalog=artifact_catalog,
                    staging_root=enrollment.artifact_staging_directory,
                    registration_index=prepared_native_mcp[0],
                    schema_derivation_registry=source_receipt_runtime.derivations,
                    expected_uid=vault.expected_uid,
                )
            else:
                schema_catalog = NativeMCPProtectedSchemaCatalog.from_protected_records(
                    enrollment.native_schema_artifact_records,
                    read_artifact=source_receipt_runtime.verifier.read_artifact,
                    verify_source_receipt=source_receipt_runtime.verifier.verify_source_receipt,
                )
        if enrollment.native_bridges and action_resolver is None:
            action_resolver = _ProtectedNativeActionResolver(
                bindings, schema_catalog,
                service_generation_digest=service.service_generation_digest,
            )

    broker_candidate = getattr(service, "native_bridge_broker", None)
    provider_selection = None
    if (service.source_observer_registry is not None and schema_catalog is None
            and (enrollment.native_bridges or enrollment.native_mcp_tool_binding_records)):
        # A caller may have attached the concrete source registry earlier in
        # the same root startup transaction. Still resolve the exact active
        # schema receipt/catalog here; never let an already-attached observer
        # silently disable selected MCP composition.
        try:
            assemble_source_schema_runtime()
        except Exception:
            source_observer_unavailable_reason = (
                "active source-derived native schemas or artifact receipt runtime are unavailable"
            )
    if service.source_observer_registry is None:
        # Root schema receipts and the bridge candidate are assembled before
        # source observers, breaking the actual provider/source dependency
        # cycle without publishing a partially attached broker.
        if enrollment.native_bridges or enrollment.native_mcp_tool_binding_records:
            try:
                assemble_source_schema_runtime()
                if enrollment.native_bridges:
                    broker_candidate, provider_selection = _build_native_bridge_candidate(
                        service=service, enrollment=enrollment, bindings=bindings, vault=vault,
                    )
            except Exception:
                source_observer_unavailable_reason = (
                    "active provider schemas, source derivation, live admission, or bridge broker did not join"
                )
    if service.source_observer_registry is None:
        observer_enrollments = getattr(bindings, "source_observer_enrollments", None)
        if not isinstance(observer_enrollments, Mapping) or not observer_enrollments:
            source_observer_unavailable_reason = "no active protected source-observer enrollment is selected"
        elif source_observer_unavailable_reason is not None:
            pass
        elif getattr(service, "native_loader_observation_store", None) is not None:
            source_observer_unavailable_reason = (
                "a loader observation store is already installed without its matching source registry"
            )
        else:
            from .source_observers import SourceObserverEnrollment

            if any(not isinstance(value, SourceObserverEnrollment)
                   or key != value.observer_enrollment_id
                   for key, value in observer_enrollments.items()):
                source_observer_unavailable_reason = (
                    "source-observer candidates are not complete typed protected joins"
                )
            else:
                manager = bindings.process_manager
                broker = broker_candidate
                from .native_bridge import NativeBridgeBroker

                if (not callable(getattr(manager, "set_native_loader_observation_store", None))
                        or not callable(getattr(manager, "is_owned_active_process_handle", None))
                        or not callable(getattr(manager, "resolve_live_peer", None))
                        or not callable(getattr(manager, "resolve_native_package_for_peer", None))):
                    source_observer_unavailable_reason = (
                        "root process manager lacks the registered native loader OpenFile custody hooks"
                    )
                elif getattr(manager, "native_loader_observation_store", None) is not None:
                    source_observer_unavailable_reason = (
                        "root process manager already owns a loader store outside this service composition"
                    )
                elif (not isinstance(broker, NativeBridgeBroker)
                      or getattr(broker, "service", None) is not service
                      or not callable(getattr(broker, "resolve_pending_pair_for_context", None))
                      or not callable(getattr(broker, "peer_role_artifact_resolver", None))
                      or not callable(getattr(bindings, "resolve_native_bridge_role_artifact", None))
                      or not isinstance(getattr(broker, "bridges", None), Mapping)
                      or not isinstance(getattr(broker, "observer_delivery_bindings", None), Mapping)):
                    source_observer_unavailable_reason = (
                        "active native bridge lacks its protected pending-pair and delivery-role resolver"
                    )
                elif (not broker.bridges
                      or dict(broker.bridges) != dict(bindings.native_bridges)
                      or set(broker.observer_delivery_bindings) != set(broker.bridges)):
                    source_observer_unavailable_reason = (
                        "active native bridges lack complete protected observer delivery bindings"
                    )
                elif (not callable(getattr(bindings, "resolve_native_package", None))
                      or not isinstance(getattr(bindings, "source_observer_enrollments", None), Mapping)
                      or not callable(getattr(service, "attach_source_observer_registry", None))):
                    source_observer_unavailable_reason = (
                        "active native package catalog or root source registry attachment is unavailable"
                    )
                else:
                    from .native_bridge import RootObserverDeliveryBinding

                    delivery_bindings_ready = True
                    for bridge_id, bridge in broker.bridges.items():
                        rows = broker.observer_delivery_bindings.get(bridge_id)
                        protected_rows = getattr(bridge, "observer_delivery_bindings", None)
                        protected_projection = tuple(
                            (getattr(item, "observer_enrollment_id", None),
                             getattr(item, "delivery_role", None))
                            for item in protected_rows
                        ) if isinstance(protected_rows, tuple) else None
                        if (not isinstance(rows, tuple) or not rows
                                or protected_projection != tuple(
                                    (item.observer_enrollment_id, item.delivery_role) for item in rows
                                )
                                or any(not isinstance(row, RootObserverDeliveryBinding)
                                       or row.delivery_role not in {"producer", "gateway"}
                                       or row.observer_enrollment_id not in observer_enrollments
                                       for row in rows)
                                or len({row.observer_enrollment_id for row in rows}) != len(rows)):
                            delivery_bindings_ready = False
                            break
                        for row in rows:
                            observer = observer_enrollments[row.observer_enrollment_id]
                            peer_role = row.delivery_role
                            if (observer.profile_id != getattr(bridge, f"{peer_role}_profile_id", None)
                                    or observer.generation != getattr(bridge, f"{peer_role}_generation", None)
                                    or observer.principal_id != getattr(bridge, f"{peer_role}_principal_id", None)
                                    or observer.producer_uid != getattr(bridge, f"{peer_role}_uid", None)):
                                delivery_bindings_ready = False
                                break
                        if not delivery_bindings_ready:
                            break
                    if not delivery_bindings_ready:
                        source_observer_unavailable_reason = (
                            "native bridge delivery rows do not join exact active source observer peers"
                        )
                if source_observer_unavailable_reason is None:
                    # These are actual root constructors, not callback
                    # declarations. Store and registry remain uninstalled if
                    # any protected join or custody constructor rejects.
                    from .native_custody_proof import (
                        RootNativeLoaderObservationStore,
                        active_native_catalog_resolver,
                        attach_root_source_observers,
                        native_bridge_source_target_selector,
                    )

                    try:
                        store = RootNativeLoaderObservationStore(
                            manager,
                            active_native_catalog_resolver(
                                bindings,
                                service_generation_digest=service.service_generation_digest,
                            ),
                            clock=service.monotonic,
                            source_target_selector=native_bridge_source_target_selector(
                                broker, clock=service.monotonic,
                            ),
                        )
                    except (TypeError, ValueError, AuthorityDenied):
                        source_observer_unavailable_reason = (
                            "active native loader catalog or pending-pair proof resolver rejected composition"
                        )
                    else:
                        registry = attach_root_source_observers(
                            service=service,
                            observer_enrollments=observer_enrollments,
                            process_resolver=manager.resolve_live_peer,
                            package_resolver=bindings.resolve_native_package,
                            loader_observations=store,
                        )
                        try:
                            manager.set_native_loader_observation_store(store)
                            if (broker_candidate is not None and provider_selection is not None
                                    and source_receipt_runtime is not None
                                    and schema_catalog is not None and action_resolver is not None):
                                from .provider_runtime_composition import attach_provider_response_registry
                                from .native_runtime_observer import NativeRuntimeObserver

                                attach_provider_response_registry(
                                    service=service, broker=broker_candidate,
                                    selection=provider_selection,
                                    source_observers=registry,
                                    process_resolver=manager.resolve_live_peer,
                                    action_resolver=action_resolver,
                                )
                                provider_effect_observers: dict[tuple[str, str, str], str] = {}
                                for (provider_id, target, recipient), observer_id in (
                                        provider_selection.provider_result_observer_ids.items()):
                                    selected_provider = provider_selection.provider_enrollments_by_id.get(provider_id)
                                    selected_bridges = [bridge for bridge in broker_candidate.bridges.values()
                                                        if bridge.provider_enrollment_id == provider_id
                                                        and bridge.target == target
                                                        and bridge.recipient == recipient]
                                    if (selected_provider is None or selected_provider.target != target
                                            or selected_provider.recipient != recipient
                                            or len(selected_bridges) != 1):
                                        raise AuthorityDenied(
                                            "native.provider.result", "provider observer differs from selected route",
                                        )
                                    producer_uid = selected_bridges[0].producer_uid
                                    producer_binding = service.bindings_by_uid.get(producer_uid)
                                    for capability in ("provider-inference", "provider-tool-call"):
                                        rule = service.rules.get((capability, "provider.dispatch", target))
                                        if (rule is not None and rule.recipient == recipient
                                                and producer_binding is not None
                                                and capability in producer_binding.capabilities):
                                            provider_effect_observers[(
                                                capability, "provider.dispatch", target,
                                            )] = observer_id
                                if provider_effect_observers:
                                    if service.native_runtime_observer is None:
                                        service.attach_native_runtime_observer(NativeRuntimeObserver(
                                            source_observers=registry,
                                            effect_observer_ids=provider_effect_observers,
                                        ))
                                    elif (service.native_runtime_observer.source_observers is not registry
                                          or any(service.native_runtime_observer.effect_observer_ids.get(key)
                                                 != value for key, value in provider_effect_observers.items())):
                                        raise AuthorityDenied(
                                            "native.provider.result", "installed result observer differs from provider selection",
                                        )
                        except BaseException:
                            try:
                                registry.close()
                            except BaseException:
                                pass
                            try:
                                store.close()
                            except BaseException:
                                pass
                            service.source_observer_registry = None
                            if getattr(service, "source_receipt_delivery", None) is registry:
                                service.source_receipt_delivery = None
                            try:
                                del service.native_loader_observation_store
                            except AttributeError:
                                pass
                            raise

    native_mcp_unavailable_reason: str | None = None
    if enrollment.native_mcp_tool_binding_records:
        if mcp_discovery_registry is None or prepared_native_mcp is None:
            native_mcp_unavailable_reason = (
                "selected native MCP service/index could not be prepared from active protected rows"
            )
        elif schema_catalog is None or service.source_observer_registry is None:
            native_mcp_unavailable_reason = (
                "source-verified native MCP schemas or the selected source-observer registry are unavailable"
            )
        elif service.native_invocation_registry is None:
            native_mcp_unavailable_reason = (
                "native MCP requires the attached root provider invocation registry"
            )
        elif service.native_mcp_dispatcher is not None:
            native_mcp_unavailable_reason = None
        else:
            try:
                mcp_discovery_registry.attach_invocation_registry(
                    service.native_invocation_registry,
                )
                _build_native_mcp_dispatcher(
                    service=service, enrollment=enrollment, bindings=bindings,
                    schema_catalog=schema_catalog,
                    source_observers=service.source_observer_registry,
                    prepared=prepared_native_mcp,
                    mcp_discovery_registry=mcp_discovery_registry,
                )
            except Exception as exc:
                native_mcp_unavailable_reason = (
                    f"selected native MCP dispatcher rejected composition ({type(exc).__name__})"
                )

    from .resource_jobs import (
        ResourceJobAuthority, index_resource_job_records,
        parse_resource_backend_records, parse_resource_body_recipes,
        parse_resource_scope_binding_records, parse_resource_validator_records,
    )

    backends = parse_resource_backend_records(enrollment.resource_backend_enrollment_records)
    recipes = parse_resource_body_recipes(enrollment.resource_body_recipe_records)
    scope_bindings = parse_resource_scope_binding_records(
        getattr(enrollment, "resource_scope_binding_records", ()))
    validators = parse_resource_validator_records(
        getattr(enrollment, "resource_validator_records", ()))
    source_observers = service.source_observer_registry
    observer_records = getattr(source_observers, "observers", MappingProxyType({}))
    issuer_records = {
        record.issuer_channel_id: record for record in enrollment.source_issuers
    }
    jobs = index_resource_job_records(
        enrollment.resource_job_records,
        backend_enrollments=backends,
        body_recipes=recipes,
        scope_bindings=scope_bindings,
        validators=validators,
        source_issuers=issuer_records,
        source_observers=observer_records,
    )

    selected_resources = None
    selected_resource_unavailable_reason: str | None = None
    selected_resource_records = getattr(enrollment, "selected_resource_execution_records", ())
    if selected_resource_records:
        resolve_selected = getattr(bindings, "resolve_selected_resource_execution", None)
        if not isinstance(selected_resource_records, tuple) or not callable(resolve_selected):
            selected_resource_unavailable_reason = (
                "active selected resource rows lack the root materialization receipt resolver"
            )
        else:
            try:
                from hermes_installer.registry.resources_runtime import (
                    SelectedResourceExecution, SelectedResourceRegistry,
                )

                selected_rows: list[Any] = []
                seen_selected: set[tuple[str, str, str]] = set()
                for raw in selected_resource_records:
                    if not isinstance(raw, Mapping):
                        raise AuthorityDenied(
                            "resource.selection", "active selected resource row is malformed",
                        )
                    resource_id = raw.get("resource_id")
                    generation = raw.get("resource_generation")
                    profile_id = raw.get("profile_id")
                    key = (resource_id, generation, profile_id)
                    if (any(not isinstance(value, str) or not value for value in key)
                            or key in seen_selected):
                        raise AuthorityDenied(
                            "resource.selection", "active selected resource identity is missing or duplicated",
                        )
                    seen_selected.add(key)
                    selected = resolve_selected(
                        resource_id, resource_generation=generation, profile_id=profile_id,
                    )
                    if (type(selected) is not SelectedResourceExecution
                            or selected.identity.resource_id != resource_id
                            or selected.generation_digest != enrollment.protected_enrollment_digest
                            or selected.profile_id != profile_id
                            or type(selected.enabled) is not bool):
                        raise AuthorityDenied(
                            "resource.selection", "materialized selected resource differs from active protected row",
                        )
                    selected_rows.append(selected)
                selected_resources = SelectedResourceRegistry(
                    selected_rows,
                    expected_generation_digest=enrollment.protected_enrollment_digest,
                )
            except Exception as exc:
                selected_resources = None
                selected_resource_unavailable_reason = (
                    f"active selected resource materialization rejected ({type(exc).__name__})"
                )
    elif jobs:
        selected_resource_unavailable_reason = (
            "active resource jobs have no digest-bound selected materialization rows"
        )

    memory_runtime = None
    if enrollment.memory_enrollments:
        if (bindings.enrollment_catalog is None
                or not callable(getattr(bindings, "resolve_root_journal", None))
                or bindings.process_manager is not service.process_effect_handler):
            raise AuthorityDenied(
                "authority.composition",
                "active memory enrollments require the protected service catalog, journal resolver, and shared process custody",
            )
        from hermes_installer.memory.broker import build_memory_handlers, build_memory_runtime
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment

        memory_targets: dict[tuple[str, str, str], Any] = {}
        by_profile_generation: dict[tuple[str, str], Any] = {}
        for item in enrollment.memory_enrollments.values():
            if not isinstance(item, MemoryServiceEnrollment):
                raise AuthorityDenied("authority.composition", "active memory enrollment is not a typed protected record")
            principal_resolver = getattr(bindings, "resolve_selected_native_principal", None)
            catalog_digest = getattr(bindings.enrollment_catalog, "digest", None)
            if not callable(principal_resolver) or not isinstance(catalog_digest, str):
                raise AuthorityDenied("authority.composition", "active memory principal binding resolver is unavailable")
            try:
                principal = principal_resolver(
                    item.profile_id, item.service_generation, catalog_digest,
                )
            except Exception:
                raise AuthorityDenied("authority.composition", "active memory principal is stale or absent") from None
            if (getattr(principal, "principal_id", None) != item.principal_id
                    or getattr(principal, "profile_id", None) != item.profile_id
                    or getattr(principal, "namespace_id", None) != item.namespace_identity
                    or service.profile_generations.get(item.profile_id) != item.service_generation):
                raise AuthorityDenied("authority.composition", "memory enrollment differs from its selected authority principal")
            target_key = (item.profile_id, item.namespace_identity, item.provider)
            prior_target = memory_targets.get(target_key)
            if prior_target is not None and prior_target != item:
                raise AuthorityDenied("authority.composition", "active memory target enrollment is ambiguous")
            memory_targets[target_key] = item
            profile_key = (item.profile_id, item.service_generation)
            prior_enrollment = by_profile_generation.get(profile_key)
            if prior_enrollment is not None and prior_enrollment != item:
                raise AuthorityDenied("authority.composition", "active memory profile generation resolves ambiguously")
            by_profile_generation[profile_key] = item

        def resolve_memory_enrollment(profile_id: str, generation: str) -> Any:
            selected = by_profile_generation.get((profile_id, generation))
            if selected is None:
                raise AuthorityDenied("memory.unavailable", "memory enrollment is not active in this generation")
            return selected

        memory_runtime = build_memory_runtime(
            memory_targets, service,
            root_journal_resolver=bindings.resolve_root_journal,
            expected_active_generation_digest=enrollment.protected_enrollment_digest,
            vault=vault, service_catalog=bindings.enrollment_catalog,
            process_manager=bindings.process_manager,
            enrollment_resolver=resolve_memory_enrollment,
        )
        if memory_runtime.get("state_root_ready") is True:
            step_authority = memory_runtime.get("step_authority")
            # Derive only fixed handlers whose selected route has a complete
            # protected compound recipe and a corresponding unique HI12 rule.
            # Capture remains unavailable until a root-observed event joins it.
            generated = build_memory_handlers(
                targets=memory_runtime["targets"],
                owner_state=memory_runtime["owner_state"],
                queue=memory_runtime["queue"], ipc=memory_runtime["ipc"],
                engines=memory_runtime["engines"],
                eligibility=memory_runtime["eligibility"],
                maximum_timeout=memory_runtime["maximum_timeout"],
                compound_executor=memory_runtime["compound_executor"],
            )
            for key, handler in generated.items():
                operation, target = key
                if operation not in {"memory.search", "memory.doctor"}:
                    continue
                action = operation.removeprefix("memory.")
                target_entry = next((value for value in memory_runtime["targets"].values()
                                     if "memory:" + value.provider + ":" + action == target), None)
                route_id = target_entry.route_for(action) if target_entry is not None else None
                connector_key = (("connector.open", target_entry.enrollment.target_id)
                                 if target_entry is not None and target_entry.enrollment is not None
                                 else None)
                installed_connector = (service.handlers.get(connector_key)
                                       if connector_key is not None else None)
                internal_handler = (getattr(step_authority, "handle_connector_open", None)
                                    if step_authority is not None else None)
                same_connector = (
                    installed_connector is internal_handler
                    or (getattr(installed_connector, "__self__", None) is step_authority
                        and getattr(installed_connector, "__func__", None)
                        is getattr(internal_handler, "__func__", None))
                )
                if (route_id is None or route_id not in target_entry.enrollment.fixed_route_map
                        or service.memory_step_effect_authority is not step_authority
                        or not same_connector
                        or not callable(internal_handler)
                        or not any(rule.operation == operation and rule.target == target
                                   for rule in service.rules.values())):
                    continue
                if key in service.handlers:
                    raise AuthorityDenied("authority.composition", "active memory route duplicates an installed handler")
                service.handlers[key] = handler

    build_execution_service = None
    build_catalog = getattr(bindings, "build_catalog", None)
    build_store = getattr(bindings, "build_store", None)
    process_manager = bindings.process_manager
    if (build_catalog is not None and build_store is not None
            and bindings.enrollment_catalog is not None
            and isinstance(enrollment.artifact_staging_directory, Path)
            and callable(getattr(bindings, "resolve_build_process_profile", None))):
        # The root store and process manager are the same protected instances
        # already held by RootRuntimeBindings; no second store, key, or manager
        # is created here. Without a root CPython probe, handlers() exposes
        # Colibri only and leaves Coral unavailable.
        from .build_execution import (
            LinuxBuildOutputFactInspector, ProtectedBuildArtifactRootResolver,
            RootBuildExecutionService,
        )
        from hermes_installer.managed_process_custodian import ManagedBuildJobRunner

        artifact_roots = ProtectedBuildArtifactRootResolver(
            artifact_catalog, enrollment.artifact_staging_directory,
            owner_uid=vault.expected_uid,
        )
        inspector = LinuxBuildOutputFactInspector(
            toolchain_root_resolver=artifact_roots.toolchain_root,
            source_root_resolver=artifact_roots.source_root,
            runtime_probe=None,
            owner_uid=vault.expected_uid,
        )
        candidate_build_execution_service = RootBuildExecutionService(
            build_catalog=build_catalog,
            service_catalog=bindings.enrollment_catalog,
            artifact_catalog=artifact_catalog,
            artifact_staging_root=enrollment.artifact_staging_directory,
            launcher=ManagedBuildJobRunner(
                process_manager,
                process_profile_resolver=bindings.resolve_build_process_profile,
            ),
            fact_inspector=inspector,
            store=build_store,
            expected_uid=vault.expected_uid,
            monotonic=service.monotonic,
        )
        installed_build_routes = 0
        for key, handler in candidate_build_execution_service.handlers().items():
            operation, target = key
            # A catalog profile alone is not activation. Install only if the
            # active service snapshot also grants this exact selected route.
            selected = False
            if not any(rule.operation == operation and rule.target == target
                       for rule in service.rules.values()):
                continue
            for protected_build_row in enrollment.protected_build_records:
                if not isinstance(protected_build_row, Mapping):
                    continue
                generation = protected_build_row.get("generation")
                if (protected_build_row.get("target_id") != target
                        or not isinstance(generation, str) or not generation):
                    continue
                try:
                    profile = build_catalog.resolve(target, generation)
                    service_profile = bindings.enrollment_catalog.resolve(
                        profile.build_service_enrollment_id,
                        profile.build_service_generation,
                    )
                except Exception:
                    continue
                if (service_profile.profile_id in service.profile_generations
                        and service.profile_generations[service_profile.profile_id]
                        == service_profile.generation):
                    selected = True
                    break
            if not selected:
                continue
            if key in service.handlers:
                raise AuthorityDenied("authority.composition", "build route duplicates an installed handler")
            service.handlers[key] = handler
            installed_build_routes += 1
        if installed_build_routes:
            build_execution_service = candidate_build_execution_service

    job_authority = None
    resource_task_unavailable_reason: str | None = None
    if jobs:
        if source_observers is None:
            raise AuthorityDenied("authority.composition", "active resource jobs have no root source observer")
        from hermes_installer.registry.resource_jobs import ResourceJobLedger

        job_store = _root_resource_job_ledger_path(bindings, enrollment)

        ledger = ResourceJobLedger(job_store, monotonic=service.monotonic)
        selected_generations: dict[str, str] = {}
        for row in enrollment.resource_job_records:
            if row.get("selected_enabled") is True:
                resource_id, generation = row.get("resource_id"), row.get("generation")
                if isinstance(resource_id, str) and isinstance(generation, str):
                    old = selected_generations.setdefault(resource_id, generation)
                    if old != generation:
                        raise AuthorityDenied("authority.composition", "active resource generations are ambiguous")

        def selected_generation(resource_id: str) -> str:
            generation = selected_generations.get(resource_id)
            if generation is None:
                raise AuthorityDenied("resource.unavailable", "resource is not selected in the active generation")
            return generation

        profile_task_adapters: Mapping[tuple[str, str], Any] = MappingProxyType({})
        if any(backend.execution_binding is not None
               for enrollment_row in jobs.values()
               for backend in enrollment_row.backends.values()):
            if source_observers is not None:
                from hermes_installer.registry.resource_backends import build_resource_profile_task_adapters
                profile_task_adapters = build_resource_profile_task_adapters(
                    jobs, protected_bindings=bindings, authority_service=service,
                )
            if not profile_task_adapters:
                resource_task_unavailable_reason = (
                    "selected process-task adapters are not joined to active protected backend catalogs"
                )
        job_authority = ResourceJobAuthority(
            service=service, enrollments=jobs, ledger=ledger,
            selected_generation=selected_generation,
            profile_task_adapters=profile_task_adapters,
        )

        if profile_task_adapters:
            broker = getattr(service, "native_bridge_broker", None)
            loader_store = getattr(service, "native_loader_observation_store", None)
            if broker is not None and loader_store is not None and service.native_invocation_registry is not None:
                task_graph: tuple[Any, ...] | None = None
                task_phase = "root task observation registries"
                try:
                    from .task_native_observation import RootTaskNativeObservationRegistry
                    from .source_observers import RootNativeExecutionSelectionRegistry
                    from .native_custody_proof import RootNativeInputTargetResolver
                    from .native_input_observer import RootNativeInputObserver
                    from .source_observers import RootNativeInputDeliveryRegistry
                    from .native_observer_wiring import RootTaskInputCoordinator
                    from .native_request_observation import NativeRequestObservationRegistry
                    from .native_turn_observation import RootNativeTurnObservationRegistry
                    from hermes_installer.registry.resource_backends import RootArtifactValidator
                    from .resource_task_execution import RootResourceTaskRunner

                    task_native = RootTaskNativeObservationRegistry(
                        source_observer_registry=source_observers,
                        native_bridge_broker=broker,
                        admitted_task_registry=job_authority,
                        process_custody_registry=process_manager,
                        monotonic=service.monotonic,
                    )
                    task_phase = "selected native execution and PIDFD target resolver"
                    selected_execution = RootNativeExecutionSelectionRegistry(
                        source_observer_registry=source_observers,
                        admitted_task_registry=job_authority,
                        process_custody_registry=process_manager,
                        task_native_observation_registry=task_native,
                        monotonic=service.monotonic,
                    )
                    loader_proof_resolver = loader_store.source_observer_loaded_package_resolver
                    target_resolver = RootNativeInputTargetResolver(
                        selected_execution, process_manager,
                        observer_enrollments=bindings.source_observer_enrollments,
                        loader_observations=loader_store,
                    )
                    selected_execution.attach_native_input_target_resolver(target_resolver)
                    input_observer = RootNativeInputObserver.for_selected_resource_tasks(
                        service=service, source_observers=source_observers,
                        selected_execution_registry=selected_execution,
                        process_resolver=process_manager.resolve_live_peer,
                        loaded_package_proof_resolver=loader_proof_resolver,
                        monotonic=service.monotonic,
                    )
                    task_native.attach_native_input_observer(input_observer, selected_execution)
                    task_phase = "selector-free native input delivery and pre-stdin coordinator"
                    input_delivery = RootNativeInputDeliveryRegistry.from_root_runtime(
                        source_observers, selected_execution, process_manager,
                    )
                    task_phase = "root native request and whole-turn observation"
                    request_observer = NativeRequestObservationRegistry(
                        service=service, source_observers=source_observers,
                        native_input_observer=input_observer,
                        bridges=broker.bridges,
                        process_resolver=broker.process_resolver,
                        monotonic=service.monotonic,
                    )
                    invocation_registry = service.native_invocation_registry
                    response_resolver = getattr(
                        invocation_registry, "resolve_turn_response_observation", None,
                    )
                    if not callable(response_resolver):
                        raise AuthorityDenied(
                            "native.turn", "provider registry has no root response resolver",
                        )
                    turn_observer = RootNativeTurnObservationRegistry(
                        service=service,
                        selected_execution_registry=selected_execution,
                        input_observer=input_observer,
                        source_observers=source_observers,
                        process_custody=process_manager,
                        response_resolver=response_resolver,
                        monotonic=service.monotonic,
                    )
                    coordinator = RootTaskInputCoordinator.from_root_runtime(
                        task_native, selected_execution, input_observer, source_observers,
                        process_manager, input_delivery, turn_observer,
                    )
                    task_phase = "protected result validator and native completion runner"
                    result_validator = RootArtifactValidator(
                        backend_enrollments=backends, validators=validators,
                        artifact_catalog=artifact_catalog,
                        staging_root=enrollment.artifact_staging_directory,
                        active_service_generation_digest=enrollment.protected_enrollment_digest,
                        expected_uid=vault.expected_uid,
                    )
                    task_runner = RootResourceTaskRunner(
                        service=service, job_authority=job_authority,
                        profile_task_adapters=profile_task_adapters,
                        protected_bindings=bindings, result_validator=result_validator,
                        native_observations=task_native,
                    )
                    task_graph = (task_native, input_delivery, request_observer,
                                  turn_observer, coordinator, task_runner)
                except Exception as exc:
                    # Keep selected task routes absent unless the complete
                    # task-input, custody, result and native-evidence graph
                    # is installed. Other service routes remain available.
                    task_graph = None
                    resource_task_unavailable_reason = (
                        f"{task_phase} rejected composition ({type(exc).__name__})"
                    )
                if task_graph is not None:
                    (_, input_delivery, request_observer, turn_observer,
                     coordinator, task_runner) = task_graph
                    broker.attach_native_request_observer(request_observer)
                    broker.attach_native_turn_observer(turn_observer)
                    service.attach_native_turn_observation_registry(turn_observer)
                    service.native_invocation_registry.attach_native_turn_observation_registry(
                        turn_observer,
                    )
                    native_effect_observer = service.native_runtime_observer
                    attach_turn_effects = getattr(native_effect_observer, "attach_turn_observation", None)
                    if not callable(attach_turn_effects):
                        raise AuthorityDenied(
                            "native.turn", "root effect observer cannot join whole-turn observation",
                        )
                    attach_turn_effects(
                        invocation_registry=service.native_invocation_registry,
                        native_turn_observation_registry=turn_observer,
                    )
                    service.attach_native_input_delivery_registry(input_delivery)
                    process_manager.set_task_input_coordinator(coordinator)
                    service.attach_resource_task_runtime(task_runner, job_authority)
                    resource_task_unavailable_reason = None
            elif profile_task_adapters:
                resource_task_unavailable_reason = (
                    "active source observers, provider response registry, or native loader proof are unavailable"
                )

        job_handlers = job_authority.handlers()
        for key in job_handlers:
            if key in service.handlers:
                raise AuthorityDenied("authority.composition", "resource job route duplicates an active handler")
            if not any(rule.operation == key[0] and rule.target == key[1]
                       for rule in service.rules.values()):
                raise AuthorityDenied("authority.composition", "resource job route lacks a protected effect rule")
        service.handlers.update(job_handlers)

    return RootAuthorityRuntime(
        service=service, enrollment=enrollment, bindings=bindings,
        artifact_catalog=artifact_catalog, vault=vault,
        boot_epoch=service.authority_epoch,
        backend_enrollments=MappingProxyType(dict(backends)),
        body_recipes=MappingProxyType(dict(recipes)),
        scope_bindings=MappingProxyType(dict(scope_bindings)),
        validators=MappingProxyType(dict(validators)),
        source_observer_unavailable_reason=source_observer_unavailable_reason,
        resource_task_unavailable_reason=resource_task_unavailable_reason,
        job_enrollments=MappingProxyType(dict(jobs)), memory_runtime=memory_runtime,
        job_authority=job_authority, build_execution_service=build_execution_service,
        native_mcp_unavailable_reason=native_mcp_unavailable_reason,
        native_mcp_discovery_registry=mcp_discovery_registry,
        selected_resources=selected_resources,
        selected_resource_unavailable_reason=selected_resource_unavailable_reason,
    )
