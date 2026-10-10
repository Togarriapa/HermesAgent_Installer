"""Capture the actual Hermes ``register_tool`` source surface without effects.

This producer invokes only each reviewed implementation's registration method
with an inert context. Captured metadata is source evidence, not an authority
receipt: callers must join source, bounded result-schema and observer receipts
before converting these rows into executable native candidates.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from hermes_installer.components.native_plugins import (
    _PLUGIN_IDS,
    _PLUGIN_VERSIONS,
    resolve_native_plugin_implementation,
)
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
    ReviewedPluginAdapterRegistry,
)


class NativeRegistrationCaptureDenied(ValueError):
    """The pinned component registration surface could not be captured safely."""


@dataclass(frozen=True, slots=True)
class CapturedHermesRegistration:
    adapter_id: str
    native_tool_name: str
    toolset: str
    argument_schema: Mapping[str, Any]
    description: str
    handler_id: str
    handler_module: str
    registration_source_path: str
    registration_source_sha256: str
    native_schema_sha256: str


@dataclass(frozen=True, slots=True)
class NativeRegistrationActionBinding:
    """One source-declared finite route from a registered tool to an action."""

    selector_values: Mapping[str, str]
    action_id: str
    argument_projection: tuple[tuple[str, str], ...]
    workflow_id: str | None = None


@dataclass(frozen=True, slots=True)
class RootNativeRegistrationActionBinding:
    """Exact v113 registration-to-selected action/workflow foreign keys."""

    selector_values: Mapping[str, str]
    action_binding_id: str | None
    argument_projection: tuple[tuple[str, str], ...]
    workflow_id: str | None


_ROOT_PROJECTION_SEAL = object()


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeRegistrationProjection:
    """One root-issued executable registration after every required join.

    Construction is sealed to the root projection producer. Source capture,
    catalog observations, and reviewed source maps alone cannot mint this row.
    """

    registration_id: str
    native_tool_name: str
    native_server_name: str
    toolset: str
    family: str
    adapter_id: str
    argument_schema: Mapping[str, Any]
    result_schema: Mapping[str, Any]
    native_schema_sha256: str
    registration_source_artifact_id: str
    registration_source_sha256: str
    registration_source_receipt_handle: str
    handler_kind: str
    handler_id: str
    selector_fields: tuple[str, ...]
    action_bindings: tuple[RootNativeRegistrationActionBinding, ...]
    observer_enrollment_ids: tuple[str, ...]
    _seal: object = field(repr=False, compare=False, default=None)

    def __post_init__(self) -> None:
        if self._seal is not _ROOT_PROJECTION_SEAL:
            raise TypeError("native registration projection rows are issued by the root resolver")


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeRegistrationProjectionBundle:
    """The exact registration tuple and its one-to-one candidate projection."""

    registrations: tuple[RootNativeRegistrationProjection, ...]
    candidate_records: tuple[Mapping[str, Any], ...]


class NativeRegistrationProjectionDenied(PermissionError):
    """Selected registration, result schema, action or observer joins are incomplete."""


def build_root_native_registration_projection(
        selection: Any, definitions: Any,
) -> RootNativeRegistrationProjectionBundle:
    """Build the complete executable all-42 projection from a sealed factory DTO.

    This is called only by the root setup session after current-selection
    revalidation. It consumes the factory's distinct v113 action, workflow,
    registration, schema, observer, and setup-receipt rows; source maps and
    inventory captures cannot be passed independently as authority.
    """
    from hermes_installer.authority.bootstrap_runtime_factory import (
        RootNativeAssemblyDefinitions, RootNativeBootstrapAssemblySelection,
    )

    if (type(selection) is not RootNativeBootstrapAssemblySelection
            or type(definitions) is not RootNativeAssemblyDefinitions
            or selection.selection_handle != definitions.selection_handle
            or not selection.selection_handle):
        raise NativeRegistrationProjectionDenied("root selected native assembly definitions are absent or stale")
    from hermes_installer.authority.bootstrap_runtime_factory import RootNativeRegistrationSchemaReceipt

    required_tuples = (
        definitions.registration_records, definitions.action_records,
        definitions.workflow_records, definitions.action_registration_records,
        definitions.native_schema_records, definitions.native_schema_bytes,
        definitions.source_issuer_records, definitions.result_schema_receipts,
        definitions.release_module_receipts, definitions.native_mcp_tool_bindings,
    )
    if any(not isinstance(value, tuple) for value in required_tuples):
        raise NativeRegistrationProjectionDenied("selected registration source/schema/action joins are unavailable")

    try:
        captured = capture_actual_hermes_registrations()
        source_rows = observe_root_native_registrations(definitions.release_module_receipts, captured)
        source_by_name = {row.native_tool_name: row for row in source_rows}
        reviewed = reviewed_native_registration_definitions(captured)
        reviewed_by_name = {row.native_tool_name: row for row in reviewed}
        if len(source_by_name) != 42 or len(reviewed_by_name) != 42:
            raise ValueError

        receipts: dict[str, tuple[Any, bytes]] = {}
        for receipt in definitions.result_schema_receipts:
            if type(receipt) is not RootNativeRegistrationSchemaReceipt:
                raise ValueError
            payload = receipt.read_current()
            reviewed_schema = next(row for row in reviewed_local_registration_result_schemas(captured)
                                   if row.artifact_id == receipt.artifact_id)
            if (receipt.sha256 != reviewed_schema.sha256
                    or receipt.size_bytes != reviewed_schema.size_bytes
                    or receipt.relative_path != reviewed_schema.relative_path
                    or len(payload) != reviewed_schema.size_bytes
                    or hashlib.sha256(payload).hexdigest() != reviewed_schema.sha256
                    or json.loads(payload) != reviewed_schema.schema
                    or receipt.artifact_id in receipts):
                raise ValueError
            receipts[receipt.artifact_id] = (receipt, payload)
        expected_local = {row.artifact_id for row in reviewed_local_registration_result_schemas(captured)}
        if set(receipts) != expected_local:
            raise ValueError

        schema_bytes = dict(definitions.native_schema_bytes)
        schema_rows: dict[str, list[Mapping[str, Any]]] = {}
        for raw in definitions.native_schema_records:
            if not isinstance(raw, Mapping):
                raise ValueError
            required_schema_fields = {
                "id", "artifact_id", "sha256", "schema_kind", "native_package_id",
                "native_package_generation", "adapter_id", "action_id", "source_receipt_handle",
                "size_bytes", "derivation_receipt_handle",
            }
            if set(raw) != required_schema_fields:
                raise ValueError
            schema_rows.setdefault(raw["id"], []).append(raw)
        parsed_schemas: dict[str, Mapping[str, Any]] = {}
        for schema_id, rows in schema_rows.items():
            body = schema_bytes.get(schema_id)
            if not isinstance(body, bytes) or not rows:
                raise ValueError
            parsed = json.loads(body)
            canonical = _canonical(parsed)
            if body not in {canonical, canonical + b"\n"}:
                raise ValueError
            digest = hashlib.sha256(body).hexdigest()
            for row in rows:
                if (row["native_package_id"] != selection.package_id
                        or row["native_package_generation"] != selection.native_package_generation
                        or row["sha256"] != digest or row["size_bytes"] != len(body)
                        or not isinstance(row["source_receipt_handle"], str)
                        or not row["source_receipt_handle"]):
                    raise ValueError
            parsed_schemas[schema_id] = parsed
        if set(schema_bytes) != set(schema_rows):
            raise ValueError

        action_rows = _index_projection_records(
            definitions.action_records, "action_binding_id",
            {"action_binding_id", "adapter_id", "action_id", "manifest_sha256",
             "adapter_artifact_id", "adapter_sha256", "argument_schema_id", "result_schema_id",
             "effect_enrollment_id", "operation", "capability", "target_id", "recipient",
             "generation", "observer_enrollment_ids"},
        )
        workflow_rows = _index_projection_records(
            definitions.workflow_records, "id",
            {"id", "registration_id", "external_argument_schema_id", "external_result_schema_id",
             "workflow_artifact_id", "workflow_sha256", "workflow_source_receipt_handle",
             "step_action_binding_ids", "generation"},
        )
        issuer_rows = _index_projection_records(
            definitions.source_issuer_records, "observer_enrollment_id",
            {"issuer_channel_id", "producer_profile_id", "producer_role_artifact_id",
             "producer_role_sha256", "capture_schema_id", "allowed_parent_channels", "generation",
             "observer_enrollment_id", "source_action_ids"}, allow_optional={"private_provider_route_ids"},
        )
        registration_rows = tuple(definitions.registration_records)
        if len(registration_rows) != 42:
            raise ValueError

        projections: list[RootNativeRegistrationProjection] = []
        candidates: list[Mapping[str, Any]] = []
        names_seen: set[str] = set()
        known_handler_kinds = {"effect-action", "finite-selector", "finite-workflow",
                               "public-registry-read", "owner-overlay", "mcp-dispatch"}
        for raw in registration_rows:
            fields = {
                "registration_id", "native_tool_name", "toolset", "family", "adapter_id",
                "argument_schema_id", "result_schema_id", "native_schema_sha256",
                "registration_source_artifact_id", "registration_source_sha256",
                "registration_source_receipt_handle", "handler_kind", "handler_id",
                "selector_fields", "action_bindings", "observer_enrollment_ids", "generation",
            }
            if not isinstance(raw, Mapping) or set(raw) != fields:
                raise ValueError
            name = raw["native_tool_name"]
            source = source_by_name.get(name)
            reviewed_row = reviewed_by_name.get(name)
            source_definition = reviewed_row
            if (source is None or source_definition is None or name in names_seen
                    or raw["registration_id"] != source.registration_id
                    or raw["adapter_id"] != source.adapter_id
                    or raw["toolset"] != source.toolset or raw["family"] != source.family
                    or raw["handler_kind"] != source.handler_kind
                    or raw["handler_kind"] not in known_handler_kinds
                    or raw["handler_id"] != source.handler_id
                    or raw["native_schema_sha256"] != source.native_schema_sha256
                    or raw["registration_source_artifact_id"] != source.registration_source_artifact_id
                    or raw["registration_source_sha256"] != source.registration_source_sha256
                    or raw["registration_source_receipt_handle"] != source.registration_source_receipt_handle
                    or raw["generation"] != selection.native_package_generation
                    or tuple(raw["selector_fields"]) != source_definition.selector_fields):
                raise ValueError
            names_seen.add(name)

            argument_id, result_id = raw["argument_schema_id"], raw["result_schema_id"]
            argument_schema = parsed_schemas.get(argument_id)
            result_schema = parsed_schemas.get(result_id)
            if (not isinstance(argument_schema, Mapping) or not isinstance(result_schema, Mapping)
                    or _canonical(argument_schema) != _canonical(source.argument_schema)
                    or hashlib.sha256(_canonical(argument_schema)).hexdigest() != source.native_schema_sha256
                    or not any(row["schema_kind"] == "arguments" and row["adapter_id"] == source.adapter_id
                               for row in schema_rows[argument_id])
                    or not any(row["schema_kind"] == "result" and row["adapter_id"] == source.adapter_id
                               for row in schema_rows[result_id])):
                raise ValueError

            local_receipt = receipts.get(result_id)
            if local_receipt is not None:
                receipt, payload = local_receipt
                matching = [row for row in schema_rows[result_id]
                            if row["schema_kind"] == "result" and row["adapter_id"] == source.adapter_id]
                if (not matching or any(row["artifact_id"] != receipt.artifact_id
                                        or row["sha256"] != receipt.sha256
                                        or row["size_bytes"] != receipt.size_bytes
                                        or row["source_receipt_handle"] != receipt.artifact_receipt_handle
                                        for row in matching)
                        or json.loads(payload) != result_schema):
                    raise ValueError

            raw_bindings = raw["action_bindings"]
            if not isinstance(raw_bindings, (tuple, list)) or len(raw_bindings) != len(source_definition.action_bindings):
                raise ValueError
            selected_workflows = [row for row in workflow_rows.values()
                                  if row["registration_id"] == source.registration_id]
            workflow_id = None
            if source_definition.handler_kind == "finite-workflow":
                if len(selected_workflows) != 1:
                    raise ValueError
                workflow = selected_workflows[0]
                workflow_id = workflow["id"]
                if (workflow["generation"] != selection.native_package_generation
                        or workflow["external_argument_schema_id"] != argument_id
                        or workflow["external_result_schema_id"] != result_id
                        or not workflow["workflow_source_receipt_handle"]):
                    raise ValueError
            elif selected_workflows:
                raise ValueError

            projected_bindings: list[RootNativeRegistrationActionBinding] = []
            for raw_binding, source_binding in zip(raw_bindings, source_definition.action_bindings, strict=True):
                expected_fields = {"selector_values", "action_binding_id", "argument_projection", "workflow_id"}
                if not isinstance(raw_binding, Mapping) or set(raw_binding) != expected_fields:
                    raise ValueError
                if dict(raw_binding["selector_values"]) != dict(source_binding.selector_values):
                    raise ValueError
                expected_id: str | None
                expected_workflow: str | None
                if source_definition.handler_kind in {"public-registry-read", "owner-overlay", "mcp-dispatch"}:
                    expected_id, expected_workflow = None, None
                elif source_definition.handler_kind == "finite-workflow":
                    expected_id, expected_workflow = None, workflow_id
                else:
                    expected_id = f"{source.adapter_id}:action:{source_binding.action_id}"
                    expected_workflow = None
                    action = action_rows.get(expected_id)
                    if (action is None or action["adapter_id"] != source.adapter_id
                            or action["action_id"] != source_binding.action_id
                            or action["generation"] != selection.native_package_generation):
                        raise ValueError
                expected_projection = tuple(source_binding.argument_projection)
                actual_projection = tuple((item["name"], item["source_field"])
                                          for item in raw_binding["argument_projection"])
                if (raw_binding["action_binding_id"] != expected_id
                        or raw_binding["workflow_id"] != expected_workflow
                        or actual_projection != expected_projection):
                    raise ValueError
                projected_bindings.append(RootNativeRegistrationActionBinding(
                    MappingProxyType(dict(source_binding.selector_values)), expected_id,
                    expected_projection, expected_workflow,
                ))

            observer_ids = raw["observer_enrollment_ids"]
            if (not isinstance(observer_ids, (tuple, list)) or not observer_ids
                    or len(set(observer_ids)) != len(observer_ids)):
                raise ValueError
            lexical_action = (source_definition.action_bindings[0].action_id
                              if source_definition.handler_kind == "effect-action"
                              else source.registration_id)
            if source_definition.handler_kind != "mcp-dispatch":
                for observer_id in observer_ids:
                    issuer = issuer_rows.get(observer_id)
                    if (issuer is None or issuer["generation"] != selection.service_generation
                            or lexical_action not in issuer["source_action_ids"]):
                        raise ValueError

            native_server_name = "hermes-installer"
            if source_definition.handler_kind == "mcp-dispatch":
                matches = [row for row in definitions.native_mcp_tool_bindings
                           if row.get("native_tool_name") == name
                           and row.get("native_schema_sha256") == source.native_schema_sha256]
                if len(matches) != 1:
                    raise ValueError
                native_server_name = matches[0]["native_server_name"]
                lexical_action = matches[0]["id"]
                if any(lexical_action not in issuer_rows[observer_id]["source_action_ids"]
                       for observer_id in observer_ids):
                    raise ValueError

            projection = RootNativeRegistrationProjection(
                registration_id=source.registration_id,
                native_tool_name=name,
                native_server_name=native_server_name,
                toolset=source.toolset,
                family=source.family,
                adapter_id=source.adapter_id,
                argument_schema=MappingProxyType(dict(argument_schema)),
                result_schema=MappingProxyType(dict(result_schema)),
                native_schema_sha256=source.native_schema_sha256,
                registration_source_artifact_id=source.registration_source_artifact_id,
                registration_source_sha256=source.registration_source_sha256,
                registration_source_receipt_handle=source.registration_source_receipt_handle,
                handler_kind=source_definition.handler_kind,
                handler_id=source.handler_id,
                selector_fields=tuple(source_definition.selector_fields),
                action_bindings=tuple(projected_bindings),
                observer_enrollment_ids=tuple(observer_ids),
                _seal=_ROOT_PROJECTION_SEAL,
            )
            projections.append(projection)
            lexical = (source_definition.action_bindings[0].action_id
                       if source_definition.handler_kind == "effect-action"
                       else lexical_action)
            candidates.append(MappingProxyType({
                "native_tool_name": name, "adapter_id": source.adapter_id,
                "action_id": lexical, "argument_schema": dict(argument_schema),
                "result_schema": dict(result_schema), "native_schema_sha256": source.native_schema_sha256,
                "observer_enrollment_ids": list(observer_ids), "native_server_name": native_server_name,
                "description": source.description, "registration_id": source.registration_id,
                "toolset": source.toolset, "family": source.family,
                "handler_kind": source_definition.handler_kind,
            }))

        if names_seen != set(source_by_name) or len(projections) != 42:
            raise ValueError
        return RootNativeRegistrationProjectionBundle(tuple(projections), tuple(candidates))
    except NativeRegistrationProjectionDenied:
        raise
    except Exception:
        raise NativeRegistrationProjectionDenied(
            "actual registrations lack a current selected result-schema, action, workflow or observer join") from None


def _index_projection_records(rows: tuple[Any, ...], key: str, fields: set[str], *,
                              allow_optional: set[str] = set()) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    if not isinstance(rows, tuple):
        raise ValueError
    for row in rows:
        if (not isinstance(row, Mapping) or frozenset(row) not in {frozenset(fields),
                                                                   frozenset(fields | allow_optional)}
                or not isinstance(row.get(key), str) or not row[key] or row[key] in result):
            raise ValueError
        result[row[key]] = row
    return result


@dataclass(frozen=True, slots=True)
class ReviewedNativeRegistrationDefinition:
    """Source-reviewed routing facts for one actual Hermes registration.

    These definitions are deliberately separate from source capture and from
    executable projection rows.  They contain no receipts or readiness flags;
    the root factory must join current source, schema, and observer proofs.
    """

    adapter_id: str
    native_tool_name: str
    family: str
    handler_kind: str
    selector_fields: tuple[str, ...]
    action_bindings: tuple[NativeRegistrationActionBinding, ...]


@dataclass(frozen=True, slots=True)
class ReviewedNativeRegistrationResultSchema:
    """Source-pinned result schema contract; it is not a protected receipt."""

    native_tool_name: str
    schema_id: str
    artifact_id: str
    relative_path: str
    sha256: str
    size_bytes: int
    handler_kind: str
    schema: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class RootNativeRegistrationSourceObservation:
    """One actual tool registration joined to a live held-release module proof."""

    registration_id: str
    adapter_id: str
    native_tool_name: str
    toolset: str
    family: str
    handler_kind: str
    handler_id: str
    argument_schema: Mapping[str, Any]
    native_schema_sha256: str
    registration_source_artifact_id: str
    registration_source_sha256: str
    registration_source_receipt_handle: str


class NativeRegistrationSourceObservationDenied(ValueError):
    """Actual registrations could not join the held release source receipts."""


def observe_root_native_registrations(
        release_module_receipts: tuple[Any, ...],
        registrations: tuple[CapturedHermesRegistration, ...] | None = None,
) -> tuple[RootNativeRegistrationSourceObservation, ...]:
    """Bind all 42 real register_tool calls to current root-held module bytes.

    `release_module_receipts` must contain actual RootReleaseModuleReceipt
    instances returned by the live root setup session. Their own `read_current`
    rechecks release/actor/session currentness on every call. This function
    emits source observations only; a separate root resolver must join result
    schemas, selected actions/workflows, and observer enrollment receipts before
    producing any executable candidate.
    """
    from hermes_installer.authority.bootstrap_runtime_factory import RootReleaseModuleReceipt

    captured = registrations if registrations is not None else capture_actual_hermes_registrations()
    if not isinstance(captured, tuple) or len(captured) != 42:
        raise NativeRegistrationSourceObservationDenied("exactly 42 actual Hermes registration calls are required")
    if not isinstance(release_module_receipts, tuple) or not release_module_receipts:
        raise NativeRegistrationSourceObservationDenied("held release module receipts are unavailable")
    by_path: dict[str, RootReleaseModuleReceipt] = {}
    for receipt in release_module_receipts:
        if not isinstance(receipt, RootReleaseModuleReceipt):
            raise NativeRegistrationSourceObservationDenied("source observation requires root-issued release module receipt types")
        path = receipt.relative_path
        if (not isinstance(path, str) or not path.startswith("src/hermes_installer/components/")
                or path in by_path):
            raise NativeRegistrationSourceObservationDenied("release source receipt path is unreviewed or duplicated")
        by_path[path] = receipt
    expected_paths = {"src/" + row.registration_source_path for row in captured}
    if set(by_path) != expected_paths:
        raise NativeRegistrationSourceObservationDenied("held release receipts do not cover the exact actual handler source modules")
    definitions = {row.native_tool_name: row for row in reviewed_native_registration_definitions(captured)}
    output: list[RootNativeRegistrationSourceObservation] = []
    for source in captured:
        definition = definitions[source.native_tool_name]
        receipt = by_path["src/" + source.registration_source_path]
        current_bytes = receipt.read_current()
        if (not isinstance(current_bytes, bytes)
                or receipt.sha256 != source.registration_source_sha256
                or len(current_bytes) != receipt.size_bytes
                or hashlib.sha256(current_bytes).hexdigest() != source.registration_source_sha256):
            raise NativeRegistrationSourceObservationDenied("held release source bytes differ from the actual handler module")
        output.append(RootNativeRegistrationSourceObservation(
            registration_id=f"{source.adapter_id}:tool:{source.native_tool_name}",
            adapter_id=source.adapter_id,
            native_tool_name=source.native_tool_name,
            toolset=source.toolset,
            family=definition.family,
            handler_kind=definition.handler_kind,
            handler_id=source.handler_id,
            argument_schema=source.argument_schema,
            native_schema_sha256=source.native_schema_sha256,
            registration_source_artifact_id=receipt.artifact_id,
            registration_source_sha256=receipt.sha256,
            registration_source_receipt_handle=receipt.source_receipt_handle,
        ))
    return tuple(sorted(output, key=lambda row: row.native_tool_name))


class NativeRegistrationResultSchemaDenied(ValueError):
    """The reviewed bounded local result-schema artifacts drifted."""


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeRegistrationResultSchemaObservation:
    """A catalog-held observation of one reviewed result-schema artifact.

    This is deliberately not a selected schema/action receipt.  It proves only
    that exact bytes are present in the current immutable root artifact catalog.
    """

    schema: ReviewedNativeRegistrationResultSchema
    catalog_observation: Any


class NativeRegistrationResultSchemaObservationDenied(ValueError):
    """The reviewed result schema could not be observed in the root catalog."""


@dataclass(frozen=True, slots=True, repr=False)
class RootNativeRegistrationResultSchemaReceipt:
    """Prepared-setup scoped root receipt for exact packaged schema bytes."""

    schema: ReviewedNativeRegistrationResultSchema
    source_receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    prepared_setup_receipt_handle: str
    prepared_generation_id: str
    _observation: Any = field(repr=False, compare=False)
    _registry_seal: object = field(repr=False, compare=False)


class RootNativeRegistrationResultSchemaReceiptRegistry:
    """Mint/resolve setup-scoped receipts from the actual root catalog APIs.

    This narrow registry avoids requiring an already-active native schema row
    to compile the catalog which will contain that row. It still requires the
    current prepared setup authorization and the held root catalog observer;
    it never turns caller-provided schema rows or hashes into receipts.
    """

    def __init__(self, observer: Any, artifact_receipt_registry: Any,
                 setup_authorization: Any) -> None:
        from hermes_installer.authority.bootstrap_enrollment import (
            RootArtifactReceiptRegistry, VerifiedRootSetupAuthorization,
        )
        from hermes_installer.authority.source_artifact_receipts import (
            RootCatalogArtifactObserver, RootSetupCatalogArtifactObserver,
        )

        if (type(observer) not in {RootCatalogArtifactObserver, RootSetupCatalogArtifactObserver}
                or type(artifact_receipt_registry) is not RootArtifactReceiptRegistry
                or type(setup_authorization) is not VerifiedRootSetupAuthorization):
            raise NativeRegistrationResultSchemaObservationDenied(
                "root setup authorization, artifact receipt registry and catalog observer are required")
        self._observer = observer
        self._receipts = artifact_receipt_registry
        self._authorization = setup_authorization
        self._seal = object()
        self._issued: dict[str, RootNativeRegistrationResultSchemaReceipt] = {}

    def mint(self, *, prepared_setup_receipt_handle: str, prepared_generation_id: str,
             artifact_id: str | None = None,
             registrations: tuple[CapturedHermesRegistration, ...] | None = None
             ) -> tuple[RootNativeRegistrationResultSchemaReceipt, ...]:
        if (not isinstance(prepared_setup_receipt_handle, str) or not prepared_setup_receipt_handle
                or not isinstance(prepared_generation_id, str) or not prepared_generation_id):
            raise NativeRegistrationResultSchemaObservationDenied(
                "current selected prepared setup identity is required")
        try:
            output: list[RootNativeRegistrationResultSchemaReceipt] = []
            reviewed_schemas = reviewed_local_registration_result_schemas(registrations)
            if artifact_id is not None:
                reviewed_schemas = tuple(row for row in reviewed_schemas if row.artifact_id == artifact_id)
                if len(reviewed_schemas) != 1:
                    raise ValueError
            for schema in reviewed_schemas:
                observation = self._observer.observe(schema.artifact_id, schema.sha256)
                if (observation.artifact_id != schema.artifact_id
                        or observation.sha256 != schema.sha256
                        or observation.size_bytes != schema.size_bytes
                        or not self._observer.verify_current(observation)):
                    observation.close()
                    raise ValueError
                handle = self._receipts.mint(
                    store_id=f"artifact:{schema.artifact_id}:{schema.sha256}",
                    receipt_id=schema.schema_id,
                    setup_authorization=self._authorization,
                )
                receipt = RootNativeRegistrationResultSchemaReceipt(
                    schema, handle, self._authorization.setup_session_id,
                    self._authorization.transaction_handle, prepared_setup_receipt_handle,
                    prepared_generation_id, observation, self._seal,
                )
                self._verify_bytes(receipt)
                self._issued[handle] = receipt
                output.append(receipt)
            if len(output) != (1 if artifact_id is not None else 8):
                raise ValueError
            return tuple(sorted(output, key=lambda row: row.schema.native_tool_name))
        except NativeRegistrationResultSchemaDenied as exc:
            raise NativeRegistrationResultSchemaObservationDenied(str(exc)) from None
        except Exception:
            raise NativeRegistrationResultSchemaObservationDenied(
                "root setup schema receipts could not be minted from the exact catalog artifacts") from None

    def resolve(self, receipt: RootNativeRegistrationResultSchemaReceipt, *,
                prepared_setup_receipt_handle: str, prepared_generation_id: str,
                setup_authorization: Any) -> bytes:
        from hermes_installer.authority.bootstrap_enrollment import VerifiedRootSetupAuthorization

        if (os.geteuid() != 0 or type(receipt) is not RootNativeRegistrationResultSchemaReceipt
                or receipt._registry_seal is not self._seal
                or self._issued.get(receipt.source_receipt_handle) is not receipt
                or type(setup_authorization) is not VerifiedRootSetupAuthorization
                or setup_authorization != self._authorization
                or receipt.setup_session_id != setup_authorization.setup_session_id
                or receipt.transaction_handle != setup_authorization.transaction_handle
                or receipt.prepared_setup_receipt_handle != prepared_setup_receipt_handle
                or receipt.prepared_generation_id != prepared_generation_id):
            raise NativeRegistrationResultSchemaObservationDenied(
                "schema receipt is stale or belongs to another selected prepared setup")
        try:
            artifact_id, digest = self._receipts.lookup(receipt.source_receipt_handle, setup_authorization)
            if (artifact_id != receipt.schema.artifact_id or digest != receipt.schema.sha256
                    or not self._observer.verify_current(receipt._observation)):
                raise ValueError
            return self._verify_bytes(receipt)
        except Exception:
            raise NativeRegistrationResultSchemaObservationDenied(
                "selected setup schema receipt is absent, stale or changed") from None

    def _verify_bytes(self, receipt: RootNativeRegistrationResultSchemaReceipt) -> bytes:
        if not self._observer.verify_current(receipt._observation):
            raise ValueError
        fd = receipt._observation.open_blob()
        try:
            data = bytearray()
            while len(data) <= receipt.schema.size_bytes:
                block = os.read(fd, min(64 * 1024, receipt.schema.size_bytes + 1 - len(data)))
                if not block:
                    break
                data.extend(block)
        finally:
            os.close(fd)
        raw = bytes(data)
        if (len(raw) != receipt.schema.size_bytes
                or hashlib.sha256(raw).hexdigest() != receipt.schema.sha256
                or json.loads(raw) != receipt.schema.schema
                or not self._observer.verify_current(receipt._observation)):
            raise ValueError
        return raw


def observe_root_native_registration_result_schemas(
        observer: Any,
        registrations: tuple[CapturedHermesRegistration, ...] | None = None,
) -> tuple[RootNativeRegistrationResultSchemaObservation, ...]:
    """Observe all eight pinned local result schemas through the root catalog.

    The observer must be a production root catalog observer bound to the
    selected setup/catalog. Callers cannot
    supply artifact IDs, hashes, bytes, or parsed schemas.  The returned held
    observations are source evidence only; active protected selection and
    action/observer enrollment proofs remain separate required joins.
    """
    from hermes_installer.authority.source_artifact_receipts import (
        RootCatalogArtifactObserver, RootSetupCatalogArtifactObserver,
    )

    if type(observer) not in {RootCatalogArtifactObserver, RootSetupCatalogArtifactObserver}:
        raise NativeRegistrationResultSchemaObservationDenied(
            "a root-bound catalog artifact observer is required")
    try:
        schemas = reviewed_local_registration_result_schemas(registrations)
        output: list[RootNativeRegistrationResultSchemaObservation] = []
        for schema in schemas:
            observation = observer.observe(schema.artifact_id, schema.sha256)
            if (observation.artifact_id != schema.artifact_id
                    or observation.sha256 != schema.sha256
                    or observation.size_bytes != schema.size_bytes
                    or not observer.verify_current(observation)):
                raise ValueError
            fd = observation.open_blob()
            try:
                data = bytearray()
                while len(data) <= schema.size_bytes:
                    block = os.read(fd, min(64 * 1024, schema.size_bytes + 1 - len(data)))
                    if not block:
                        break
                    data.extend(block)
            finally:
                os.close(fd)
            if (len(data) != schema.size_bytes
                    or hashlib.sha256(data).hexdigest() != schema.sha256
                    or json.loads(data) != schema.schema
                    or not observer.verify_current(observation)):
                observation.close()
                raise ValueError
            output.append(RootNativeRegistrationResultSchemaObservation(schema, observation))
        if {row.schema.native_tool_name for row in output} != {
                "agent37_discover_skills", "agent37_inspect_skill", "mcp_registry_discover",
                "mcp_registry_inspect", "resource_overlay_read", "resource_overlay_write",
                "resource_overlay_history", "resource_overlay_delete"}:
            raise ValueError
        return tuple(sorted(output, key=lambda row: row.schema.native_tool_name))
    except NativeRegistrationResultSchemaDenied as exc:
        raise NativeRegistrationResultSchemaObservationDenied(str(exc)) from None
    except Exception:
        raise NativeRegistrationResultSchemaObservationDenied(
            "exact reviewed result-schema artifacts are unavailable or stale in the root catalog") from None


def reviewed_local_registration_result_schemas(
        registrations: tuple[CapturedHermesRegistration, ...] | None = None,
) -> tuple[ReviewedNativeRegistrationResultSchema, ...]:
    """Load the eight source-pinned local schemas from the v114 artifact map.

    This validates the released source contract and exact schema file bytes.
    The returned rows are not selected protected schema receipts and cannot
    independently make a native candidate executable.
    """
    captured = registrations if registrations is not None else capture_actual_hermes_registrations()
    if not isinstance(captured, tuple) or len(captured) != 42:
        raise NativeRegistrationResultSchemaDenied("all actual registration sources are required")
    by_name = {row.native_tool_name: row for row in captured}
    root = Path(__file__).resolve().parents[3]
    map_path = root / "plans/amendments/2026-10-10-native-schema-catalog-identities-v114/native-local-schema-artifact-map-v2.json"
    bounds_path = root / "plans/amendments/2026-10-10-native-local-result-bounds-v110/native-local-registration-results-v1.json"
    try:
        artifact_map = json.loads(map_path.read_text(encoding="utf-8"))
        bounds = json.loads(bounds_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise NativeRegistrationResultSchemaDenied("reviewed local result schema source files are unavailable") from None
    rows = artifact_map.get("artifact_rows") if isinstance(artifact_map, Mapping) else None
    schemas = bounds.get("result_schemas") if isinstance(bounds, Mapping) else None
    if (not isinstance(artifact_map, Mapping) or not isinstance(bounds, Mapping)
            or artifact_map.get("schema") != 1 or bounds.get("schema") != 1
                or not isinstance(rows, list) or len(rows) != 8 or not isinstance(schemas, Mapping)
                or set(artifact_map) != {"schema", "artifact_rows", "publication", "native_schema_record_join",
                                        "result_constraints", "catalog_identity_correction_v114"}
                or set(bounds) != {"artifact_id", "result_schemas", "schema", "source_pins", "trust",
                               "unavailable_reason", "unavailable_results", "validation_limits", "validators"}):
        raise NativeRegistrationResultSchemaDenied("reviewed local result schema catalog has an unsupported shape")
    expected_handlers = {
        "agent37_discover_skills": "public-registry-read",
        "agent37_inspect_skill": "public-registry-read",
        "mcp_registry_discover": "public-registry-read",
        "mcp_registry_inspect": "public-registry-read",
        "resource_overlay_read": "owner-overlay",
        "resource_overlay_write": "owner-overlay",
        "resource_overlay_history": "owner-overlay",
        "resource_overlay_delete": "owner-overlay",
    }
    if set(schemas) != set(expected_handlers):
        raise NativeRegistrationResultSchemaDenied("reviewed result schemas do not cover the exact eight bounded local tools")
    # The v110 claims are only accepted while their source implementation
    # pins still match the actual registrations observed above.
    source_pins = bounds.get("source_pins")
    native_plugins_digest = hashlib.sha256(
        (root / "src/hermes_installer/components/native_plugins.py").read_bytes()).hexdigest()
    public_registries_digest = hashlib.sha256(
        (root / "src/hermes_installer/components/public_registries.py").read_bytes()).hexdigest()
    if (not isinstance(source_pins, Mapping)
            or source_pins.get("src/hermes_installer/components/native_plugins.py") != native_plugins_digest
            or native_plugins_digest != by_name["resource_overlay_read"].registration_source_sha256
            or source_pins.get("src/hermes_installer/components/public_registries.py") != public_registries_digest):
        raise NativeRegistrationResultSchemaDenied("bounded result schema source pins differ from actual handler modules")
    output: list[ReviewedNativeRegistrationResultSchema] = []
    seen: set[str] = set()
    for raw in rows:
        expected = {"tool_name", "schema_id", "artifact_id", "path", "sha256", "size_bytes",
                    "schema_role", "handler_kind"}
        if not isinstance(raw, Mapping) or set(raw) != expected:
            raise NativeRegistrationResultSchemaDenied("local result schema artifact row is malformed")
        tool = raw["tool_name"]
        if (tool not in expected_handlers or tool in seen or tool not in by_name
                or raw["handler_kind"] != expected_handlers[tool] or raw["schema_role"] != "result"
                or raw["schema_id"] != f"installer-native-local-result-{tool}-v1"
                or raw["artifact_id"] != raw["schema_id"]):
            raise NativeRegistrationResultSchemaDenied("local result schema artifact identity is not source-reviewed")
        relative = raw["path"]
        if not isinstance(relative, str) or not relative.startswith(
                "plans/amendments/2026-10-10-native-local-schema-artifacts-v112/"):
            raise NativeRegistrationResultSchemaDenied("local result schema file is outside its fixed reviewed directory")
        path = root / relative
        try:
            data = path.read_bytes()
        except OSError:
            raise NativeRegistrationResultSchemaDenied("local result schema artifact bytes are unavailable") from None
        if (type(raw["size_bytes"]) is not int or len(data) != raw["size_bytes"]
                or not isinstance(raw["sha256"], str)
                or hashlib.sha256(data).hexdigest() != raw["sha256"]):
            raise NativeRegistrationResultSchemaDenied("local result schema artifact bytes differ from the reviewed pin")
        try:
            parsed = json.loads(data)
            canonical = _canonical(parsed)
        except (ValueError, RecursionError):
            raise NativeRegistrationResultSchemaDenied("local result schema artifact is invalid JSON") from None
        if data not in {canonical, canonical + b"\n"} or parsed != schemas[tool]:
            raise NativeRegistrationResultSchemaDenied("local schema artifact differs from its reviewed result definition")
        seen.add(tool)
        output.append(ReviewedNativeRegistrationResultSchema(
            tool, raw["schema_id"], raw["artifact_id"], relative,
            raw["sha256"], raw["size_bytes"], raw["handler_kind"], parsed,
        ))
    if seen != set(expected_handlers):
        raise NativeRegistrationResultSchemaDenied("local result schema artifact coverage is incomplete")
    return tuple(sorted(output, key=lambda row: row.native_tool_name))


class NativeRegistrationDefinitionDenied(ValueError):
    """Actual captured registrations do not match the reviewed finite map."""


def reviewed_native_registration_definitions(
        registrations: tuple[CapturedHermesRegistration, ...] | None = None,
) -> tuple[ReviewedNativeRegistrationDefinition, ...]:
    """Resolve the exact 42-tool source map from current register_tool calls.

    This is source evidence only.  It does not issue result schemas, source
    receipts, observer enrollments, or effect authority.
    """
    captured = registrations if registrations is not None else capture_actual_hermes_registrations()
    if not isinstance(captured, tuple) or len(captured) != 42:
        raise NativeRegistrationDefinitionDenied("all 42 reviewed Hermes registrations are required")

    def direct(adapter: str, tool: str, action: str, fields: tuple[str, ...],
               *, kind: str = "effect-action"):
        return ReviewedNativeRegistrationDefinition(
            adapter, tool, adapter, kind, (),
            (NativeRegistrationActionBinding({}, action, tuple((field, field) for field in fields)),),
        )

    definitions: dict[str, ReviewedNativeRegistrationDefinition] = {}
    direct_rows = (
        ("github", "github_repository", "repo.get", ("repository",)),
        ("github", "github_list_issues", "issues.list", ("repository",)),
        ("github", "github_read_file", "content.get", ("path", "repository")),
        ("github", "github_write_file", "content.put", ("content", "message", "path", "repository", "sha")),
        ("github", "github_create_issue", "issue.create", ("body", "repository", "title")),
        ("composio", "composio_read", "invoke.read", ("arguments", "tool_slug")),
        ("composio", "composio_write", "invoke.write", ("arguments", "tool_slug")),
        ("codex", "codex_run", "run", ("prompt", "workspace_id")),
        ("ebook-toolchain", "ebook_toolchain_build", "run", ("format", "recipe_id", "source_id", "title")),
        ("ebook-toolchain", "ebook_toolchain_inspect", "inspect", ("recipe_id", "source_id")),
        ("ebook-toolchain", "ebook_toolchain_validate", "validate", ("recipe_id", "source_id")),
        ("kobo-bridge", "kobo_bridge_deliver", "deliver", ("enrollment_id", "export_id")),
        ("kobo-bridge", "kobo_bridge_read_export", "read", ("book_id", "enrollment_id")),
        ("authentik-authorization", "authentik_current_principal", "resolve-session-principal-to-user", ()),
        ("authentik-authorization", "authentik_active_user_identity", "read-active-user-identity", ()),
        ("authentik-authorization", "authentik_effective_groups", "read-user-effective-groups", ()),
        ("authentik-authorization", "authentik_verify_system_membership", "verify-effective-System-membership", ()),
        ("authentik-authorization", "authentik_system_alarm_recipients", "list-current-effective-System-members-for-alarm-delivery", ()),
        ("cloudflare-homelab", "cloudflare_homelab_read_dns", "read-approved-dns-records", ("hostname",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel", "read-approved-tunnel-state", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel_configuration", "read-approved-tunnel-configuration", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_read_tunnel_connectors", "read-approved-tunnel-connectors", ("tunnel",)),
        ("cloudflare-homelab", "cloudflare_homelab_update_dns", "update-approved-dns-record", ("content", "hostname", "proxied", "ttl")),
        ("cloudflare-homelab", "cloudflare_homelab_update_tunnel", "update-approved-tunnel-configuration", ("hostname", "tunnel")),
        ("mcp-registry", "mcp_registry_discover", "discover-servers", ("cursor", "latest_only", "limit", "search")),
        ("mcp-registry", "mcp_registry_inspect", "inspect-server-metadata", ("server_name", "version")),
        ("agent37-discovery", "agent37_discover_skills", "discover-skill-candidates", ("cursor", "limit", "minimum_stars", "owner", "recently_updated", "repo", "search", "sort")),
        ("agent37-discovery", "agent37_inspect_skill", "inspect-public-metadata", ("skill_id",)),
        ("resource-overlay-store", "resource_overlay_read", "read", ("record_id",)),
        ("resource-overlay-store", "resource_overlay_write", "write", ("expected_revision", "record_id", "value_base64")),
        ("resource-overlay-store", "resource_overlay_history", "history", ("record_id",)),
        ("resource-overlay-store", "resource_overlay_delete", "delete", ("expected_revision", "record_id")),
        ("web", "web_retrieve", "retrieve", ("url",)),
    )
    # The repeated GitHub row above is avoided below by keyed registration
    # definitions; the capture itself remains the authority for name coverage.
    for adapter, tool, action, fields in direct_rows:
        if tool in definitions:
            continue
        kind = ("public-registry-read" if adapter in {"mcp-registry", "agent37-discovery"}
                else "owner-overlay" if adapter == "resource-overlay-store" else "effect-action")
        if kind in {"public-registry-read", "owner-overlay"}:
            # The lexical action is the actual registered tool identity. Its
            # existing source handler owns the internal public/overlay route.
            action = f"{adapter}:tool:{tool}"
        definitions[tool] = direct(adapter, tool, action, fields, kind=kind)

    def finite(adapter: str, tool: str, family: str, kind: str, selector_fields: tuple[str, ...],
               rows: tuple[tuple[Mapping[str, str], str, tuple[tuple[str, str], ...]], ...]):
        definitions[tool] = ReviewedNativeRegistrationDefinition(
            adapter, tool, family, kind, selector_fields,
            tuple(NativeRegistrationActionBinding(dict(selector), action, projection)
                  for selector, action, projection in rows),
        )

    # Epic operation dispatch is explicit in LocalKanbanPlugin.invoke.
    epic_fields = {
        "create": ("epic-kanban", (("epic_id", "epic_id"), ("title", "title"))),
        "read": ("epic-kanban", (("board_id", "board_id"),)),
        "add_item": ("epic-kanban", (("board_id", "board_id"), ("description", "description"), ("item_type", "item_type"), ("title", "title"))),
        "move_item": ("epic-kanban", (("board_id", "board_id"), ("item_id", "item_id"), ("state", "state"))),
        "delete_accepted": ("epic-kanban", (("accepted_lifecycle_attestation_id", "accepted_lifecycle_attestation_id"), ("board_id", "board_id"))),
    }
    finite("epic-kanban", "epic_board", "epic-kanban", "finite-selector", ("operation",),
           tuple(({"operation": op}, action, projection) for op, (action, projection) in epic_fields.items()))

    # Financial data valid provider/operation pairs come from the exact source
    # scope table; invalid Cartesian combinations are intentionally absent.
    from hermes_installer.components.plugin_finance import _DATA_SCOPES
    finite("financial-data-hub", "financial_data_read", "financial-data-hub", "finite-selector",
           ("provider", "operation"), tuple(
               ({"provider": provider.value, "operation": operation.value}, "read",
                (("filters", "filters"), ("operation", "operation"), ("provider", "provider")))
               for provider, operations in sorted(_DATA_SCOPES.items(), key=lambda item: item[0].value)
               for operation in sorted(operations, key=lambda item: item.value)))

    from hermes_installer.components.plugin_finance import _EXECUTION_OPERATIONS, _LIVE_READS, _SANDBOX_READS
    finite("financial-execution-gateway", "financial_execute_one_order", "financial-execution-gateway",
           "finite-selector", ("provider", "operation"), tuple(
               ({"provider": provider, "operation": operation}, "execute",
                (("action", "action"), ("operation", "operation"), ("provider", "provider")))
               for provider, operations in sorted(_EXECUTION_OPERATIONS.items())
               for operation in sorted(operations)))
    finite("agent-live-wallet", "agent_live_wallet_action", "agent-live-wallet", "finite-selector",
           ("operation",), tuple(
               ({"operation": operation}, "read" if operation in _LIVE_READS else "execute",
                (("action", "action"), ("network", "network"), ("operation", "operation")))
               for operation in ("construct", "simulate", "estimate-fee", "inspect", "sign", "broadcast")))
    finite("agent-sandbox-wallet", "agent_sandbox_wallet_action", "agent-sandbox-wallet", "finite-selector",
           ("operation",), tuple(
               ({"operation": operation}, "read" if operation in _SANDBOX_READS else "execute",
                (("action", "action"), ("network", "network"), ("operation", "operation")))
               for operation in ("read-balance", "simulate", "inspect-receipt", "create-account", "reset-account",
                                 "sign-test-transaction", "send-test-asset", "deploy-test-contract", "reviewed-testnet-dapp")))

    from hermes_installer.components.plugin_homelab import _READ_QUERIES, _WRITE_ACTIONS
    finite("homelab-ops-broker", "homelab_ops_inspect", "homelab-ops-broker", "finite-selector",
           ("query",), tuple(({"query": value}, value, (("host", "host"), ("query", "query")))
                              for value in sorted(_READ_QUERIES)))
    finite("homelab-ops-broker", "homelab_ops_run", "homelab-ops-broker", "finite-selector",
           ("action",), tuple(({"action": value}, value, (("action", "action"), ("host", "host")))
                              for value in sorted(_WRITE_ACTIONS)))

    # These actual handlers invoke the fixed selected voice actions and return
    # source receipt/workflow records. The protected workflow identity is
    # joined later from the selected workflow catalog.
    for tool, action in (("voice_transcribe", "voice_transcribe"), ("voice_speak", "voice_speak")):
        definitions[tool] = ReviewedNativeRegistrationDefinition(
            "voice-pipeline", tool, "voice-pipeline", "finite-workflow", (),
            (NativeRegistrationActionBinding({}, action, (), None),),
        )

    captured_by_name = {row.native_tool_name: row for row in captured}
    if len(captured_by_name) != 42 or set(captured_by_name) != set(definitions):
        missing = sorted(set(captured_by_name) ^ set(definitions))
        raise NativeRegistrationDefinitionDenied(
            "reviewed source map does not cover the actual Hermes registration set: " + ", ".join(missing)
        )
    output = []
    for name, definition in definitions.items():
        source = captured_by_name[name]
        if source.adapter_id != definition.adapter_id:
            raise NativeRegistrationDefinitionDenied("captured registration adapter differs from its reviewed definition")
        properties = source.argument_schema.get("properties", {})
        if not isinstance(properties, Mapping):
            raise NativeRegistrationDefinitionDenied("captured registration argument properties are malformed")
        if any(field not in properties for field in definition.selector_fields):
            raise NativeRegistrationDefinitionDenied("reviewed selector field is absent from the actual source schema")
        for binding in definition.action_bindings:
            if any(field not in properties for _target, field in binding.argument_projection):
                raise NativeRegistrationDefinitionDenied("reviewed argument projection is absent from the actual source schema")
            for field, value in binding.selector_values.items():
                enum = properties.get(field, {}).get("enum") if isinstance(properties.get(field), Mapping) else None
                if not isinstance(enum, (tuple, list)) or value not in enum:
                    raise NativeRegistrationDefinitionDenied("reviewed selector literal is absent from the actual source enum")
        if definition.selector_fields:
            if any(not set(definition.selector_fields).issubset(binding.selector_values)
                   for binding in definition.action_bindings):
                raise NativeRegistrationDefinitionDenied("finite source selector coverage is incomplete")
            if len({tuple(sorted(binding.selector_values.items())) for binding in definition.action_bindings}) != len(definition.action_bindings):
                raise NativeRegistrationDefinitionDenied("finite source selector contains duplicate branches")
        output.append(definition)
    return tuple(sorted(output, key=lambda row: row.native_tool_name))


class _NoEffects:
    def invoke(self, *_args: Any, **_kwargs: Any) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted an effect")


class _NoAuthority:
    def __getattr__(self, _name: str) -> Any:
        raise NativeRegistrationCaptureDenied("registration capture attempted authority access")


class _OverlayFixture:
    def read(self, _record_id: str) -> None:
        return None

    def write(self, _record_id: str, _value: bytes, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay write")

    def history(self, _record_id: str) -> tuple[str, ...]:
        return ()

    def delete(self, _record_id: str, expected_revision: str | None = None) -> str:
        raise NativeRegistrationCaptureDenied("registration capture attempted an overlay delete")


class _CaptureContext:
    def __init__(self, adapter_id: str):
        self.adapter_id = adapter_id
        self.rows: list[CapturedHermesRegistration] = []

    def register_tool(self, *args: Any, **kwargs: Any) -> None:
        if args:
            if len(args) not in {4, 5}:
                raise NativeRegistrationCaptureDenied("Hermes tool registration positional shape is unsupported")
            fields = {"name": args[0], "toolset": args[1], "schema": args[2], "handler": args[3]}
            if len(args) == 5:
                fields["description"] = args[4]
            if set(fields) & set(kwargs):
                raise NativeRegistrationCaptureDenied("Hermes tool registration duplicates a field")
            fields.update(kwargs)
        else:
            fields = dict(kwargs)
        required = {"name", "toolset", "schema", "handler", "description"}
        allowed = required | {"requires_env", "is_async"}
        if set(fields) - allowed or not required.issubset(fields):
            raise NativeRegistrationCaptureDenied("Hermes tool registration has an unreviewed shape")
        name, toolset = fields["name"], fields["toolset"]
        schema, description, handler = fields["schema"], fields["description"], fields["handler"]
        if (not isinstance(name, str) or not name or len(name) > 512
                or not isinstance(toolset, str) or not toolset or len(toolset) > 128
                or not isinstance(schema, Mapping) or schema.get("type") != "object"
                or not isinstance(description, str) or not description
                or not callable(handler) or fields.get("is_async", False) is not False
                or fields.get("requires_env") is not None):
            raise NativeRegistrationCaptureDenied("Hermes tool registration fields are invalid")
        handler_module = getattr(handler, "__module__", None)
        handler_id = getattr(handler, "__qualname__", None)
        if not isinstance(handler_module, str) or not isinstance(handler_id, str):
            raise NativeRegistrationCaptureDenied("captured tool handler has no stable source identity")
        code = getattr(handler, "__code__", None)
        source_filename = getattr(code, "co_filename", None)
        if not isinstance(source_filename, str):
            source_filename = inspect.getsourcefile(handler)
        source_path = _relative_component_path(source_filename)
        source_bytes = (Path(__file__).resolve().parents[2] / source_path).read_bytes()
        plain_schema = json.loads(json.dumps(schema, sort_keys=True, ensure_ascii=False, allow_nan=False))
        schema_bytes = _canonical(plain_schema)
        self.rows.append(CapturedHermesRegistration(
            self.adapter_id, name, toolset, plain_schema, description,
            handler_id, handler_module, source_path,
            hashlib.sha256(source_bytes).hexdigest(),
            hashlib.sha256(schema_bytes).hexdigest(),
        ))


def capture_actual_hermes_registrations() -> tuple[CapturedHermesRegistration, ...]:
    """Run all 18 implementation registration methods with an effect-denying context.

    The returned projection reflects actual ``PluginContext.register_tool``
    calls. It deliberately lacks result schemas, source receipt handles, and
    observer enrollment IDs, so it cannot itself qualify a candidate index.
    """
    result: list[CapturedHermesRegistration] = []
    identity_digest = "0" * 64
    for adapter_id in _PLUGIN_IDS:
        implementation = resolve_native_plugin_implementation(adapter_id)
        if implementation is None or not callable(getattr(implementation, "register", None)):
            raise NativeRegistrationCaptureDenied("one reviewed native plugin has no registration implementation")
        identity = ResourceIdentity(
            adapter_id, "plugins", _PLUGIN_VERSIONS[adapter_id],
            f"plugins/{adapter_id}.yaml", "source-capture", identity_digest,
        )
        runtime = NativePluginRuntimeContext(
            identity=identity, declared_capabilities=(), authority=_NoAuthority(),
            invocation_contexts=lambda **_kwargs: (),
            selected_adapters=ReviewedPluginAdapterRegistry(),
            plugin_effects=_NoEffects(), local_overlay_store=_OverlayFixture(),
            voice_session_enrollment_id="capture-only-voice-session",
        )
        context = _CaptureContext(adapter_id)
        try:
            implementation.register(context, runtime)
        except NativeRegistrationCaptureDenied:
            raise
        except Exception as exc:
            raise NativeRegistrationCaptureDenied(
                f"source registration capture failed for {adapter_id}: {type(exc).__name__}"
            ) from None
        if not context.rows:
            raise NativeRegistrationCaptureDenied("native plugin registered no Hermes tools")
        result.extend(context.rows)
    names = [row.native_tool_name for row in result]
    if len(names) != len(set(names)):
        raise NativeRegistrationCaptureDenied("actual Hermes registration names collide")
    return tuple(sorted(result, key=lambda row: row.native_tool_name))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _relative_component_path(filename: str | None) -> str:
    if not isinstance(filename, str):
        raise NativeRegistrationCaptureDenied("registration source path is unavailable")
    root = Path(__file__).resolve().parents[2]
    try:
        relative = Path(filename).resolve(strict=True).relative_to(root).as_posix()
    except (OSError, ValueError):
        raise NativeRegistrationCaptureDenied("registration source is outside the installed component root") from None
    if not relative.startswith("hermes_installer/components/"):
        raise NativeRegistrationCaptureDenied("registration source is outside the reviewed component modules")
    return relative
