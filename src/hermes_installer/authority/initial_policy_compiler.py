"""Closed-template renderer for the installed root's initial policy.

This module deliberately knows one reviewed template and one finite binding
grammar.  It does not accept caller policy documents, paths, IDs, or an
``EnrollmentPolicy``.  Stage-zero session issuance and immutable publication
remain owned by :mod:`bootstrap_runtime_factory` and the policy publisher.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending

if TYPE_CHECKING:
    from .bootstrap_runtime_factory import CompiledRootSetupPublication


TEMPLATE_ARTIFACT_ID = "installer-bootstrap-compiler-template-v1"
TEMPLATE_SHA256 = "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5"
TEMPLATE_SIZE_BYTES = 4281
PREPARED_BASE_TEMPLATE_ARTIFACT_ID = "installer-prepared-authority-base-template-v1"
PREPARED_BASE_TEMPLATE_SHA256 = "da20ce244bbbc771dfaf463d8ce8914d87b6eb9898228952a55681e1aa6fb953"
PREPARED_BASE_TEMPLATE_SIZE_BYTES = 369
RECEIPT_BINDINGS_TEMPLATE_ARTIFACT_ID = "installer-bootstrap-receipt-bindings-template-v1"
RECEIPT_BINDINGS_TEMPLATE_SHA256 = "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609"
RECEIPT_BINDINGS_TEMPLATE_SIZE_BYTES = 10195
_POLICY_ARTIFACT_ID = "installer-bootstrap-policy-v1"
_POLICY_RELATIVE_PATH = "plans/bootstrap-policy-v1.json"
_SELECTION_ID = "installer-root-setup-selection-v1"
_ARTIFACT_CATALOG_ID = "installer-protected-artifact-catalog-v1"
_ARTIFACT_CATALOG_PATH = "catalog/artifacts.json"
_ARTIFACT_STORE_ID = "installer-bootstrap-artifact-store-v1"
_AUTHORITY_JOURNAL_ID = "installer-authority-journal-v1"
_TEMPLATE_KEYS = frozenset({
    "schema", "id", "source_artifact_id", "authority_base_source",
    "empty_parameter_schema", "identity", "initial_catalog_mode", "roots",
    "service_record_template", "stage",
})
_BINDING_KEYS = frozenset({
    "principal.principal_id",
    "transaction.process_generation", "transaction.namespace_identity",
    "nss.service_uid", "nss.service_gid",
    "roots.home", "roots.work", "roots.data",
    "pm.catalog_executable_path", "pm.executable_sha256",
    "pm.executable_artifact_id", "pm.runtime_artifact_ids",
    "pm.package_runtime_records", "native.child_artifact_refs",
    "authority_key.key_id", "prepared_service_generation.exact_empty_snapshot",
})
_PREPARED_DEFERRED_BINDINGS = frozenset({
    "nss.service_uid", "nss.service_gid", "pm.catalog_executable_path",
    "pm.executable_sha256", "pm.executable_artifact_id",
    "pm.runtime_artifact_ids", "pm.package_runtime_records",
    "native.child_artifact_refs",
})
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")


class InitialPolicyCompilationError(BootstrapEnrollmentPending):
    """The initial policy cannot be safely rendered from current root facts."""


@dataclass(frozen=True, slots=True)
class _RootBindings:
    """Finite values obtained by the root registry, never from setup choices."""

    values: Mapping[str, Any]
    principal_id: str | None


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _parse_closed_template(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) != TEMPLATE_SIZE_BYTES:
        raise InitialPolicyCompilationError("closed compiler template has the wrong size")
    if not hashlib.sha256(raw).hexdigest() == TEMPLATE_SHA256:
        raise InitialPolicyCompilationError("closed compiler template differs from the reviewed v30 artifact")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise InitialPolicyCompilationError("closed compiler template is not strict JSON") from exc
    if (not isinstance(doc, dict) or set(doc) != _TEMPLATE_KEYS or type(doc.get("schema")) is not int
            or doc.get("schema") != 1
            or doc.get("id") != TEMPLATE_ARTIFACT_ID):
        raise InitialPolicyCompilationError("closed compiler template has an unexpected schema")
    return doc


def _validate_root_binding_values(bindings: _RootBindings) -> None:
    if not isinstance(bindings, _RootBindings) or not isinstance(bindings.values, Mapping):
        raise InitialPolicyCompilationError("root binding values are not a verified compiler input")
    if set(bindings.values) - _BINDING_KEYS:
        raise InitialPolicyCompilationError("root binding values contain an unsupported binding")
    if bindings.principal_id is not None and (
            not isinstance(bindings.principal_id, str) or not _ID.fullmatch(bindings.principal_id)):
        raise InitialPolicyCompilationError("selected principal receipt has a malformed principal ID")
    for key, value in bindings.values.items():
        if key.endswith("sha256") and (not isinstance(value, str) or not _SHA.fullmatch(value)):
            raise InitialPolicyCompilationError(f"root binding {key} is not an observed SHA-256")
        if key in {"nss.service_uid", "nss.service_gid"} and (type(value) is not int or value <= 0):
            raise InitialPolicyCompilationError(f"root binding {key} is not an allocated service ID")
        if key in {"roots.home", "roots.work", "roots.data", "pm.catalog_executable_path"}:
            if not isinstance(value, str) or not value.startswith("/") or "\x00" in value:
                raise InitialPolicyCompilationError(f"root binding {key} is not an absolute observed path")


def _render(value: Any, bindings: _RootBindings) -> Any:
    if isinstance(value, dict):
        if set(value) == {"root_binding"}:
            name = value["root_binding"]
            if not isinstance(name, str) or name not in _BINDING_KEYS:
                raise InitialPolicyCompilationError("template contains an unknown root-binding expression")
            if name == "principal.principal_id":
                resolved = bindings.principal_id
            else:
                resolved = bindings.values.get(name)
            if resolved is None:
                if name in _PREPARED_DEFERRED_BINDINGS:
                    return None
                raise InitialPolicyCompilationError(f"required root fact or receipt is pending: {name}")
            return resolved
        return {key: _render(item, bindings) for key, item in value.items()}
    if isinstance(value, list):
        return [_render(item, bindings) for item in value]
    return value


def _render_closed_template(raw: bytes, bindings: _RootBindings) -> dict[str, Any]:
    """Render source-verified v30 bytes through its closed root-binding grammar."""
    _validate_root_binding_values(bindings)
    template = _parse_closed_template(raw)
    rendered = _render(template, bindings)
    if any(isinstance(value, dict) and set(value) == {"root_binding"}
           for value in _walk(rendered)):
        raise InitialPolicyCompilationError("rendered template still contains an unresolved binding")
    return rendered


def _empty_prepared_service_generation(root_journal_root: Mapping[str, Any], *,
                                       generation_id: str | None = None) -> dict[str, Any]:
    """Create the exact dormant service catalog from the held journal-root fact."""
    if not isinstance(root_journal_root, Mapping):
        raise InitialPolicyCompilationError("prepared service snapshot requires the held root journal receipt")
    generation_id = generation_id or "prepared-" + secrets.token_hex(16)
    if not isinstance(generation_id, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", generation_id):
        raise InitialPolicyCompilationError("prepared service snapshot generation ID is malformed")
    rows = dict(root_journal_root)
    expected_root_fields = {"root_id", "absolute_path", "owner_uid", "owner_gid", "mode",
                            "device", "inode", "generation", "purpose"}
    if set(rows) != expected_root_fields or rows.get("root_id") != "installer-authority-journal-v1":
        raise InitialPolicyCompilationError("prepared service snapshot has no exact selected journal-root row")
    value = {
        "schema": 1, "generation_id": generation_id, "service_records": [],
        "protected_devices": [], "protected_build_records": [], "native_packages": [],
        "memory_enrollments": [], "operation_parameter_schemas": [], "source_issuers": [],
        "resource_jobs": [], "remote_session_enrollments": [], "resource_backend_enrollments": [],
        "resource_body_recipes": [], "resource_scope_bindings": [], "resource_validators": [],
        "resource_controller_roles": [], "native_mcp_tool_bindings": [],
        "remote_observation_enrollments": [],
        "native_schema_artifacts": [], "composio_channel_enrollments": [],
        "channel_delivery_bindings": [],
        "remote_startup_enrollments": [], "private_loopback_networks": [],
        "selected_resource_executions": [], "selected_application_runtimes": [],
        # These rows require separately verified root endpoint/model receipts;
        # a prepared snapshot must not derive or activate them.
        "private_memory_endpoint_selections": [], "private_memory_model_selections": [],
        "root_journal_roots": [rows],
    }
    value["generation_digest"] = hashlib.sha256(_canonical_json(value)).hexdigest()
    from .enrollment import _validate_service_generations
    try:
        return _validate_service_generations(value)
    except Exception as exc:
        raise InitialPolicyCompilationError("prepared service snapshot failed the installed authority schema") from exc


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _parse_prepared_base_template(raw: bytes) -> dict[str, Any]:
    if not isinstance(raw, bytes) or len(raw) != PREPARED_BASE_TEMPLATE_SIZE_BYTES:
        raise InitialPolicyCompilationError("prepared authority-base template has the wrong size")
    if hashlib.sha256(raw).hexdigest() != PREPARED_BASE_TEMPLATE_SHA256:
        raise InitialPolicyCompilationError("prepared authority-base template differs from v63")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise InitialPolicyCompilationError("prepared authority-base template is not strict JSON") from exc
    required = {"schema", "key_id", "principals", "rules", "authentik", "process_profiles",
                "provider_enrollments", "mcp_services", "mcp_http_bindings", "memory_providers",
                "native_bridges", "normalization_policies", "delegations", "service_generations"}
    if not isinstance(doc, dict) or set(doc) != required or doc.get("schema") != 1:
        raise InitialPolicyCompilationError("prepared authority-base template has an unexpected schema")
    return doc


def _parse_receipt_bindings_template(raw: bytes) -> dict[str, Any]:
    """Verify the v72 literal policy/rule source before any root binding."""
    if not isinstance(raw, bytes) or len(raw) != RECEIPT_BINDINGS_TEMPLATE_SIZE_BYTES:
        raise InitialPolicyCompilationError("bootstrap receipt-binding template has the wrong size")
    if hashlib.sha256(raw).hexdigest() != RECEIPT_BINDINGS_TEMPLATE_SHA256:
        raise InitialPolicyCompilationError("bootstrap receipt-binding template differs from v72")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                         parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise InitialPolicyCompilationError("bootstrap receipt-binding template is not strict JSON") from exc
    expected = {"id", "schema", "service_record_templates", "receipt_binding_rules",
                "root_bindings", "root_binding_resolver", "typed_receipt_fields"}
    if (not isinstance(doc, dict) or set(doc) != expected or type(doc.get("schema")) is not int
            or doc["schema"] != 1 or doc.get("id") != RECEIPT_BINDINGS_TEMPLATE_ARTIFACT_ID
            or not isinstance(doc.get("service_record_templates"), list)
            or len(doc["service_record_templates"]) != 1
            or not isinstance(doc.get("receipt_binding_rules"), list)
            or not isinstance(doc.get("typed_receipt_fields"), dict)):
        raise InitialPolicyCompilationError("bootstrap receipt-binding template has an unexpected schema")
    return doc


def _render_prepared_receipt_bindings(raw: bytes, *, source_template_raw: bytes,
                                      service_record: Mapping[str, Any],
                                      artifact_catalog: Mapping[str, Any],
                                      allowed_plan_artifact_ids: tuple[str, ...] | list[str]
                                      ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Render v72's literal rules for a prepared transaction only.

    Source IDs are joined to the actual installed catalog and selected plan.
    Runnable and health roles stay empty until their current-transaction typed
    receipts exist; no empty prepared rule authorizes an output.
    """
    template = _parse_receipt_bindings_template(raw)
    source_template = _parse_closed_template(source_template_raw)
    if (not isinstance(service_record, Mapping)
            or not isinstance(artifact_catalog, Mapping)
            or artifact_catalog.get("schema") != 1
            or not isinstance(artifact_catalog.get("artifacts"), list)
            or not isinstance(allowed_plan_artifact_ids, (tuple, list))):
        raise InitialPolicyCompilationError("prepared receipt rules require the sealed plan and artifact catalog")
    allowed = tuple(allowed_plan_artifact_ids)
    if (not allowed or len(allowed) != len(set(allowed))
            or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in allowed)):
        raise InitialPolicyCompilationError("selected plan artifact allowlist is malformed")
    rows = artifact_catalog["artifacts"]
    catalog_by_id: dict[str, Mapping[str, Any]] = {}
    for row in rows:
        if not isinstance(row, Mapping) or not isinstance(row.get("artifact_id"), str):
            raise InitialPolicyCompilationError("selected protected artifact catalog is malformed")
        artifact_id = row["artifact_id"]
        if artifact_id in catalog_by_id:
            raise InitialPolicyCompilationError("selected protected artifact catalog has duplicate IDs")
        catalog_by_id[artifact_id] = row

    script_matches = [row for row in rows if row.get("source_url") ==
                      "https://raw.githubusercontent.com/NousResearch/hermes-agent/"
                      "7085fbf7753266fc4943c55ac04926186bc90005/scripts/install.sh"
                      and row.get("sha256") == "034845e34289813ff5fb7fd3e071ec69f6b14aee8ba297a477b31dda6374cb86"
                      and row.get("size_bytes") == 52776]
    if (len(script_matches) != 1 or script_matches[0].get("artifact_id") != "hermes-agent-install-script"
            or script_matches[0]["artifact_id"] not in allowed):
        raise InitialPolicyCompilationError("verified official installer-script catalog role is absent or ambiguous")

    resolved_rules: list[dict[str, Any]] = []
    for rule in template["receipt_binding_rules"]:
        if not isinstance(rule, dict):
            raise InitialPolicyCompilationError("literal receipt rule is malformed")
        role = rule.get("receipt_role")
        ids = rule.get("allowed_artifact_ids")
        if isinstance(ids, dict):
            if role == "official-installer-script" and ids == {
                    "root_binding": "selected_source_roles.official-installer-script.artifact_ids"}:
                selected_ids = [script_matches[0]["artifact_id"]]
            elif (role in {"official-pm-runtime", "native-compiled-closure",
                           "native-entrypoint-manifest", "native-action-resolver",
                           "native-boundary-overlay", "native-candidate-index", "native-health"}
                  and ids == {"root_binding": f"selected_receipts.{role}.artifact_ids"}):
                selected_ids = []
            else:
                raise InitialPolicyCompilationError("literal receipt rule uses an unsupported root binding")
        elif isinstance(ids, list):
            selected_ids = list(ids)
        else:
            raise InitialPolicyCompilationError("literal receipt rule artifact IDs are malformed")
        phase = rule.get("required_phase")
        if phase in {"runnable", "functional-health"}:
            if selected_ids:
                raise InitialPolicyCompilationError("prepared policy cannot claim future runtime or health receipts")
        elif phase != "prepared-source" or not selected_ids:
            raise InitialPolicyCompilationError("prepared source receipt rule must select its fixed artifact")
        if any(item not in allowed or item not in catalog_by_id for item in selected_ids):
            raise InitialPolicyCompilationError("literal receipt rule escapes the selected plan/catalog")
        resolved = {key: value for key, value in rule.items() if key != "allowed_artifact_ids"}
        resolved["allowed_artifact_ids"] = selected_ids
        resolved_rules.append(resolved)

    service_templates = template["service_record_templates"]
    source_service = service_templates[0]
    if (set(source_service) != {"id", "record", "receipt_bindings"}
            or source_service.get("id") != "hermes-agent-native-template-v1"
            or source_service.get("record") != source_template["service_record_template"]
            or not _same_json_shape(source_service["record"], service_record)):
        raise InitialPolicyCompilationError("v72 service record does not exactly wrap the rendered v30 template")
    rendered_service = {
        "id": source_service["id"],
        "record": dict(service_record),
        "receipt_bindings": source_service["receipt_bindings"],
    }
    return resolved_rules, rendered_service


def _render_prepared_authority_base(raw: bytes, *, key_id: str,
                                    root_journal_root: Mapping[str, Any],
                                    generation_id: str | None = None) -> dict[str, Any]:
    """Render v63's dormant-only authority base; it does not authorize effects."""
    if not isinstance(key_id, str) or not re.fullmatch(r"authority-key-[0-9a-f]{32}", key_id):
        raise InitialPolicyCompilationError("prepared authority base requires the verified root key receipt ID")
    template = _parse_prepared_base_template(raw)
    template["key_id"] = key_id
    template["service_generations"] = _empty_prepared_service_generation(
        root_journal_root, generation_id=generation_id)
    required_maps = {"principals", "rules", "authentik", "process_profiles", "provider_enrollments",
                     "mcp_services", "mcp_http_bindings", "memory_providers", "native_bridges",
                     "normalization_policies", "delegations"}
    if any(not isinstance(template[name], dict) or template[name] for name in required_maps):
        raise InitialPolicyCompilationError("prepared authority snapshot contains unsupported authority rows")
    from .bootstrap_enrollment import _validate_authority_base
    _validate_authority_base(template)
    return template


def _walk(value: Any):
    yield value
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk(item)


def _same_json_shape(left: Any, right: Any) -> bool:
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_same_json_shape(left[key], right[key]) for key in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(_same_json_shape(a, b) for a, b in zip(left, right))
    return True


class RootFirstStagePolicyCompiler:
    """Root-only facade for closed initial-policy rendering.

    The factory constructs this facade from its verified release/actor receipts
    and injects the same root-local initial-compilation registry it owns.  The
    stage-zero registry remains the only issuer of session and transaction
    handles; this class never takes those handles from a caller.
    """

    def __init__(self, verified_installer_release_receipt: Any,
                 root_actor_observation: Any, initial_compilation_registry: Any,
                 principal_selection_registry: Any,
                 authority_key_selection_registry: Any):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        from .enrollment import RootAuthorityKeySelectionRegistry
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        if not isinstance(verified_installer_release_receipt, VerifiedInstallerReleaseReceipt):
            raise InitialPolicyCompilationError("compiler requires the sealed installed-release receipt")
        if not isinstance(root_actor_observation, RootActorObservation):
            raise InitialPolicyCompilationError("compiler requires the current root actor observation")
        if not isinstance(initial_compilation_registry, RootInitialCompilationRegistry):
            raise InitialPolicyCompilationError("compiler requires the installed stage-zero registry")
        if not isinstance(principal_selection_registry, RootSetupPrincipalSelectionRegistry):
            raise InitialPolicyCompilationError("compiler requires the root Authentik principal registry")
        if (not isinstance(authority_key_selection_registry, RootAuthorityKeySelectionRegistry)
                or authority_key_selection_registry.release is not verified_installer_release_receipt
                or authority_key_selection_registry.initial_compilation_registry is not initial_compilation_registry
                or authority_key_selection_registry.actor_verifier is not initial_compilation_registry.actor_verifier
                or authority_key_selection_registry.root_journal != initial_compilation_registry.root_journal):
            raise InitialPolicyCompilationError("compiler requires the same-registry root authority-key selector")
        self._release = verified_installer_release_receipt
        self._actor = root_actor_observation
        self._registry = initial_compilation_registry
        self._principal_registry = principal_selection_registry
        self._key_registry = authority_key_selection_registry

    @classmethod
    def from_installed_release(cls, verified_installer_release_receipt: Any,
                               root_actor_observation: Any, *,
                               initial_compilation_registry: Any,
                               principal_selection_registry: Any,
                               authority_key_selection_registry: Any) -> "RootFirstStagePolicyCompiler":
        verified_installer_release_receipt.verify_current()
        root_actor_observation.verify_current(verified_installer_release_receipt)
        return cls(verified_installer_release_receipt, root_actor_observation,
                   initial_compilation_registry, principal_selection_registry,
                   authority_key_selection_registry)

    def compile_initial_policy(self, choices: Any) -> "CompiledRootSetupPublication":
        """Compile one sealed initial publication from explicit root UI choices.

        Missing verified inputs raise the existing typed pending condition. A
        partial template is never returned as policy and no caller receives raw
        authority or root-selection rows.
        """
        from .bootstrap_runtime_factory import RootSetupChoices
        if not isinstance(choices, RootSetupChoices):
            raise InitialPolicyCompilationError("initial setup requires validated RootSetupChoices")
        session = self._registry.begin_initial_compilation(choices)
        return self.compile_initial_policy_for_session(session)

    def compile_initial_policy_for_session(self, session: Any) -> "CompiledRootSetupPublication":
        """Compile the already-issued stage-zero session after identity selection."""
        from .bootstrap_runtime_factory import RootInitialCompilationSession
        if not isinstance(session, RootInitialCompilationSession):
            raise InitialPolicyCompilationError("initial policy requires the typed stage-zero session")
        current = self._registry.resolve_initial_session(session.compilation_session_handle)
        if current is not session:
            raise InitialPolicyCompilationError("initial policy session is stale or replaced")
        choices = session._choices
        self._actor.verify_current(self._release)
        self._registry.verify_initial_session(session)
        plan = self._registry.resolve_actor_plan(session.compilation_session_handle)
        if plan.digest != session.plan_sha256:
            raise InitialPolicyCompilationError("selected installed plan changed during compilation")
        self._registry.resolve_identity_policy_template(session.compilation_session_handle)
        principal_handle = choices.selected_principal_binding_receipt_handle
        if principal_handle is None:
            raise InitialPolicyCompilationError(
                "pending-principal-selection: complete root-authenticated identity selection")
        selected = self._principal_registry.resolve_selected_principal(
            principal_handle, session.compilation_session_handle,
            session.compilation_transaction_handle, session.plan_sha256)
        from .bootstrap_runtime_factory import InstalledBootstrapPolicyResolver
        def release_bytes(artifact_id: str, expected_sha: str, expected_size: int,
                          expected_path: str) -> tuple[Any, bytes]:
            descriptor, content = self._registry._release_file(artifact_id)
            if (descriptor.sha256 != expected_sha or descriptor.size_bytes != expected_size
                    or descriptor.relative_path != expected_path):
                raise InitialPolicyCompilationError("installed release compiler source differs from its exact pin")
            return descriptor, content

        _, raw = release_bytes(
            TEMPLATE_ARTIFACT_ID, TEMPLATE_SHA256, TEMPLATE_SIZE_BYTES,
            "plans/amendments/2026-10-09-closed-bootstrap-compiler-template-v30/bootstrap-compiler-template-v1.json")
        _, base_raw = release_bytes(
            PREPARED_BASE_TEMPLATE_ARTIFACT_ID, PREPARED_BASE_TEMPLATE_SHA256,
            PREPARED_BASE_TEMPLATE_SIZE_BYTES,
            "templates/prepared-authority-base-template-v1.json")
        _, receipt_raw = release_bytes(
            RECEIPT_BINDINGS_TEMPLATE_ARTIFACT_ID, RECEIPT_BINDINGS_TEMPLATE_SHA256,
            RECEIPT_BINDINGS_TEMPLATE_SIZE_BYTES,
            "templates/bootstrap-receipt-bindings-template-v1.json")
        # Fixed roots come from the reviewed v30 template, and namespace
        # identity is the selected principal receipt's reviewed capability
        # scope. Neither is caller-controlled. Dynamic UID/PM/native outputs
        # remain unresolved in this prepared policy.
        template_doc = _parse_closed_template(raw)
        roots = template_doc["roots"]
        if (roots.get("service_parent_root") != "/var/lib/hermes-installer/services/hermes-agent-native-v1"
                or roots.get("home_child") != "home" or roots.get("work_child") != "work"
                or roots.get("data_child") != "data"):
            raise InitialPolicyCompilationError("closed template does not select the reviewed fixed root layout")
        parent = roots["service_parent_root"]
        bindings = _RootBindings(
            values={
                "transaction.process_generation": session.compilation_transaction_handle,
                "transaction.namespace_identity": selected.namespace_id,
                "roots.home": f"{parent}/home", "roots.work": f"{parent}/work",
                "roots.data": f"{parent}/data",
            },
            principal_id=selected.principal_id,
        )
        rendered_v30 = _render_closed_template(raw, bindings)
        source_record = rendered_v30["service_record_template"]
        receipt_template = _parse_receipt_bindings_template(receipt_raw)
        plan_artifacts = tuple(plan.allowed_artifact_ids)
        catalog_descriptor, catalog_raw = self._registry._release_file(_ARTIFACT_CATALOG_ID)
        try:
            catalog_doc = json.loads(catalog_raw.decode("utf-8"), object_pairs_hook=_unique_object,
                                     parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise InitialPolicyCompilationError("installed protected artifact catalog is not strict JSON") from exc
        if (not isinstance(catalog_doc, dict) or set(catalog_doc) != {"schema", "artifacts", "packages"}
                or type(catalog_doc.get("schema")) is not int or catalog_doc["schema"] != 1):
            raise InitialPolicyCompilationError("installed protected artifact catalog has an unexpected schema")
        try:
            from ..artifacts import ArtifactCatalog, _artifact_from_record, _package_from_record
            ArtifactCatalog.from_records(
                tuple(_artifact_from_record(row) for row in catalog_doc["artifacts"]),
                tuple(_package_from_record(row) for row in catalog_doc["packages"]))
        except (KeyError, TypeError, ValueError) as exc:
            raise InitialPolicyCompilationError("installed protected artifact catalog failed strict parsing") from exc
        receipt_rules, service_template = _render_prepared_receipt_bindings(
            receipt_raw, source_template_raw=raw, service_record=source_record,
            artifact_catalog=catalog_doc, allowed_plan_artifact_ids=plan_artifacts)

        # Ensure every static v72 source rule is present in the selected exact
        # catalog and plan, before creating a root signing-key receipt.
        authority_key = self._key_registry.ensure_selected_key(session.compilation_session_handle)
        authority_key = self._key_registry.resolve_selected_key(
            authority_key.receipt_handle, session.compilation_session_handle)
        if (not isinstance(authority_key.key_id, str)
                or not re.fullmatch(r"authority-key-[0-9a-f]{32}", authority_key.key_id)):
            raise InitialPolicyCompilationError("root authority-key receipt is malformed")
        journal_row = dict(session._root_journal_root)
        base = _render_prepared_authority_base(
            base_raw, key_id=authority_key.key_id, root_journal_root=journal_row,
            generation_id="prepared-" + session.compilation_transaction_handle[:32])
        identity = template_doc["identity"]
        roots_doc = template_doc["roots"]
        policy = {
            "schema": 1,
            "id": _POLICY_ARTIFACT_ID,
            "source_artifact_id": template_doc["source_artifact_id"],
            "identity_policy": {
                "service_profile_id": identity["service_profile_id"],
                "principal_id": selected.principal_id,
                "service_account_name": identity["service_account_name"],
                "exclusive_group_name": identity["exclusive_group_name"],
                "uid_allocation": identity["uid_allocation"],
            },
            "root_policy": {
                "journal_root_id": roots_doc["journal_root_id"],
                "service_home_root_id": roots_doc["service_home_root_id"],
                "service_work_root_id": roots_doc["service_work_root_id"],
                "service_data_root_id": roots_doc["service_data_root_id"],
                "service_parent_root": roots_doc["service_parent_root"],
            },
            "authority_base_template": base,
            "service_record_templates": [service_template],
            "catalog_selections": {
                "protected_devices": [], "protected_build_records": [], "native_packages": [],
                "memory_enrollments": [], "operation_parameter_schemas": [], "source_issuers": [],
                "resource_jobs": [], "remote_session_enrollments": [],
                "resource_backend_enrollments": [], "resource_body_recipes": [],
                "resource_scope_bindings": [], "resource_validators": [],
                "root_journal_roots": [journal_row], "resource_controller_roles": [],
                "native_mcp_tool_bindings": [], "remote_observation_enrollments": [],
                "native_schema_artifacts": [], "composio_channel_enrollments": [],
                "channel_delivery_bindings": [],
            },
            "receipt_binding_rules": receipt_rules,
        }
        policy_raw = _canonical_json(policy)
        plan_file = next((row for row in self._release.files
                          if row.artifact_id == session.plan_artifact_id), None)
        launcher_file = next((row for row in self._release.files
                              if row.artifact_id == "installer-root-setup-launcher-v1"), None)
        interpreter_file = next((row for row in self._release.files
                                 if row.artifact_id == "installer-root-setup-interpreter-v1"), None)
        if plan_file is None or launcher_file is None or interpreter_file is None:
            raise InitialPolicyCompilationError("selected root setup release lacks plan/launcher/interpreter bytes")
        module_rows = []
        for row in sorted((item for item in self._release.files if "module" in item.roles),
                          key=lambda item: item.relative_path):
            module_name = row.artifact_id.removeprefix("installer-module:")
            if module_name == row.artifact_id:
                raise InitialPolicyCompilationError("release module has no sealed import identity")
            module_rows.append({"module_name": module_name, "artifact_id": row.artifact_id,
                                "relative_path": row.relative_path, "sha256": row.sha256})
        plan_row = {
            "artifact_id": session.plan_artifact_id,
            "relative_path": plan_file.relative_path,
            "sha256": plan_file.sha256,
            "baseline_tag_object": self._release.baseline_tag_object,
            "baseline_commit": self._release.baseline_commit,
            "baseline_tree_sha256": self._release.baseline_tree_sha256,
            "amendment_manifest_sha256": self._release.amendment_manifest_sha256,
            "allowed_artifact_ids": list(plan_artifacts),
            "bootstrap_policy_artifact_id": _POLICY_ARTIFACT_ID,
        }
        policy_row = {"artifact_id": _POLICY_ARTIFACT_ID,
                      "relative_path": _POLICY_RELATIVE_PATH,
                      "sha256": hashlib.sha256(policy_raw).hexdigest()}
        selection_doc = {
            "schema": 1, "selection_id": _SELECTION_ID,
            "installer_release_commit": self._release.release_commit,
            "release_root": {
                "root_id": "installer-release:" + self._release.release_commit,
                "absolute_path": str(self._release.release_root),
                "device": self._release.root_device, "inode": self._release.root_inode,
                "deployment_receipt_sha256": self._release.deployment_receipt_sha256,
            },
            "launcher": {"artifact_id": launcher_file.artifact_id,
                         "relative_path": launcher_file.relative_path,
                         "sha256": launcher_file.sha256},
            "interpreter": {"artifact_id": interpreter_file.artifact_id,
                            "relative_path": interpreter_file.relative_path,
                            "sha256": interpreter_file.sha256},
            "module_closure": module_rows,
            "plans": [plan_row],
            "catalog_sha256": "0" * 64,
            "artifact_catalog": {"artifact_id": _ARTIFACT_CATALOG_ID,
                                 "relative_path": _ARTIFACT_CATALOG_PATH,
                                 "sha256": catalog_descriptor.sha256},
            "artifact_store": {"root_id": _ARTIFACT_STORE_ID,
                               "journal_root_id": _AUTHORITY_JOURNAL_ID,
                               "relative_path": "bootstrap-artifacts",
                               "owner_uid": 0, "owner_gid": 0, "mode": 0o700},
            "bootstrap_policies": [policy_row],
        }
        selection_unsigned = {key: value for key, value in selection_doc.items() if key != "catalog_sha256"}
        selection_doc["catalog_sha256"] = hashlib.sha256(_canonical_json(selection_unsigned)).hexdigest()

        # Run the installed resolver's exact strict policy validation before
        # returning bytes to the same-session store/publisher.
        resolver = InstalledBootstrapPolicyResolver.__new__(InstalledBootstrapPolicyResolver)
        resolver._parse_policy(policy, policy_row["sha256"], plan_row, None,
                               compilation_phase="prepared")
        package = getattr(self._registry, "package_compilation", None)
        if not callable(package):
            raise InitialPolicyCompilationError(
                "installed stage-zero registry has no sealed publication packaging API")
        # Preserve the actual root-minted inputs in the prepared publication
        # chain. The principal handle alone binds identity labels/capability
        # namespace, while its Authentik observation handle binds those facts
        # to a fresh current identity read. Neither is a source artifact proof.
        identity_receipt_handle = selected.identity_receipt_handle
        principal_receipt_handle = selected.receipt_id
        if (not isinstance(identity_receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", identity_receipt_handle)
                or not isinstance(principal_receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", principal_receipt_handle)):
            raise InitialPolicyCompilationError("selected principal lacks its actual identity receipt closure")
        return package(
            session, policy_raw, catalog_raw, selection_doc,
            source_receipt_handles=(identity_receipt_handle, principal_receipt_handle))


__all__ = ["RootFirstStagePolicyCompiler", "InitialPolicyCompilationError"]
