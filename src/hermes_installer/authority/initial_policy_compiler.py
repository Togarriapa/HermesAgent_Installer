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
        release_files = {item.artifact_id: item for item in self._release.files}
        descriptor = release_files.get(TEMPLATE_ARTIFACT_ID)
        if descriptor is None or descriptor.sha256 != TEMPLATE_SHA256 or descriptor.size_bytes != TEMPLATE_SIZE_BYTES:
            raise InitialPolicyCompilationError("verified release does not contain the reviewed closed template")
        fd = self._release.open_file(TEMPLATE_ARTIFACT_ID)
        try:
            chunks: list[bytes] = []
            total = 0
            while True:
                part = os.read(fd, min(65536, TEMPLATE_SIZE_BYTES + 1 - total))
                if not part:
                    break
                total += len(part)
                if total > TEMPLATE_SIZE_BYTES:
                    raise InitialPolicyCompilationError("closed template exceeds its reviewed bound")
                chunks.append(part)
            raw = b"".join(chunks)
        finally:
            os.close(fd)
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
        _render_closed_template(raw, bindings)
        # The selected plan and renderer are now verified. Publication still
        # requires the literal strict policy/receipt-rule source set and the
        # initial selector/catalog identity pins to be installed in this
        # release; do not mint a signing-key receipt until those are present.
        raise InitialPolicyCompilationError(
            "pending-policy-source: selected release lacks the closed initial policy and receipt-binding source")


__all__ = ["RootFirstStagePolicyCompiler", "InitialPolicyCompilationError"]
