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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending

if TYPE_CHECKING:
    from .bootstrap_runtime_factory import CompiledRootSetupPublication


TEMPLATE_ARTIFACT_ID = "installer-bootstrap-compiler-template-v1"
TEMPLATE_SHA256 = "27854f8f8c67ce42832f020dbfd96512607e39576b27e484598ff397cb9432e5"
TEMPLATE_SIZE_BYTES = 4281
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
                 principal_selection_registry: Any):
        from .installer_release import RootActorObservation, VerifiedInstallerReleaseReceipt
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        from .setup_principal import RootSetupPrincipalSelectionRegistry
        if not isinstance(verified_installer_release_receipt, VerifiedInstallerReleaseReceipt):
            raise InitialPolicyCompilationError("compiler requires the sealed installed-release receipt")
        if not isinstance(root_actor_observation, RootActorObservation):
            raise InitialPolicyCompilationError("compiler requires the current root actor observation")
        if not isinstance(initial_compilation_registry, RootInitialCompilationRegistry):
            raise InitialPolicyCompilationError("compiler requires the installed stage-zero registry")
        if not isinstance(principal_selection_registry, RootSetupPrincipalSelectionRegistry):
            raise InitialPolicyCompilationError("compiler requires the root Authentik principal registry")
        self._release = verified_installer_release_receipt
        self._actor = root_actor_observation
        self._registry = initial_compilation_registry
        self._principal_registry = principal_selection_registry

    @classmethod
    def from_installed_release(cls, verified_installer_release_receipt: Any,
                               root_actor_observation: Any, *,
                               initial_compilation_registry: Any,
                               principal_selection_registry: Any) -> "RootFirstStagePolicyCompiler":
        verified_installer_release_receipt.verify_current()
        root_actor_observation.verify_current(verified_installer_release_receipt)
        return cls(verified_installer_release_receipt, root_actor_observation,
                   initial_compilation_registry, principal_selection_registry)

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
        bindings = _RootBindings(
            values={"transaction.process_generation": session.compilation_transaction_handle},
            principal_id=selected.principal_id,
        )
        try:
            _render_closed_template(raw, bindings)
        except InitialPolicyCompilationError as exc:
            # Stage zero has not issued these ownership and process facts yet.
            # The profile namespace selected in policy is not kernel evidence.
            raise InitialPolicyCompilationError(
                f"pending-root-observation: resolve held root and process observations: {exc}") from exc
        raise InitialPolicyCompilationError(
            "strict policy envelope assembly requires a source-verified authority-base template and signer key ID")


__all__ = ["RootFirstStagePolicyCompiler", "InitialPolicyCompilationError"]
