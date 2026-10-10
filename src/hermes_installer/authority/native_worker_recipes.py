"""Root-issued worker recipe and prepared AF_UNIX endpoint custody.

The recipe is source authority for one finite Hermes worker.  It is not a
process handle, a network grant, or evidence that the worker has loaded.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .bootstrap_enrollment import BootstrapEnrollmentPending
from .native_worker_start_recipe import (
    RECIPE_ID,
    RootNativeHermesWorkerStartRecipe,
    RootNativeHermesWorkerStartRecipeSource,
)

_ROOT_JOURNAL = Path("/var/lib/hermes-installer/authority-journal")
_SOCKET_DIR = Path("/run/hermes-installer/authority")
_ENDPOINT_ID = "hermes-agent-authority-endpoint-v1"
_PROFILE_ID = "hermes-agent-native-v1"
_SERVICE_ACCOUNT = "hermes-agent-native"
_MAX_LEASE = 300.0


class NativeWorkerRecipeUnavailable(BootstrapEnrollmentPending):
    """A current root setup lacks an exact source or custody prerequisite."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedUnixAuthorityEndpointReceipt:
    """Held observation of the one fixed root authority socket for a service UID."""

    receipt_handle: str
    endpoint_id: str
    endpoint_root_id: str
    endpoint_relative_socket: str
    service_uid: int
    service_gid: int
    directory_device: int
    directory_inode: int
    socket_device: int
    socket_inode: int
    socket_mode: int
    endpoint_sha256: str
    endpoint_binding_phase: str
    issued_monotonic: float
    expires_monotonic: float
    _directory_fd: int = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedUnixAuthorityEndpointReceipt(<root-held>)"

    def close(self) -> None:
        try:
            os.close(self._directory_fd)
        except OSError:
            pass


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedServiceIdentityReceipt:
    """Fresh NSS, marker, and root ownership observations for the worker account."""

    service_user: str
    service_uid: int
    service_gid: int
    identity_marker_sha256: str
    profile_id: str
    generation: str
    home_root_id: str
    work_root_id: str
    data_root_id: str
    home_root: Path
    work_root: Path
    data_root: Path
    roots_device_inode: tuple[tuple[int, int], ...]
    receipt_handle: str
    home_root_fd: int = field(repr=False, compare=False)
    work_root_fd: int = field(repr=False, compare=False)
    data_root_fd: int = field(repr=False, compare=False)
    issued_monotonic: float
    expires_monotonic: float
    _marker_device_inode: tuple[int, int] = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedServiceIdentityReceipt(<root-held>)"

    def close(self) -> None:
        for descriptor in (self.home_root_fd, self.work_root_fd, self.data_root_fd):
            try:
                os.close(descriptor)
            except OSError:
                pass


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedWorkingRootReceipt:
    """Independent held work-root identity used by the worker recipe."""

    receipt_handle: str
    root_id: str
    service_uid: int
    service_gid: int
    device: int
    inode: int
    mode: int
    issued_monotonic: float
    expires_monotonic: float
    directory_fd: int = field(repr=False, compare=False)
    _identity_receipt_handle: str = field(repr=False, compare=False)
    _issuer: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedWorkingRootReceipt(<root-held>)"

    def close(self) -> None:
        try:
            os.close(self.directory_fd)
        except OSError:
            pass


@dataclass(frozen=True, slots=True, repr=False)
class RootPreparedNativeWorkerRecipe:
    """Opaque source recipe joined to held source, NSS, and endpoint receipts."""

    schema: int
    receipt_handle: str
    recipe_id: str
    definition_member_receipt_handle: str
    definition_member_sha256: str
    source_artifact_receipt_handles: tuple[str, ...]
    prepared_generation_id: str
    prepared_generation_digest: str
    setup_session_id: str
    transaction_handle: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    service_profile_id: str
    profile_generation: str
    resources_profile_id: str
    service_identity_receipt_handle: str
    service_enrollment_id: str
    process_profile_id: str
    network_id: str
    network_role: str
    endpoint_binding_receipt_handle: str
    endpoint_binding_phase: str
    unix_endpoint_root_id: str
    endpoint_relative_socket: str
    executable_member_receipt_handle: str
    executable_sha256: str
    pm_runtime_receipt_handle: str
    pm_base_closure_sha256: str
    source_role_definition_closure_sha256: str
    native_entrypoint_source_receipt_handle: str
    native_entrypoint_source_sha256: str
    native_boundary_source_receipt_handle: str
    native_boundary_source_sha256: str
    argument_recipe_id: str
    argv_token_recipe_sha256: str
    sanitized_environment_recipe_sha256: str
    working_root_receipt_handle: str
    controller_binding_handle: str
    complete_recipe_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer: object = field(repr=False, compare=False)
    _start_recipe: RootNativeHermesWorkerStartRecipe = field(repr=False, compare=False)
    _identity: RootPreparedServiceIdentityReceipt = field(repr=False, compare=False)
    _endpoint: RootPreparedUnixAuthorityEndpointReceipt = field(repr=False, compare=False)
    _working_root: RootPreparedWorkingRootReceipt = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPreparedNativeWorkerRecipe(<root-held>)"

    def public_projection(self) -> Mapping[str, Any]:
        """Canonical non-secret source-input record placed in the signed choice."""
        return MappingProxyType({
            "schema": self.schema,
            "recipe_id": self.recipe_id,
            "definition_member_receipt_handle": self.definition_member_receipt_handle,
            "definition_member_sha256": self.definition_member_sha256,
            "source_artifact_receipt_handles": list(self.source_artifact_receipt_handles),
            "prepared_generation_id": self.prepared_generation_id,
            "setup_session_id": self.setup_session_id,
            "transaction_handle": self.transaction_handle,
            "principal_binding_sha256": self.principal_binding_sha256,
            "namespace_binding_sha256": self.namespace_binding_sha256,
            "service_profile_id": self.service_profile_id,
            "profile_generation": self.profile_generation,
            "resources_profile_id": self.resources_profile_id,
            "service_identity_receipt_handle": self.service_identity_receipt_handle,
            "service_enrollment_id": self.service_enrollment_id,
            "process_profile_id": self.process_profile_id,
            "network_id": self.network_id,
            "network_role": self.network_role,
            "endpoint_binding_receipt_handle": self.endpoint_binding_receipt_handle,
            "endpoint_binding_phase": self.endpoint_binding_phase,
            "unix_endpoint_root_id": self.unix_endpoint_root_id,
            "endpoint_relative_socket": self.endpoint_relative_socket,
            "executable_member_receipt_handle": self.executable_member_receipt_handle,
            "executable_sha256": self.executable_sha256,
            "pm_runtime_receipt_handle": self.pm_runtime_receipt_handle,
            "pm_base_closure_sha256": self.pm_base_closure_sha256,
            "source_role_definition_closure_sha256": self.source_role_definition_closure_sha256,
            "native_entrypoint_source_receipt_handle": self.native_entrypoint_source_receipt_handle,
            "native_entrypoint_source_sha256": self.native_entrypoint_source_sha256,
            "native_boundary_source_receipt_handle": self.native_boundary_source_receipt_handle,
            "native_boundary_source_sha256": self.native_boundary_source_sha256,
            "argument_recipe_id": self.argument_recipe_id,
            "argv_token_recipe_sha256": self.argv_token_recipe_sha256,
            "sanitized_environment_recipe_sha256": self.sanitized_environment_recipe_sha256,
            "working_root_receipt_handle": self.working_root_receipt_handle,
            "controller_binding_handle": self.controller_binding_handle,
            "complete_recipe_sha256": self.complete_recipe_sha256,
        })


class RootPreparedUnixAuthorityEndpointObserver:
    """Adapt the custodian's live prepared-no-effects listener receipt."""

    def __init__(self, binding: Any):
        from .bootstrap_runtime_factory import RootSelectedInstallationBinding
        if type(binding) is not RootSelectedInstallationBinding:
            raise NativeWorkerRecipeUnavailable("a live root installation binding is required")
        self._binding = binding
        self._issuer = object()
        self._receipts: dict[str, RootPreparedUnixAuthorityEndpointReceipt] = {}
        from .native_worker_endpoint_custody import RootPreparedAuthorityEndpointCustodian
        session = binding._session
        custodian = getattr(session, "_native_worker_endpoint_custodian", None)
        if custodian is None:
            authority_root = session.ensure_current_prepared_authority_runtime_root()
            custodian = RootPreparedAuthorityEndpointCustodian.from_root_setup(
                binding, session._resolve_current_prepared_enrollment(),
                session._factory._release, session._factory._actor,
                prepared_authority_root_receipt=authority_root)
            session._native_worker_endpoint_custodian = custodian
        if (not isinstance(custodian, RootPreparedAuthorityEndpointCustodian)
                or custodian.binding is not binding):
            raise NativeWorkerRecipeUnavailable("retained preactive endpoint custodian changed")
        self._custodian = custodian

    @classmethod
    def from_root_setup(cls, binding: Any) -> "RootPreparedUnixAuthorityEndpointObserver":
        return cls(binding)

    def observe(self, identity: RootPreparedServiceIdentityReceipt) -> RootPreparedUnixAuthorityEndpointReceipt:
        self._binding._session._check_live()
        if type(identity) is not RootPreparedServiceIdentityReceipt:
            raise NativeWorkerRecipeUnavailable("a fresh typed prepared service identity is required")
        identity_handle = self._custodian.retain_prepared_identity(identity)
        listener = self._custodian.ensure_selected_listener(identity_handle, identity.profile_id)
        payload = {
            "schema": 1, "endpoint_id": listener.endpoint_id,
            "endpoint_root_id": listener.root_id,
            "endpoint_relative_socket": listener.relative_socket,
            "service_uid": listener.service_uid, "service_gid": listener.service_gid,
            "socket_device": listener.socket_device, "socket_inode": listener.socket_inode,
            "socket_mode": listener.socket_mode,
            "endpoint_binding_phase": "prepared-no-effects",
            "custodian_challenge_sha256": listener.challenge_sha256,
        }
        now = time.monotonic()
        receipt = RootPreparedUnixAuthorityEndpointReceipt(
            receipt_handle=listener.receipt_handle, endpoint_id=listener.endpoint_id,
            endpoint_root_id=listener.root_id, endpoint_relative_socket=listener.relative_socket,
            service_uid=listener.service_uid, service_gid=listener.service_gid,
            directory_device=0, directory_inode=0,
            socket_device=listener.socket_device, socket_inode=listener.socket_inode,
            socket_mode=listener.socket_mode, endpoint_sha256=_sha(payload),
            endpoint_binding_phase="prepared-no-effects",
            issued_monotonic=listener.issued_monotonic,
            expires_monotonic=listener.expires_monotonic,
            _directory_fd=-1, _issuer=self._issuer,
        )
        self._receipts[receipt.receipt_handle] = receipt
        return receipt

    def verify_current(self, receipt: RootPreparedUnixAuthorityEndpointReceipt) -> RootPreparedUnixAuthorityEndpointReceipt:
        if (type(receipt) is not RootPreparedUnixAuthorityEndpointReceipt
                or receipt._issuer is not self._issuer
                or self._receipts.get(receipt.receipt_handle) is not receipt
                or receipt.expires_monotonic <= time.monotonic()):
            raise NativeWorkerRecipeUnavailable("authority endpoint receipt is foreign, stale, or expired")
        current = self._custodian.resolve_current(receipt.receipt_handle)
        if (current.socket_device, current.socket_inode, current.service_uid,
                current.service_gid, current.endpoint_id, current.relative_socket) != (
                receipt.socket_device, receipt.socket_inode, receipt.service_uid,
                receipt.service_gid, receipt.endpoint_id, receipt.endpoint_relative_socket):
            self._receipts.pop(receipt.receipt_handle, None)
            raise NativeWorkerRecipeUnavailable("authority endpoint socket identity changed")
        return receipt


class RootSetupNativeWorkerRecipeRegistry:
    """Resolve one source-backed worker recipe from current setup custody."""

    def __init__(self, binding: Any, pm_registry: Any, runnable_roles: Any,
                 native_outputs: Any, root_journal: Path):
        from .bootstrap_runtime_factory import (
            RootRunnableRoleProjectionRegistry, RootSelectedInstallationBinding,
        )
        from .native_output_receipts import RootMaterializationReceiptRegistry
        from .pm_runtime import RootPMRuntimeReceiptRegistry
        if (type(binding) is not RootSelectedInstallationBinding
                or not isinstance(pm_registry, RootPMRuntimeReceiptRegistry)
                or not isinstance(runnable_roles, RootRunnableRoleProjectionRegistry)
                or not isinstance(native_outputs, RootMaterializationReceiptRegistry)
                or root_journal != _ROOT_JOURNAL
                or runnable_roles.binding is not binding
                or runnable_roles.pm_registry is not pm_registry
                or runnable_roles.output_registry is not native_outputs):
            raise ValueError("native worker recipe registry requires one exact root setup receipt graph")
        self.binding = binding
        self.pm_registry = pm_registry
        self.runnable_roles = runnable_roles
        self.native_outputs = native_outputs
        self.root_journal = root_journal
        self.start_recipe_source = RootNativeHermesWorkerStartRecipeSource(binding)
        self.endpoint_observer = RootPreparedUnixAuthorityEndpointObserver.from_root_setup(binding)
        self._issuer = object()
        self._recipes: dict[str, RootPreparedNativeWorkerRecipe] = {}
        self._working_roots: dict[str, RootPreparedWorkingRootReceipt] = {}
        self._service_identity: RootPreparedServiceIdentityReceipt | None = None
        self._current_selection_handle: str | None = None
        self._current_runnable_closure: Any | None = None

    @classmethod
    def from_root_setup(cls, binding: Any, pm_registry: Any, runnable_roles: Any,
                        native_outputs: Any, root_journal: Path) -> "RootSetupNativeWorkerRecipeRegistry":
        return cls(binding, pm_registry, runnable_roles, native_outputs, root_journal)

    def resolve_prepared_candidates(self, prepared_bundle: Any,
                                    runnable_closure: Any | None = None
                                    ) -> tuple[RootPreparedNativeWorkerRecipe, ...]:
        from .bootstrap_runtime_factory import RootPreparedNativeBundle, RootSelectedRunnableRoleClosure
        if (type(prepared_bundle) is not RootPreparedNativeBundle
                or (runnable_closure is not None
                    and type(runnable_closure) is not RootSelectedRunnableRoleClosure)):
            raise NativeWorkerRecipeUnavailable("native worker recipe candidates require the exact prepared bundle")
        session = self.binding._session
        session._check_live()
        current_bundle = self.binding.resolve_current_prepared_native_bundle(prepared_bundle)
        current_roles = (self.runnable_roles.verify_current(runnable_closure)
                         if runnable_closure is not None else None)
        self._current_selection_handle = None
        self._current_runnable_closure = None
        prepared = session._resolve_current_prepared_enrollment()
        self._current_runnable_closure = current_roles
        if session._native_worker_endpoint_receipt is None:
            raise NativeWorkerRecipeUnavailable(
                "root setup did not prepare the no-effects listener before signing the native source choice")
        if (current_bundle is not prepared_bundle
                or (current_roles is not None and (
                    current_roles.setup_session_id != prepared_bundle.setup_session_id
                    or current_roles.transaction_handle != prepared_bundle.transaction_handle
                    or current_roles.prepared_generation_id != prepared_bundle.prepared_generation_id))
                or prepared_bundle.prepared_generation_id != prepared.generation_id
                or prepared_bundle.prepared_generation_digest != prepared.generation_digest):
            raise NativeWorkerRecipeUnavailable("prepared worker inputs do not share the current setup generation")
        # The source adapter audits exact upstream and installer module bytes,
        # and resolves the official interpreter only through held PM members.
        start_recipe = self.start_recipe_source.compile()
        identity = session._native_worker_service_identity_receipt or self._service_identity
        if identity is not None:
            try:
                verify_prepared_service_identity(self.binding, identity)
            except NativeWorkerRecipeUnavailable:
                identity.close()
                self._service_identity = None
                identity = None
        if identity is None:
            identity = observe_prepared_service_identity(self.binding)
            self._service_identity = identity
            session._native_worker_service_identity_receipt = identity
        endpoint = self.endpoint_observer.observe(identity)
        root_identity = self.binding.resolve_current_setup_identity()
        principal = root_identity.principal
        namespace = root_identity.namespace
        if (principal.binding_sha256 != root_identity.principal_binding_sha256
                or namespace.binding_sha256 != root_identity.namespace_binding_sha256):
            endpoint.close()
            raise NativeWorkerRecipeUnavailable("current principal or namespace binding changed")
        # The source-selected installer adapter receipt is the recipe definition;
        # final native output handles stay outside the signed input digest.
        definition_path = "lib/python/hermes_installer/authority/native_worker_start_recipe.py"
        definition = next((row for row in session._resolve_prepared_native_worker_start_source_module_receipts()
                          if row.relative_path == definition_path), None)
        if definition is None:
            endpoint.close()
            raise NativeWorkerRecipeUnavailable("held native Hermes start source member is unavailable")
        definition.read_current()
        source_handles = tuple(sorted({
            prepared_bundle.hermes_source_receipt_handle,
            prepared_bundle.pm_runtime_receipt_handle,
            *start_recipe.installer_member_receipt_handles,
            *start_recipe.worker_member_receipt_handles,
        }))
        if any(not isinstance(handle, str) or not handle for handle in source_handles):
            endpoint.close()
            raise NativeWorkerRecipeUnavailable("held worker recipe has an incomplete source receipt closure")
        expiry_inputs = [prepared.expires_monotonic, endpoint.expires_monotonic,
                         time.monotonic() + _MAX_LEASE]
        if current_roles is not None:
            expiry_inputs.append(current_roles.expires_monotonic)
        expires = min(expiry_inputs)
        if expires <= time.monotonic():
            endpoint.close()
            raise NativeWorkerRecipeUnavailable("prepared worker recipe source lease expired")
        service_generation = prepared.generation_id
        resource_profile_id = session.resolve_selected_resource_profile(
            prepared_bundle.resource_profile_selection_receipt_handle).profile_id
        pm = self.pm_registry.resolve_runtime_projection(
            prepared_bundle.pm_runtime_receipt_handle,
            prepared_bundle.transaction_handle,
            prepared_bundle.prepared_generation_id,
        )
        try:
            argv_recipe_digest = _sha([str(pm.selection.python_path), *start_recipe.argv_suffix])
            environment_recipe_digest = _sha({
                "recipe_id": start_recipe.environment_recipe_id,
                "bindings": list(start_recipe.environment_binding_names),
                "network": "af-unix-only",
            })
            # Use the start adapter's exact source-owned member IDs. Do not
            # infer entrypoint or boundary roles from filenames or manifests.
            from .bootstrap_runtime_factory import RootPreparedReleaseMemberReceipt
            worker_members = self.binding.resolve_prepared_worker_role_module_receipts()
            entrypoint_path = "src/hermes_installer/native_invocations.py"
            boundary_path = "src/hermes_installer/native_boundary.py"
            def member_receipt(path: str, expected_sha: str) -> Any:
                matches = [row for row in worker_members
                           if type(row) is RootPreparedReleaseMemberReceipt
                           and row.relative_path == path and row.sha256 == expected_sha]
                if len(matches) != 1:
                    raise NativeWorkerRecipeUnavailable(
                        "the exact held native worker source member is missing or ambiguous")
                return matches[0]
            source_by_path = {row.relative_path: row for row in start_recipe.worker_members}
            if set(source_by_path) != {entrypoint_path, boundary_path}:
                raise NativeWorkerRecipeUnavailable(
                    "start recipe does not declare the exact fixed entrypoint and boundary source IDs")
            entrypoint_receipt = member_receipt(
                entrypoint_path, source_by_path[entrypoint_path].sha256)
            boundary_receipt = member_receipt(
                boundary_path, source_by_path[boundary_path].sha256)
            entrypoint_receipt.read_current()
            boundary_receipt.read_current()
            definition_rows = [
                {"artifact_id": receipt.artifact_id, "relative_path": receipt.relative_path,
                 "sha256": receipt.sha256, "size_bytes": receipt.size_bytes,
                 "receipt_handle": receipt.source_receipt_handle}
                for receipt in (entrypoint_receipt, boundary_receipt)
            ]
            definitions_sha256 = _sha(sorted(definition_rows, key=lambda row: row["relative_path"]))
            input_source = {
                "source_recipe_sha256": start_recipe.recipe_sha256,
                "definition_member_sha256": definition.sha256,
                "source_receipt_handles": list(source_handles),
                "prepared_generation_id": prepared.generation_id,
                "principal_binding_sha256": principal.binding_sha256,
                "namespace_binding_sha256": namespace.binding_sha256,
                "profile_id": _PROFILE_ID,
                "profile_generation": service_generation,
                "resources_profile_id": resource_profile_id,
                "service_identity": [identity.service_user, identity.service_uid, identity.service_gid],
                "endpoint_sha256": endpoint.endpoint_sha256,
                "endpoint_binding_phase": endpoint.endpoint_binding_phase,
                "entrypoint_source": [entrypoint_receipt.receipt_handle, entrypoint_receipt.sha256],
                "boundary_source": [boundary_receipt.receipt_handle, boundary_receipt.sha256],
                "pm_runtime_sha256": pm.base_closure_sha256,
                "source_role_definition_closure_sha256": definitions_sha256,
                "argv_token_recipe_sha256": argv_recipe_digest,
                "sanitized_environment_recipe_sha256": environment_recipe_digest,
            }
            now = time.monotonic()
            work_root = self._issue_work_root(identity)
            self._working_roots[work_root.receipt_handle] = work_root
            recipe = RootPreparedNativeWorkerRecipe(
                schema=1, receipt_handle=secrets.token_urlsafe(36), recipe_id=RECIPE_ID,
                definition_member_receipt_handle=definition.receipt_handle,
                definition_member_sha256=definition.sha256,
                source_artifact_receipt_handles=source_handles,
                prepared_generation_id=prepared.generation_id,
                prepared_generation_digest=prepared.generation_digest,
                setup_session_id=prepared_bundle.setup_session_id,
                transaction_handle=prepared_bundle.transaction_handle,
                principal_binding_sha256=principal.binding_sha256,
                namespace_binding_sha256=namespace.binding_sha256,
                service_profile_id=_PROFILE_ID, profile_generation=service_generation,
                resources_profile_id=resource_profile_id,
                service_identity_receipt_handle=_issue_identity_handle(identity),
                service_enrollment_id="hermes-agent-native-enrollment-v1",
                process_profile_id=_PROFILE_ID,
                network_id="native-owner-overlay-network-v1",
                network_role="af-unix",
                endpoint_binding_receipt_handle=endpoint.receipt_handle,
                endpoint_binding_phase=endpoint.endpoint_binding_phase,
                unix_endpoint_root_id=endpoint.endpoint_root_id,
                endpoint_relative_socket=endpoint.endpoint_relative_socket,
                executable_member_receipt_handle=pm.selection.receipt_handle,
                executable_sha256=pm.executable_member.sha256,
                pm_runtime_receipt_handle=pm.selection.receipt_handle,
                pm_base_closure_sha256=pm.base_closure_sha256,
                source_role_definition_closure_sha256=definitions_sha256,
                native_entrypoint_source_receipt_handle=entrypoint_receipt.receipt_handle,
                native_entrypoint_source_sha256=entrypoint_receipt.sha256,
                native_boundary_source_receipt_handle=boundary_receipt.receipt_handle,
                native_boundary_source_sha256=boundary_receipt.sha256,
                argument_recipe_id=RECIPE_ID,
                argv_token_recipe_sha256=argv_recipe_digest,
                sanitized_environment_recipe_sha256=environment_recipe_digest,
                working_root_receipt_handle=work_root.receipt_handle,
                controller_binding_handle=prepared_bundle.materialization_receipt_handle,
                complete_recipe_sha256=_sha(input_source),
                issued_monotonic=now, expires_monotonic=expires,
                _issuer=self._issuer, _start_recipe=start_recipe,
                _identity=identity, _endpoint=endpoint, _working_root=work_root,
            )
            self._recipes[recipe.receipt_handle] = recipe
            return (recipe,)
        except BaseException:
            if "work_root" in locals():
                self._working_roots.pop(work_root.receipt_handle, None)
                work_root.close()
            endpoint.close()
            raise
        finally:
            pm.close()

    def verify_current(self, recipe: RootPreparedNativeWorkerRecipe) -> RootPreparedNativeWorkerRecipe:
        if (type(recipe) is not RootPreparedNativeWorkerRecipe
                or recipe._issuer is not self._issuer
                or self._recipes.get(recipe.receipt_handle) is not recipe
                or recipe.expires_monotonic <= time.monotonic()):
            raise NativeWorkerRecipeUnavailable("worker recipe is foreign, stale, or expired")
        self.start_recipe_source.verify_current(recipe._start_recipe)
        self.endpoint_observer.verify_current(recipe._endpoint)
        verify_prepared_service_identity(self.binding, recipe._identity)
        self._verify_work_root(recipe._working_root, recipe._identity)
        policy_handle = getattr(self.binding._session, "_current_native_policy_selection_handle", None)
        if policy_handle is None:
            # A pre-choice source candidate is current under the prepared
            # identity and held source graph; it has no signed-choice authority yet.
            if self._current_selection_handle is not None:
                raise NativeWorkerRecipeUnavailable("selected worker recipe lost its signed choice")
            prepared = self.binding._session._resolve_current_prepared_enrollment()
            identity = self.binding.resolve_current_setup_identity()
            if (prepared.generation_id != recipe.prepared_generation_id
                    or prepared.generation_digest != recipe.prepared_generation_digest
                    or identity.principal_binding_sha256 != recipe.principal_binding_sha256
                    or identity.namespace_binding_sha256 != recipe.namespace_binding_sha256):
                self._recipes.pop(recipe.receipt_handle, None)
                raise NativeWorkerRecipeUnavailable("worker source candidate setup identity changed")
        else:
            current = self.binding.resolve_current_native_policy_selection(policy_handle)
            if (policy_handle != self._current_selection_handle
                    or recipe.receipt_handle not in current.selected_worker_recipe_handles
                    or current.principal_binding_sha256 != recipe.principal_binding_sha256
                    or current.namespace_binding_sha256 != recipe.namespace_binding_sha256
                    or current.service_generation != recipe.profile_generation):
                self._recipes.pop(recipe.receipt_handle, None)
                raise NativeWorkerRecipeUnavailable("worker recipe setup selection changed")
        return recipe

    def resolve_current_recipe(self, receipt_handle: str) -> RootPreparedNativeWorkerRecipe:
        recipe = self._recipes.get(receipt_handle)
        if recipe is None:
            raise NativeWorkerRecipeUnavailable("worker recipe handle is not retained by this issuer")
        return self.verify_current(recipe)

    def verify_prechoice_candidate(self, recipe: RootPreparedNativeWorkerRecipe
                                   ) -> RootPreparedNativeWorkerRecipe:
        """Revalidate an unselected source candidate before the TTY signs its choice."""
        session = self.binding._session
        if (type(recipe) is not RootPreparedNativeWorkerRecipe
                or session._current_native_policy_selection_handle is not None
                or self._current_selection_handle is not None):
            raise NativeWorkerRecipeUnavailable("worker source candidate is not in the pre-choice setup phase")
        return self.verify_current(recipe)

    def resolve_current_runnable_closure(self, selection: Any) -> Any:
        """Return the exact held role closure joined when selected recipes were issued."""
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        if (type(selection) is not RootNativePolicyPreparationSelection
                or selection.selection_handle != self._current_selection_handle
                or self._current_runnable_closure is None):
            raise NativeWorkerRecipeUnavailable(
                "current selected native policy has no retained runnable-role closure")
        current = self.binding.resolve_current_native_policy_selection(selection.selection_handle)
        if current is not selection:
            raise NativeWorkerRecipeUnavailable("native policy selection changed after role closure issuance")
        return self.runnable_roles.verify_current(self._current_runnable_closure)

    def bind_selected_candidates(self, selection: Any) -> Any:
        """Bind pre-choice source receipts to the actual signed TTY choice."""
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        if type(selection) is not RootNativePolicyPreparationSelection:
            raise NativeWorkerRecipeUnavailable("recipe binding requires the exact signed policy selection")
        current = self.binding.resolve_current_native_policy_selection(selection.selection_handle)
        if current is not selection:
            raise NativeWorkerRecipeUnavailable("recipe binding selection is not current")
        handles = selection.selected_worker_recipe_handles
        digests = selection.selected_worker_recipe_digests
        records = selection.selected_worker_recipe_records
        if (len(handles) > 1 or len(handles) != len(digests) or len(handles) != len(records)
                or tuple(sorted(handles)) != handles):
            raise NativeWorkerRecipeUnavailable("signed worker recipe choice is not the exact bounded candidate set")
        for handle, digest, projection in zip(handles, digests, records, strict=True):
            recipe = self._recipes.get(handle)
            if (recipe is None or recipe.complete_recipe_sha256 != digest
                    or _plain(recipe.public_projection()) != _plain(projection)):
                raise NativeWorkerRecipeUnavailable("signed worker recipe differs from the retained source candidate")
        self._current_selection_handle = selection.selection_handle
        # The final six-role output closure is downstream of this signed
        # source choice and is attached only after compilation/reservation.
        self._current_runnable_closure = None
        return selection

    def retain_runnable_closure(self, selection: Any, runnable_closure: Any) -> Any:
        from .bootstrap_runtime_factory import RootSelectedRunnableRoleClosure
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        if (type(selection) is not RootNativePolicyPreparationSelection
                or type(runnable_closure) is not RootSelectedRunnableRoleClosure
                or self.binding.resolve_current_native_policy_selection(selection.selection_handle) is not selection
                or selection.selection_handle != self._current_selection_handle):
            raise NativeWorkerRecipeUnavailable("final runnable closure is outside the signed recipe selection")
        current = self.runnable_roles.verify_current(runnable_closure)
        recipe_handles = selection.selected_worker_recipe_handles
        if (len(recipe_handles) != 1
                or current.setup_session_id != selection.setup_session_id
                or current.transaction_handle != selection.transaction_handle
                or current.prepared_generation_id != selection.prepared_generation_id):
            raise NativeWorkerRecipeUnavailable("final runnable closure does not join the exact selected recipe")
        self._current_runnable_closure = current
        return current

    def resolve_current_runnable_closure(self, selection_handle: str) -> Any:
        """Resolve the closure retained after the exact signed worker choice."""
        from .bootstrap_runtime_factory import RootSelectedRunnableRoleClosure
        from .native_policy_preparation import RootNativePolicyPreparationSelection
        selection = self.binding.resolve_current_native_policy_selection(selection_handle)
        closure = self._current_runnable_closure
        if (type(selection) is not RootNativePolicyPreparationSelection
                or selection.selection_handle != self._current_selection_handle
                or len(selection.selected_worker_recipe_handles) != 1
                or type(closure) is not RootSelectedRunnableRoleClosure):
            raise NativeWorkerRecipeUnavailable(
                "selected worker has no retained final runnable-role closure")
        current = self.runnable_roles.verify_current(closure)
        if (current is not closure
                or current.setup_session_id != selection.setup_session_id
                or current.transaction_handle != selection.transaction_handle
                or current.prepared_generation_id != selection.prepared_generation_id):
            raise NativeWorkerRecipeUnavailable(
                "retained runnable-role closure differs from the current signed worker choice")
        return closure

    def close(self) -> None:
        """Release only root-held duplicate work-root descriptors."""
        for receipt in tuple(self._working_roots.values()):
            receipt.close()
        self._working_roots.clear()
        self._recipes.clear()
        self._current_runnable_closure = None
        self._current_selection_handle = None
        self._service_identity = None

    def _issue_work_root(self, identity: RootPreparedServiceIdentityReceipt) -> RootPreparedWorkingRootReceipt:
        try:
            held = os.dup(identity.work_root_fd)
            info = os.fstat(held)
        except OSError:
            raise NativeWorkerRecipeUnavailable("selected worker working-root descriptor is unavailable") from None
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != identity.service_uid
                or info.st_gid != identity.service_gid or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != identity.roots_device_inode[1]):
            os.close(held)
            raise NativeWorkerRecipeUnavailable("selected worker working-root descriptor changed")
        now = time.monotonic()
        root = RootPreparedWorkingRootReceipt(
            receipt_handle=secrets.token_urlsafe(36), root_id=identity.work_root_id,
            service_uid=identity.service_uid, service_gid=identity.service_gid,
            device=info.st_dev, inode=info.st_ino, mode=stat.S_IMODE(info.st_mode),
            issued_monotonic=now, expires_monotonic=identity.expires_monotonic,
            directory_fd=held, _identity_receipt_handle=identity.receipt_handle,
            _issuer=self._issuer)
        return root

    def _verify_work_root(self, receipt: RootPreparedWorkingRootReceipt,
                          identity: RootPreparedServiceIdentityReceipt) -> None:
        if (type(receipt) is not RootPreparedWorkingRootReceipt
                or self._working_roots.get(receipt.receipt_handle) is not receipt
                or receipt._issuer is not self._issuer
                or receipt._identity_receipt_handle != identity.receipt_handle
                or receipt.expires_monotonic <= time.monotonic()):
            raise NativeWorkerRecipeUnavailable("working-root receipt is foreign, stale, or expired")
        try:
            info = os.fstat(receipt.directory_fd)
            path_info = identity.work_root.lstat()
        except OSError:
            raise NativeWorkerRecipeUnavailable("working-root custody is no longer available") from None
        if ((info.st_dev, info.st_ino) != (receipt.device, receipt.inode)
                or (path_info.st_dev, path_info.st_ino) != (receipt.device, receipt.inode)
                or info.st_uid != receipt.service_uid or info.st_gid != receipt.service_gid
                or stat.S_IMODE(info.st_mode) != receipt.mode):
            raise NativeWorkerRecipeUnavailable("working-root identity changed")


def observe_prepared_service_identity(binding: Any) -> RootPreparedServiceIdentityReceipt:
    """Observe current service NSS, protected marker, and three private roots."""
    session = binding._session
    session._check_live()
    from .bootstrap_enrollment import SERVICE_NAME, _read_json_if_owned
    import grp
    import pwd

    policy = session._policy
    prepared = session._resolve_current_prepared_enrollment()
    account_name = policy.identity_policy.get("service_account_name")
    if account_name != _SERVICE_ACCOUNT or account_name == SERVICE_NAME:
        raise NativeWorkerRecipeUnavailable("prepared native worker service account differs from its fixed identity")
    try:
        account, group = pwd.getpwnam(account_name), grp.getgrnam(account_name)
        marker_path = session._identity.marker
        marker = _read_json_if_owned(marker_path)
        marker_info = marker_path.lstat()
    except (KeyError, OSError):
        raise NativeWorkerRecipeUnavailable("prepared native worker NSS account or root marker is absent") from None
    if (account.pw_uid <= 0 or account.pw_gid <= 0 or account.pw_gid != group.gr_gid
            or account.pw_dir not in {"/nonexistent", "/"}
            or account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}
            or marker != {"schema": 1, "name": account_name, "uid": account.pw_uid, "gid": account.pw_gid}
            or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != 0
            or stat.S_IMODE(marker_info.st_mode) != 0o600):
        raise NativeWorkerRecipeUnavailable("prepared worker NSS identity no longer matches its root marker")
    root = Path(policy.root_policy["service_parent_root"])
    roots = tuple(root / child for child in ("home", "work", "data"))
    identities = []
    descriptors = []
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    for path in roots:
        try:
            info = path.lstat()
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
        except OSError:
            for held in descriptors:
                os.close(held)
            raise NativeWorkerRecipeUnavailable("prepared worker home/work/data root is absent") from None
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != account.pw_uid or info.st_gid != account.pw_gid
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (opened.st_dev, opened.st_ino)):
            os.close(descriptor)
            for held in descriptors:
                os.close(held)
            raise NativeWorkerRecipeUnavailable("prepared worker root ownership or mode is invalid")
        identities.append((info.st_dev, info.st_ino))
        descriptors.append(descriptor)
    now = time.monotonic()
    return RootPreparedServiceIdentityReceipt(
        service_user=account_name, service_uid=account.pw_uid, service_gid=account.pw_gid,
        identity_marker_sha256=hashlib.sha256(_canonical(marker)).hexdigest(),
        profile_id=_PROFILE_ID, generation=prepared.generation_id,
        home_root_id=policy.root_policy["service_home_root_id"],
        work_root_id=policy.root_policy["service_work_root_id"],
        data_root_id=policy.root_policy["service_data_root_id"],
        home_root=roots[0], work_root=roots[1], data_root=roots[2],
        roots_device_inode=tuple(identities), issued_monotonic=now,
        receipt_handle=secrets.token_urlsafe(36),
        home_root_fd=descriptors[0], work_root_fd=descriptors[1], data_root_fd=descriptors[2],
        expires_monotonic=min(now + _MAX_LEASE, prepared.expires_monotonic),
        _marker_device_inode=(marker_info.st_dev, marker_info.st_ino), _issuer=session._seal,
    )


def verify_prepared_service_identity(binding: Any,
                                     receipt: RootPreparedServiceIdentityReceipt) -> RootPreparedServiceIdentityReceipt:
    current = observe_prepared_service_identity(binding)
    try:
        if (type(receipt) is not RootPreparedServiceIdentityReceipt
                or receipt._issuer is not binding._session._seal
                or receipt.expires_monotonic <= time.monotonic()
                or (current.service_user, current.service_uid, current.service_gid,
                    current.identity_marker_sha256, current.roots_device_inode)
                   != (receipt.service_user, receipt.service_uid, receipt.service_gid,
                       receipt.identity_marker_sha256, receipt.roots_device_inode)):
            raise NativeWorkerRecipeUnavailable("prepared service identity or root custody changed")
        return receipt
    finally:
        current.close()


def _issue_identity_handle(receipt: RootPreparedServiceIdentityReceipt) -> str:
    return receipt.receipt_handle


__all__ = [
    "NativeWorkerRecipeUnavailable", "RootPreparedNativeWorkerRecipe",
    "RootPreparedServiceIdentityReceipt", "RootPreparedUnixAuthorityEndpointReceipt",
    "RootPreparedWorkingRootReceipt",
    "RootPreparedUnixAuthorityEndpointObserver", "RootSetupNativeWorkerRecipeRegistry",
    "observe_prepared_service_identity", "verify_prepared_service_identity",
]
