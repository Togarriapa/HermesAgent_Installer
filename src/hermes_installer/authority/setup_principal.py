"""Root-local Authentik identity observation and first-setup principal selection.

These receipts are setup-session capabilities, not worker claims or active
runtime authority.  The selected Authentik credential is resolved only from
the root credential vault; the current-user and complete group reads use the
existing bounded Authentik implementation and fixed HTTPS transport.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import sys
import time
import fcntl
import getpass
import grp
import pwd
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Protocol

from .authentik import (
    AuthentikEnrollment,
    AuthentikSystemPolicy,
    TLSAuthentikTransport,
)
from .bootstrap_enrollment import (
    BootstrapEnrollmentError,
    BootstrapEnrollmentPending,
    EnrollmentReceipt,
    VerifiedCommittedEnrollment,
    RootSetupSessionHandle,
    RootSetupSessionStore,
    VerifiedRootSetupAuthorization,
    _LiveRootSetupAuthorizer,
    _canonical,
)
from .service import PrincipalBinding

AUTHENTIK_POLICY_REVISION = "authentik-policy-v1"
AUTHENTIK_POLICY_SELECTION_ID = "installer-authentik-policy-template-v1"

SCHEMA = 1
IDENTITY_RECEIPT_TTL_SECONDS = 30.0
SELECTION_RECEIPT_TTL_SECONDS = 30.0
SETUP_POLICY_SELECTION_TTL_SECONDS = 300.0
MAX_RECEIPT_BYTES = 64 * 1024
_HANDLE = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_CREDENTIAL_REF = re.compile(r"[A-Za-z0-9_.-]{1,96}\Z")


class RootSetupAuthentikPolicyResolver(Protocol):
    """Resolve a wizard-issued policy handle from the current root setup."""

    def resolve_policy_selection(
        self, setup_session_handle: Any,
        policy_selection_handle: str,
    ) -> "VerifiedAuthentikPolicySelection": ...

    def resolve_policy_selection_by_digest(
        self, setup_session_handle: Any,
        policy_selection_digest: str,
    ) -> "VerifiedAuthentikPolicySelection": ...


@dataclass(frozen=True, slots=True)
class VerifiedAuthentikPolicySelection:
    """Root-reviewed Authentik settings; no URL or group is request supplied."""

    selection_id: str
    https_origin: str
    system_group_id: str
    recipient_group_id: str
    policy_revision: str
    actor_credential_ref: str
    selection_digest: str


@dataclass(frozen=True, slots=True)
class RootSetupAuthentikPolicyRecord:
    schema: int
    selection_handle: str
    compilation_session_handle: str
    compilation_transaction_handle: str
    plan_sha256: str
    https_origin: str
    system_group_id: str
    recipient_group_id: str
    policy_revision: str
    actor_credential_ref: str
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class _PrincipalSetupContext:
    session_id: str
    transaction_handle: str
    plan_digest: str
    expires_monotonic: float
    phase: str
    authorization: VerifiedRootSetupAuthorization | None = None
    registry: Any = field(default=None, compare=False, repr=False)
    resolver_handle: Any = field(default=None, compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class AuthentikIdentityReceipt:
    schema: int
    receipt_id: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    policy_selection_digest: str
    username: str
    email: str
    authentik_subject_id: str
    actor_credential_ref: str
    direct_group_ids: tuple[str, ...]
    effective_group_ids: tuple[str, ...]
    system_member: bool
    policy_revision: str
    checked_at_monotonic: float
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class VerifiedRootSetupPrincipalSelection:
    schema: int
    receipt_id: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    principal_id: str
    username: str
    email: str
    authentik_subject_id: str
    actor_credential_ref: str
    service_profile_id: str
    namespace_id: str
    capabilities: tuple[str, ...]
    identity_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float

    @property
    def identity_kind(self) -> str:
        return "authentik-subject-v1"

    @property
    def principal_binding(self) -> "PrincipalBindingFactory":
        """Return a deferred join; the dedicated NSS UID is issued at activation."""
        return PrincipalBindingFactory(
            self.principal_id, self.service_profile_id, self.namespace_id,
            frozenset(self.capabilities),
        )


@dataclass(frozen=True, slots=True)
class VerifiedRootNamespaceSelection:
    """Distinct root-issued namespace choice bound to a prepared generation."""

    schema: int
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_digest: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_receipt_id: str
    target_profile_id: str
    namespace_id: str
    issued_monotonic: float
    expires_monotonic: float
    _registry_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class RootSetupPrincipalSelector:
    """Stable, non-authorizing setup intent; never a substitute for a lease."""
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    principal_id: str
    authentik_subject_id: str
    username: str
    email: str
    authentik_policy_selection_handle: str
    policy_selection_sha256: str
    policy_revision: str
    direct_group_ids: tuple[str, ...]
    effective_group_ids: tuple[str, ...]
    system_member: bool
    service_profile_id: str
    reviewed_capability_map_sha256: str
    selected_capability_ceiling: tuple[str, ...]
    binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int


@dataclass(frozen=True, slots=True)
class RootSetupNamespaceSelector:
    """Stable namespace intent bound to the prepared-generation predecessor."""
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    principal_binding_sha256: str
    target_profile_id: str
    namespace_id: str
    namespace_policy: str
    binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int


@dataclass(frozen=True, slots=True)
class RootCurrentSetupIdentitySnapshot:
    """Atomic fresh principal/namespace evidence pair, bounded to 30 seconds."""
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_binding_sha256: str
    namespace_binding_sha256: str
    principal: VerifiedRootSetupPrincipalSelection
    namespace: VerifiedRootNamespaceSelection
    identity_receipt_handle: str
    issued_monotonic: float
    expires_monotonic: float


_LOCAL_OWNER_REGISTRATIONS = frozenset({
    "resource-overlay-store:tool:resource_overlay_read",
    "resource-overlay-store:tool:resource_overlay_history",
    "resource-overlay-store:tool:resource_overlay_write",
    "resource-overlay-store:tool:resource_overlay_delete",
})
_LOCAL_OWNER_PROFILE_ID = "hermes-agent-native-v1"


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupCapabilitySelection:
    """Finite root TTY choice for the four owner-overlay operations."""
    schema: int
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    selected_registration_ids: tuple[str, ...]
    selection_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootLocalOwnerIdentityReceipt:
    schema: int
    receipt_handle: str
    identity_kind: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    installed_release_receipt_handle: str
    actor_receipt_handle: str
    machine_target_binding_digest: str
    target_account_name: str
    observed_uid: int
    observed_primary_gid: int
    observed_primary_group_name: str
    account_binding_sha256: str
    observation_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _issuer_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootLocalOwnerPrincipalSelection:
    schema: int
    receipt_handle: str
    identity_kind: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    owner_identity_receipt_handle: str
    principal_id: str
    service_profile_id: str
    namespace_id: str
    capability_selection_handle: str
    capability_selection_sha256: str
    selected_capability_ceiling: tuple[str, ...]
    principal_binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _issuer_seal: str = field(repr=False, compare=False)

    @property
    def capabilities(self) -> tuple[str, ...]:
        return self.selected_capability_ceiling

    @property
    def receipt_id(self) -> str:
        return self.receipt_handle

    @property
    def selection_handle(self) -> str:
        return self.receipt_handle

    @property
    def binding_sha256(self) -> str:
        return self.principal_binding_sha256

    @property
    def identity_receipt_handle(self) -> str:
        return self.owner_identity_receipt_handle

    @property
    def principal_binding(self) -> "PrincipalBindingFactory":
        return PrincipalBindingFactory(self.principal_id, self.service_profile_id,
                                      self.namespace_id,
                                      frozenset(self.selected_capability_ceiling))


@dataclass(frozen=True, slots=True, repr=False)
class RootCurrentLocalOwnerIdentitySnapshot:
    snapshot_handle: str
    principal_selection_handle: str
    owner_identity_receipt_handle: str
    capability_selection_handle: str
    principal: RootLocalOwnerPrincipalSelection
    owner_identity: RootLocalOwnerIdentityReceipt
    capability_selection: RootSetupCapabilitySelection
    issued_monotonic: float
    expires_monotonic: float
    _registry_seal: str = field(repr=False, compare=False)
    namespace_selection_handle: str | None = None
    namespace_binding_sha256: str | None = None
    namespace: Any | None = field(default=None, repr=False, compare=False)

    @property
    def identity_kind(self) -> str:
        return self.principal.identity_kind

    @property
    def principal_id(self) -> str:
        return self.principal.principal_id

    @property
    def service_profile_id(self) -> str:
        return self.principal.service_profile_id

    @property
    def namespace_id(self) -> str:
        return self.principal.namespace_id

    @property
    def principal_binding_sha256(self) -> str:
        return self.principal.principal_binding_sha256

    @property
    def identity_receipt_handle(self) -> str:
        return self.owner_identity_receipt_handle

    @property
    def principal_receipt_handle(self) -> str:
        return self.principal.receipt_handle


@dataclass(frozen=True, slots=True, repr=False)
class RootLocalOwnerNamespaceSelector:
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_handle: str
    principal_binding_sha256: str
    target_profile_id: str
    namespace_id: str
    namespace_policy: str
    binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _issuer_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootLocalOwnerPrincipalSelector:
    """Stable local-owner setup intent with no Authentik-shaped identity fields."""
    selection_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    identity_kind: str
    principal_id: str
    service_profile_id: str
    selected_capability_ceiling: tuple[str, ...]
    binding_sha256: str
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _issuer_seal: str = field(repr=False, compare=False)


@dataclass(frozen=True, slots=True, repr=False)
class RootCurrentLocalOwnerNamespaceSelection:
    receipt_handle: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    prepared_generation_id: str
    prepared_generation_digest: str
    principal_selection_receipt_id: str
    target_profile_id: str
    namespace_id: str
    binding_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _issuer_seal: str = field(repr=False, compare=False)


class RootSetupLocalOwnerIdentityRegistry:
    """Root-observed local ownership identity, isolated from Authentik types.

    The selected account comes only from the root-issued stage-zero session.
    Every resolve repeats NSS and current release/actor/session observations;
    persisted JSON is an audit record and never restores an in-memory handle.
    """

    def __init__(self, initial_compilation_registry: Any, root_journal: Path,
                 *, monotonic=time.monotonic) -> None:
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
        if (type(initial_compilation_registry) is not RootInitialCompilationRegistry
                or Path(initial_compilation_registry.root_journal) != root_journal
                or not root_journal.is_absolute() or not callable(monotonic)):
            raise ValueError("local-owner identity requires the selected root compilation registry and journal")
        self._registry = initial_compilation_registry
        self._journal = root_journal
        self._clock = monotonic
        self._seal = secrets.token_hex(32)
        self._capabilities: dict[str, RootSetupCapabilitySelection] = {}
        self._receipts: dict[str, RootLocalOwnerIdentityReceipt] = {}
        self._principals: dict[str, RootLocalOwnerPrincipalSelection] = {}
        self._snapshots: dict[str, RootCurrentLocalOwnerIdentitySnapshot] = {}
        self._normal_adoptions: dict[str, dict[str, Any]] = {}

    @classmethod
    def from_initial_compilation(cls, initial_compilation_registry: Any,
                                 root_journal: Path, *, monotonic=time.monotonic
                                 ) -> "RootSetupLocalOwnerIdentityRegistry":
        return cls(initial_compilation_registry, root_journal, monotonic=monotonic)

    def select_capabilities(self, session_handle: str,
                            selected_registration_ids: tuple[str, ...]
                            ) -> RootSetupCapabilitySelection:
        session = self._current_initial_session(session_handle)
        if (not isinstance(selected_registration_ids, tuple)
                or len(set(selected_registration_ids)) != len(selected_registration_ids)
                or any(not isinstance(item, str) or item not in _LOCAL_OWNER_REGISTRATIONS
                       for item in selected_registration_ids)):
            raise BootstrapEnrollmentError("local capability selection must use exact reviewed overlay registrations")
        now = self._clock()
        expiry = min(now + SETUP_POLICY_SELECTION_TTL_SECONDS, session.expires_monotonic)
        if expiry <= now:
            raise BootstrapEnrollmentPending("local capability selection expired")
        body = {"session": session.compilation_session_handle,
                "transaction": session.compilation_transaction_handle,
                "plan": session.plan_sha256,
                "registrations": list(selected_registration_ids)}
        digest = hashlib.sha256(_canonical(body)).hexdigest()
        result = RootSetupCapabilitySelection(
            SCHEMA, secrets.token_hex(32), session.compilation_session_handle,
            session.compilation_transaction_handle, session.plan_sha256,
            selected_registration_ids, digest, now, expiry, self._seal)
        self._capabilities[result.selection_handle] = result
        self._write_record("local-capability-", result.selection_handle,
                           {**body, "selection_sha256": digest, "state": "selected"})
        return result

    def select_principal(self, session_handle: str,
                         capability_selection_handle: str) -> str:
        session = self._current_initial_session(session_handle)
        capability = self._resolve_capability(session, capability_selection_handle)
        owner = self._observe_owner(session)
        now = self._clock()
        expiry = min(now + IDENTITY_RECEIPT_TTL_SECONDS, owner.expires_monotonic,
                     capability.expires_monotonic, session.expires_monotonic)
        if expiry <= now:
            raise BootstrapEnrollmentPending("local-owner principal selection expired")
        # The ID includes the Linux-owner domain and the machine-bound NSS
        # binding; it cannot collide with the existing Authentik subject recipe.
        principal_id = "linux-local-owner:" + hashlib.sha256(
            (owner.machine_target_binding_digest + "\0" + owner.account_binding_sha256).encode()
        ).hexdigest()
        namespace_id = "hermes-native-" + hashlib.sha256(
            (principal_id + "\0" + _LOCAL_OWNER_PROFILE_ID).encode()).hexdigest()[:32]
        controller = hashlib.sha256((session.compilation_session_handle + "\0" +
                                     session.compilation_transaction_handle).encode()).hexdigest()
        body = {"identity_kind": owner.identity_kind, "session": owner.setup_session_id,
                "transaction": owner.transaction_handle, "plan": owner.plan_sha256,
                "owner_receipt": owner.receipt_handle,
                "owner_binding": owner.account_binding_sha256,
                "machine_target": owner.machine_target_binding_digest,
                "target_account_name": owner.target_account_name,
                "observed_uid": owner.observed_uid,
                "observed_primary_gid": owner.observed_primary_gid,
                "observed_primary_group_name": owner.observed_primary_group_name,
                "principal": principal_id, "profile": _LOCAL_OWNER_PROFILE_ID,
                "namespace": namespace_id, "capability_selection": capability.selection_sha256,
                "selected_capabilities": list(capability.selected_registration_ids),
                "controller": controller}
        binding = hashlib.sha256(_canonical(body)).hexdigest()
        selected = RootLocalOwnerPrincipalSelection(
            SCHEMA, secrets.token_hex(32), "linux-local-owner-v1",
            session.compilation_session_handle, session.compilation_transaction_handle,
            session.plan_sha256, owner.receipt_handle, principal_id,
            _LOCAL_OWNER_PROFILE_ID, namespace_id, capability.selection_handle,
            capability.selection_sha256, capability.selected_registration_ids,
            binding, controller, now, expiry, 0, self._seal)
        self._receipts[owner.receipt_handle] = owner
        self._principals[selected.receipt_handle] = selected
        self._write_record("local-owner-", selected.receipt_handle, body | {
            "principal_binding_sha256": binding, "state": "selected"})
        return selected.receipt_handle

    def resolve_selected_principal(self, principal_selection_handle: str,
                                   setup_session_id: str, transaction_handle: str,
                                   plan_sha256: str) -> RootLocalOwnerPrincipalSelection:
        snapshot = self.resolve_current_selection(setup_session_id,
                                                  principal_selection_handle)
        selected = snapshot.principal
        expected_session_id = (setup_session_id.session_id
                               if isinstance(setup_session_id, RootSetupSessionHandle)
                               else setup_session_id)
        if (selected.setup_session_id != expected_session_id
                or selected.transaction_handle != transaction_handle
                or selected.plan_sha256 != plan_sha256):
            raise BootstrapEnrollmentPending("local-owner principal belongs to another session, transaction, or plan")
        return selected

    def resolve_current_selection(self, session_handle: str,
                                  principal_selection_handle: str
                                  ) -> RootCurrentLocalOwnerIdentitySnapshot:
        normal = isinstance(session_handle, RootSetupSessionHandle)
        if normal:
            adoption = self._normal_adoptions.get(session_handle.session_id)
            if (adoption is None or adoption.get("handle") != session_handle
                    or adoption.get("store") is None):
                raise BootstrapEnrollmentPending("normal local-owner selection is not adopted by this live session")
            store = adoption["store"]
            proof = _current_setup_proof(store, session_handle)
            session_key = proof.setup_session_id
            transaction, plan = proof.transaction_handle, proof.plan_digest
        else:
            session = self._current_initial_session(session_handle)
            session_key = session.compilation_session_handle
            transaction, plan = session.compilation_transaction_handle, session.plan_sha256
        selected = self._principals.get(principal_selection_handle)
        if (selected is None or selected._issuer_seal != self._seal
                or selected.identity_kind != "linux-local-owner-v1"
                or selected.setup_session_id != session_key
                or selected.transaction_handle != transaction
                or selected.plan_sha256 != plan
                or selected.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("local-owner principal selection is stale or foreign")
        if normal:
            _account, owner = self._observe_normal_owner(
                adoption["store"]._live(session_handle).record.get("target_account_name"),
                proof, adoption["store"], session_handle)
            capability = self._capabilities.get(selected.capability_selection_handle)
            if (capability is None or capability._issuer_seal != self._seal
                    or capability.setup_session_id != session_key
                    or capability.transaction_handle != transaction
                    or capability.plan_sha256 != plan
                    or capability.expires_monotonic <= self._clock()):
                raise BootstrapEnrollmentPending("normal local capability choice is stale or foreign")
        else:
            owner = self._observe_owner(session)
            capability = self._resolve_capability(session, selected.capability_selection_handle)
        original_owner = self._receipts.get(selected.owner_identity_receipt_handle)
        if (original_owner is None
                or owner.account_binding_sha256 != original_owner.account_binding_sha256
                or owner.machine_target_binding_digest != original_owner.machine_target_binding_digest
                or capability.selection_sha256 != selected.capability_selection_sha256
                or capability.selected_registration_ids != selected.selected_capability_ceiling):
            raise BootstrapEnrollmentPending("local-owner account or finite selection changed")
        self._receipts[owner.receipt_handle] = owner
        now = self._clock()
        expiry = min(now + IDENTITY_RECEIPT_TTL_SECONDS, selected.expires_monotonic,
                     owner.expires_monotonic, capability.expires_monotonic)
        if expiry <= now:
            raise BootstrapEnrollmentPending("current local-owner snapshot expired")
        snapshot = RootCurrentLocalOwnerIdentitySnapshot(
            secrets.token_hex(32), selected.receipt_handle, owner.receipt_handle,
            capability.selection_handle, selected, owner, capability, now, expiry,
            self._seal)
        self._snapshots[snapshot.snapshot_handle] = snapshot
        if len(self._snapshots) > 4096:
            self._snapshots = {snapshot.snapshot_handle: snapshot}
        return snapshot

    def resolve_adopted_initial_principal(self, normal_session_store: RootSetupSessionStore,
                                          normal_session_handle: RootSetupSessionHandle
                                          ) -> RootLocalOwnerPrincipalSelection:
        if (self._normal_adoptions.get(normal_session_handle.session_id, {}).get("store")
                is not normal_session_store):
            raise BootstrapEnrollmentPending("normal setup has no adopted local-owner principal")
        handle = self._normal_adoptions[normal_session_handle.session_id]["principal_handle"]
        proof = _current_setup_proof(normal_session_store, normal_session_handle)
        return self.resolve_selected_principal(
            handle, normal_session_handle, proof.transaction_handle, proof.plan_digest)

    def resolve_adopted_principal_selector(self, normal_session_store: RootSetupSessionStore,
                                           normal_session_handle: RootSetupSessionHandle
                                           ) -> RootLocalOwnerPrincipalSelector:
        principal = self.resolve_adopted_initial_principal(normal_session_store, normal_session_handle)
        now = self._clock()
        return RootLocalOwnerPrincipalSelector(
            principal.receipt_handle, principal.setup_session_id,
            principal.transaction_handle, principal.plan_sha256,
            "linux-local-owner-v1", principal.principal_id,
            principal.service_profile_id, principal.selected_capability_ceiling,
            principal.principal_binding_sha256, principal.controller_binding_handle,
            now, principal.expires_monotonic, 0, self._seal)

    def resolve_adopted_namespace_selector(self, normal_session_store: RootSetupSessionStore,
                                            normal_session_handle: RootSetupSessionHandle
                                            ) -> RootLocalOwnerNamespaceSelector:
        principal_selector = self.resolve_adopted_principal_selector(
            normal_session_store, normal_session_handle)
        proof = _current_setup_proof(normal_session_store, normal_session_handle)
        authority = normal_session_store.authority_loader_for_session()
        generations = authority.get("service_generations") if isinstance(authority, Mapping) else None
        from .enrollment import _validate_service_generations
        try:
            generation = _validate_service_generations(dict(generations))
        except Exception:
            raise BootstrapEnrollmentPending("current prepared namespace generation is unavailable") from None
        gid, gdigest = generation.get("generation_id"), generation.get("generation_digest")
        if (not isinstance(gid, str) or not isinstance(gdigest, str)
                or proof.expected_previous_generation_digest != gdigest):
            raise BootstrapEnrollmentPending("prepared namespace generation changed")
        body = {"session": proof.setup_session_id, "transaction": proof.transaction_handle,
                "plan": proof.plan_digest, "generation": gid, "generation_digest": gdigest,
                "principal": principal_selector.binding_sha256,
                "namespace": self.resolve_adopted_initial_principal(
                    normal_session_store, normal_session_handle).namespace_id,
                "policy": "per-selected-principal-native-profile-v1"}
        binding = hashlib.sha256(_canonical(body)).hexdigest()
        return RootLocalOwnerNamespaceSelector(
            hashlib.sha256((principal_selector.selection_handle + "\0" + binding).encode()).hexdigest(),
            proof.setup_session_id, proof.transaction_handle, proof.plan_digest,
            gid, gdigest, principal_selector.selection_handle, principal_selector.binding_sha256,
            _LOCAL_OWNER_PROFILE_ID, body["namespace"], "per-selected-principal-native-profile-v1",
            binding, principal_selector.controller_binding_handle, self._clock(),
            _session_expiry(normal_session_store, normal_session_handle), 0, self._seal)

    def resolve_adopted_namespace_selection(self, normal_session_store: RootSetupSessionStore,
                                            normal_session_handle: RootSetupSessionHandle
                                            ) -> RootCurrentLocalOwnerNamespaceSelection:
        selector = self.resolve_adopted_namespace_selector(normal_session_store, normal_session_handle)
        principal = self.resolve_adopted_initial_principal(normal_session_store, normal_session_handle)
        now = self._clock()
        return RootCurrentLocalOwnerNamespaceSelection(
            secrets.token_hex(32), selector.setup_session_id, selector.transaction_handle,
            selector.plan_sha256, selector.prepared_generation_id,
            selector.prepared_generation_digest, principal.receipt_handle,
            selector.target_profile_id, selector.namespace_id, selector.binding_sha256, now,
            min(now + IDENTITY_RECEIPT_TTL_SECONDS, selector.expires_monotonic), self._seal)

    def resolve_current_setup_identity(self, principal_selection_handle: str,
                                       namespace_selection_handle: str,
                                       normal_session_handle: RootSetupSessionHandle
                                       ) -> RootCurrentLocalOwnerIdentitySnapshot:
        snapshot = self.resolve_current_selection(normal_session_handle, principal_selection_handle)
        selector = self.resolve_adopted_namespace_selector(
            self._normal_adoptions[normal_session_handle.session_id]["store"], normal_session_handle)
        if namespace_selection_handle != selector.selection_handle:
            raise BootstrapEnrollmentPending("local-owner namespace selector changed")
        namespace = self.resolve_adopted_namespace_selection(
            self._normal_adoptions[normal_session_handle.session_id]["store"], normal_session_handle)
        current = RootCurrentLocalOwnerIdentitySnapshot(
            snapshot.snapshot_handle, snapshot.principal_selection_handle,
            snapshot.owner_identity_receipt_handle, snapshot.capability_selection_handle,
            snapshot.principal, snapshot.owner_identity, snapshot.capability_selection,
            snapshot.issued_monotonic, min(snapshot.expires_monotonic, namespace.expires_monotonic),
            self._seal, namespace_selection_handle, selector.binding_sha256, namespace)
        self._snapshots[current.snapshot_handle] = current
        return current

    def resolve_current_snapshot(self, session_handle: str, snapshot_handle: str
                                 ) -> RootCurrentLocalOwnerIdentitySnapshot:
        snapshot = self._snapshots.get(snapshot_handle)
        if (snapshot is None or snapshot._registry_seal != self._seal
                or snapshot.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("local-owner current snapshot handle is absent or expired")
        current = self.resolve_current_selection(
            session_handle, snapshot.principal_selection_handle)
        if (current.principal.principal_binding_sha256 != snapshot.principal.principal_binding_sha256
                or current.owner_identity.account_binding_sha256
                   != snapshot.owner_identity.account_binding_sha256
                or current.owner_identity.machine_target_binding_digest
                   != snapshot.owner_identity.machine_target_binding_digest
                or current.capability_selection.selection_sha256
                   != snapshot.capability_selection.selection_sha256):
            self._snapshots.pop(snapshot_handle, None)
            raise BootstrapEnrollmentPending("local-owner current snapshot no longer matches its issuer binding")
        if isinstance(session_handle, RootSetupSessionHandle):
            store = self._normal_adoptions[session_handle.session_id]["store"]
            selector = self.resolve_adopted_namespace_selector(store, session_handle)
            if (snapshot.namespace_selection_handle != selector.selection_handle
                    or snapshot.namespace_binding_sha256 != selector.binding_sha256
                    or snapshot.namespace is None
                    or snapshot.namespace.prepared_generation_id != selector.prepared_generation_id
                    or snapshot.namespace.prepared_generation_digest != selector.prepared_generation_digest
                    or snapshot.namespace.namespace_id != selector.namespace_id):
                self._snapshots.pop(snapshot_handle, None)
                raise BootstrapEnrollmentPending("local-owner namespace snapshot no longer matches current prepared generation")
        return snapshot

    def adopt_initial_publication(self, *, normal_session_store: RootSetupSessionStore,
                                  normal_session_handle: RootSetupSessionHandle
                                  ) -> tuple["RootSetupLocalOwnerIdentityRegistry", str]:
        """Rebind a published local-owner choice to a fresh normal root session."""
        if (not isinstance(normal_session_store, RootSetupSessionStore)
                or normal_session_store.initial_compilation_registry is not self._registry):
            raise BootstrapEnrollmentPending("local-owner adoption requires the matching normal root store")
        from .bootstrap_runtime_factory import RootInitialPublicationHandoff
        handoff = self._registry.resolve_adopted_handoff(normal_session_handle)
        if (not isinstance(handoff, RootInitialPublicationHandoff)
                or handoff.principal_identity_kind != "linux-local-owner-v1"
                or not isinstance(handoff.principal_selection_receipt_handle, str)):
            raise BootstrapEnrollmentPending("published handoff is not in the local-owner identity domain")
        old = self._principals.get(handoff.principal_selection_receipt_handle)
        if (old is None or old.identity_kind != "linux-local-owner-v1"
                or old.setup_session_id != handoff.compilation_session_handle
                or old.transaction_handle != handoff.compilation_transaction_handle
                or old.plan_sha256 != handoff.plan_sha256
                or old.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("published local-owner selection is stale or mismatched")
        proof = _current_setup_proof(normal_session_store, normal_session_handle)
        live = normal_session_store._live(normal_session_handle)
        account, owner = self._observe_normal_owner(
            live.record.get("target_account_name"), proof, normal_session_store, normal_session_handle)
        original_owner = self._receipts.get(old.owner_identity_receipt_handle)
        if (original_owner is None or owner.account_binding_sha256 != original_owner.account_binding_sha256
                or owner.machine_target_binding_digest != original_owner.machine_target_binding_digest):
            raise BootstrapEnrollmentPending("normal-session NSS owner differs from the published local principal")
        old_capability = self._capabilities.get(old.capability_selection_handle)
        if (old_capability is None or old_capability.selection_sha256 != old.capability_selection_sha256
                or old_capability.selected_registration_ids != old.selected_capability_ceiling
                or old_capability.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("published finite owner capability selection is stale")
        normal = RootSetupLocalOwnerIdentityRegistry.from_initial_compilation(
            self._registry, self._journal, monotonic=self._clock)
        cap_body = {"session": proof.setup_session_id, "transaction": proof.transaction_handle,
                    "plan": proof.plan_digest,
                    "registrations": list(old.selected_capability_ceiling)}
        cap = RootSetupCapabilitySelection(
            SCHEMA, secrets.token_hex(32), proof.setup_session_id, proof.transaction_handle,
            proof.plan_digest, old.selected_capability_ceiling,
            hashlib.sha256(_canonical(cap_body)).hexdigest(), self._clock(),
            min(self._clock() + SETUP_POLICY_SELECTION_TTL_SECONDS,
                _session_expiry(normal_session_store, normal_session_handle)), normal._seal)
        principal_handle = normal._bind_normal_principal(
            owner, cap, proof, normal_session_store, normal_session_handle)
        normal._normal_adoptions[proof.setup_session_id] = {
            "store": normal_session_store, "handle": normal_session_handle,
            "principal_handle": principal_handle,
        }
        return normal, principal_handle

    def _bind_normal_principal(self, owner: RootLocalOwnerIdentityReceipt,
                               capability: RootSetupCapabilitySelection, proof: Any,
                               store: RootSetupSessionStore,
                               handle: RootSetupSessionHandle) -> str:
        controller = hashlib.sha256((proof.setup_session_id + "\0" + proof.transaction_handle).encode()).hexdigest()
        principal_id = "linux-local-owner:" + hashlib.sha256(
            (owner.machine_target_binding_digest + "\0" + owner.account_binding_sha256).encode()).hexdigest()
        namespace_id = "hermes-native-" + hashlib.sha256(
            (principal_id + "\0" + _LOCAL_OWNER_PROFILE_ID).encode()).hexdigest()[:32]
        body = {"identity_kind": "linux-local-owner-v1", "session": proof.setup_session_id,
                "transaction": proof.transaction_handle, "plan": proof.plan_digest,
                "owner_binding": owner.account_binding_sha256,
                "machine_target": owner.machine_target_binding_digest,
                "principal": principal_id, "profile": _LOCAL_OWNER_PROFILE_ID,
                "namespace": namespace_id, "capability_selection": capability.selection_sha256,
                "selected_capabilities": list(capability.selected_registration_ids),
                "controller": controller}
        binding = hashlib.sha256(_canonical(body)).hexdigest()
        now = self._clock()
        # Stable selected intent lasts for the bounded root setup session;
        # each authority-bearing observation below remains a separate <=30s
        # receipt and re-reads NSS, release, actor, and the prepared CAS.
        expiry = min(now + SETUP_POLICY_SELECTION_TTL_SECONDS,
                     capability.expires_monotonic, _session_expiry(store, handle))
        if expiry <= now:
            raise BootstrapEnrollmentPending("normal local-owner identity lease expired")
        selected = RootLocalOwnerPrincipalSelection(
            SCHEMA, secrets.token_hex(32), "linux-local-owner-v1", proof.setup_session_id,
            proof.transaction_handle, proof.plan_digest, owner.receipt_handle,
            principal_id, _LOCAL_OWNER_PROFILE_ID, namespace_id,
            capability.selection_handle, capability.selection_sha256,
            capability.selected_registration_ids, binding, controller, now, expiry, 0, self._seal)
        self._capabilities[capability.selection_handle] = capability
        self._receipts[owner.receipt_handle] = owner
        self._principals[selected.receipt_handle] = selected
        self._write_record("local-owner-", selected.receipt_handle, body | {
            "owner_receipt": owner.receipt_handle,
            "principal_binding_sha256": binding, "state": "normal-adopted"})
        return selected.receipt_handle

    def _observe_normal_owner(self, name: Any, proof: Any, store: RootSetupSessionStore,
                              handle: RootSetupSessionHandle
                              ) -> tuple[Any, RootLocalOwnerIdentityReceipt]:
        if not isinstance(name, str):
            raise BootstrapEnrollmentPending("normal setup has no selected local owner account")
        try:
            account = pwd.getpwnam(name)
            group = grp.getgrgid(account.pw_gid)
            reverse = grp.getgrnam(group.gr_name)
            live = store._live(handle)
            if (account.pw_name != name or account.pw_uid <= 0 or account.pw_gid <= 0
                    or group.gr_gid != account.pw_gid or reverse.gr_gid != account.pw_gid
                    or live.record.get("target_uid") != account.pw_uid
                    or live.record.get("target_gid") != account.pw_gid):
                raise BootstrapEnrollmentPending("normal root setup UID/GID no longer joins selected NSS owner")
            initial_registry = store.initial_compilation_registry
            handoff = initial_registry.resolve_adopted_handoff(handle)
            initial = handoff._initial_session
            if initial is None:
                raise BootstrapEnrollmentPending("local-owner publication lost its held root release and actor")
            initial._release.verify_current()
            initial._actor.verify_current(initial._release)
            from .bootstrap_enrollment import _read_machine_id
            machine_id = _read_machine_id()
        except (KeyError, OSError):
            raise BootstrapEnrollmentPending("current normal-session NSS owner is unavailable") from None
        account_digest = hashlib.sha256(_canonical({
            "name": account.pw_name, "uid": account.pw_uid,
            "primary_gid": account.pw_gid, "primary_group": group.gr_name})).hexdigest()
        target_digest = hashlib.sha256(_canonical({
            "machine_id": machine_id, "account_binding": account_digest})).hexdigest()
        now = self._clock()
        receipt = RootLocalOwnerIdentityReceipt(
            SCHEMA, secrets.token_hex(32), "linux-local-owner-v1", proof.setup_session_id,
            proof.transaction_handle, proof.plan_digest,
            initial.verified_release_receipt_handle,
            initial.actor_observation_receipt_handle,
            target_digest, account.pw_name, account.pw_uid, account.pw_gid,
            group.gr_name, account_digest, now,
            min(now + IDENTITY_RECEIPT_TTL_SECONDS, _session_expiry(store, handle)), 0, self._seal)
        return account, receipt

    def _current_initial_session(self, session_handle: str) -> Any:
        if os.getuid() != 0 or os.geteuid() != 0 or not sys.platform.startswith("linux"):
            raise BootstrapEnrollmentPending("local-owner setup requires the installed Linux root CLI")
        try:
            session = self._registry.resolve_initial_session(session_handle)
            self._registry.verify_initial_session(session)
            session._release.verify_current()
            session._actor.verify_current(session._release)
        except Exception:
            raise BootstrapEnrollmentPending("current root setup session, release, or actor is unavailable") from None
        return session

    def _resolve_capability(self, session: Any, handle: str) -> RootSetupCapabilitySelection:
        value = self._capabilities.get(handle)
        if (value is None or value._issuer_seal != self._seal
                or value.setup_session_id != session.compilation_session_handle
                or value.transaction_handle != session.compilation_transaction_handle
                or value.plan_sha256 != session.plan_sha256
                or value.expires_monotonic <= self._clock()):
            raise BootstrapEnrollmentPending("local capability choice is absent, stale, or belongs to another transaction")
        return value

    def _observe_owner(self, session: Any) -> RootLocalOwnerIdentityReceipt:
        name = session._choices.target_account_name
        try:
            account = pwd.getpwnam(name)
            group = grp.getgrgid(account.pw_gid)
            reverse = grp.getgrnam(group.gr_name)
        except (KeyError, OSError):
            raise BootstrapEnrollmentPending("selected local owner account or primary group is unavailable") from None
        if (account.pw_name != name or account.pw_uid <= 0 or account.pw_gid <= 0
                or group.gr_gid != account.pw_gid or reverse.gr_gid != account.pw_gid):
            raise BootstrapEnrollmentError("selected local owner NSS binding is invalid or privileged")
        try:
            from .bootstrap_enrollment import _read_machine_id
            machine_id = _read_machine_id()
        except Exception:
            raise BootstrapEnrollmentPending("machine target binding is unavailable") from None
        account_body = {"name": account.pw_name, "uid": account.pw_uid,
                        "primary_gid": account.pw_gid, "primary_group": group.gr_name}
        account_digest = hashlib.sha256(_canonical(account_body)).hexdigest()
        target_digest = hashlib.sha256(_canonical({"machine_id": machine_id,
                                                    "account_binding": account_digest})).hexdigest()
        now = self._clock()
        return RootLocalOwnerIdentityReceipt(
            SCHEMA, secrets.token_hex(32), "linux-local-owner-v1",
            session.compilation_session_handle, session.compilation_transaction_handle,
            session.plan_sha256, session.verified_release_receipt_handle,
            session.actor_observation_receipt_handle, target_digest,
            account.pw_name, account.pw_uid, account.pw_gid, group.gr_name,
            account_digest, now, min(now + IDENTITY_RECEIPT_TTL_SECONDS,
                                     session.expires_monotonic), 0, self._seal)

    def _write_record(self, prefix: str, handle: str, value: Mapping[str, Any]) -> None:
        try:
            _ensure_receipt_root(self._journal, self._journal / "setup-principal-receipts")
            _atomic_json(self._journal / "setup-principal-receipts" / f"{prefix}{handle}.json",
                         dict(value))
        except Exception:
            raise BootstrapEnrollmentPending("protected local-owner setup journal is unavailable") from None


@dataclass(frozen=True, slots=True)
class PrincipalBindingFactory:
    principal_id: str
    profile_id: str
    namespace_id: str
    capabilities: frozenset[str]

    def bind(self, service_uid: int) -> PrincipalBinding:
        return PrincipalBinding(service_uid, self.principal_id, self.profile_id,
                                self.namespace_id, self.capabilities)


class VerifiedAuthentikIdentityResolver(Protocol):
    def resolve_authenticated_identity(
        self, receipt_handle: str, setup_session_handle: Any,
        setup_authorization: Any,
    ) -> AuthentikIdentityReceipt: ...


@dataclass(frozen=True, slots=True)
class ReviewedPrincipalCapabilities:
    service_profile_id: str
    namespace_id: str
    capabilities: tuple[str, ...]


class ReviewedCapabilitySelection(Protocol):
    def select_for_identity(
        self, identity: AuthentikIdentityReceipt,
        setup_authorization: Any,
    ) -> ReviewedPrincipalCapabilities: ...


class RootSetupIdentityIntake:
    """Root-local policy and Authentik credential intake for stage zero.

    The public surface accepts the explicit nonsecret origin/group choices and
    optionally an existing root-vault reference. When no reference is supplied,
    the token is read only from a controlling TTY with echo disabled; it never
    arrives in argv, environment, a worker request or the user-private journal.
    """

    def __init__(
        self, *, initial_registry: Any, installed_actor_verifier: Any,
        root_credential_vault: Any, root_journal: Path,
        masked_secret_reader: Any = getpass.getpass,
    ) -> None:
        try:
            from .bootstrap_runtime_factory import RootInitialCompilationRegistry
            from .bootstrap_enrollment import InstalledRootSetupActorVerifier
            from .enrollment import RootCredentialVault
        except ImportError as exc:
            raise ValueError("installed root stage-zero setup components are unavailable") from exc
        if (not isinstance(initial_registry, RootInitialCompilationRegistry)
                or not isinstance(installed_actor_verifier, InstalledRootSetupActorVerifier)
                or getattr(initial_registry, "actor_verifier", None) is not installed_actor_verifier
                or not isinstance(root_credential_vault, RootCredentialVault)
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or not callable(masked_secret_reader)):
            raise ValueError("root setup identity intake dependencies are not the selected installed objects")
        if Path(initial_registry.root_journal) != root_journal:
            raise ValueError("identity intake must use the initial registry's fixed root journal")
        self.initial_registry = initial_registry
        self.actor_verifier = installed_actor_verifier
        self.vault = root_credential_vault
        self.root_journal = root_journal
        self.receipt_root = root_journal / "setup-principal-receipts"
        self._read_masked_secret = masked_secret_reader

    @classmethod
    def from_initial_compilation(
        cls, initial_registry: Any, installed_actor_verifier: Any,
        root_credential_vault: Any, root_journal: Path,
        *, masked_secret_reader: Any = getpass.getpass,
    ) -> "RootSetupIdentityIntake":
        return cls(
            initial_registry=initial_registry,
            installed_actor_verifier=installed_actor_verifier,
            root_credential_vault=root_credential_vault,
            root_journal=root_journal,
            masked_secret_reader=masked_secret_reader,
        )

    def select_authentik_policy(
        self, stage0_session_handle: str, *, https_origin: str,
        system_group_id: str, recipient_group_id: str,
    ) -> str:
        context = _current_principal_setup_context(
            self.initial_registry, stage0_session_handle, "initial-compilation")
        self._verify_installed_actor(context)
        policy_revision = self._reviewed_policy_revision(stage0_session_handle)
        _validate_origin_and_groups(https_origin, system_group_id, recipient_group_id)
        handle = secrets.token_hex(32)
        now = time.monotonic()
        pending = {
            "schema": SCHEMA, "selection_handle": handle,
            "compilation_session_handle": context.session_id,
            "compilation_transaction_handle": context.transaction_handle,
            "plan_sha256": context.plan_digest, "https_origin": https_origin.rstrip("/"),
            "system_group_id": system_group_id,
            "recipient_group_id": recipient_group_id,
            "policy_revision": policy_revision,
            "issued_monotonic": now,
            "expires_monotonic": min(now + SETUP_POLICY_SELECTION_TTL_SECONDS, context.expires_monotonic),
        }
        if pending["expires_monotonic"] <= now:
            raise BootstrapEnrollmentPending("root setup session expired before identity selection")
        _ensure_receipt_root(self.root_journal, self.receipt_root)
        _atomic_json(self.receipt_root / f"policy-pending-{handle}.json", pending)
        return handle

    def collect_authentik_actor_credential(
        self, stage0_session_handle: str, policy_selection_handle: str, *,
        secure_existing_vault_reference: str | None = None,
    ) -> str:
        context = _current_principal_setup_context(
            self.initial_registry, stage0_session_handle, "initial-compilation")
        self._verify_installed_actor(context)
        _validate_handle(policy_selection_handle, "Authentik policy selection")
        pending_path = self.receipt_root / f"policy-pending-{policy_selection_handle}.json"
        pending = self._read_pending_policy(pending_path, context)
        if secure_existing_vault_reference is not None:
            if not _CREDENTIAL_REF.fullmatch(secure_existing_vault_reference):
                raise BootstrapEnrollmentPending("root Authentik vault reference is malformed")
            secret = self.vault.resolve_reference(
                secure_existing_vault_reference, peer_uid=0,
                required_scope="authentik-system-read",
                principal_id="root-setup-authentik")
            if not secret:
                raise BootstrapEnrollmentPending("root Authentik vault reference is empty")
            del secret
            reference = secure_existing_vault_reference
        else:
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                raise BootstrapEnrollmentPending(
                    "masked Authentik credential entry needs the installed root setup terminal")
            token = self._read_masked_secret("Authentik API token (input hidden): ")
            try:
                if (not isinstance(token, str) or not token or len(token.encode("utf-8")) > 16 * 1024
                        or any(char in token for char in "\x00\r\n")):
                    raise BootstrapEnrollmentPending("Authentik credential is empty or exceeds its bounded input")
                reference = "setup-authentik-" + secrets.token_hex(20)
                self.vault.write_credential(
                    reference, token, principal_id="root-setup-authentik",
                    allowed_uids=[0], scopes=["authentik-system-read"],
                )
                # Resolve it through the protected store before minting a policy
                # record, so a failed/unsafe write never becomes a selection.
                check = self.vault.resolve_reference(
                    reference, peer_uid=0, required_scope="authentik-system-read",
                    principal_id="root-setup-authentik")
                if check != token:
                    raise BootstrapEnrollmentPending("root Authentik vault verification failed")
                del check
            finally:
                # The vault writer accepts str, so Python cannot guarantee
                # physical string-memory erasure; minimize lifetime and do not
                # retain or log the value after this scope.
                token = ""
        record = {
            **pending, "actor_credential_ref": reference,
        }
        record["selection_sha256"] = _policy_record_digest(record)
        policy = self._validate_policy_record(record, context)
        _atomic_json(self.receipt_root / f"policy-{policy.selection_handle}.json", _policy_record_json(policy))
        try:
            pending_path.unlink()
        except FileNotFoundError:
            pass
        return reference

    def resolve_policy_selection(
        self, initial_session: Any, policy_selection_handle: str,
    ) -> VerifiedAuthentikPolicySelection:
        context = self._context_for_session(initial_session)
        _validate_handle(policy_selection_handle, "Authentik policy selection")
        record = self._read_policy_record(policy_selection_handle, context)
        return self._verified_policy(record)

    def resolve_policy_selection_by_digest(
        self, initial_session: Any, policy_selection_digest: str,
    ) -> VerifiedAuthentikPolicySelection:
        if not re.fullmatch(r"[0-9a-f]{64}", str(policy_selection_digest)):
            raise BootstrapEnrollmentPending("Authentik policy digest is malformed")
        context = self._context_for_session(initial_session)
        _ensure_receipt_root(self.root_journal, self.receipt_root)
        matches = []
        for path in self.receipt_root.glob("policy-*.json"):
            if len(matches) > 256:
                raise BootstrapEnrollmentError("setup identity policy registry exceeded its bound")
            handle = path.name[len("policy-"):-len(".json")]
            if not _HANDLE.fullmatch(handle):
                continue
            try:
                row = self._read_policy_record(handle, context)
            except BootstrapEnrollmentPending:
                continue
            if self._verified_policy(row).selection_digest == policy_selection_digest:
                matches.append(row)
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("Authentik policy selection is absent or ambiguous")
        return self._verified_policy(matches[0])

    def rebind_published_policy(
        self, *, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
        initial_principal_registry: "RootSetupPrincipalSelectionRegistry",
        initial_identity_observer: "RootSetupAuthentikIdentityObserver",
    ) -> tuple["RootSetupAuthentikIdentityObserver", str]:
        """Rebind only the published policy, then make a fresh normal-session read.

        The stage-zero records identify the policy and subject to preserve; they
        are never accepted as current identity evidence. The returned observer
        is bound to the new live setup session and has performed new TLS reads.
        """
        if (not _is_initial_compilation_registry(self.initial_registry)
                or not isinstance(normal_session_store, RootSetupSessionStore)
                or initial_principal_registry.setup_session_store is not self.initial_registry
                or initial_principal_registry.identity_resolver is not initial_identity_observer
                or initial_identity_observer.policy_resolver is not self
                or initial_identity_observer.setup_session_store is not self.initial_registry
                or initial_identity_observer.vault is not self.vault
                or initial_identity_observer.root_journal != self.root_journal):
            raise BootstrapEnrollmentPending("published identity rebind dependencies are not the selected root objects")
        from .bootstrap_runtime_factory import RootInitialPublicationHandoff
        try:
            handoff = self.initial_registry.resolve_adopted_handoff(normal_session_handle)
        except Exception:
            raise BootstrapEnrollmentPending("normal setup session has no current published identity handoff") from None
        if (not isinstance(handoff, RootInitialPublicationHandoff)
                or handoff._initial_session is None
                or not _HANDLE.fullmatch(handoff.principal_selection_receipt_handle)):
            raise BootstrapEnrollmentPending("published handoff lacks its typed initial principal selection")
        normal = _current_principal_setup_context(normal_session_store, normal_session_handle, "setup")
        initial = handoff._initial_session
        # Publication revokes the stage-zero session, so validate its retained
        # signed handoff and original records rather than resurrecting that session.
        if (initial.compilation_session_handle != handoff.compilation_session_handle
                or initial.compilation_transaction_handle != handoff.compilation_transaction_handle
                or initial.plan_sha256 != handoff.plan_sha256
                or initial.choices_sha256 != handoff.choices_sha256
                or handoff.normal_setup_session_id != normal.session_id
                or handoff.normal_transaction_handle != normal.transaction_handle):
            raise BootstrapEnrollmentPending("published stage-zero identity linkage changed")
        old_selection = initial_principal_registry._read_selection(
            handoff.principal_selection_receipt_handle)
        if (old_selection.setup_session_id != initial.compilation_session_handle
                or old_selection.transaction_handle != initial.compilation_transaction_handle
                or old_selection.plan_digest != initial.plan_sha256
                or initial_principal_registry._is_consumed(old_selection.receipt_id)):
            raise BootstrapEnrollmentPending("published stage-zero principal selection is malformed or consumed")
        old_identity = initial_identity_observer._read_identity_receipt(
            old_selection.identity_receipt_handle)
        if (old_identity.setup_session_id != initial.compilation_session_handle
                or old_identity.transaction_handle != initial.compilation_transaction_handle
                or old_identity.plan_digest != initial.plan_sha256
                or old_identity.authentik_subject_id != old_selection.authentik_subject_id
                or old_identity.actor_credential_ref != old_selection.actor_credential_ref
                or old_identity.policy_selection_digest == ""):
            raise BootstrapEnrollmentPending("published stage-zero Authentik identity linkage is invalid")
        policy = self.resolve_policy_selection_by_digest(
            initial, old_identity.policy_selection_digest)
        if (policy.actor_credential_ref != old_selection.actor_credential_ref
                or policy.policy_revision != old_identity.policy_revision):
            raise BootstrapEnrollmentPending("published Authentik policy no longer matches the selected principal")
        resolver = _AdoptedNormalPolicyResolver(
            store=normal_session_store, handle=normal_session_handle,
            initial_registry=self.initial_registry, principal_registry=initial_principal_registry,
            principal_selection_receipt_handle=old_selection.receipt_id,
            policy=policy, initial_subject=old_selection.authentik_subject_id,
            initial_credential_ref=old_selection.actor_credential_ref,
            normal_session_id=normal.session_id,
            normal_transaction_handle=normal.transaction_handle,
            normal_plan_digest=normal.plan_digest,
        )
        observer = RootSetupAuthentikIdentityObserver(
            setup_session_store=normal_session_store, policy_resolver=resolver,
            vault=self.vault, root_journal=self.root_journal,
            transport_factory=initial_identity_observer.transport_factory,
            monotonic=initial_identity_observer._clock,
        )
        handle = observer.observe_selected_authentik_identity(
            normal_session_handle, resolver.selection_handle)
        identity = observer._read_identity_receipt(handle)
        if (identity.authentik_subject_id != old_selection.authentik_subject_id
                or identity.actor_credential_ref != old_selection.actor_credential_ref
                or identity.direct_group_ids != old_identity.direct_group_ids
                or identity.effective_group_ids != old_identity.effective_group_ids
                or identity.system_member != old_identity.system_member
                or identity.policy_revision != old_identity.policy_revision):
            raise BootstrapEnrollmentPending(
                "fresh Authentik identity or group snapshot differs from the published principal; reselect")
        return observer, handle


    def _verify_installed_actor(self, context: _PrincipalSetupContext) -> None:
        try:
            plan = self.initial_registry.resolve_actor_plan(context.session_id)
            self.actor_verifier.verify_current(plan)
            self.initial_registry.verify_initial_session(context.resolver_handle)
        except Exception:
            raise BootstrapEnrollmentPending("installed root setup actor or stage-zero session is no longer current") from None

    def _reviewed_policy_revision(self, stage0_session_handle: str) -> str:
        try:
            from .bootstrap_runtime_factory import VerifiedIdentityPolicyTemplate
            template = self.initial_registry.resolve_identity_policy_template(stage0_session_handle)
        except Exception:
            raise BootstrapEnrollmentPending("installed Authentik policy template is unavailable") from None
        if (not isinstance(template, VerifiedIdentityPolicyTemplate)
                or template.artifact_id != "installer-authentik-policy-template-v1"
                or template.sha256 != "617f78fc4a692de6a22dd69456fd92b874c9bc82e0869f3817910c953bd2ceb8"
                or template.policy_revision != AUTHENTIK_POLICY_REVISION
                or template.identity_effect_authority is not False
                or tuple(template.identity_read_paths) != (
                    "/api/v3/core/users/me/",
                    "/api/v3/core/groups/{root_observed_group_id}/",
                )
                or template.max_identity_lease_seconds != IDENTITY_RECEIPT_TTL_SECONDS):
            raise BootstrapEnrollmentPending("installed Authentik policy template differs from its reviewed pin")
        return template.policy_revision

    def _context_for_session(self, session: Any) -> _PrincipalSetupContext:
        from .bootstrap_runtime_factory import RootInitialCompilationSession
        if not isinstance(session, RootInitialCompilationSession):
            raise BootstrapEnrollmentPending("Authentik policy resolver requires a verified initial session")
        return _current_principal_setup_context(
            self.initial_registry, session.compilation_session_handle, "initial-compilation")

    def _read_pending_policy(self, path: Path, context: _PrincipalSetupContext) -> dict[str, Any]:
        value = _read_json(path)
        expected = {
            "schema", "selection_handle", "compilation_session_handle",
            "compilation_transaction_handle", "plan_sha256", "https_origin",
            "system_group_id", "recipient_group_id", "policy_revision",
            "issued_monotonic", "expires_monotonic",
        }
        if (not isinstance(value, dict) or set(value) != expected
                or value.get("schema") != SCHEMA
                or value.get("selection_handle") != path.name[len("policy-pending-"):-len(".json")]
                or value.get("compilation_session_handle") != context.session_id
                or value.get("compilation_transaction_handle") != context.transaction_handle
                or value.get("plan_sha256") != context.plan_digest
                or type(value.get("issued_monotonic")) not in (int, float)
                or type(value.get("expires_monotonic")) not in (int, float)
                or value["expires_monotonic"] <= value["issued_monotonic"]
                or value["expires_monotonic"] - value["issued_monotonic"] > SETUP_POLICY_SELECTION_TTL_SECONDS + 0.001
                or value["expires_monotonic"] <= time.monotonic()
                or value["expires_monotonic"] > context.expires_monotonic):
            raise BootstrapEnrollmentPending("Authentik policy selection is stale or malformed")
        _validate_origin_and_groups(value["https_origin"], value["system_group_id"], value["recipient_group_id"])
        if value["policy_revision"] != self._reviewed_policy_revision(context.session_id):
            raise BootstrapEnrollmentPending("Authentik policy revision is not the reviewed template revision")
        return value

    def _read_policy_record(
        self, handle: str, context: _PrincipalSetupContext,
    ) -> RootSetupAuthentikPolicyRecord:
        value = _read_json(self.receipt_root / f"policy-{handle}.json")
        expected = {
            "schema", "selection_handle", "compilation_session_handle",
            "compilation_transaction_handle", "plan_sha256", "https_origin",
            "system_group_id", "recipient_group_id", "policy_revision",
            "actor_credential_ref", "selection_sha256", "issued_monotonic",
            "expires_monotonic",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise BootstrapEnrollmentPending("Authentik policy selection is absent or malformed")
        policy = self._validate_policy_record(value, context)
        if policy.selection_handle != handle:
            raise BootstrapEnrollmentPending("Authentik policy selection handle does not match its record")
        return policy

    def _validate_policy_record(
        self, value: Mapping[str, Any], context: _PrincipalSetupContext,
    ) -> RootSetupAuthentikPolicyRecord:
        try:
            policy = RootSetupAuthentikPolicyRecord(
                value["schema"], value["selection_handle"],
                value["compilation_session_handle"], value["compilation_transaction_handle"],
                value["plan_sha256"], value["https_origin"], value["system_group_id"],
                value["recipient_group_id"], value["policy_revision"],
                value["actor_credential_ref"], value["selection_sha256"],
                value["issued_monotonic"], value["expires_monotonic"],
            )
        except (KeyError, TypeError):
            raise BootstrapEnrollmentPending("Authentik policy selection is malformed") from None
        if (policy.schema != SCHEMA or not _HANDLE.fullmatch(policy.selection_handle)
                or policy.compilation_session_handle != context.session_id
                or policy.compilation_transaction_handle != context.transaction_handle
                or policy.plan_sha256 != context.plan_digest
                or policy.policy_revision != AUTHENTIK_POLICY_REVISION
                or not _CREDENTIAL_REF.fullmatch(policy.actor_credential_ref)
                or type(policy.issued_monotonic) not in (int, float)
                or type(policy.expires_monotonic) not in (int, float)
                or policy.expires_monotonic <= time.monotonic()
                or policy.expires_monotonic > context.expires_monotonic
                or _policy_record_digest(_policy_record_json(policy)) != policy.selection_sha256):
            raise BootstrapEnrollmentPending("Authentik policy selection is stale or malformed")
        _validate_origin_and_groups(policy.https_origin, policy.system_group_id, policy.recipient_group_id)
        return policy

    @staticmethod
    def _verified_policy(record: RootSetupAuthentikPolicyRecord) -> VerifiedAuthentikPolicySelection:
        return VerifiedAuthentikPolicySelection(
            AUTHENTIK_POLICY_SELECTION_ID, record.https_origin,
            record.system_group_id, record.recipient_group_id,
            record.policy_revision, record.actor_credential_ref,
            hashlib.sha256(_canonical({
                "id": AUTHENTIK_POLICY_SELECTION_ID,
                "https_origin": record.https_origin,
                "system_group_id": record.system_group_id,
                "recipient_group_id": record.recipient_group_id,
                "policy_revision": record.policy_revision,
                "actor_credential_ref": record.actor_credential_ref,
            })).hexdigest(),
        )


class _AdoptedNormalPolicyResolver:
    """In-process sealed view of the one policy joined through publication."""

    def __init__(
        self, *, store: RootSetupSessionStore, handle: RootSetupSessionHandle,
        initial_registry: Any, principal_registry: "RootSetupPrincipalSelectionRegistry",
        principal_selection_receipt_handle: str,
        policy: VerifiedAuthentikPolicySelection, initial_subject: str,
        initial_credential_ref: str, normal_session_id: str,
        normal_transaction_handle: str, normal_plan_digest: str,
    ) -> None:
        self.store = store
        self.handle = handle
        self.initial_registry = initial_registry
        self.principal_registry = principal_registry
        self.principal_selection_receipt_handle = principal_selection_receipt_handle
        self.policy = policy
        self.initial_subject = initial_subject
        self.initial_credential_ref = initial_credential_ref
        self.normal_session_id = normal_session_id
        self.normal_transaction_handle = normal_transaction_handle
        self.normal_plan_digest = normal_plan_digest
        self.selection_handle = secrets.token_hex(32)
        self._seal = secrets.token_hex(32)

    def _resolve(self, session_handle: Any) -> VerifiedAuthentikPolicySelection:
        if session_handle != self.handle:
            raise BootstrapEnrollmentPending("adopted Authentik policy belongs to another root setup session")
        proof = _current_principal_setup_context(self.store, self.handle, "setup")
        if (proof.session_id != self.normal_session_id
                or proof.transaction_handle != self.normal_transaction_handle
                or proof.plan_digest != self.normal_plan_digest):
            raise BootstrapEnrollmentPending("adopted Authentik policy session binding changed")
        try:
            handoff = self.initial_registry.resolve_adopted_handoff(self.handle)
        except Exception:
            raise BootstrapEnrollmentPending("adopted Authentik policy publication is no longer current") from None
        if (handoff.normal_setup_session_id != proof.session_id
                or handoff.normal_transaction_handle != proof.transaction_handle
                or handoff.principal_selection_receipt_handle != self.principal_selection_receipt_handle):
            raise BootstrapEnrollmentPending("adopted Authentik policy handoff changed")
        original = self.principal_registry._read_selection(
            handoff.principal_selection_receipt_handle)
        if (original.setup_session_id != handoff.compilation_session_handle
                or original.transaction_handle != handoff.compilation_transaction_handle
                or original.plan_digest != handoff.plan_sha256
                or original.authentik_subject_id != self.initial_subject
                or original.actor_credential_ref != self.initial_credential_ref):
            raise BootstrapEnrollmentPending("published Authentik subject or credential binding changed")
        return self.policy

    def resolve_policy_selection(
        self, setup_session_handle: Any, policy_selection_handle: str,
    ) -> VerifiedAuthentikPolicySelection:
        if (not isinstance(policy_selection_handle, str)
                or not secrets.compare_digest(policy_selection_handle, self.selection_handle)):
            raise BootstrapEnrollmentPending("adopted Authentik policy handle is invalid")
        return self._resolve(setup_session_handle)

    def resolve_policy_selection_by_digest(
        self, setup_session_handle: Any, policy_selection_digest: str,
    ) -> VerifiedAuthentikPolicySelection:
        policy = self._resolve(setup_session_handle)
        if not secrets.compare_digest(policy.selection_digest, policy_selection_digest):
            raise BootstrapEnrollmentPending("adopted Authentik policy digest changed")
        return policy


class RootSetupAuthentikIdentityObserver:
    """Mint/resolve short-lived identity receipts after real fixed Authentik reads.

    ``policy_resolver`` is the root setup UI's one-use policy-selection store;
    ``vault`` is the existing root credential vault. The public method accepts
    opaque handles only, never a credential, URL, username, group ID or token.
    """

    def __init__(
        self, *, setup_session_store: Any,
        policy_resolver: RootSetupAuthentikPolicyResolver,
        vault: Any, root_journal: Path,
        transport_factory: Any = TLSAuthentikTransport,
        monotonic: Any = time.monotonic,
    ) -> None:
        if (not (callable(getattr(setup_session_store, "_live", None))
                 or _is_initial_compilation_registry(setup_session_store))
                or not callable(getattr(policy_resolver, "resolve_policy_selection", None))
                or not callable(getattr(policy_resolver, "resolve_policy_selection_by_digest", None))
                or not callable(getattr(vault, "resolve_reference", None))
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()
                or not callable(transport_factory) or not callable(monotonic)):
            raise ValueError("root setup Authentik observer dependencies are incomplete")
        self.setup_session_store = setup_session_store
        self.policy_resolver = policy_resolver
        self.vault = vault
        self.root_journal = root_journal
        self.receipt_root = root_journal / "setup-principal-receipts"
        self.transport_factory = transport_factory
        self._clock = monotonic
        if callable(getattr(setup_session_store, "_live", None)):
            self._session_mode = "setup"
            _validate_store_journal(setup_session_store, root_journal)
        else:
            self._session_mode = "initial-compilation"

    @classmethod
    def from_initial_compilation(
        cls, initial_compilation_registry: Any,
        policy_resolver: RootSetupAuthentikPolicyResolver, vault: Any,
        root_journal: Path, *, transport_factory: Any = TLSAuthentikTransport,
        monotonic: Any = time.monotonic,
    ) -> "RootSetupAuthentikIdentityObserver":
        if not _is_initial_compilation_registry(initial_compilation_registry):
            raise ValueError("stage0 Authentik observation requires the installed initial-compilation registry")
        return cls(
            setup_session_store=initial_compilation_registry,
            policy_resolver=policy_resolver, vault=vault, root_journal=root_journal,
            transport_factory=transport_factory, monotonic=monotonic,
        )

    def observe_selected_authentik_identity(
        self, setup_session_handle: RootSetupSessionHandle,
        authentik_policy_selection_handle: str,
    ) -> str:
        proof = _current_principal_setup_context(
            self.setup_session_store, setup_session_handle, self._session_mode)
        policy = self.policy_resolver.resolve_policy_selection(
            proof.resolver_handle, authentik_policy_selection_handle)
        _validate_policy_selection(policy)
        token = self.vault.resolve_reference(
            policy.actor_credential_ref, peer_uid=0,
            required_scope="authentik-system-read", principal_id="root-setup-authentik",
        )
        try:
            observed = self._observe(policy, token)
        finally:
            token = ""
        now = self._clock()
        expires = min(now + IDENTITY_RECEIPT_TTL_SECONDS, proof.expires_monotonic)
        if expires <= now:
            raise BootstrapEnrollmentPending("root setup session expired during Authentik identity check")
        receipt = AuthentikIdentityReceipt(
            SCHEMA, secrets.token_hex(32), proof.session_id,
            proof.transaction_handle, proof.plan_digest, policy.selection_digest,
            observed["username"], observed["email"], observed["subject"],
            policy.actor_credential_ref, tuple(sorted(observed["direct"])),
            tuple(sorted(observed["effective"])),
            policy.system_group_id in observed["effective"],
            policy.policy_revision, now, expires,
        )
        self._save_identity_receipt(receipt)
        return receipt.receipt_id

    def resolve_authenticated_identity(
        self, receipt_handle: str, setup_session_handle: RootSetupSessionHandle,
        setup_authorization: VerifiedRootSetupAuthorization | _PrincipalSetupContext,
    ) -> AuthentikIdentityReceipt:
        _validate_handle(receipt_handle, "Authentik identity receipt")
        current = _current_principal_setup_context(
            self.setup_session_store, setup_session_handle, self._session_mode)
        _join_authorization(setup_authorization, current)
        receipt = self._read_identity_receipt(receipt_handle)
        if (receipt.setup_session_id != current.session_id
                or receipt.transaction_handle != current.transaction_handle
                or receipt.plan_digest != current.plan_digest
                or receipt.expires_monotonic <= self._clock()
                or receipt.expires_monotonic > current.expires_monotonic):
            raise BootstrapEnrollmentPending("Authentik identity receipt is stale or belongs to another setup session")
        policy = self.policy_resolver.resolve_policy_selection_by_digest(
            current.resolver_handle, receipt.policy_selection_digest)
        _validate_policy_selection(policy)
        if (policy.selection_digest != receipt.policy_selection_digest
                or policy.actor_credential_ref != receipt.actor_credential_ref):
            raise BootstrapEnrollmentPending("Authentik identity policy selection changed")
        token = self.vault.resolve_reference(
            receipt.actor_credential_ref, peer_uid=0,
            required_scope="authentik-system-read", principal_id="root-setup-authentik",
        )
        try:
            observed = self._observe(policy, token)
        finally:
            token = ""
        if (observed["subject"] != receipt.authentik_subject_id
                or observed["username"].casefold() != receipt.username.casefold()
                or observed["email"].casefold() != receipt.email.casefold()):
            raise BootstrapEnrollmentPending("current Authentik identity no longer matches the setup receipt")
        now = self._clock()
        refreshed = AuthentikIdentityReceipt(
            receipt.schema, receipt.receipt_id, receipt.setup_session_id,
            receipt.transaction_handle, receipt.plan_digest,
            receipt.policy_selection_digest, receipt.username, receipt.email,
            receipt.authentik_subject_id, receipt.actor_credential_ref,
            tuple(sorted(observed["direct"])), tuple(sorted(observed["effective"])),
            policy.system_group_id in observed["effective"], policy.policy_revision,
            now, min(now + IDENTITY_RECEIPT_TTL_SECONDS, current.expires_monotonic),
        )
        if (refreshed.direct_group_ids != receipt.direct_group_ids
                or refreshed.effective_group_ids != receipt.effective_group_ids
                or refreshed.system_member != receipt.system_member
                or refreshed.policy_revision != receipt.policy_revision):
            raise BootstrapEnrollmentPending("Authentik identity/group snapshot changed; reselect the principal")
        # Identity receipts remain immutable and retain their original expiry.
        return receipt

    def _observe(self, policy: VerifiedAuthentikPolicySelection, token: str) -> dict[str, Any]:
        enrollment = AuthentikEnrollment(
            principal_identities={}, system_group_id=policy.system_group_id,
            write_group_by_target={}, recipient_group_id=policy.recipient_group_id,
            recipient_email_by_id={}, allowed_effects=frozenset({("setup", "local-read")}),
            policy_revision=policy.policy_revision,
        )
        client = AuthentikSystemPolicy(
            enrollment=enrollment, actor_token=lambda _principal: token,
            directory_token=lambda: None,
            transport=self.transport_factory(policy.https_origin, timeout=8.0), timeout=8.0,
        )
        # Reuse Authentik's existing unique/current/active subject parser and
        # bounded cycle-safe complete hierarchy walk. Both calls use fixed
        # internal API paths; the caller cannot select a path or destination.
        actor = client._current_user(token)
        direct = frozenset(actor["groups"])
        effective = client._complete_groups(token, tuple(sorted(direct)))
        return {"username": actor["username"], "email": actor["email"],
                "subject": actor["subject"], "direct": direct, "effective": effective}

    def _save_identity_receipt(self, receipt: AuthentikIdentityReceipt) -> None:
        _ensure_receipt_root(self.root_journal, self.receipt_root)
        payload = _identity_json(receipt)
        _atomic_json(self.receipt_root / f"{receipt.receipt_id}.json", payload)

    def _read_identity_receipt(self, receipt_id: str) -> AuthentikIdentityReceipt:
        value = _read_json(self.receipt_root / f"{receipt_id}.json")
        expected = {
            "schema", "receipt_id", "setup_session_id", "transaction_handle", "plan_digest",
            "policy_selection_digest", "username", "email", "authentik_subject_id",
            "actor_credential_ref", "direct_group_ids", "effective_group_ids", "system_member",
            "policy_revision", "checked_at_monotonic", "expires_monotonic",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise BootstrapEnrollmentPending("Authentik identity receipt is absent or malformed")
        if (not isinstance(value.get("direct_group_ids"), list)
                or not isinstance(value.get("effective_group_ids"), list)):
            raise BootstrapEnrollmentPending("Authentik identity receipt group lists are malformed")
        try:
            receipt = AuthentikIdentityReceipt(
                value["schema"], value["receipt_id"], value["setup_session_id"],
                value["transaction_handle"], value["plan_digest"],
                value["policy_selection_digest"], value["username"], value["email"],
                value["authentik_subject_id"], value["actor_credential_ref"],
                tuple(value["direct_group_ids"]), tuple(value["effective_group_ids"]),
                value["system_member"], value["policy_revision"],
                value["checked_at_monotonic"], value["expires_monotonic"],
            )
        except (KeyError, TypeError, ValueError):
            raise BootstrapEnrollmentPending("Authentik identity receipt is malformed") from None
        _validate_identity_receipt(receipt, receipt_id)
        return receipt


class RootSetupPrincipalSelectionRegistry:
    """Issue pathless v32 principal-selection handles for the root policy factory."""

    def __init__(
        self, *, setup_session_store: RootSetupSessionStore,
        verified_authentik_identity_resolver: VerifiedAuthentikIdentityResolver,
        reviewed_capability_selection: ReviewedCapabilitySelection,
        root_journal: Path,
    ) -> None:
        if (not (callable(getattr(setup_session_store, "_live", None))
                 or _is_initial_compilation_registry(setup_session_store))
                or not callable(getattr(verified_authentik_identity_resolver,
                                        "resolve_authenticated_identity", None))
                or not callable(getattr(reviewed_capability_selection, "select_for_identity", None))
                or not isinstance(root_journal, Path) or not root_journal.is_absolute()):
            raise ValueError("root setup principal registry dependencies are incomplete")
        self.setup_session_store = setup_session_store
        self.identity_resolver = verified_authentik_identity_resolver
        self.capability_selection = reviewed_capability_selection
        self.root_journal = root_journal
        self.receipt_root = root_journal / "setup-principal-receipts"
        self._seal = secrets.token_hex(32)
        self._adopted_identity_choice = False
        self._current_identity_receipt_handles: dict[str, str] = {}
        if callable(getattr(setup_session_store, "_live", None)):
            self._session_mode = "setup"
            _validate_store_journal(setup_session_store, root_journal)
        else:
            self._session_mode = "initial-compilation"

    @classmethod
    def from_root_setup(
        cls, setup_session_store: RootSetupSessionStore,
        verified_authentik_identity_resolver: VerifiedAuthentikIdentityResolver,
        reviewed_capability_selection: ReviewedCapabilitySelection,
        root_journal: Path,
    ) -> "RootSetupPrincipalSelectionRegistry":
        return cls(
            setup_session_store=setup_session_store,
            verified_authentik_identity_resolver=verified_authentik_identity_resolver,
            reviewed_capability_selection=reviewed_capability_selection,
            root_journal=root_journal,
        )

    @classmethod
    def from_initial_compilation(
        cls, initial_compilation_registry: Any,
        verified_authentik_identity_resolver: VerifiedAuthentikIdentityResolver,
        reviewed_capability_selection: ReviewedCapabilitySelection,
        root_journal: Path,
    ) -> "RootSetupPrincipalSelectionRegistry":
        if not _is_initial_compilation_registry(initial_compilation_registry):
            raise ValueError("stage0 principal selection requires the installed initial-compilation registry")
        return cls(
            setup_session_store=initial_compilation_registry,
            verified_authentik_identity_resolver=verified_authentik_identity_resolver,
            reviewed_capability_selection=reviewed_capability_selection,
            root_journal=root_journal,
        )

    def select_principal(
        self, setup_session_handle: RootSetupSessionHandle,
        authenticated_identity_receipt_handle: str,
    ) -> str:
        proof = _current_principal_setup_context(
            self.setup_session_store, setup_session_handle, self._session_mode)
        identity = self.identity_resolver.resolve_authenticated_identity(
            authenticated_identity_receipt_handle, setup_session_handle,
            _capability_authorization(proof))
        _validate_identity_receipt(identity, authenticated_identity_receipt_handle)
        selected = self.capability_selection.select_for_identity(
            identity, _capability_authorization(proof))
        _validate_capability_selection(
            selected, allow_empty=proof.phase == "initial-compilation")
        now = time.monotonic()
        expires = min(now + SELECTION_RECEIPT_TTL_SECONDS,
                      proof.expires_monotonic, identity.expires_monotonic)
        if expires <= now:
            raise BootstrapEnrollmentPending("setup identity selection expired")
        principal_id = "authentik:" + hashlib.sha256(
            identity.authentik_subject_id.encode("utf-8")).hexdigest()
        receipt = VerifiedRootSetupPrincipalSelection(
            SCHEMA, secrets.token_hex(32), proof.session_id,
            proof.transaction_handle, proof.plan_digest, principal_id,
            identity.username, identity.email, identity.authentik_subject_id,
            identity.actor_credential_ref, selected.service_profile_id,
            selected.namespace_id, tuple(selected.capabilities),
            authenticated_identity_receipt_handle, now, expires,
        )
        _ensure_receipt_root(self.root_journal, self.receipt_root)
        _atomic_json(self.receipt_root / f"{receipt.receipt_id}.json",
                     _selection_json(receipt))
        return receipt.receipt_id

    def resolve_selected_principal(
        self, receipt_handle: str, setup_session_handle: RootSetupSessionHandle,
        transaction_handle: str, plan_digest: str,
    ) -> VerifiedRootSetupPrincipalSelection:
        _validate_handle(receipt_handle, "principal selection receipt")
        proof = _current_principal_setup_context(
            self.setup_session_store, setup_session_handle, self._session_mode)
        if (transaction_handle != proof.transaction_handle or plan_digest != proof.plan_digest):
            raise BootstrapEnrollmentPending("principal selection does not match the current setup transaction")
        receipt = self._read_selection(receipt_handle)
        if (self._is_consumed(receipt_handle) or receipt.setup_session_id != proof.session_id
                or receipt.transaction_handle != transaction_handle or receipt.plan_digest != plan_digest
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("principal selection receipt is stale, consumed, or out of scope")
        if self._adopted_identity_choice:
            identity = self._resolve_current_adopted_identity(
                receipt, setup_session_handle, proof)
        else:
            identity = self.identity_resolver.resolve_authenticated_identity(
                receipt.identity_receipt_handle, setup_session_handle,
                _capability_authorization(proof))
        if (identity.authentik_subject_id != receipt.authentik_subject_id
                or identity.actor_credential_ref != receipt.actor_credential_ref
                or identity.username.casefold() != receipt.username.casefold()
                or identity.email.casefold() != receipt.email.casefold()):
            raise BootstrapEnrollmentPending("selected Authentik identity lease changed")
        selected = self.capability_selection.select_for_identity(
            identity, _capability_authorization(proof))
        _validate_capability_selection(
            selected, allow_empty=proof.phase == "initial-compilation")
        if (selected.service_profile_id != receipt.service_profile_id
                or selected.namespace_id != receipt.namespace_id
                or tuple(selected.capabilities) != receipt.capabilities):
            raise BootstrapEnrollmentPending("reviewed principal capability selection changed")
        return receipt

    def _resolve_current_adopted_identity(
        self, selection: VerifiedRootSetupPrincipalSelection,
        setup_session_handle: RootSetupSessionHandle,
        proof: _PrincipalSetupContext,
    ) -> AuthentikIdentityReceipt:
        observer = self.identity_resolver
        if (not isinstance(observer, RootSetupAuthentikIdentityObserver)
                or observer.setup_session_store is not self.setup_session_store
                or not isinstance(observer.policy_resolver, _AdoptedNormalPolicyResolver)):
            raise BootstrapEnrollmentPending("adopted principal has no current root Authentik observer")
        original = observer._read_identity_receipt(selection.identity_receipt_handle)
        policy = observer.policy_resolver.resolve_policy_selection_by_digest(
            setup_session_handle, original.policy_selection_digest)
        if (policy.actor_credential_ref != selection.actor_credential_ref
                or policy.policy_revision != original.policy_revision):
            raise BootstrapEnrollmentPending("adopted Authentik identity policy changed")
        cached_handle = self._current_identity_receipt_handles.get(selection.receipt_id)
        current: AuthentikIdentityReceipt | None = None
        if cached_handle is not None:
            cached = observer._read_identity_receipt(cached_handle)
            if cached.expires_monotonic > observer._clock():
                current = observer.resolve_authenticated_identity(
                    cached_handle, setup_session_handle,
                    _capability_authorization(proof))
        if current is None:
            fresh_handle = observer.observe_selected_authentik_identity(
                setup_session_handle, observer.policy_resolver.selection_handle)
            current = observer._read_identity_receipt(fresh_handle)
            cached_handle = fresh_handle
        if (current.setup_session_id != proof.session_id
                or current.transaction_handle != proof.transaction_handle
                or current.plan_digest != proof.plan_digest
                or current.policy_selection_digest != original.policy_selection_digest
                or current.authentik_subject_id != original.authentik_subject_id
                or current.actor_credential_ref != original.actor_credential_ref
                or current.username.casefold() != original.username.casefold()
                or current.email.casefold() != original.email.casefold()
                or current.direct_group_ids != original.direct_group_ids
                or current.effective_group_ids != original.effective_group_ids
                or current.system_member != original.system_member
                or current.policy_revision != original.policy_revision
                or current.expires_monotonic <= observer._clock()):
            raise BootstrapEnrollmentPending(
                "current Authentik identity/group snapshot differs from the selected principal; reselect")
        self._current_identity_receipt_handles[selection.receipt_id] = cached_handle
        return current

    def resolve_reviewed_capability_selection(
        self, current_identity_receipt_handle: str,
        selected_effect_policy_receipt_handle: str,
    ) -> Any:
        """Resolve only a live selector-issued map/effect intersection receipt."""
        resolver = getattr(self.capability_selection,
                           "resolve_reviewed_capability_selection", None)
        if not callable(resolver):
            raise BootstrapEnrollmentPending(
                "root-reviewed capability selector does not expose sealed receipt resolution")
        return resolver(current_identity_receipt_handle,
                        selected_effect_policy_receipt_handle)

    def adopt_initial_publication(
        self, *, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
        authenticated_identity_receipt_handle: str,
        normal_identity_resolver: RootSetupAuthentikIdentityObserver | None = None,
    ) -> tuple["RootSetupPrincipalSelectionRegistry", str]:
        """Re-observe and rebind the stage-zero identity to the new setup session.

        The compiler handoff is resolved by its concrete registry. The original
        selection is used only to pin the subject and root-vault reference; a new
        Authentik observation and capability selection are required for the live
        normal session before a new scoped selection handle is minted.
        """
        if self._session_mode != "initial-compilation" or not isinstance(normal_session_store, RootSetupSessionStore):
            raise BootstrapEnrollmentPending("principal adoption requires the original stage-zero registry and concrete setup store")
        if not _is_initial_compilation_registry(self.setup_session_store):
            raise BootstrapEnrollmentPending("stage-zero principal issuer is no longer available")
        from .bootstrap_runtime_factory import RootInitialPublicationHandoff
        initial_registry = self.setup_session_store
        try:
            handoff = initial_registry.resolve_adopted_handoff(normal_session_handle)
        except Exception:
            raise BootstrapEnrollmentPending("normal setup session has no current adopted stage-zero handoff") from None
        if (not isinstance(handoff, RootInitialPublicationHandoff)
                or not isinstance(handoff.principal_selection_receipt_handle, str)):
            raise BootstrapEnrollmentPending("published setup did not bind an initial principal selection")
        old_handle = handoff.principal_selection_receipt_handle
        old_selection = self._read_selection(old_handle)
        if (old_selection.setup_session_id != handoff.compilation_session_handle
                or old_selection.transaction_handle != handoff.compilation_transaction_handle
                or old_selection.plan_digest != handoff.plan_sha256
                or self._is_consumed(old_handle)):
            raise BootstrapEnrollmentPending("stage-zero principal selection is stale, consumed, or mismatched")
        proof = _current_principal_setup_context(normal_session_store, normal_session_handle, "setup")
        identity_resolver = normal_identity_resolver or self.identity_resolver
        if (not isinstance(identity_resolver, RootSetupAuthentikIdentityObserver)
                or identity_resolver.setup_session_store is not normal_session_store
                or identity_resolver.vault is not self.identity_resolver.vault
                or identity_resolver.root_journal != self.root_journal
                or identity_resolver._session_mode != "setup"):
            raise BootstrapEnrollmentPending("principal adoption requires a fresh observer bound to the normal session")
        fresh = identity_resolver.resolve_authenticated_identity(
            authenticated_identity_receipt_handle, normal_session_handle,
            _capability_authorization(proof))
        _validate_identity_receipt(fresh, authenticated_identity_receipt_handle)
        if (fresh.setup_session_id != proof.session_id
                or fresh.transaction_handle != proof.transaction_handle
                or fresh.plan_digest != proof.plan_digest
                or fresh.authentik_subject_id != old_selection.authentik_subject_id
                or fresh.actor_credential_ref != old_selection.actor_credential_ref):
            raise BootstrapEnrollmentPending("fresh setup identity does not match the published Authentik subject and vault reference")
        normal_registry = RootSetupPrincipalSelectionRegistry.from_root_setup(
            normal_session_store, identity_resolver, self.capability_selection, self.root_journal)
        normal_registry._adopted_identity_choice = True
        lock = _exclusive_registry_lock(self.receipt_root, self.root_journal)
        try:
            adopted_path = self.receipt_root / f"adopted-{old_handle}.json"
            if adopted_path.exists() or self._is_consumed(old_handle):
                raise BootstrapEnrollmentPending("stage-zero principal selection handoff was already used")
            # Reservation precedes minting so a crash cannot make the original
            # handle reusable. A stale reservation requires explicit root recovery.
            _exclusive_json(adopted_path, {
                "schema": SCHEMA, "receipt_id": old_handle,
                "initial_session_id": handoff.compilation_session_handle,
                "normal_setup_session_id": proof.session_id,
                "normal_transaction_handle": proof.transaction_handle,
                "normal_plan_digest": proof.plan_digest,
                "fresh_identity_receipt_handle": authenticated_identity_receipt_handle,
                "state": "reserved", "issued_monotonic": time.monotonic(),
            })
            new_handle = normal_registry.select_principal(
                normal_session_handle, authenticated_identity_receipt_handle)
            normal_registry._current_identity_receipt_handles[new_handle] = authenticated_identity_receipt_handle
            selected = normal_registry._read_selection(new_handle)
            selector_identity = identity_resolver._read_identity_receipt(authenticated_identity_receipt_handle)
            principal_selector = normal_registry._make_principal_selector(
                selected, selector_identity, proof, normal_session_store, normal_session_handle)
            value = _read_json(adopted_path)
            if (not isinstance(value, dict) or value.get("state") != "reserved"
                    or value.get("receipt_id") != old_handle):
                raise BootstrapEnrollmentPending("principal adoption reservation changed")
            value["state"] = "adopted"
            value["new_principal_selection_receipt_handle"] = new_handle
            value["principal_selector"] = _principal_selector_json(principal_selector)
            value["actor_credential_ref"] = fresh.actor_credential_ref
            _atomic_replace_json(adopted_path, value)
            return normal_registry, new_handle
        finally:
            os.close(lock)

    def resolve_adopted_initial_principal(
        self, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
    ) -> VerifiedRootSetupPrincipalSelection:
        """Resolve the one root-journaled stage-zero adoption for this session.

        The new selection is revalidated against the live normal setup session,
        current Authentik identity, and reviewed capability selector on every
        call. Callers receive no filesystem path or raw stage-zero handle.
        """
        if (self._session_mode != "setup"
                or not isinstance(self.setup_session_store, RootSetupSessionStore)
                or normal_session_store is not self.setup_session_store):
            raise BootstrapEnrollmentPending("adopted principal lookup requires its concrete normal root session store")
        proof = _current_principal_setup_context(
            normal_session_store, normal_session_handle, "setup")
        matches: list[Mapping[str, Any]] = []
        for path in self.receipt_root.glob("adopted-*.json"):
            try:
                value = _read_json(path)
            except FileNotFoundError:
                continue
            if (isinstance(value, dict) and value.get("schema") == SCHEMA
                    and value.get("state") == "adopted"
                    and value.get("normal_setup_session_id") == proof.session_id):
                matches.append(value)
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("normal root setup session has no unique adopted principal selection")
        adoption = matches[0]
        handle = adoption.get("new_principal_selection_receipt_handle")
        if (not isinstance(handle, str) or not _HANDLE.fullmatch(handle)
                or adoption.get("normal_transaction_handle") != proof.transaction_handle
                or adoption.get("normal_plan_digest") != proof.plan_digest):
            raise BootstrapEnrollmentPending("adopted principal selection does not match the current setup transaction")
        return self.resolve_selected_principal(
            handle, normal_session_handle, proof.transaction_handle, proof.plan_digest)

    def resolve_adopted_namespace_selection(
        self, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
    ) -> VerifiedRootNamespaceSelection:
        """Issue/reuse a separate namespace receipt for pre-active source staging.

        Namespace identity comes from the freshly revalidated adopted principal
        selector, while generation identity comes from the current root authority
        snapshot and setup CAS predecessor. No profile, namespace, or generation
        value is accepted from a caller.
        """
        if (self._session_mode != "setup"
                or not isinstance(self.setup_session_store, RootSetupSessionStore)
                or normal_session_store is not self.setup_session_store):
            raise BootstrapEnrollmentPending("namespace selection requires its concrete normal root setup store")
        authorization = _current_setup_proof(normal_session_store, normal_session_handle)
        principal = self.resolve_adopted_initial_principal(
            normal_session_store, normal_session_handle)
        if principal.service_profile_id != "hermes-agent-native-v1":
            raise BootstrapEnrollmentPending("selected principal does not bind the reviewed native service profile")
        authority = normal_session_store.authority_loader_for_session()
        generations = authority.get("service_generations") if isinstance(authority, Mapping) else None
        if not isinstance(generations, Mapping):
            raise BootstrapEnrollmentPending("current prepared protected generation is unavailable")
        try:
            from .enrollment import _validate_service_generations
            current = _validate_service_generations(dict(generations))
        except Exception:
            raise BootstrapEnrollmentPending("current protected generation failed strict root validation") from None
        generation_id = current.get("generation_id")
        generation_digest = current.get("generation_digest")
        if (not isinstance(generation_id, str) or not _ID.fullmatch(generation_id)
                or not isinstance(generation_digest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", generation_digest)
                or authorization.expected_previous_generation_digest != generation_digest):
            raise BootstrapEnrollmentPending("prepared protected generation changed during namespace selection")
        _ensure_receipt_root(self.root_journal, self.receipt_root)
        path = self.receipt_root / f"namespace-{authorization.setup_session_id}.json"
        if path.exists():
            receipt = _namespace_from_json(_read_json(path), self._seal)
            self._validate_namespace_receipt(
                receipt, authorization, principal, generation_id, generation_digest)
            return receipt
        now = time.monotonic()
        expires = min(now + SELECTION_RECEIPT_TTL_SECONDS, principal.expires_monotonic,
                      _session_expiry(normal_session_store, normal_session_handle))
        if expires <= now:
            raise BootstrapEnrollmentPending("adopted namespace selection has expired")
        receipt = VerifiedRootNamespaceSelection(
            SCHEMA, secrets.token_hex(32), authorization.setup_session_id,
            authorization.transaction_handle, authorization.plan_digest,
            generation_id, generation_digest, principal.receipt_id,
            principal.service_profile_id, principal.namespace_id, now, expires,
            self._seal,
        )
        _atomic_json(path, _namespace_json(receipt))
        return receipt

    def resolve_adopted_principal_selector(
        self, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
    ) -> RootSetupPrincipalSelector:
        """Resolve immutable selected identity intent; grants no current authority."""
        proof = _current_principal_setup_context(
            normal_session_store, normal_session_handle, "setup")
        adoption = self._adoption_for_session(proof.session_id)
        selector = _principal_selector_from_json(adoption.get("principal_selector"))
        if (selector.setup_session_id != proof.session_id
                or selector.transaction_handle != proof.transaction_handle
                or selector.plan_sha256 != proof.plan_digest
                or selector.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("principal selector is stale or belongs to another setup")
        return selector

    def _make_principal_selector(
        self, selected: VerifiedRootSetupPrincipalSelection,
        identity: AuthentikIdentityReceipt, proof: _PrincipalSetupContext,
        store: RootSetupSessionStore, handle: RootSetupSessionHandle,
    ) -> RootSetupPrincipalSelector:
        observer = self.identity_resolver
        if (not isinstance(observer, RootSetupAuthentikIdentityObserver)
                or not isinstance(observer.policy_resolver, _AdoptedNormalPolicyResolver)):
            raise BootstrapEnrollmentPending("principal selector requires the normal root Authentik policy")
        controller = hashlib.sha256((proof.session_id + "\0" + proof.transaction_handle).encode()).hexdigest()
        map_sha = getattr(self.capability_selection, "map_sha256", None)
        if not isinstance(map_sha, str):
            try:
                from .setup_capabilities import MAP_SHA256
                map_sha = MAP_SHA256
            except Exception:
                raise BootstrapEnrollmentPending("reviewed capability-map provenance is unavailable") from None
        body = {"session": proof.session_id, "transaction": proof.transaction_handle,
                "plan": proof.plan_digest, "principal": selected.principal_id,
                "subject": selected.authentik_subject_id, "username": selected.username,
                "email": selected.email, "profile": selected.service_profile_id,
                "policy": identity.policy_selection_digest,
                "policy_revision": identity.policy_revision,
                "direct_groups": list(identity.direct_group_ids),
                "effective_groups": list(identity.effective_group_ids),
                "system_member": identity.system_member,
                "map_sha256": map_sha,
                "caps": list(selected.capabilities),
                "controller": controller}
        binding = hashlib.sha256(_canonical(body)).hexdigest()
        selection_handle = secrets.token_hex(32)
        return RootSetupPrincipalSelector(
            selection_handle, proof.session_id, proof.transaction_handle, proof.plan_digest,
            selected.principal_id, selected.authentik_subject_id, selected.username,
            selected.email, observer.policy_resolver.selection_handle,
            identity.policy_selection_digest, identity.policy_revision,
            identity.direct_group_ids, identity.effective_group_ids, identity.system_member,
            selected.service_profile_id,
            map_sha,
            selected.capabilities, binding, controller, time.monotonic(),
            _session_expiry(store, handle), 0)

    def _adoption_for_session(self, session_id: str) -> Mapping[str, Any]:
        matches = []
        for path in self.receipt_root.glob("adopted-*.json"):
            try:
                value = _read_json(path)
            except OSError:
                continue
            if (isinstance(value, dict) and value.get("state") == "adopted"
                    and value.get("normal_setup_session_id") == session_id):
                matches.append(value)
        if len(matches) != 1:
            raise BootstrapEnrollmentPending("normal setup has no unique root-journaled principal selector")
        return matches[0]

    def resolve_adopted_namespace_selector(
        self, normal_session_store: RootSetupSessionStore,
        normal_session_handle: RootSetupSessionHandle,
    ) -> RootSetupNamespaceSelector:
        """Resolve stable namespace intent from the current prepared CAS."""
        principal = self.resolve_adopted_principal_selector(
            normal_session_store, normal_session_handle)
        proof = _current_setup_proof(normal_session_store, normal_session_handle)
        authority = normal_session_store.authority_loader_for_session()
        generations = authority.get("service_generations") if isinstance(authority, Mapping) else None
        if not isinstance(generations, Mapping):
            raise BootstrapEnrollmentPending("current prepared protected generation is unavailable")
        from .enrollment import _validate_service_generations
        try:
            current = _validate_service_generations(dict(generations))
        except Exception:
            raise BootstrapEnrollmentPending("current prepared protected generation failed strict validation") from None
        generation_id, generation_digest = current.get("generation_id"), current.get("generation_digest")
        if (not isinstance(generation_id, str) or not isinstance(generation_digest, str)
                or proof.expected_previous_generation_digest != generation_digest):
            raise BootstrapEnrollmentPending("prepared generation changed during namespace selection")
        controller = principal.controller_binding_handle
        adoption = self._adoption_for_session(proof.setup_session_id)
        adopted_selection = self._read_selection(
            adoption.get("new_principal_selection_receipt_handle", ""))
        body = {"session": proof.setup_session_id, "transaction": proof.transaction_handle,
                "plan": proof.plan_digest, "generation": generation_id,
                "generation_digest": generation_digest, "principal": principal.binding_sha256,
                "profile": principal.service_profile_id, "namespace": adopted_selection.namespace_id,
                "policy": "per-selected-principal-native-profile-v1", "controller": controller}
        binding = hashlib.sha256(_canonical(body)).hexdigest()
        handle = hashlib.sha256((principal.selection_handle + "\0" + binding).encode()).hexdigest()
        selector = RootSetupNamespaceSelector(
            handle, proof.setup_session_id, proof.transaction_handle, proof.plan_digest,
            generation_id, generation_digest, principal.selection_handle,
            principal.binding_sha256, principal.service_profile_id, adopted_selection.namespace_id,
            "per-selected-principal-native-profile-v1", binding, controller,
            principal.issued_monotonic, _session_expiry(normal_session_store, normal_session_handle), 0,
        )
        path = self.receipt_root / f"namespace-selector-{proof.setup_session_id}.json"
        if path.exists():
            previous = _namespace_selector_from_json(_read_json(path))
            if previous != selector:
                raise BootstrapEnrollmentPending("prepared namespace selector changed during setup")
            return previous
        _atomic_json(path, _namespace_selector_json(selector))
        return selector

    def resolve_current_setup_identity(
        self, principal_selection_handle: str, namespace_selection_handle: str,
        normal_session_handle: RootSetupSessionHandle,
    ) -> RootCurrentSetupIdentitySnapshot:
        """Refresh actual TLS identity and mint a coherent <=30s evidence pair."""
        store = self.setup_session_store
        if not isinstance(store, RootSetupSessionStore):
            raise BootstrapEnrollmentPending("current identity resolution requires the normal root setup store")
        principal_selector = self.resolve_adopted_principal_selector(store, normal_session_handle)
        namespace_selector = self.resolve_adopted_namespace_selector(store, normal_session_handle)
        if (principal_selection_handle != principal_selector.selection_handle
                or namespace_selection_handle != namespace_selector.selection_handle):
            raise BootstrapEnrollmentPending("stable setup selectors are stale or belong to another transaction")
        proof = _current_principal_setup_context(store, normal_session_handle, "setup")
        observer = self.identity_resolver
        if (not isinstance(observer, RootSetupAuthentikIdentityObserver)
                or observer.setup_session_store is not store
                or not isinstance(observer.policy_resolver, _AdoptedNormalPolicyResolver)):
            raise BootstrapEnrollmentPending("current setup identity has no session-bound root observer")
        try:
            fresh_identity_handle = observer.observe_selected_authentik_identity(
                normal_session_handle, principal_selector.authentik_policy_selection_handle)
            current_identity = observer.resolve_authenticated_identity(
                fresh_identity_handle, normal_session_handle, _capability_authorization(proof))
        except Exception:
            raise BootstrapEnrollmentPending("fresh Authentik identity observation is unavailable") from None
        adoption = self._adoption_for_session(proof.session_id)
        if (current_identity.authentik_subject_id != principal_selector.authentik_subject_id
                or current_identity.username.casefold() != principal_selector.username.casefold()
                or current_identity.email.casefold() != principal_selector.email.casefold()
                or current_identity.actor_credential_ref != adoption.get("actor_credential_ref")
                or current_identity.policy_selection_digest != principal_selector.policy_selection_sha256
                or current_identity.policy_revision != principal_selector.policy_revision
                or current_identity.direct_group_ids != principal_selector.direct_group_ids
                or current_identity.effective_group_ids != principal_selector.effective_group_ids
                or current_identity.system_member != principal_selector.system_member):
            raise BootstrapEnrollmentPending("fresh Authentik identity differs from selected setup intent")
        selected = self.capability_selection.select_for_identity(
            current_identity, _capability_authorization(proof))
        _validate_capability_selection(selected)
        if (selected.service_profile_id != principal_selector.service_profile_id
                or selected.namespace_id != namespace_selector.namespace_id
                or tuple(selected.capabilities) != principal_selector.selected_capability_ceiling):
            raise BootstrapEnrollmentPending("fresh reviewed profile or capability ceiling changed")
        now = time.monotonic()
        principal = VerifiedRootSetupPrincipalSelection(
            SCHEMA, secrets.token_hex(32), proof.session_id, proof.transaction_handle,
            proof.plan_digest, principal_selector.principal_id, current_identity.username,
            current_identity.email, current_identity.authentik_subject_id,
            current_identity.actor_credential_ref, selected.service_profile_id,
            selected.namespace_id, tuple(selected.capabilities), fresh_identity_handle,
            now, min(current_identity.expires_monotonic, _session_expiry(store, normal_session_handle)))
        _atomic_json(self.receipt_root / f"{principal.receipt_id}.json", _selection_json(principal))
        authorization = _current_setup_proof(store, normal_session_handle)
        namespace = VerifiedRootNamespaceSelection(
            SCHEMA, secrets.token_hex(32), authorization.setup_session_id,
            authorization.transaction_handle, authorization.plan_digest,
            namespace_selector.prepared_generation_id,
            namespace_selector.prepared_generation_digest, principal.receipt_id,
            principal.service_profile_id, principal.namespace_id, now,
                min(now + IDENTITY_RECEIPT_TTL_SECONDS, principal.expires_monotonic,
                _session_expiry(store, normal_session_handle)), self._seal)
        path = self.receipt_root / (
            f"namespace-current-{authorization.setup_session_id}-{namespace.receipt_handle}.json")
        _atomic_json(path, _namespace_json(namespace))
        now = time.monotonic()
        expiry = min(principal.expires_monotonic, namespace.expires_monotonic,
                     now + IDENTITY_RECEIPT_TTL_SECONDS)
        if expiry <= now:
            raise BootstrapEnrollmentPending("fresh setup identity snapshot expired")
        return RootCurrentSetupIdentitySnapshot(
            principal_selector.selection_handle, namespace_selector.selection_handle,
            principal_selector.binding_sha256, namespace_selector.binding_sha256,
            principal, namespace, principal.identity_receipt_handle, now, expiry)

    def _validate_namespace_receipt(
        self, receipt: VerifiedRootNamespaceSelection,
        authorization: VerifiedRootSetupAuthorization,
        principal: VerifiedRootSetupPrincipalSelection,
        generation_id: str, generation_digest: str,
    ) -> None:
        if (not isinstance(receipt, VerifiedRootNamespaceSelection)
                or receipt.schema != SCHEMA
                or not _HANDLE.fullmatch(receipt.receipt_handle)
                or receipt.setup_session_id != authorization.setup_session_id
                or receipt.transaction_handle != authorization.transaction_handle
                or receipt.plan_digest != authorization.plan_digest
                or receipt.prepared_generation_id != generation_id
                or receipt.prepared_generation_digest != generation_digest
                or receipt.principal_selection_receipt_id != principal.receipt_id
                or receipt.target_profile_id != "hermes-agent-native-v1"
                or receipt.target_profile_id != principal.service_profile_id
                or receipt.namespace_id != principal.namespace_id
                or not secrets.compare_digest(receipt._registry_seal, self._seal)
                or receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("root namespace selection receipt is stale or mismatched")

    def consume_selected_principal(
        self, receipt_handle: str, setup_session_handle: RootSetupSessionHandle,
        transaction_handle: str, plan_digest: str, activation_receipt: EnrollmentReceipt,
    ) -> VerifiedRootSetupPrincipalSelection:
        """Consume only after the matching committed activation CAS receipt."""
        if self._session_mode != "setup" or not isinstance(self.setup_session_store, RootSetupSessionStore):
            raise BootstrapEnrollmentPending("principal activation requires the adopted normal setup-session registry")
        if (not isinstance(activation_receipt, EnrollmentReceipt)
                or activation_receipt.state != "committed"
                or activation_receipt.transaction_handle != transaction_handle
                or not _ID.fullmatch(activation_receipt.generation_id)
                or not re.fullmatch(r"[0-9a-f]{64}", activation_receipt.generation_digest)
                or activation_receipt.expires_monotonic <= time.monotonic()):
            raise BootstrapEnrollmentPending("principal receipt consumption requires the committed current activation receipt")
        authorization = _current_setup_proof(self.setup_session_store, setup_session_handle)
        verified_commit = self.setup_session_store.verify_committed_receipt(
            activation_receipt, authorization)
        if (not isinstance(verified_commit, VerifiedCommittedEnrollment)
                or not secrets.compare_digest(verified_commit._store_seal,
                                              self.setup_session_store._instance_seal)
                or verified_commit.setup_session_id != authorization.setup_session_id
                or verified_commit.plan_digest != plan_digest
                or verified_commit.receipt != activation_receipt):
            raise BootstrapEnrollmentPending("principal receipt consumption requires root-verified durable activation CAS")
        lock = _exclusive_registry_lock(self.receipt_root, self.root_journal)
        try:
            receipt = self.resolve_selected_principal(
                receipt_handle, setup_session_handle, transaction_handle, plan_digest)
            if self._is_consumed(receipt_handle):
                raise BootstrapEnrollmentPending("principal selection receipt was already consumed")
            _exclusive_json(self.receipt_root / f"consumed-{receipt.receipt_id}.json", {
                "schema": SCHEMA, "receipt_id": receipt.receipt_id,
                "setup_session_id": receipt.setup_session_id,
                "transaction_handle": receipt.transaction_handle,
                "plan_digest": receipt.plan_digest,
                "generation_id": activation_receipt.generation_id,
                "generation_digest": activation_receipt.generation_digest,
                "consumed_monotonic": time.monotonic(),
            })
            return receipt
        finally:
            os.close(lock)

    def principal_binding_factory(
        self, receipt_handle: str, setup_session_handle: RootSetupSessionHandle,
        transaction_handle: str, plan_digest: str,
    ) -> PrincipalBindingFactory:
        selection = self.resolve_selected_principal(
            receipt_handle, setup_session_handle, transaction_handle, plan_digest)
        return selection.principal_binding

    def _read_selection(self, receipt_id: str) -> VerifiedRootSetupPrincipalSelection:
        value = _read_json(self.receipt_root / f"{receipt_id}.json")
        fields = {
            "schema", "receipt_id", "setup_session_id", "transaction_handle", "plan_digest",
            "principal_id", "username", "email", "authentik_subject_id", "actor_credential_ref",
            "service_profile_id", "namespace_id", "capabilities", "identity_receipt_handle",
            "issued_monotonic", "expires_monotonic",
        }
        if not isinstance(value, dict) or set(value) != fields:
            raise BootstrapEnrollmentPending("principal selection receipt is absent or malformed")
        try:
            receipt = VerifiedRootSetupPrincipalSelection(
                value["schema"], value["receipt_id"], value["setup_session_id"],
                value["transaction_handle"], value["plan_digest"], value["principal_id"],
                value["username"], value["email"], value["authentik_subject_id"],
                value["actor_credential_ref"], value["service_profile_id"],
                value["namespace_id"], tuple(value["capabilities"]),
                value["identity_receipt_handle"], value["issued_monotonic"],
                value["expires_monotonic"],
            )
        except (KeyError, TypeError, ValueError):
            raise BootstrapEnrollmentPending("principal selection receipt is malformed") from None
        _validate_selection_receipt(receipt, receipt_id)
        return receipt

    def _is_consumed(self, receipt_id: str) -> bool:
        path = self.receipt_root / f"consumed-{receipt_id}.json"
        dirfd = os.open(self.receipt_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.stat(path.name, dir_fd=dirfd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        finally:
            os.close(dirfd)
        value = _read_json(path)
        if (not isinstance(value, dict)
                or set(value) != {"schema", "receipt_id", "setup_session_id", "transaction_handle",
                                  "plan_digest", "generation_id", "generation_digest", "consumed_monotonic"}
                or value.get("schema") != SCHEMA or value.get("receipt_id") != receipt_id
                or not _ID.fullmatch(str(value.get("generation_id", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(value.get("generation_digest", "")))
                or type(value.get("consumed_monotonic")) not in (int, float)):
            raise BootstrapEnrollmentPending("principal activation-consumption record is malformed")
        return True


def _current_setup_proof(
    store: RootSetupSessionStore, handle: RootSetupSessionHandle,
) -> VerifiedRootSetupAuthorization:
    if (os.geteuid() != 0 or not sys.platform.startswith("linux")
            or not isinstance(handle, RootSetupSessionHandle)):
        raise BootstrapEnrollmentPending("root-local setup identity observation requires installed Linux root")
    try:
        live = store._live(handle)
        proof = _LiveRootSetupAuthorizer._proof(live)
    except Exception:
        raise BootstrapEnrollmentPending("root setup session is absent or expired") from None
    if (proof.setup_session_id != live.record.get("setup_session_id")
            or proof.transaction_handle != live.record.get("transaction_handle")
            or proof.plan_digest != live.record.get("plan_digest")
            or proof.target_id != live.record.get("target_id")):
        raise BootstrapEnrollmentError("root setup session proof does not match its current journal")
    return proof


def _is_initial_compilation_registry(value: Any) -> bool:
    """Use the installed compiler's concrete registry type, never duck typing."""
    try:
        from .bootstrap_runtime_factory import RootInitialCompilationRegistry
    except ImportError:
        return False
    return isinstance(value, RootInitialCompilationRegistry)


def _current_principal_setup_context(
    store: Any, handle: Any, mode: str,
) -> _PrincipalSetupContext:
    if mode == "setup":
        proof = _current_setup_proof(store, handle)
        return _PrincipalSetupContext(
            proof.setup_session_id, proof.transaction_handle, proof.plan_digest,
            _session_expiry(store, handle), "root-setup", proof,
            store, handle,
        )
    if (mode != "initial-compilation" or os.geteuid() != 0
            or not sys.platform.startswith("linux")
            or not _is_initial_compilation_registry(store)
            or not isinstance(handle, str) or not _HANDLE.fullmatch(handle)):
        raise BootstrapEnrollmentPending(
            "first-stage Authentik observation requires the installed Linux root compiler session")
    try:
        from .bootstrap_runtime_factory import RootInitialCompilationSession
        session = store.resolve_initial_session(handle)
        if not isinstance(session, RootInitialCompilationSession):
            raise TypeError("wrong initial session type")
        store.verify_initial_session(session)
    except Exception:
        raise BootstrapEnrollmentPending("root initial-compilation session is absent or expired") from None
    if (getattr(session, "phase", None) != "initial-compilation"
            or session.compilation_session_handle != handle
            or not _HANDLE.fullmatch(session.compilation_transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", session.plan_sha256)
            or type(session.expires_monotonic) not in (int, float)
            or session.expires_monotonic <= time.monotonic()):
        raise BootstrapEnrollmentPending("root initial-compilation session is malformed or no longer current")
    _verify_initial_journal_binding(session, store.root_journal)
    return _PrincipalSetupContext(
        session.compilation_session_handle,
        session.compilation_transaction_handle,
        session.plan_sha256,
        float(session.expires_monotonic),
        "initial-compilation", None, store, session,
    )


def _capability_authorization(context: _PrincipalSetupContext) -> Any:
    return context.authorization if context.phase == "root-setup" else context


def _verify_initial_journal_binding(session: Any, root_journal: Path) -> None:
    """Join stage0 to the exact root journal inode selected by the compiler."""
    binding = getattr(session, "_root_journal_root", None)
    if not isinstance(binding, Mapping):
        raise BootstrapEnrollmentPending("initial compilation has no verified root-journal binding")
    expected = {
        "root_id": "installer-authority-journal-v1",
        "absolute_path": str(root_journal), "owner_uid": 0,
        "owner_gid": 0, "mode": 0o700,
    }
    for key, value in expected.items():
        if binding.get(key) != value:
            raise BootstrapEnrollmentPending("initial compilation selected a different root journal")
    try:
        info = root_journal.lstat()
    except OSError:
        raise BootstrapEnrollmentPending("initial compilation root journal is unavailable") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_dev != binding.get("device") or info.st_ino != binding.get("inode")):
        raise BootstrapEnrollmentPending("initial compilation root journal custody changed")


def _session_expiry(store: RootSetupSessionStore, handle: RootSetupSessionHandle) -> float:
    return float(store._live(handle).record["expires_monotonic"])


def _validate_store_journal(store: RootSetupSessionStore, root_journal: Path) -> None:
    session_root = getattr(store, "session_root", None)
    if not isinstance(session_root, Path) or not session_root.is_absolute() or session_root.parent != root_journal:
        raise ValueError("principal receipts must share the current root setup journal")


def _join_authorization(
    supplied: Any,
    current: _PrincipalSetupContext,
) -> None:
    if current.phase == "root-setup":
        auth = current.authorization
        if (not isinstance(supplied, VerifiedRootSetupAuthorization) or auth is None
                or supplied.setup_session_id != auth.setup_session_id
                or supplied.transaction_handle != auth.transaction_handle
                or supplied.plan_digest != auth.plan_digest
                or supplied.target_id != auth.target_id):
            raise BootstrapEnrollmentPending("Authentik receipt does not match current root setup authorization")
        return
    if (not isinstance(supplied, _PrincipalSetupContext)
            or supplied.phase != "initial-compilation"
            or supplied.registry is not current.registry
            or supplied.session_id != current.session_id
            or supplied.transaction_handle != current.transaction_handle
            or supplied.plan_digest != current.plan_digest):
        raise BootstrapEnrollmentPending("Authentik receipt does not match current root initial compilation")


def _validate_policy_selection(policy: VerifiedAuthentikPolicySelection) -> None:
    if (not isinstance(policy, VerifiedAuthentikPolicySelection)
            or not _ID.fullmatch(policy.selection_id)
            or not _ID.fullmatch(policy.system_group_id)
            or not _ID.fullmatch(policy.recipient_group_id)
            or not _CREDENTIAL_REF.fullmatch(policy.actor_credential_ref)
            or not _ID.fullmatch(policy.policy_revision)
            or not isinstance(policy.https_origin, str)
            or not re.fullmatch(r"[0-9a-f]{64}", policy.selection_digest)):
        raise BootstrapEnrollmentPending("root-selected Authentik identity policy is invalid")
    parsed = urllib.parse.urlsplit(policy.https_origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise BootstrapEnrollmentPending("root-selected Authentik origin is not a fixed HTTPS origin")
    content = {
        "id": policy.selection_id, "https_origin": policy.https_origin.rstrip("/"),
        "system_group_id": policy.system_group_id,
        "recipient_group_id": policy.recipient_group_id,
        "policy_revision": policy.policy_revision,
        "actor_credential_ref": policy.actor_credential_ref,
    }
    if hashlib.sha256(_canonical(content)).hexdigest() != policy.selection_digest:
        raise BootstrapEnrollmentPending("root-selected Authentik policy digest is invalid")
    # Preserve the existing TLS/no-redirect implementation as the transport
    # authority; URL selection itself comes only from the root plan handle.
    if TLSAuthentikTransport(policy.https_origin).origin != policy.https_origin.rstrip("/"):
        raise BootstrapEnrollmentPending("root-selected Authentik origin is not canonical")


def _validate_origin_and_groups(origin: Any, system_group_id: Any, recipient_group_id: Any) -> None:
    if (not isinstance(origin, str) or len(origin) > 512
            or not _ID.fullmatch(system_group_id)
            or not _ID.fullmatch(recipient_group_id)
            or system_group_id == recipient_group_id):
        raise BootstrapEnrollmentPending("Authentik HTTPS origin or group choices are malformed")
    parsed = urllib.parse.urlsplit(origin)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
        raise BootstrapEnrollmentPending("Authentik identity origin must be a fixed HTTPS origin")
    try:
        transport = TLSAuthentikTransport(origin)
    except Exception:
        raise BootstrapEnrollmentPending("Authentik identity origin failed strict TLS validation") from None
    if transport.origin != origin.rstrip("/"):
        raise BootstrapEnrollmentPending("Authentik identity origin is not canonical")


def _policy_record_json(record: RootSetupAuthentikPolicyRecord) -> dict[str, Any]:
    return {
        "schema": record.schema,
        "selection_handle": record.selection_handle,
        "compilation_session_handle": record.compilation_session_handle,
        "compilation_transaction_handle": record.compilation_transaction_handle,
        "plan_sha256": record.plan_sha256,
        "https_origin": record.https_origin,
        "system_group_id": record.system_group_id,
        "recipient_group_id": record.recipient_group_id,
        "policy_revision": record.policy_revision,
        "actor_credential_ref": record.actor_credential_ref,
        "selection_sha256": record.selection_sha256,
        "issued_monotonic": record.issued_monotonic,
        "expires_monotonic": record.expires_monotonic,
    }


def _policy_record_digest(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical({key: value[key] for key in sorted(value)
                                     if key != "selection_sha256"})).hexdigest()


def _validate_identity_receipt(receipt: AuthentikIdentityReceipt, receipt_id: str) -> None:
    if (not isinstance(receipt, AuthentikIdentityReceipt) or receipt.schema != SCHEMA
            or receipt.receipt_id != receipt_id or not _HANDLE.fullmatch(receipt_id)
            or not _ID.fullmatch(receipt.setup_session_id)
            or not isinstance(receipt.transaction_handle, str) or not _ID.fullmatch(receipt.transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.plan_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.policy_selection_digest)
            or not isinstance(receipt.username, str) or not 1 <= len(receipt.username) <= 256
            or not isinstance(receipt.email, str) or not 3 <= len(receipt.email) <= 320 or "@" not in receipt.email
            or not isinstance(receipt.authentik_subject_id, str) or not _ID.fullmatch(receipt.authentik_subject_id)
            or not _CREDENTIAL_REF.fullmatch(receipt.actor_credential_ref)
            or len(receipt.direct_group_ids) > 256 or len(receipt.effective_group_ids) > 256
            or any(not _ID.fullmatch(group) for group in (*receipt.direct_group_ids, *receipt.effective_group_ids))
            or len(set(receipt.direct_group_ids)) != len(receipt.direct_group_ids)
            or len(set(receipt.effective_group_ids)) != len(receipt.effective_group_ids)
            or type(receipt.system_member) is not bool or not _ID.fullmatch(receipt.policy_revision)
            or type(receipt.checked_at_monotonic) not in (int, float)
            or type(receipt.expires_monotonic) not in (int, float)
            or receipt.expires_monotonic <= receipt.checked_at_monotonic
            or receipt.expires_monotonic - receipt.checked_at_monotonic > IDENTITY_RECEIPT_TTL_SECONDS + 0.001):
        raise BootstrapEnrollmentPending("Authentik identity receipt is malformed")


def _validate_capability_selection(value: ReviewedPrincipalCapabilities, *,
                                   allow_empty: bool = False) -> None:
    if (not isinstance(value, ReviewedPrincipalCapabilities)
            or not _ID.fullmatch(value.service_profile_id)
            or not _ID.fullmatch(value.namespace_id)
            or not isinstance(value.capabilities, tuple)
            or not (0 if allow_empty else 1) <= len(value.capabilities) <= 64
            or any(not _ID.fullmatch(item) for item in value.capabilities)
            or len(set(value.capabilities)) != len(value.capabilities)):
        raise BootstrapEnrollmentPending("root-reviewed setup capabilities are absent or malformed")


def _validate_selection_receipt(receipt: VerifiedRootSetupPrincipalSelection, receipt_id: str) -> None:
    if (not isinstance(receipt, VerifiedRootSetupPrincipalSelection) or receipt.schema != SCHEMA
            or receipt.receipt_id != receipt_id or not _HANDLE.fullmatch(receipt_id)
            or not _ID.fullmatch(receipt.setup_session_id)
            or not _ID.fullmatch(receipt.transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.plan_digest)
            or not isinstance(receipt.username, str) or not 1 <= len(receipt.username) <= 256
            or not isinstance(receipt.email, str) or not 3 <= len(receipt.email) <= 320 or "@" not in receipt.email
            or not isinstance(receipt.authentik_subject_id, str) or not _ID.fullmatch(receipt.authentik_subject_id)
            or not _CREDENTIAL_REF.fullmatch(receipt.actor_credential_ref)
            or receipt.principal_id != "authentik:" + hashlib.sha256(receipt.authentik_subject_id.encode()).hexdigest()
            or not _ID.fullmatch(receipt.service_profile_id) or not _ID.fullmatch(receipt.namespace_id)
            or not isinstance(receipt.capabilities, tuple) or not 0 <= len(receipt.capabilities) <= 64
            or any(not _ID.fullmatch(item) for item in receipt.capabilities)
            or len(set(receipt.capabilities)) != len(receipt.capabilities)
            or not _HANDLE.fullmatch(receipt.identity_receipt_handle)
            or type(receipt.issued_monotonic) not in (int, float)
            or type(receipt.expires_monotonic) not in (int, float)
            or receipt.expires_monotonic <= receipt.issued_monotonic
            or receipt.expires_monotonic - receipt.issued_monotonic > SELECTION_RECEIPT_TTL_SECONDS + 0.001):
        raise BootstrapEnrollmentPending("principal selection receipt is malformed")


def _namespace_json(receipt: VerifiedRootNamespaceSelection) -> dict[str, Any]:
    return {
        "schema": receipt.schema, "receipt_handle": receipt.receipt_handle,
        "setup_session_id": receipt.setup_session_id,
        "transaction_handle": receipt.transaction_handle,
        "plan_digest": receipt.plan_digest,
        "prepared_generation_id": receipt.prepared_generation_id,
        "prepared_generation_digest": receipt.prepared_generation_digest,
        "principal_selection_receipt_id": receipt.principal_selection_receipt_id,
        "target_profile_id": receipt.target_profile_id,
        "namespace_id": receipt.namespace_id,
        "issued_monotonic": receipt.issued_monotonic,
        "expires_monotonic": receipt.expires_monotonic,
    }


def _namespace_from_json(value: Any, registry_seal: str) -> VerifiedRootNamespaceSelection:
    expected = {
        "schema", "receipt_handle", "setup_session_id", "transaction_handle",
        "plan_digest", "prepared_generation_id", "prepared_generation_digest",
        "principal_selection_receipt_id", "target_profile_id", "namespace_id",
        "issued_monotonic", "expires_monotonic",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise BootstrapEnrollmentPending("root namespace selection record is absent or malformed")
    try:
        receipt = VerifiedRootNamespaceSelection(
            value["schema"], value["receipt_handle"], value["setup_session_id"],
            value["transaction_handle"], value["plan_digest"],
            value["prepared_generation_id"], value["prepared_generation_digest"],
            value["principal_selection_receipt_id"], value["target_profile_id"],
            value["namespace_id"], value["issued_monotonic"],
            value["expires_monotonic"], registry_seal,
        )
    except (KeyError, TypeError, ValueError):
        raise BootstrapEnrollmentPending("root namespace selection record is malformed") from None
    if (receipt.schema != SCHEMA or not _HANDLE.fullmatch(receipt.receipt_handle)
            or not _ID.fullmatch(receipt.setup_session_id)
            or not _ID.fullmatch(receipt.transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.plan_digest)
            or not _ID.fullmatch(receipt.prepared_generation_id)
            or not re.fullmatch(r"[0-9a-f]{64}", receipt.prepared_generation_digest)
            or not _HANDLE.fullmatch(receipt.principal_selection_receipt_id)
            or receipt.target_profile_id != "hermes-agent-native-v1"
            or not _ID.fullmatch(receipt.namespace_id)
            or type(receipt.issued_monotonic) not in (int, float)
            or type(receipt.expires_monotonic) not in (int, float)
            or receipt.expires_monotonic <= receipt.issued_monotonic
            or receipt.expires_monotonic - receipt.issued_monotonic > SELECTION_RECEIPT_TTL_SECONDS + 0.001):
        raise BootstrapEnrollmentPending("root namespace selection record is malformed")
    return receipt


def _identity_json(receipt: AuthentikIdentityReceipt) -> dict[str, Any]:
    return {
        "schema": receipt.schema, "receipt_id": receipt.receipt_id,
        "setup_session_id": receipt.setup_session_id,
        "transaction_handle": receipt.transaction_handle, "plan_digest": receipt.plan_digest,
        "policy_selection_digest": receipt.policy_selection_digest, "username": receipt.username,
        "email": receipt.email, "authentik_subject_id": receipt.authentik_subject_id,
        "actor_credential_ref": receipt.actor_credential_ref,
        "direct_group_ids": list(receipt.direct_group_ids),
        "effective_group_ids": list(receipt.effective_group_ids),
        "system_member": receipt.system_member, "policy_revision": receipt.policy_revision,
        "checked_at_monotonic": receipt.checked_at_monotonic,
        "expires_monotonic": receipt.expires_monotonic,
    }


def _selection_json(receipt: VerifiedRootSetupPrincipalSelection) -> dict[str, Any]:
    return {
        "schema": receipt.schema, "receipt_id": receipt.receipt_id,
        "setup_session_id": receipt.setup_session_id,
        "transaction_handle": receipt.transaction_handle, "plan_digest": receipt.plan_digest,
        "principal_id": receipt.principal_id, "username": receipt.username,
        "email": receipt.email, "authentik_subject_id": receipt.authentik_subject_id,
        "actor_credential_ref": receipt.actor_credential_ref,
        "service_profile_id": receipt.service_profile_id, "namespace_id": receipt.namespace_id,
        "capabilities": list(receipt.capabilities),
        "identity_receipt_handle": receipt.identity_receipt_handle,
        "issued_monotonic": receipt.issued_monotonic,
        "expires_monotonic": receipt.expires_monotonic,
    }


def _principal_selector_json(value: RootSetupPrincipalSelector) -> dict[str, Any]:
    return {"selection_handle": value.selection_handle,
            "setup_session_id": value.setup_session_id,
            "transaction_handle": value.transaction_handle, "plan_sha256": value.plan_sha256,
            "principal_id": value.principal_id, "authentik_subject_id": value.authentik_subject_id,
            "username": value.username, "email": value.email,
            "authentik_policy_selection_handle": value.authentik_policy_selection_handle,
            "policy_selection_sha256": value.policy_selection_sha256,
            "policy_revision": value.policy_revision,
            "direct_group_ids": list(value.direct_group_ids),
            "effective_group_ids": list(value.effective_group_ids),
            "system_member": value.system_member, "service_profile_id": value.service_profile_id,
            "reviewed_capability_map_sha256": value.reviewed_capability_map_sha256,
            "selected_capability_ceiling": list(value.selected_capability_ceiling),
            "binding_sha256": value.binding_sha256,
            "controller_binding_handle": value.controller_binding_handle,
            "issued_monotonic": value.issued_monotonic,
            "expires_monotonic": value.expires_monotonic,
            "revocation_epoch": value.revocation_epoch}


def _principal_selector_from_json(value: Any) -> RootSetupPrincipalSelector:
    expected = {"selection_handle", "setup_session_id", "transaction_handle", "plan_sha256",
                "principal_id", "authentik_subject_id", "username", "email",
                "authentik_policy_selection_handle", "policy_selection_sha256", "policy_revision",
                "direct_group_ids", "effective_group_ids", "system_member", "service_profile_id",
                "reviewed_capability_map_sha256", "selected_capability_ceiling", "binding_sha256",
                "controller_binding_handle", "issued_monotonic", "expires_monotonic", "revocation_epoch"}
    if not isinstance(value, dict) or set(value) != expected:
        raise BootstrapEnrollmentPending("root principal selector is absent or malformed")
    try:
        result = RootSetupPrincipalSelector(
            value["selection_handle"], value["setup_session_id"], value["transaction_handle"],
            value["plan_sha256"], value["principal_id"], value["authentik_subject_id"],
            value["username"], value["email"], value["authentik_policy_selection_handle"],
            value["policy_selection_sha256"], value["policy_revision"],
            tuple(value["direct_group_ids"]), tuple(value["effective_group_ids"]),
            value["system_member"], value["service_profile_id"],
            value["reviewed_capability_map_sha256"], tuple(value["selected_capability_ceiling"]),
            value["binding_sha256"], value["controller_binding_handle"],
            value["issued_monotonic"], value["expires_monotonic"], value["revocation_epoch"])
    except (KeyError, TypeError, ValueError):
        raise BootstrapEnrollmentPending("root principal selector is malformed") from None
    if (not _HANDLE.fullmatch(result.selection_handle)
            or not _ID.fullmatch(result.setup_session_id)
            or not _ID.fullmatch(result.transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", result.plan_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", result.binding_sha256)
            or not _HANDLE.fullmatch(result.controller_binding_handle)
            or not _HANDLE.fullmatch(result.authentik_policy_selection_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", result.policy_selection_sha256)
            or type(result.system_member) is not bool or result.revocation_epoch != 0
            or type(result.issued_monotonic) not in (int, float)
            or type(result.expires_monotonic) not in (int, float)
            or result.expires_monotonic <= result.issued_monotonic
            or len(result.direct_group_ids) > 256 or len(result.effective_group_ids) > 256
            or len(result.selected_capability_ceiling) > 64):
        raise BootstrapEnrollmentPending("root principal selector failed validation")
    controller = hashlib.sha256((result.setup_session_id + "\0" + result.transaction_handle).encode()).hexdigest()
    body = {"session": result.setup_session_id, "transaction": result.transaction_handle,
            "plan": result.plan_sha256, "principal": result.principal_id,
            "subject": result.authentik_subject_id, "username": result.username,
            "email": result.email, "profile": result.service_profile_id,
            "policy": result.policy_selection_sha256, "policy_revision": result.policy_revision,
            "direct_groups": list(result.direct_group_ids),
            "effective_groups": list(result.effective_group_ids), "system_member": result.system_member,
            "map_sha256": result.reviewed_capability_map_sha256,
            "caps": list(result.selected_capability_ceiling), "controller": controller}
    if (controller != result.controller_binding_handle
            or hashlib.sha256(_canonical(body)).hexdigest() != result.binding_sha256):
        raise BootstrapEnrollmentPending("root principal selector binding digest is invalid")
    return result


def _namespace_selector_json(value: RootSetupNamespaceSelector) -> dict[str, Any]:
    return {"selection_handle": value.selection_handle, "setup_session_id": value.setup_session_id,
            "transaction_handle": value.transaction_handle, "plan_sha256": value.plan_sha256,
            "prepared_generation_id": value.prepared_generation_id,
            "prepared_generation_digest": value.prepared_generation_digest,
            "principal_selection_handle": value.principal_selection_handle,
            "principal_binding_sha256": value.principal_binding_sha256,
            "target_profile_id": value.target_profile_id, "namespace_id": value.namespace_id,
            "namespace_policy": value.namespace_policy, "binding_sha256": value.binding_sha256,
            "controller_binding_handle": value.controller_binding_handle,
            "issued_monotonic": value.issued_monotonic, "expires_monotonic": value.expires_monotonic,
            "revocation_epoch": value.revocation_epoch}


def _namespace_selector_from_json(value: Any) -> RootSetupNamespaceSelector:
    expected = {"selection_handle", "setup_session_id", "transaction_handle", "plan_sha256",
                "prepared_generation_id", "prepared_generation_digest", "principal_selection_handle",
                "principal_binding_sha256", "target_profile_id", "namespace_id", "namespace_policy",
                "binding_sha256", "controller_binding_handle", "issued_monotonic", "expires_monotonic",
                "revocation_epoch"}
    if not isinstance(value, dict) or set(value) != expected:
        raise BootstrapEnrollmentPending("root namespace selector is absent or malformed")
    try:
        result = RootSetupNamespaceSelector(**value)
    except (TypeError, ValueError):
        raise BootstrapEnrollmentPending("root namespace selector is malformed") from None
    if (not _HANDLE.fullmatch(result.selection_handle)
            or not _ID.fullmatch(result.setup_session_id)
            or not _ID.fullmatch(result.transaction_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", result.plan_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", result.prepared_generation_digest)
            or not _HANDLE.fullmatch(result.principal_selection_handle)
            or not re.fullmatch(r"[0-9a-f]{64}", result.principal_binding_sha256)
            or not re.fullmatch(r"[0-9a-f]{64}", result.binding_sha256)
            or not _HANDLE.fullmatch(result.controller_binding_handle)
            or type(result.revocation_epoch) is not int or result.revocation_epoch != 0
            or result.namespace_policy != "per-selected-principal-native-profile-v1"):
        raise BootstrapEnrollmentPending("root namespace selector failed validation")
    controller = hashlib.sha256((result.setup_session_id + "\0" + result.transaction_handle).encode()).hexdigest()
    body = {"session": result.setup_session_id, "transaction": result.transaction_handle,
            "plan": result.plan_sha256, "generation": result.prepared_generation_id,
            "generation_digest": result.prepared_generation_digest,
            "principal": result.principal_binding_sha256, "profile": result.target_profile_id,
            "namespace": result.namespace_id, "policy": result.namespace_policy,
            "controller": controller}
    expected_handle = hashlib.sha256((result.principal_selection_handle + "\0" +
                                       hashlib.sha256(_canonical(body)).hexdigest()).encode()).hexdigest()
    if (controller != result.controller_binding_handle
            or hashlib.sha256(_canonical(body)).hexdigest() != result.binding_sha256
            or expected_handle != result.selection_handle):
        raise BootstrapEnrollmentPending("root namespace selector binding digest is invalid")
    return result


def _ensure_receipt_root(root_journal: Path, receipt_root: Path) -> None:
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("setup identity receipts require the root authority")
    if receipt_root.parent != root_journal:
        raise BootstrapEnrollmentError("setup receipt storage escaped the selected root journal")
    root_fd = os.open(root_journal, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                       getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        root_stat = os.fstat(root_fd)
    finally:
        os.close(root_fd)
    if (stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode)
            or root_stat.st_uid != 0 or root_stat.st_gid != 0
            or stat.S_IMODE(root_stat.st_mode) != 0o700):
        raise BootstrapEnrollmentError("selected root journal has unsafe ownership or mode")
    try:
        receipt_root.mkdir(mode=0o700)
    except FileExistsError:
        pass
    info = receipt_root.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) != 0o700):
        raise BootstrapEnrollmentError("setup receipt journal has unsafe ownership or mode")


def _atomic_json(path: Path, document: Mapping[str, Any]) -> None:
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("setup receipt write requires root")
    _ensure_receipt_root(path.parent.parent, path.parent)
    payload = _canonical(dict(document))
    if len(payload) > MAX_RECEIPT_BYTES:
        raise BootstrapEnrollmentError("setup receipt exceeds its storage bound")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise BootstrapEnrollmentError("root setup receipt handle already exists")
    dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    temporary = "." + path.name + "." + secrets.token_hex(12) + ".tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=dirfd)
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, 0, 0)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path.name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    finally:
        try:
            os.unlink(temporary, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        os.close(dirfd)


def _atomic_replace_json(path: Path, document: Mapping[str, Any]) -> None:
    """Replace a root-owned journal record atomically while caller holds its lock."""
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("setup receipt write requires root")
    _ensure_receipt_root(path.parent.parent, path.parent)
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise BootstrapEnrollmentPending("root journal transition record disappeared") from None
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600):
        raise BootstrapEnrollmentPending("root journal transition record custody changed")
    payload = _canonical(dict(document))
    if len(payload) > MAX_RECEIPT_BYTES:
        raise BootstrapEnrollmentError("setup receipt exceeds its storage bound")
    dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    temporary = "." + path.name + "." + secrets.token_hex(12) + ".tmp"
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=dirfd)
        try:
            os.fchmod(fd, 0o600)
            os.fchown(fd, 0, 0)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path.name, src_dir_fd=dirfd, dst_dir_fd=dirfd)
        os.fsync(dirfd)
    finally:
        try:
            os.unlink(temporary, dir_fd=dirfd)
        except FileNotFoundError:
            pass
        os.close(dirfd)


def _exclusive_json(path: Path, document: Mapping[str, Any]) -> None:
    if os.geteuid() != 0:
        raise BootstrapEnrollmentPending("setup receipt write requires root")
    _ensure_receipt_root(path.parent.parent, path.parent)
    payload = _canonical(dict(document))
    if len(payload) > MAX_RECEIPT_BYTES:
        raise BootstrapEnrollmentError("setup receipt exceeds its storage bound")
    dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                     0o600, dir_fd=dirfd)
        try:
            os.fchown(fd, 0, 0)
            offset = 0
            while offset < len(payload):
                offset += os.write(fd, payload[offset:])
            os.fsync(fd)
        finally:
            os.close(fd)
        os.fsync(dirfd)
    except FileExistsError:
        raise BootstrapEnrollmentPending("principal selection receipt was already consumed") from None
    finally:
        os.close(dirfd)


def _read_json(path: Path) -> Any:
    dirfd = -1
    fd = -1
    try:
        dirfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                        getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), dir_fd=dirfd)
    except OSError:
        if fd >= 0:
            os.close(fd)
        if dirfd >= 0:
            os.close(dirfd)
        raise BootstrapEnrollmentPending("root setup receipt is absent") from None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > MAX_RECEIPT_BYTES):
            raise BootstrapEnrollmentError("root setup receipt has unsafe custody")
        chunks = bytearray()
        while len(chunks) <= MAX_RECEIPT_BYTES:
            chunk = os.read(fd, min(4096, MAX_RECEIPT_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        if len(chunks) > MAX_RECEIPT_BYTES:
            raise BootstrapEnrollmentError("root setup receipt exceeds its read bound")
    finally:
        os.close(fd)
        os.close(dirfd)
    try:
        return json.loads(bytes(chunks).decode("utf-8"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError, ValueError):
        raise BootstrapEnrollmentPending("root setup receipt is malformed") from None


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_handle(value: str, label: str) -> None:
    if not isinstance(value, str) or not _HANDLE.fullmatch(value):
        raise BootstrapEnrollmentPending(f"{label} is malformed")


def _exclusive_registry_lock(receipt_root: Path, root_journal: Path) -> int:
    _ensure_receipt_root(root_journal, receipt_root)
    dirfd = os.open(receipt_root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                    getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    try:
        fd = os.open(".registry.lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=dirfd)
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600):
            os.close(fd)
            raise BootstrapEnrollmentError("setup receipt registry lock has unsafe custody")
    finally:
        os.close(dirfd)
    fcntl.flock(fd, fcntl.LOCK_EX)
    return fd
