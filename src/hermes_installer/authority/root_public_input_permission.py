"""Root-owned, purpose-specific permission for public web reads from public input.

Persistent TTY configuration is an intent. Each actual PUBLIC selected-input
observation receives a separate short permission snapshot; private and unknown
source ancestry can never be reclassified by this registry.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .root_private_input_consent import _ProtectedStore
from .runtime_bindings import RootRuntimeBindings
from .service import AuthorityService, PrincipalBinding
from .source_observers import RootNativeExecutionSelectionRegistry, SourceObserverRegistry
from ..components.plugin_public_https import EnrolledPublicWebScope
from ..protected_enrollment import RootJournalSelection
from .types import AuthorityDenied, Sensitivity, canonical_digest

_SEAL = object()
_PURPOSE = "public-free-web-read"
_OPERATION = "plugin.web.read"
_MAX_LEASE = 30.0


@dataclass(frozen=True, slots=True, repr=False)
class RootPublicInputPermissionSelection:
    """Current active projection of one persistent root TTY scope choice."""

    selection_handle: str
    consent_id: str
    purpose: str
    choice_observation_id: str
    setup_session_id: str
    transaction_handle: str
    plan_sha256: str
    principal_selection_handle: str
    namespace_selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    web_scope_ids: tuple[str, ...]
    web_scope_sha256: str
    public_recipient_ids: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    additional_metered_budget_usd: float
    controller_binding_handle: str
    issued_monotonic: float
    expires_monotonic: float
    revocation_epoch: int
    _registry_seal: object = field(repr=False, compare=False)

    def __repr__(self) -> str:
        return "RootPublicInputPermissionSelection(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootPublicInputPermission:
    """Sealed permission receipt for one exact root-retained public input."""

    receipt_handle: str
    consent_id: str
    purpose: str
    selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    profile_generation: str
    service_generation_digest: str
    retained_input_selection_handle: str
    input_observation_handle: str
    input_sha256: str
    web_scope_ids: tuple[str, ...]
    web_scope_sha256: str
    public_recipient_ids: tuple[str, ...]
    allowed_operations: tuple[str, ...]
    additional_metered_budget_usd: float
    revocation_epoch: int
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("public input permission is minted by its root registry")
        if (self.purpose != _PURPOSE or self.allowed_operations != (_OPERATION,)
                or self.additional_metered_budget_usd != 0.0
                or type(self.revocation_epoch) is not int or self.revocation_epoch < 1
                or not self.issued_monotonic < self.expires_monotonic
                or self.expires_monotonic - self.issued_monotonic > _MAX_LEASE):
            raise AuthorityDenied("public-permission.invalid", "public input permission claims are invalid")

    def claims(self) -> dict[str, Any]:
        return {
            "receipt_handle": self.receipt_handle,
            "consent_id": self.consent_id,
            "purpose": self.purpose,
            "selection_handle": self.selection_handle,
            "principal_id": self.principal_id,
            "profile_id": self.profile_id,
            "namespace_id": self.namespace_id,
            "profile_generation": self.profile_generation,
            "service_generation_digest": self.service_generation_digest,
            "retained_input_selection_handle": self.retained_input_selection_handle,
            "input_observation_handle": self.input_observation_handle,
            "input_sha256": self.input_sha256,
            "web_scope_ids": list(self.web_scope_ids),
            "web_scope_sha256": self.web_scope_sha256,
            "public_recipient_ids": list(self.public_recipient_ids),
            "allowed_operations": list(self.allowed_operations),
            "additional_metered_budget_usd": self.additional_metered_budget_usd,
            "revocation_epoch": self.revocation_epoch,
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        }

    def __repr__(self) -> str:
        return "RootPublicInputPermission(<root-private>)"


class RootPublicInputPermissionRegistry:
    """Resolve durable public web intent into current per-input snapshots."""

    def __init__(self, authority_service: AuthorityService,
                 active_bindings: RootRuntimeBindings,
                 root_native_input_selection_registry: RootNativeExecutionSelectionRegistry,
                 root_source_observer_registry: SourceObserverRegistry,
                 root_journal: RootJournalSelection, *, monotonic: Any = time.monotonic):
        digest = _active_digest(active_bindings)
        if (os.geteuid() != 0 or type(authority_service) is not AuthorityService
                or type(active_bindings) is not RootRuntimeBindings
                or authority_service.root_runtime_bindings is not active_bindings
                or type(root_native_input_selection_registry) is not RootNativeExecutionSelectionRegistry
                or type(root_source_observer_registry) is not SourceObserverRegistry
                or authority_service.source_observer_registry is not root_source_observer_registry
                or type(root_journal) is not RootJournalSelection or digest is None
                or root_journal.service_generation_digest != digest
                or not callable(monotonic)):
            raise AuthorityDenied("public-permission.binding", "active root public-input authority is incomplete")
        self.service = authority_service
        self.bindings = active_bindings
        self.selections = root_native_input_selection_registry
        self.sources = root_source_observer_registry
        self.journal = root_journal
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._receipts: dict[str, tuple[RootPublicInputPermission, Any, Any,
                                        RootPublicInputPermissionSelection]] = {}
        self._pending: dict[str, tuple[Any, Any, RootPublicInputPermissionSelection]] = {}
        self._store = _ProtectedStore(root_journal, "public-input-permission", authority_service)
        self._rows = self._store.load()
        self._check_journal()

    @classmethod
    def from_root_runtime(cls, authority_service: AuthorityService,
                          active_bindings: RootRuntimeBindings,
                          root_native_input_selection_registry: RootNativeExecutionSelectionRegistry,
                          root_source_observer_registry: SourceObserverRegistry,
                          root_journal: RootJournalSelection) -> "RootPublicInputPermissionRegistry":
        registry = cls(authority_service, active_bindings, root_native_input_selection_registry,
                       root_source_observer_registry, root_journal)
        authority_service.attach_root_public_input_permission_registry(registry)
        return registry

    def selection_handle_for_current_profile(self, binding: PrincipalBinding) -> str | None:
        """Return only the current explicit foreground TTY intent handle."""
        current = self._current_binding(binding)
        resolver = getattr(self.bindings, "resolve_current_public_input_permission_selection", None)
        if not callable(resolver):
            return None
        try:
            selection = resolver(current, service_generation_digest=_active_digest(self.bindings))
            self._validate_selection(selection, current)
        except Exception:
            return None
        return selection.selection_handle

    def resolve_current_selection(self, selection_handle: str) -> RootPublicInputPermissionSelection:
        """Reproject persistent setup intent onto the current active scope generation."""
        if not isinstance(selection_handle, str) or not selection_handle:
            raise AuthorityDenied("public-permission.selection", "selection handle is malformed")
        resolver = getattr(self.bindings, "resolve_current_public_input_permission_selection", None)
        if not callable(resolver):
            raise AuthorityDenied("public-permission.selection", "active public web selection projection is unavailable")
        # Resolve through the active profile selector; a caller cannot provide a
        # PrincipalBinding or a scope row to make an old preference current.
        match = [binding for binding in self.service.bindings_by_uid.values()
                 if type(binding) is PrincipalBinding]
        rows = []
        for binding in match:
            try:
                selection = resolver(binding, service_generation_digest=_active_digest(self.bindings))
                if selection.selection_handle == selection_handle:
                    rows.append(self._validate_selection(selection, binding))
            except Exception:
                continue
        if len(rows) != 1:
            raise AuthorityDenied("public-permission.selection", "public web selection is absent, stale, or ambiguous")
        return rows[0]

    def resolve_for_selected_input(self, observed_public_input_proof: Any,
                                   selected_input_binding: Any) -> RootPublicInputPermission:
        """Consume one exact root-observed PUBLIC input and mint a <=30s receipt."""
        proof, execution, selection, scopes = self._resolve_public_observation(
            observed_public_input_proof, selected_input_binding)
        now = self.monotonic()
        expires = min(now + _MAX_LEASE, float(proof.expires_monotonic), selection.expires_monotonic)
        if not now < expires:
            raise AuthorityDenied("public-permission.expired", "public input or selection snapshot expired")
        candidate = RootPublicInputPermission(
            receipt_handle=secrets.token_urlsafe(32),
            consent_id=selection.consent_id,
            purpose=_PURPOSE,
            selection_handle=selection.selection_handle,
            principal_id=selection.principal_id,
            profile_id=selection.profile_id,
            namespace_id=selection.namespace_id,
            profile_generation=str(self.service.profile_generations.get(selection.profile_id, "")),
            service_generation_digest=str(_active_digest(self.bindings)),
            retained_input_selection_handle=execution.selection_handle,
            input_observation_handle=proof.observation_handle,
            input_sha256=proof.input_sha256,
            web_scope_ids=selection.web_scope_ids,
            web_scope_sha256=selection.web_scope_sha256,
            public_recipient_ids=selection.public_recipient_ids,
            allowed_operations=(_OPERATION,),
            additional_metered_budget_usd=0.0,
            revocation_epoch=selection.revocation_epoch,
            issued_monotonic=now,
            expires_monotonic=expires,
            signature="",
            _seal=_SEAL,
        )
        with self._lock:
            if proof.observation_handle in self._pending:
                raise AuthorityDenied("public-permission.replay", "public input observation is already being resolved")
            self._pending[proof.observation_handle] = (proof, execution, selection)
        try:
            self._validate_candidate(candidate, proof, execution, selection, scopes)
            signer = self._signer()
            receipt = signer.issue_permission(candidate)
            if (type(receipt) is not RootPublicInputPermission or receipt._seal is not _SEAL
            or receipt.receipt_handle != candidate.receipt_handle
                    or receipt.signature == ""):
                raise AuthorityDenied("public-permission.signer", "root permission signer returned an invalid receipt")
            with self._lock:
                retained = self._receipts.get(receipt.receipt_handle)
                if retained is None or retained[0] is not receipt:
                    raise AuthorityDenied("public-permission.signer", "signed receipt was not retained by the root signer")
            consume = getattr(self.sources, "consume_public_input_observation", None)
            if not callable(consume):
                raise AuthorityDenied("public-permission.source", "root public input observation consumer is unavailable")
            try:
                consume(proof, execution)
            except Exception:
                # The signature is durable for audit, but no live membership is
                # retained if the one-use source observation could not consume.
                with self._lock:
                    self._receipts.pop(receipt.receipt_handle, None)
                raise
            return receipt
        finally:
            with self._lock:
                self._pending.pop(proof.observation_handle, None)

    def resolve_current_for_selection(self, receipt_handle: str,
                                      retained_input_selection_handle: str,
                                      expected_consent_id: str,
                                      expected_revocation_epoch: int) -> RootPublicInputPermission:
        """Non-consuming exact receipt currentness check; never refreshes its lease."""
        with self._lock:
            retained = self._receipts.get(receipt_handle)
        if retained is None:
            raise AuthorityDenied("public-permission.stale", "retained public permission receipt is unknown")
        receipt, proof, execution, original_selection = retained
        if (receipt.receipt_handle != receipt_handle or receipt.consent_id != expected_consent_id
                or receipt.revocation_epoch != expected_revocation_epoch
                or receipt.retained_input_selection_handle != retained_input_selection_handle
                or execution.selection_handle != retained_input_selection_handle
                or self.monotonic() >= receipt.expires_monotonic):
            raise AuthorityDenied("public-permission.stale", "public permission receipt mismatches or expired")
        current_execution = self.selections.resolve_current_selected_execution(retained_input_selection_handle)
        if current_execution is not execution:
            raise AuthorityDenied("public-permission.input", "retained public input selection is no longer current")
        selection = self.resolve_current_selection(receipt.selection_handle)
        if (not _same_selection_identity(selection, original_selection)
                or selection.consent_id != expected_consent_id
                or selection.revocation_epoch != expected_revocation_epoch):
            raise AuthorityDenied("public-permission.revoked", "public permission selection or epoch changed")
        self._validate_retained_public_observation(proof, execution, receipt)
        signer = self._signer()
        if signer.verify_permission(receipt) is not True:
            raise AuthorityDenied("public-permission.signature", "public permission signature is not current")
        return receipt

    def revoke_selection(self, selection_handle: str, current_authorized_owner_request: Any) -> Any:
        revoke = getattr(self.bindings, "revoke_public_input_permission_selection", None)
        if not callable(revoke):
            raise AuthorityDenied("public-permission.owner", "current public permission revocation is unavailable")
        return revoke(selection_handle, current_authorized_owner_request)

    def verify_observation_for_authority(self, candidate: RootPublicInputPermission) -> bool:
        """Callback for AuthorityService's fixed-domain permission signer."""
        if type(candidate) is not RootPublicInputPermission or candidate._seal is not _SEAL:
            return False
        with self._lock:
            pending = self._pending.get(candidate.input_observation_handle)
        if pending is None:
            return False
        proof, execution, selection = pending
        try:
            scopes = self._current_scopes(selection)
            self._validate_candidate(candidate, proof, execution, selection, scopes)
            verify = getattr(self.sources, "verify_current_public_input_observation", None)
            return bool(callable(verify) and verify(proof, execution))
        except Exception:
            return False

    def verify_permission_membership(self, receipt: RootPublicInputPermission) -> bool:
        if type(receipt) is not RootPublicInputPermission or receipt._seal is not _SEAL:
            return False
        with self._lock:
            retained = self._receipts.get(receipt.receipt_handle)
            return retained is not None and retained[0] is receipt

    def retain_authority_signed_observation(self, receipt: RootPublicInputPermission) -> bool:
        """Retain only the exact signed candidate currently being authorized."""
        if (type(receipt) is not RootPublicInputPermission or receipt._seal is not _SEAL
                or not isinstance(receipt.signature, str) or not receipt.signature):
            return False
        with self._lock:
            pending = self._pending.get(receipt.input_observation_handle)
            if pending is None or receipt.receipt_handle in self._receipts:
                return False
            proof, execution, selection = pending
            if (receipt.retained_input_selection_handle != execution.selection_handle
                    or receipt.input_observation_handle != proof.observation_handle
                    or receipt.selection_handle != selection.selection_handle
                    or receipt.consent_id != selection.consent_id
                    or receipt.input_sha256 != proof.input_sha256
                    or not self._valid_source_material(proof, execution, consumed=False)):
                return False
            try:
                self._validate_candidate(receipt, proof, execution, selection,
                                         self._current_scopes(selection), signed=True)
            except Exception:
                return False
            self._receipts[receipt.receipt_handle] = (receipt, proof, execution, selection)
            self._persist_receipt(receipt)
            return True

    def _resolve_public_observation(self, proof: Any, selected_input_binding: Any
                                    ) -> tuple[Any, Any, RootPublicInputPermissionSelection,
                                      tuple[Any, ...]]:
        from .source_observers import RootSelectedNativeExecution, RootPublicNativeInputObservation
        if (type(proof) is not RootPublicNativeInputObservation
                or type(selected_input_binding) is not RootSelectedNativeExecution):
            raise AuthorityDenied("public-permission.input", "exact root public input proof and native selection are required")
        execution = selected_input_binding
        if (proof.retained_input_selection_handle != execution.selection_handle
                or proof.public_permission_selection_handle != execution.public_input_permission_selection_handle
                or execution.private_consent_selection_handle is not None
                or proof.source_classification is not Sensitivity.PUBLIC):
            raise AuthorityDenied("public-permission.input", "public observation does not bind this exact public input")
        verify = getattr(self.sources, "verify_current_public_input_observation", None)
        if not callable(verify) or verify(proof, execution) is not True:
            raise AuthorityDenied("public-permission.input", "public observation is forged, stale, or consumed")
        selection = self.resolve_current_selection(proof.public_permission_selection_handle)
        if (selection.profile_id != execution.profile_id
                or selection.namespace_id != proof.namespace_id
                or proof.profile_id != execution.profile_id
                or proof.profile_generation != execution.generation
                or proof.service_generation_digest != execution.service_generation_digest
                or selection.selection_handle != execution.public_input_permission_selection_handle):
            raise AuthorityDenied("public-permission.profile", "public permission does not join current selected execution")
        scopes = self._current_scopes(selection)
        if not self._valid_source_material(proof, execution, consumed=False):
            raise AuthorityDenied("public-permission.ancestry", "input has PRIVATE or UNKNOWN ancestry")
        return proof, execution, selection, scopes

    def _validate_candidate(self, candidate: RootPublicInputPermission, proof: Any,
                            execution: Any, selection: RootPublicInputPermissionSelection,
                            scopes: tuple[Any, ...], *, signed: bool = False) -> None:
        expected = {
            "consent_id": selection.consent_id,
            "purpose": _PURPOSE,
            "selection_handle": selection.selection_handle,
            "principal_id": selection.principal_id,
            "profile_id": selection.profile_id,
            "namespace_id": selection.namespace_id,
            "profile_generation": proof.profile_generation,
            "service_generation_digest": _active_digest(self.bindings),
            "retained_input_selection_handle": execution.selection_handle,
            "input_observation_handle": proof.observation_handle,
            "input_sha256": proof.input_sha256,
            "web_scope_ids": selection.web_scope_ids,
            "web_scope_sha256": selection.web_scope_sha256,
            "public_recipient_ids": selection.public_recipient_ids,
            "allowed_operations": (_OPERATION,),
            "additional_metered_budget_usd": 0.0,
            "revocation_epoch": selection.revocation_epoch,
        }
        if (any(getattr(candidate, key) != value for key, value in expected.items())
                or candidate.expires_monotonic > min(proof.expires_monotonic,
                                                     candidate.issued_monotonic + _MAX_LEASE)
                or ((candidate.signature != "") if not signed else not candidate.signature)
                or not self._scope_projection_matches(selection, scopes)):
            raise AuthorityDenied("public-permission.claims", "permission candidate differs from current public input selection")

    def _validate_retained_public_observation(self, proof: Any, execution: Any,
                                              receipt: RootPublicInputPermission) -> None:
        if (proof.observation_handle != receipt.input_observation_handle
                or proof.input_sha256 != receipt.input_sha256
                or proof.retained_input_selection_handle != receipt.retained_input_selection_handle
                or proof.public_permission_selection_handle != receipt.selection_handle
                or proof.source_classification is not Sensitivity.PUBLIC):
            raise AuthorityDenied("public-permission.input", "retained public observation differs from receipt")
        if not self._valid_source_material(proof, execution, consumed=True):
            raise AuthorityDenied("public-permission.input", "retained public observation membership is stale")

    def _valid_source_material(self, proof: Any, execution: Any, *, consumed: bool) -> bool:
        resolver = (getattr(self.sources, "resolve_consumed_public_input_source_material", None)
                    if consumed else getattr(self.sources, "resolve_public_input_source_material", None))
        if not callable(resolver):
            return False
        try:
            material = resolver(proof) if consumed else resolver(proof, execution)
        except Exception:
            return False
        return bool(
            material.observation is proof
            and material.selected_execution is execution
            and len(material.payload_bytes) == proof.input_size_bytes
            and hashlib.sha256(material.payload_bytes).hexdigest() == proof.input_sha256
            and tuple(material.parent_receipt_handles) == proof.parent_source_receipt_handles
            and len(material.parent_receipts) == len(proof.parent_source_receipt_handles)
            and bool(material.parent_receipts)
            and all(receipt.sensitivity is Sensitivity.PUBLIC
                    for receipt in material.parent_receipts)
        )

    def _current_scopes(self, selection: RootPublicInputPermissionSelection) -> tuple[Any, ...]:
        resolver = getattr(self.bindings, "resolve_current_public_web_scopes", None)
        if not callable(resolver):
            raise AuthorityDenied("public-permission.scope", "active protected public web scope catalog is unavailable")
        rows = resolver(selection.web_scope_ids, principal_id=selection.principal_id,
                        profile_id=selection.profile_id,
                        profile_generation=self.service.profile_generations.get(selection.profile_id),
                        service_generation_digest=_active_digest(self.bindings))
        verify_provenance = getattr(self.bindings, "verify_current_public_web_scope_provenance", None)
        if (not isinstance(rows, tuple) or not rows
                or not callable(verify_provenance)
                or tuple(sorted(row.enrolled_scope.enrollment_id for row in rows)) != selection.web_scope_ids
                or any(getattr(row, "service_generation_digest", None) != _active_digest(self.bindings)
                       or type(getattr(row, "enrolled_scope", None)) is not EnrolledPublicWebScope
                       or getattr(row, "scope_payload_sha256", None) != _scope_payload_digest(row.enrolled_scope)
                       or any(not isinstance(getattr(row, name, None), str) or not getattr(row, name, None)
                              for name in ("target_selection_handle", "configuration_observation_handle",
                                           "configuration_sha256", "target_contract_artifact_id",
                                           "target_contract_sha256", "target_contract_source_receipt_handle"))
                       or verify_provenance(row) is not True
                       for row in rows)):
            raise AuthorityDenied("public-permission.scope", "active protected scope rows are absent or malformed")
        return rows

    def _scope_projection_matches(self, selection: RootPublicInputPermissionSelection,
                                  scopes: tuple[Any, ...]) -> bool:
        enrolled = tuple(row.enrolled_scope for row in scopes)
        if (tuple(sorted({scope.recipient for scope in enrolled})) != selection.public_recipient_ids
                or any(scope.principal_id != selection.principal_id or scope.profile_id != selection.profile_id
                       or scope.generation != self.service.profile_generations.get(selection.profile_id)
                       for scope in enrolled)):
            return False
        return _scope_digest(enrolled) == selection.web_scope_sha256

    def _validate_selection(self, selection: Any,
                            binding: PrincipalBinding) -> RootPublicInputPermissionSelection:
        if (type(selection) is not RootPublicInputPermissionSelection
                or selection._registry_seal is not _SEAL
                or selection.purpose != _PURPOSE
                or selection.principal_id != binding.principal_id
                or selection.profile_id != binding.profile_id
                or selection.namespace_id != binding.namespace_id
                or selection.web_scope_ids != tuple(sorted(set(selection.web_scope_ids)))
                or selection.public_recipient_ids != tuple(sorted(set(selection.public_recipient_ids)))
                or selection.allowed_operations != (_OPERATION,)
                or selection.additional_metered_budget_usd != 0.0
                or selection.revocation_epoch < 1
                or selection.expires_monotonic <= self.monotonic()
                or selection.expires_monotonic - selection.issued_monotonic > _MAX_LEASE):
            raise AuthorityDenied("public-permission.selection", "active public selection is stale or malformed")
        scopes = self._current_scopes(selection)
        if not self._scope_projection_matches(selection, scopes):
            raise AuthorityDenied("public-permission.scope", "current scope projection differs from the selection")
        return selection

    def _current_binding(self, binding: PrincipalBinding) -> PrincipalBinding:
        if type(binding) is not PrincipalBinding:
            raise AuthorityDenied("public-permission.profile", "exact current principal binding is required")
        resolver = getattr(self.service, "resolve_current_active_principal_binding", None)
        current = resolver(binding.profile_id) if callable(resolver) else None
        if current is not binding:
            raise AuthorityDenied("public-permission.profile", "profile binding is not current")
        return current

    def _validate_journal(self) -> None:
        self._check_journal()

    def _check_journal(self) -> None:
        resolver = getattr(self.bindings, "resolve_root_journal", None)
        if not callable(resolver) or _active_digest(self.bindings) != self.journal.service_generation_digest:
            raise AuthorityDenied("public-permission.journal", "active public permission journal is unavailable")
        current = resolver(self.journal.root_id,
                           expected_active_generation_digest=_active_digest(self.bindings))
        info = self.journal.path.stat(follow_symlinks=False)
        if (current != self.journal or not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_dev, info.st_ino) != (self.journal.device, self.journal.inode)):
            raise AuthorityDenied("public-permission.journal", "root permission journal identity changed")

    def _signer(self) -> Any:
        factory = getattr(self.service, "root_public_input_permission_signer", None)
        if not callable(factory):
            raise AuthorityDenied("public-permission.signer", "fixed-domain root permission signer is unavailable")
        return factory()

    def _persist_receipt(self, receipt: RootPublicInputPermission) -> None:
        with self._lock:
            self._rows[receipt.receipt_handle] = {
                **receipt.claims(), "signature": receipt.signature,
            }
            self._store.save(self._rows)


def _active_digest(bindings: Any) -> str | None:
    digest = getattr(bindings, "service_generation_digest", None)
    if digest is None:
        digest = getattr(getattr(bindings, "enrollment_catalog", None), "digest", None)
    if (not isinstance(digest, str) or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)):
        return None
    return digest


def _scope_digest(scopes: tuple[Any, ...]) -> str:
    rows = []
    for scope in sorted(scopes, key=lambda item: item.enrollment_id):
        rows.append({
            "enrollment_id": scope.enrollment_id,
            "target_id": scope.target_id,
            "generation": scope.generation,
            "principal_id": scope.principal_id,
            "profile_id": scope.profile_id,
            "recipient": scope.recipient,
            "targets": [{"hostname": target.hostname,
                         "path_prefixes": list(target.path_prefixes),
                         "query_keys": sorted(target.query_keys)}
                        for target in scope.targets],
            "request_bytes_limit": scope.request_bytes_limit,
            "response_bytes_limit": scope.response_bytes_limit,
            "deadline_seconds": scope.deadline_seconds,
        })
    return canonical_digest(rows)


def _scope_payload_digest(scope: EnrolledPublicWebScope) -> str:
    """v142 exact per-row payload digest; provenance is validated separately."""
    row = {
        "enrollment_id": scope.enrollment_id,
        "target_id": scope.target_id,
        "generation": scope.generation,
        "principal_id": scope.principal_id,
        "profile_id": scope.profile_id,
        "recipient": scope.recipient,
        "targets": [{"hostname": target.hostname,
                     "path_prefixes": list(target.path_prefixes),
                     "query_keys": sorted(target.query_keys)} for target in scope.targets],
        "request_bytes_limit": scope.request_bytes_limit,
        "response_bytes_limit": scope.response_bytes_limit,
        "deadline_seconds": scope.deadline_seconds,
    }
    import json
    encoded = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _same_selection_identity(current: RootPublicInputPermissionSelection,
                             original: RootPublicInputPermissionSelection) -> bool:
    """Compare durable choice identity while permitting only a fresh projection.

    Permission receipt expiry remains fixed; refreshing the active projection
    never changes or extends that receipt.
    """
    fields = (
        "selection_handle", "consent_id", "purpose", "choice_observation_id",
        "setup_session_id", "transaction_handle", "plan_sha256",
        "principal_selection_handle", "namespace_selection_handle", "principal_id",
        "profile_id", "namespace_id", "web_scope_ids", "web_scope_sha256",
        "public_recipient_ids", "allowed_operations", "additional_metered_budget_usd",
        "controller_binding_handle", "revocation_epoch",
    )
    return all(getattr(current, name) == getattr(original, name) for name in fields)
