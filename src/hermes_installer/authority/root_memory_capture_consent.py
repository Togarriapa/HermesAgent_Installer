"""Persistent root TTY opt-in for one automatic memory capture engine.

This preference is purpose-specific and profile-private. It does not create a
turn receipt, background job authority, provider grant, account permission, or
metered budget.
"""
from __future__ import annotations

import hmac
import secrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Mapping

from .root_private_input_consent import _ProtectedStore, _id, _ids
from .service import AuthorityService, PrincipalBinding
from .types import AuthorityDenied, canonical_digest

_DOMAIN = "root-memory-capture-consent-v1"
_RECORD_DOMAIN = "root-memory-capture-consent-record-v1"
_SEAL = object()
_ALLOWED_PROVIDERS = frozenset({"openviking", "claude-mem", "agentmemory"})


@dataclass(frozen=True, slots=True, repr=False)
class RootMemoryCaptureConsent:
    schema: int
    receipt_handle: str
    consent_id: str
    principal_id: str
    profile_id: str
    namespace_id: str
    memory_owner_generation: int
    service_enrollment_id: str
    service_generation: str
    provider: str
    route_ids: tuple[str, ...]
    private_recipient_ids: tuple[str, ...]
    policy_revision: str
    choice_receipt_handle: str
    source_selection_digest: str
    state: str
    issued_monotonic: float
    revocation_epoch: int
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("memory capture consent is minted by its root registry")
        if (self.schema != 1 or self.state not in {"enabled", "revoked"}
                or self.provider not in _ALLOWED_PROVIDERS
                or self.memory_owner_generation <= 0 or self.revocation_epoch <= 0):
            raise AuthorityDenied("memory.consent", "memory capture consent fields are invalid")

    def claims(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "consent_id": self.consent_id, "principal_id": self.principal_id,
            "profile_id": self.profile_id, "namespace_id": self.namespace_id,
            "memory_owner_generation": self.memory_owner_generation,
            "service_enrollment_id": self.service_enrollment_id,
            "service_generation": self.service_generation, "provider": self.provider,
            "route_ids": list(self.route_ids), "private_recipient_ids": list(self.private_recipient_ids),
            "policy_revision": self.policy_revision,
            "choice_receipt_handle": self.choice_receipt_handle,
            "source_selection_digest": self.source_selection_digest, "state": self.state,
            "issued_monotonic": self.issued_monotonic,
            "revocation_epoch": self.revocation_epoch,
        }


@dataclass(frozen=True, slots=True)
class RootMemoryCaptureConsentRevocationReceipt:
    schema: int
    receipt_handle: str
    consent_id: str
    profile_id: str
    revocation_epoch: int
    revoked_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("memory consent revocation receipts are minted by their root registry")


class RootMemoryCaptureConsentRegistry:
    """Persistent opt-in registry with current owner, engine, and policy joins."""

    def __init__(self, service: AuthorityService, root_setup_choice_registry: Any,
                 memory_enrollment_catalog: Any, root_journal: Any, *,
                 monotonic: Any = time.monotonic):
        if (not isinstance(service, AuthorityService) or root_setup_choice_registry is None
                or memory_enrollment_catalog is None or not callable(monotonic)):
            raise ValueError("authority, root TTY choice, and selected memory catalogs are required")
        self.service = service
        self.choices = root_setup_choice_registry
        self.catalog = memory_enrollment_catalog
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        self._receipts: dict[str, RootMemoryCaptureConsent] = {}
        self._store = _ProtectedStore(root_journal, "memory-capture-consent", service)
        self._load()

    @classmethod
    def from_authority_service(cls, service: AuthorityService,
                               root_setup_choice_registry: Any,
                               memory_enrollment_catalog: Any,
                               root_journal: Any) -> "RootMemoryCaptureConsentRegistry":
        existing = getattr(service, "memory_capture_consent_registry", None)
        if existing is not None:
            raise ValueError("memory capture consent registry is already attached")
        registry = cls(service, root_setup_choice_registry, memory_enrollment_catalog, root_journal)
        service.attach_memory_capture_consent_registry(registry)
        return registry

    def resolve_selected_memory_binding(self, enrollment_id: str) -> Any:
        """Return only the exact active immutable memory enrollment from root catalog."""
        _id(enrollment_id, "memory enrollment ID")
        resolver = getattr(self.catalog, "resolve_current_memory_enrollment", None)
        if not callable(resolver):
            raise AuthorityDenied("memory.binding", "current protected memory enrollment resolver is unavailable")
        selected = resolver(enrollment_id)
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment
        if (type(selected) is not MemoryServiceEnrollment
                or selected.service_enrollment_id != enrollment_id):
            raise AuthorityDenied("memory.binding", "memory enrollment is not the current protected selection")
        return selected

    def issue_selected_capture_consent(self, current_explicit_choice_receipt_handle: str,
                                       selected_memory_binding: Any) -> str:
        enrollment = self._require_current_binding(selected_memory_binding)
        resolver = getattr(self.choices, "resolve_memory_capture_choice", None)
        if not callable(resolver):
            raise AuthorityDenied("memory.consent", "root TTY memory capture choice resolver is unavailable")
        profile_selection_handle = self._current_profile_selection_handle(enrollment)
        choice = resolver(current_explicit_choice_receipt_handle, profile_selection_handle)
        if (getattr(choice, "_registry_seal", None) is not getattr(self.choices, "_registry_seal", object())
                or getattr(choice, "choice_receipt_handle", None) != current_explicit_choice_receipt_handle
                or getattr(choice, "profile_selection_handle", None) != profile_selection_handle
                or getattr(choice, "principal_id", None) != enrollment.principal_id
                or getattr(choice, "profile_id", None) != enrollment.profile_id
                or getattr(choice, "namespace_id", None) != enrollment.namespace_identity
                or getattr(choice, "memory_owner_generation", None) != enrollment.memory_owner_generation
                or getattr(choice, "service_enrollment_id", None) != enrollment.service_enrollment_id
                or getattr(choice, "service_generation", None) != enrollment.service_generation
                or getattr(choice, "provider", None) != enrollment.provider):
            raise AuthorityDenied("memory.consent", "memory TTY choice is stale or belongs to another owner/engine")
        current_choice = getattr(self.choices, "is_current_memory_capture_choice", None)
        if not callable(current_choice) or current_choice(choice) is not True:
            raise AuthorityDenied("memory.consent", "root TTY memory capture choice is no longer current")
        routes = _ids(getattr(choice, "route_ids", None), "memory route IDs")
        recipients = _ids(getattr(choice, "private_recipient_ids", None), "memory private recipient IDs")
        if not set(routes).issubset(enrollment.fixed_route_map):
            raise AuthorityDenied("memory.consent", "memory choice contains a route outside the selected engine")
        policy_revision = _id(getattr(choice, "policy_revision", None), "memory policy revision")
        if policy_revision != enrollment.background_consent_revision:
            raise AuthorityDenied("memory.consent", "TTY choice policy revision differs from selected enrollment")
        source_digest = getattr(choice, "source_selection_digest", None)
        if not isinstance(source_digest, str) or len(source_digest) != 64 or any(c not in "0123456789abcdef" for c in source_digest):
            raise AuthorityDenied("memory.consent", "memory selection policy digest is invalid")
        handle = secrets.token_urlsafe(32)
        profile = enrollment.profile_id
        with self._lock:
            prior = self._records.get(profile)
            epoch = int(prior["revocation_epoch"]) + 1 if prior else 1
            record = {
                "schema": 1, "background_consent_handle": handle,
                "consent_id": secrets.token_urlsafe(24), "principal_id": enrollment.principal_id,
                "profile_id": profile, "namespace_id": enrollment.namespace_identity,
                "memory_owner_generation": enrollment.memory_owner_generation,
                "service_enrollment_id": enrollment.service_enrollment_id,
                "service_generation": enrollment.service_generation, "provider": enrollment.provider,
                "route_ids": list(routes), "private_recipient_ids": list(recipients),
                "policy_revision": policy_revision,
                "choice_receipt_handle": current_explicit_choice_receipt_handle,
                "profile_selection_handle": profile_selection_handle,
                "source_selection_digest": source_digest, "state": "enabled",
                "issued_monotonic": self.monotonic(), "revocation_epoch": epoch,
            }
            record["signature"] = self.service._sign({"domain": _RECORD_DOMAIN, **record})
            self._records[profile] = record
            self._save()
        return handle

    def resolve_capture_consent(self, background_consent_handle: str, *,
                                completed_turn_receipt_handle: str,
                                selected_memory_binding: Any) -> RootMemoryCaptureConsent:
        enrollment = self._require_current_binding(selected_memory_binding)
        self._verify_completed_turn_receipt(completed_turn_receipt_handle, enrollment)
        with self._lock:
            row = self._records.get(enrollment.profile_id)
            if (row is None or row.get("background_consent_handle") != background_consent_handle
                    or row.get("state") != "enabled"):
                raise AuthorityDenied("memory.consent", "automatic memory capture is not explicitly enabled")
            self._verify_row(row, enrollment)
            claims = {
                "schema": 1, "receipt_handle": secrets.token_urlsafe(32),
                "consent_id": row["consent_id"], "principal_id": row["principal_id"],
                "profile_id": row["profile_id"], "namespace_id": row["namespace_id"],
                "memory_owner_generation": row["memory_owner_generation"],
                "service_enrollment_id": row["service_enrollment_id"],
                "service_generation": row["service_generation"], "provider": row["provider"],
                "route_ids": tuple(row["route_ids"]),
                "private_recipient_ids": tuple(row["private_recipient_ids"]),
                "policy_revision": row["policy_revision"],
                "choice_receipt_handle": row["choice_receipt_handle"],
                "source_selection_digest": row["source_selection_digest"], "state": "enabled",
                "issued_monotonic": self.monotonic(), "revocation_epoch": row["revocation_epoch"],
            }
            receipt = RootMemoryCaptureConsent(
                **claims, signature=self.service._sign({"domain": _DOMAIN, **claims}), _seal=_SEAL)
            self._receipts[receipt.receipt_handle] = receipt
            return receipt

    def revoke_capture_consent(self, background_consent_handle: str,
                               current_authorized_owner_request: Any
                               ) -> RootMemoryCaptureConsentRevocationReceipt:
        resolver = getattr(self.choices, "resolve_current_authorized_owner_request", None)
        if not callable(resolver):
            raise AuthorityDenied("memory.owner", "root current owner request verifier is unavailable")
        binding = resolver(current_authorized_owner_request)
        if type(binding) is not PrincipalBinding or self.service.bindings_by_uid.get(binding.uid) is not binding:
            raise AuthorityDenied("memory.owner", "revoke request is not the current selected owner")
        with self._lock:
            row = self._records.get(binding.profile_id)
            if (row is None or row.get("background_consent_handle") != background_consent_handle
                    or row.get("principal_id") != binding.principal_id
                    or row.get("namespace_id") != binding.namespace_id):
                raise AuthorityDenied("memory.owner", "owner request does not select this capture preference")
            row = dict(row)
            row["state"] = "revoked"
            row["revocation_epoch"] = int(row["revocation_epoch"]) + 1
            row["signature"] = self.service._sign({"domain": _RECORD_DOMAIN,
                                                    **{k: v for k, v in row.items() if k != "signature"}})
            self._records[binding.profile_id] = row
            self._save()
            claims = {"schema": 1, "receipt_handle": secrets.token_urlsafe(32),
                      "consent_id": row["consent_id"], "profile_id": binding.profile_id,
                      "revocation_epoch": row["revocation_epoch"], "revoked_monotonic": self.monotonic()}
            return RootMemoryCaptureConsentRevocationReceipt(
                **claims, signature=self.service._sign({"domain": "root-memory-capture-consent-revocation-v1", **claims}),
                _seal=_SEAL)

    def _current_profile_selection_handle(self, enrollment: Any) -> str:
        resolver = getattr(self.choices, "current_profile_selection_handle", None)
        if not callable(resolver):
            raise AuthorityDenied("memory.profile", "current root profile-selection resolver is unavailable")
        active_binding = getattr(self.service, "resolve_current_active_principal_binding", None)
        if not callable(active_binding):
            raise AuthorityDenied("memory.profile", "active protected principal resolver is unavailable")
        principal = active_binding(enrollment.profile_id)
        if (principal.principal_id != enrollment.principal_id
                or principal.namespace_id != enrollment.namespace_identity):
            raise AuthorityDenied("memory.profile", "memory owner differs from active principal binding")
        handle = resolver(principal)
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise AuthorityDenied("memory.profile", "current root profile-selection handle is unavailable")
        return handle

    def _require_current_binding(self, binding: Any) -> Any:
        from hermes_installer.memory.enrollment import MemoryServiceEnrollment
        if type(binding) is not MemoryServiceEnrollment:
            raise AuthorityDenied("memory.binding", "typed selected memory enrollment is required")
        current = self.resolve_selected_memory_binding(binding.service_enrollment_id)
        if current is not binding:
            raise AuthorityDenied("memory.binding", "memory binding differs from active root selection")
        return current

    def _verify_row(self, row: Mapping[str, Any], enrollment: Any) -> None:
        unsigned = {k: v for k, v in row.items() if k != "signature"}
        if not hmac.compare_digest(self.service._sign({"domain": _RECORD_DOMAIN, **unsigned}), str(row.get("signature", ""))):
            raise AuthorityDenied("memory.signature", "persistent memory consent signature is invalid")
        if (row.get("principal_id") != enrollment.principal_id
                or row.get("profile_id") != enrollment.profile_id
                or row.get("namespace_id") != enrollment.namespace_identity
                or row.get("memory_owner_generation") != enrollment.memory_owner_generation
                or row.get("service_enrollment_id") != enrollment.service_enrollment_id
                or row.get("service_generation") != enrollment.service_generation
                or row.get("provider") != enrollment.provider
                or row.get("policy_revision") != enrollment.background_consent_revision
                or self.service.profile_generations.get(enrollment.profile_id) != enrollment.service_generation):
            raise AuthorityDenied("memory.stale", "current owner, service, or profile generation changed")
        if not set(row.get("route_ids", ())).issubset(enrollment.fixed_route_map):
            raise AuthorityDenied("memory.stale", "selected memory routes changed")
        choice_resolver = getattr(self.choices, "resolve_memory_capture_choice", None)
        choice_current = getattr(self.choices, "is_current_memory_capture_choice", None)
        if not callable(choice_resolver) or not callable(choice_current):
            raise AuthorityDenied("memory.choice", "current protected memory TTY choice registry is unavailable")
        profile_selection_handle = self._current_profile_selection_handle(enrollment)
        if row.get("profile_selection_handle") != profile_selection_handle:
            raise AuthorityDenied("memory.stale", "current profile selection changed")
        choice = choice_resolver(row.get("choice_receipt_handle"), profile_selection_handle)
        if (choice_current(choice) is not True
                or getattr(choice, "source_selection_digest", None) != row.get("source_selection_digest")
                or getattr(choice, "policy_revision", None) != row.get("policy_revision")
                or tuple(getattr(choice, "route_ids", ())) != tuple(row.get("route_ids", ()))
                or tuple(getattr(choice, "private_recipient_ids", ())) != tuple(row.get("private_recipient_ids", ()))):
            raise AuthorityDenied("memory.stale", "current memory TTY choice or policy changed")

    def _verify_completed_turn_receipt(self, handle: str, enrollment: Any) -> Any:
        from .native_turn_observation import RootCompletedNativeTurn
        registry = getattr(self.service, "native_turn_observation_registry", None)
        resolver = getattr(registry, "resolve_completed_turn", None)
        if not isinstance(handle, str) or not callable(resolver):
            raise AuthorityDenied("memory.turn", "root completed-turn receipt resolver is unavailable")
        receipt = resolver(handle)
        if (type(receipt) is not RootCompletedNativeTurn
                or receipt.receipt_handle != handle
                or receipt.profile_id != enrollment.profile_id
                or receipt.expires_monotonic <= self.monotonic()
                or getattr(self.service, "service_generation_digest", None) is None
                or receipt.service_generation_digest != self.service.service_generation_digest
                or receipt.process_generation != self.service.profile_generations.get(receipt.profile_id)):
            raise AuthorityDenied("memory.turn", "completed turn receipt is not current for this profile")
        return receipt

    def _load(self) -> None:
        self._records = self._store.load()

    def _save(self) -> None:
        self._store.save(self._records)
