"""Root-held opt-in for private provider egress from retained native input.

The persistent selection is a profile preference only. Every source issuance
must resolve the exact live root input proof and gets a fresh short receipt;
dispatch-time revalidation looks up that same receipt without consuming or
extending it.
"""
from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .service import AuthorityService, PrincipalBinding
from .types import AuthorityDenied, canonical_digest

_DOMAIN = "root-private-input-consent-v1"
_SELECTION_DOMAIN = "root-private-input-consent-selection-v1"
_DIR = "private-input-consent"
_FILE = "registry.json"
_SEAL = object()
_MAX_LEASE = 30.0
_MAX_RECORD = 1_048_576


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _id(value: Any, name: str) -> str:
    if (not isinstance(value, str) or not 1 <= len(value) <= 256
            or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:@/-" for char in value)):
        raise AuthorityDenied("consent.invalid", f"{name} is malformed")
    return value


def _ids(value: Any, name: str, *, maximum: int = 1024) -> tuple[str, ...]:
    if not isinstance(value, (tuple, list)) or not 1 <= len(value) <= maximum:
        raise AuthorityDenied("consent.invalid", f"{name} must be a nonempty finite selection")
    result = tuple(_id(item, name) for item in value)
    if tuple(sorted(set(result))) != result:
        raise AuthorityDenied("consent.invalid", f"{name} must be sorted and unique")
    if any(item.lower() in {"public", "*", "all", "wildcard"} for item in result):
        raise AuthorityDenied("consent.invalid", f"{name} contains a public or wildcard recipient")
    return result


def _read_json(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, json.JSONDecodeError):
        raise AuthorityDenied("consent.store", "protected consent registry is corrupt") from None
    if not isinstance(value, dict) or _canonical(value) != data:
        raise AuthorityDenied("consent.store", "protected consent registry is not canonical")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True, repr=False)
class RootPrivateInputConsent:
    schema: int
    receipt_handle: str
    consent_id: str
    purpose: str
    selection_handle: str
    principal_id: str
    profile_id: str
    namespace_id: str
    profile_generation: str
    service_generation_digest: str
    input_selection_digest: str
    input_observation_handle: str
    retained_input_selection_handle: str
    provider_route_ids: tuple[str, ...]
    private_recipient_ids: tuple[str, ...]
    additional_metered_budget_usd: float
    policy_revision: str
    policy_selection_sha256: str
    revocation_epoch: int
    issued_monotonic: float
    expires_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("private input consent is minted by its root registry")
        if (self.schema != 1 or self.purpose != "private-provider-egress"
                or self.additional_metered_budget_usd != 0.0
                or self.revocation_epoch <= 0
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > _MAX_LEASE):
            raise AuthorityDenied("consent.invalid", "private input consent fields are invalid")

    def claims(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "receipt_handle": self.receipt_handle,
            "consent_id": self.consent_id, "purpose": self.purpose,
            "selection_handle": self.selection_handle, "principal_id": self.principal_id,
            "profile_id": self.profile_id, "namespace_id": self.namespace_id,
            "profile_generation": self.profile_generation,
            "service_generation_digest": self.service_generation_digest,
            "input_selection_digest": self.input_selection_digest,
            "input_observation_handle": self.input_observation_handle,
            "retained_input_selection_handle": self.retained_input_selection_handle,
            "provider_route_ids": list(self.provider_route_ids),
            "private_recipient_ids": list(self.private_recipient_ids),
            "additional_metered_budget_usd": self.additional_metered_budget_usd,
            "policy_revision": self.policy_revision,
            "policy_selection_sha256": self.policy_selection_sha256,
            "revocation_epoch": self.revocation_epoch,
            "issued_monotonic": self.issued_monotonic,
            "expires_monotonic": self.expires_monotonic,
        }


@dataclass(frozen=True, slots=True)
class RootPrivateInputConsentRevocationReceipt:
    schema: int
    selection_handle: str
    consent_id: str
    revocation_epoch: int
    revoked_monotonic: float
    signature: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL:
            raise TypeError("private input revocation receipts are minted by their root registry")


class RootPrivateInputConsentRegistry:
    """Durable private-route opt-in and per-input short receipt issuer."""

    def __init__(self, service: AuthorityService, root_setup_choice_registry: Any,
                 selected_provider_catalog: Any, root_journal: Any, *,
                 monotonic: Any = time.monotonic):
        if not isinstance(service, AuthorityService) or not callable(monotonic):
            raise ValueError("root authority service and monotonic clock are required")
        if root_setup_choice_registry is None or selected_provider_catalog is None:
            raise ValueError("root TTY choice registry and selected provider catalog are required")
        self.service = service
        self.choices = root_setup_choice_registry
        self.provider_catalog = selected_provider_catalog
        self.monotonic = monotonic
        self._lock = threading.RLock()
        self._records: dict[str, dict[str, Any]] = {}
        self._receipts: dict[str, tuple[RootPrivateInputConsent, Any, Any]] = {}
        self._store = _ProtectedStore(root_journal, _DIR, service)
        self._load()

    @classmethod
    def from_authority_service(cls, service: AuthorityService,
                               root_setup_choice_registry: Any,
                               selected_provider_catalog: Any,
                               root_journal: Any) -> "RootPrivateInputConsentRegistry":
        existing = getattr(service, "private_input_consent_registry", None)
        if existing is not None:
            raise ValueError("private input consent registry is already attached")
        registry = cls(service, root_setup_choice_registry, selected_provider_catalog, root_journal)
        service.attach_private_input_consent_registry(registry)
        return registry

    def issue_selected_private_input_consent(self, current_explicit_choice_receipt_handle: str,
                                             selected_private_profile_binding: PrincipalBinding) -> str:
        """Persist the current actual root TTY choice as a private profile preference."""
        binding = self._current_binding(selected_private_profile_binding)
        resolver = getattr(self.choices, "resolve_private_provider_routes_choice", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.choice", "root TTY private-route choice resolver is unavailable")
        profile_selection_handle = self._current_profile_selection_handle(binding)
        choice = resolver(current_explicit_choice_receipt_handle, profile_selection_handle)
        if (getattr(choice, "_registry_seal", None) is not getattr(self.choices, "_registry_seal", object())
                or getattr(choice, "choice_receipt_handle", None) != current_explicit_choice_receipt_handle
                or getattr(choice, "profile_id", None) != binding.profile_id
                or getattr(choice, "principal_id", None) != binding.principal_id
                or getattr(choice, "namespace_id", None) != binding.namespace_id
                or getattr(choice, "profile_generation", None) != self.service.profile_generations.get(binding.profile_id, "unversioned")):
            raise AuthorityDenied("consent.choice", "TTY choice is forged, stale, or belongs to another profile")
        routes = _ids(getattr(choice, "provider_route_ids", None), "provider route IDs")
        recipients = _ids(getattr(choice, "private_recipient_ids", None), "private recipient IDs")
        if getattr(choice, "additional_metered_budget_usd", None) != 0:
            raise AuthorityDenied("consent.budget", "private consent cannot increase metered budget")
        policy_revision = _id(getattr(choice, "policy_revision", None), "policy revision")
        policy_hash = getattr(choice, "policy_selection_sha256", None)
        if not isinstance(policy_hash, str) or len(policy_hash) != 64 or any(c not in "0123456789abcdef" for c in policy_hash):
            raise AuthorityDenied("consent.policy", "current root policy selection digest is invalid")
        route_rows = self._route_rows()
        for route_id in routes:
            route = route_rows.get(route_id)
            if (route is None or getattr(route, "recipient", None) not in recipients
                    or getattr(route, "allowed_sensitivities", frozenset()) & {"public"}):
                raise AuthorityDenied("consent.route", "TTY choice contains an unselected or public provider route")
        handle = secrets.token_urlsafe(32)
        record = {
            "schema": 1, "selection_handle": handle,
            "consent_id": secrets.token_urlsafe(24), "purpose": "private-provider-egress",
            "principal_id": binding.principal_id, "profile_id": binding.profile_id,
            "namespace_id": binding.namespace_id,
            "profile_generation": self.service.profile_generations.get(binding.profile_id, "unversioned"),
            "provider_route_ids": list(routes), "private_recipient_ids": list(recipients),
            "additional_metered_budget_usd": 0,
            "policy_revision": policy_revision, "policy_selection_sha256": policy_hash,
            "choice_receipt_handle": current_explicit_choice_receipt_handle,
            "profile_selection_handle": profile_selection_handle,
            "state": "enabled", "revocation_epoch": 1,
        }
        record["signature"] = self.service._sign({"domain": _SELECTION_DOMAIN, **record})
        with self._lock:
            previous = self._records.get(binding.profile_id)
            if previous is not None:
                record["revocation_epoch"] = int(previous["revocation_epoch"]) + 1
                record["signature"] = self.service._sign({"domain": _SELECTION_DOMAIN,
                                                            **{k: v for k, v in record.items() if k != "signature"}})
            self._records[binding.profile_id] = record
            self._save()
        return handle

    def selection_handle_for_current_profile(self, binding: PrincipalBinding) -> str | None:
        current = self._current_binding(binding)
        with self._lock:
            row = self._records.get(current.profile_id)
            if row is None or row.get("state") != "enabled":
                return None
            self._verify_selection(row, current)
            return str(row["selection_handle"])

    def resolve_for_selected_input(self, private_consent_selection_handle: str, *,
                                   observed_input_proof: Any,
                                   selected_input_binding: Any) -> RootPrivateInputConsent:
        """Resolve actual retained input proof and current selection without fabricating proof."""
        proof, selection, input_handle, route_ids, selection_registry = self._resolve_actual_input(
            observed_input_proof, selected_input_binding)
        with self._lock:
            row = self._records.get(selection.profile_id)
            if (row is None or row.get("state") != "enabled"
                    or row.get("selection_handle") != private_consent_selection_handle):
                raise AuthorityDenied("consent.missing", "no current private egress preference exists")
            self._verify_selection(row, self._current_binding_for_selection(selection))
            if not set(route_ids).intersection(row["provider_route_ids"]):
                raise AuthorityDenied("consent.route", "selected input has no currently consented private provider route")
            route_set = tuple(sorted(set(route_ids).intersection(row["provider_route_ids"])))
            routes = self._route_rows()
            recipients = tuple(sorted({routes[route].recipient for route in route_set
                                       if route in routes and routes[route].recipient in row["private_recipient_ids"]}))
            if not recipients:
                raise AuthorityDenied("consent.route", "selected input has no current private recipient intersection")
            parent_recipients = self._parent_recipient_ceiling(proof)
            if parent_recipients is not None:
                recipients = tuple(item for item in recipients if item in parent_recipients)
                if not recipients:
                    raise AuthorityDenied("consent.ancestry", "parent recipient ceiling is empty")
            return self._mint(row, selection, selection_registry, input_handle, proof, route_set, recipients)

    def revalidate_retained_input_consent(self, consent_receipt_handle: str, *,
                                           retained_input_selection_handle: str,
                                           expected_consent_id: str,
                                           expected_revocation_epoch: int) -> RootPrivateInputConsent:
        """Non-consuming currentness check; returns the exact original short receipt."""
        with self._lock:
            retained = self._receipts.get(consent_receipt_handle)
            if retained is None:
                raise AuthorityDenied("consent.stale", "retained private consent receipt is unknown")
            receipt, selected_execution, selection_registry = retained
            now = self.monotonic()
            if (receipt.receipt_handle != consent_receipt_handle
                    or receipt.consent_id != expected_consent_id
                    or receipt.revocation_epoch != expected_revocation_epoch
                    or getattr(selected_execution, "selection_handle", None) != retained_input_selection_handle
                    or now >= receipt.expires_monotonic):
                raise AuthorityDenied("consent.stale", "retained private consent is mismatched or expired")
            current = self._records.get(receipt.profile_id)
            if current is None or current.get("state") != "enabled":
                raise AuthorityDenied("consent.revoked", "private input consent is currently revoked")
            binding = self.service.bindings_by_uid.get(int(selected_execution.peer_uid)) if hasattr(selected_execution, "peer_uid") else None
            if binding is None:
                binding = self._binding_for_retained(selected_execution)
            self._verify_selection(current, self._current_binding(binding))
            if (current["consent_id"] != receipt.consent_id
                    or int(current["revocation_epoch"]) != expected_revocation_epoch
                    or current["policy_revision"] != receipt.policy_revision
                    or self.service.profile_generations.get(receipt.profile_id, "unversioned") != receipt.profile_generation):
                raise AuthorityDenied("consent.stale", "private consent selection or profile epoch changed")
            self._verify_signature(receipt.claims(), receipt.signature)
            resolver = getattr(selection_registry, "resolve_current_selected_execution", None)
            if (not callable(resolver)
                    or getattr(selected_execution, "selection_handle", None) != retained_input_selection_handle
                    or resolver(retained_input_selection_handle) is not selected_execution):
                raise AuthorityDenied("consent.input", "retained native input selection is no longer current")
            return receipt

    def revoke_selected_private_input_consent(self, selection_handle: str,
                                              current_authorized_owner_request: Any
                                              ) -> RootPrivateInputConsentRevocationReceipt:
        authorized = self._resolve_owner_request(current_authorized_owner_request)
        with self._lock:
            row = self._records.get(authorized.profile_id)
            if (row is None or row.get("selection_handle") != selection_handle
                    or row.get("principal_id") != authorized.principal_id
                    or row.get("namespace_id") != authorized.namespace_id):
                raise AuthorityDenied("consent.owner", "current owner request does not select this consent")
            row = dict(row)
            row["state"] = "revoked"
            row["revocation_epoch"] = int(row["revocation_epoch"]) + 1
            row["signature"] = self.service._sign({"domain": _SELECTION_DOMAIN,
                                                    **{k: v for k, v in row.items() if k != "signature"}})
            self._records[authorized.profile_id] = row
            self._save()
            claims = {"schema": 1, "selection_handle": selection_handle,
                      "consent_id": row["consent_id"], "revocation_epoch": row["revocation_epoch"],
                      "revoked_monotonic": self.monotonic()}
            return RootPrivateInputConsentRevocationReceipt(
                **claims, signature=self.service._sign({"domain": "root-private-input-consent-revocation-v1", **claims}),
                _seal=_SEAL)

    def _mint(self, row: Mapping[str, Any], selection: Any, selection_registry: Any,
              input_handle: str, proof: Any, route_ids: tuple[str, ...],
              recipients: tuple[str, ...]) -> RootPrivateInputConsent:
        now = self.monotonic()
        expires = min(now + _MAX_LEASE, float(getattr(proof, "expires_monotonic")),
                      float(getattr(selection, "expires_monotonic")))
        if expires <= now:
            raise AuthorityDenied("consent.expired", "selected input or execution lease has expired")
        handle = secrets.token_urlsafe(32)
        service_digest = getattr(selection, "service_generation_digest", None) or getattr(
            self.service, "service_generation_digest", None)
        if not isinstance(service_digest, str) or len(service_digest) != 64:
            raise AuthorityDenied("consent.generation", "current service generation digest is unavailable")
        input_digest = canonical_digest({
            "selection_handle": input_handle,
            "input_proof_nonce": getattr(proof, "proof_nonce", ""),
            "payload_sha256": getattr(proof, "payload_sha256", ""),
            "profile_id": getattr(selection, "profile_id", ""),
            "generation": getattr(selection, "generation", ""),
            "route_ids": list(route_ids),
            "source_action_id": getattr(selection, "source_action_id", ""),
            "native_package_id": getattr(selection, "native_package_id", ""),
            "native_package_generation": getattr(selection, "native_package_generation", ""),
            "parent_receipt_handles": list(getattr(proof, "parent_receipt_handles", ())),
            "parent_receipt_digests": [canonical_digest(item.to_wire()) for item in getattr(proof, "parent_receipts", ())],
        })
        claims = {
            "schema": 1, "receipt_handle": handle, "consent_id": row["consent_id"],
            "purpose": "private-provider-egress", "selection_handle": row["selection_handle"],
            "principal_id": row["principal_id"], "profile_id": row["profile_id"],
            "namespace_id": row["namespace_id"], "profile_generation": row["profile_generation"],
            "service_generation_digest": service_digest, "input_selection_digest": input_digest,
            "input_observation_handle": getattr(proof, "proof_nonce", input_handle), "provider_route_ids": route_ids,
            "retained_input_selection_handle": input_handle,
            "private_recipient_ids": recipients, "additional_metered_budget_usd": 0.0,
            "policy_revision": row["policy_revision"],
            "policy_selection_sha256": row["policy_selection_sha256"],
            "revocation_epoch": row["revocation_epoch"], "issued_monotonic": now,
            "expires_monotonic": expires,
        }
        signature = self.service._sign({"domain": _DOMAIN, **claims})
        receipt = RootPrivateInputConsent(**claims, signature=signature, _seal=_SEAL)
        self._receipts[handle] = (receipt, selection, selection_registry)
        return receipt

    def _resolve_actual_input(self, proof: Any, selected_input_binding: Any) -> tuple[Any, Any, str, tuple[str, ...]]:
        from .source_observers import VerifiedSourceObservation
        from .source_observers import RootSelectedNativeExecution
        if type(proof) is not VerifiedSourceObservation or type(selected_input_binding) is not RootSelectedNativeExecution:
            raise AuthorityDenied("consent.input", "actual retained root input proof and selection are required")
        if (proof.selected_execution is not selected_input_binding
                or proof.private_consent_selection_handle is None
                or not hasattr(proof, "proof_nonce")):
            raise AuthorityDenied("consent.input", "input proof is not bound to a selected private input")
        registry = getattr(self.service, "source_observer_registry", None)
        if registry is None or not callable(getattr(registry, "verify_current_selected_input_proof", None)):
            raise AuthorityDenied("consent.input", "root selected input proof registry is unavailable")
        if not registry.verify_current_selected_input_proof(proof, selected_input_binding):
            raise AuthorityDenied("consent.input", "selected input proof is forged, consumed, or stale")
        selection_registry_resolver = getattr(registry, "resolve_selected_input_execution_registry", None)
        if not callable(selection_registry_resolver):
            raise AuthorityDenied("consent.input", "selected input execution registry resolver is unavailable")
        selection_registry = selection_registry_resolver(proof, selected_input_binding)
        if not callable(getattr(selection_registry, "resolve_current_selected_execution", None)):
            raise AuthorityDenied("consent.input", "selected input registry lacks current selection resolution")
        if selected_input_binding.private_consent_selection_handle != proof.private_consent_selection_handle:
            raise AuthorityDenied("consent.input", "selected input consent handle differs from root proof")
        if getattr(proof, "profile_id", None) != selected_input_binding.profile_id:
            raise AuthorityDenied("consent.input", "input and selected profile differ")
        routes = tuple(sorted(set(getattr(proof, "private_provider_route_ids", ()))))
        if not routes:
            raise AuthorityDenied("consent.route", "selected input has no private provider routes")
        return proof, selected_input_binding, selected_input_binding.selection_handle, routes, selection_registry

    def _current_binding(self, binding: Any) -> PrincipalBinding:
        if type(binding) is not PrincipalBinding:
            raise AuthorityDenied("consent.profile", "root selected principal binding is required")
        resolve = getattr(self.service, "resolve_current_active_principal_binding", None)
        current = resolve(binding.profile_id) if callable(resolve) else None
        if current is not binding or current.uid != binding.uid:
            raise AuthorityDenied("consent.profile", "selected principal binding is not current")
        return current

    def _current_binding_for_selection(self, selection: Any) -> PrincipalBinding:
        profile_id = getattr(selection, "profile_id", None)
        resolve = getattr(self.service, "resolve_current_active_principal_binding", None)
        if not callable(resolve):
            raise AuthorityDenied("consent.profile", "selected input profile has no unique current principal")
        return resolve(profile_id)

    def _binding_for_retained(self, selection: Any) -> PrincipalBinding:
        return self._current_binding_for_selection(selection)

    def _current_profile_selection_handle(self, binding: PrincipalBinding) -> str:
        resolver = getattr(self.choices, "current_profile_selection_handle", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.profile", "current root profile-selection resolver is unavailable")
        handle = resolver(binding)
        if not isinstance(handle, str) or not 32 <= len(handle) <= 128:
            raise AuthorityDenied("consent.profile", "current root profile-selection handle is unavailable")
        return handle

    def _route_rows(self) -> Mapping[str, Any]:
        routes = getattr(self.provider_catalog, "provider_enrollments_by_id", None)
        if not isinstance(routes, Mapping):
            raise AuthorityDenied("consent.route", "selected provider catalog is unavailable")
        return routes

    @staticmethod
    def _parent_recipient_ceiling(proof: Any) -> frozenset[str] | None:
        context = getattr(proof, "parent_context", None)
        receipts = getattr(proof, "parent_receipts", ())
        if context is None:
            return None
        if not receipts:
            return None
        ceilings = [getattr(item, "recipient_ceiling", frozenset()) for item in receipts]
        if not ceilings:
            return frozenset()
        return frozenset.intersection(*(frozenset(item) for item in ceilings))

    def _verify_selection(self, row: Mapping[str, Any], binding: PrincipalBinding) -> None:
        claims = {k: v for k, v in row.items() if k != "signature"}
        self._verify_signature({"domain": _SELECTION_DOMAIN, **claims}, str(row.get("signature", "")))
        if (row.get("principal_id") != binding.principal_id
                or row.get("profile_id") != binding.profile_id
                or row.get("namespace_id") != binding.namespace_id
                or row.get("profile_generation") != self.service.profile_generations.get(binding.profile_id, "unversioned")
                or row.get("additional_metered_budget_usd") != 0
                or row.get("purpose") != "private-provider-egress"):
            raise AuthorityDenied("consent.stale", "persisted private consent no longer matches profile policy")
        choice_resolver = getattr(self.choices, "resolve_private_provider_routes_choice", None)
        choice_current = getattr(self.choices, "is_current_private_provider_choice", None)
        if not callable(choice_resolver) or not callable(choice_current):
            raise AuthorityDenied("consent.choice", "current protected TTY choice registry is unavailable")
        profile_selection_handle = self._current_profile_selection_handle(binding)
        if row.get("profile_selection_handle") != profile_selection_handle:
            raise AuthorityDenied("consent.stale", "current profile selection changed")
        choice = choice_resolver(row.get("choice_receipt_handle"), profile_selection_handle)
        if (choice_current(choice) is not True
                or getattr(choice, "policy_revision", None) != row.get("policy_revision")
                or getattr(choice, "policy_selection_sha256", None) != row.get("policy_selection_sha256")
                or tuple(getattr(choice, "provider_route_ids", ())) != tuple(row.get("provider_route_ids", ()))
                or tuple(getattr(choice, "private_recipient_ids", ())) != tuple(row.get("private_recipient_ids", ()))):
            raise AuthorityDenied("consent.stale", "current root TTY private-route selection or policy changed")
        for route_id in row.get("provider_route_ids", ()):
            route = self._route_rows().get(route_id)
            if route is None or getattr(route, "recipient", None) not in row.get("private_recipient_ids", ()):
                raise AuthorityDenied("consent.stale", "private provider route enrollment changed")

    def _verify_signature(self, claims: Mapping[str, Any], signature: str) -> None:
        unsigned = dict(claims)
        unsigned.pop("key_id", None)
        if not hmac.compare_digest(self.service._sign(unsigned), signature):
            raise AuthorityDenied("consent.signature", "private consent signature is invalid")

    def _resolve_owner_request(self, request: Any) -> PrincipalBinding:
        resolver = getattr(self.choices, "resolve_current_authorized_owner_request", None)
        if not callable(resolver):
            raise AuthorityDenied("consent.owner", "root current owner-request verifier is unavailable")
        result = resolver(request)
        return self._current_binding(result)

    def _load(self) -> None:
        self._records = self._store.load()

    def _save(self) -> None:
        self._store.save(self._records)


class _ProtectedStore:
    """Atomic no-follow root-journal file store used by the registry."""

    def __init__(self, root_journal: Any, directory_name: str, service: AuthorityService):
        root = getattr(root_journal, "path", root_journal)
        if not isinstance(root, Path):
            raise ValueError("selected root journal path is required")
        self.root = root
        self.root_selection = root_journal
        self.directory_name = directory_name
        self.path = root / directory_name
        self.file = self.path / _FILE
        self.uid = 0 if os.geteuid() == 0 else os.geteuid()
        self._root_identity: tuple[int, int] | None = None
        self._validate_root()
        self.service = service

    def _validate_root(self) -> None:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            fd = os.open(self.root, flags)
        except OSError:
            raise ValueError("selected protected root journal is unavailable") from None
        try:
            root_stat = os.fstat(fd)
            if not stat.S_ISDIR(root_stat.st_mode) or root_stat.st_uid != self.uid or stat.S_IMODE(root_stat.st_mode) & 0o077:
                raise ValueError("selected root journal is not private and correctly owned")
            selected_device = getattr(self.root_selection, "device", root_stat.st_dev)
            selected_inode = getattr(self.root_selection, "inode", root_stat.st_ino)
            if (selected_device, selected_inode) != (root_stat.st_dev, root_stat.st_ino):
                raise ValueError("selected root journal identity changed")
            self._root_identity = (root_stat.st_dev, root_stat.st_ino)
            try:
                os.mkdir(self.directory_name, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            dir_fd = os.open(self.directory_name, flags, dir_fd=fd)
            try:
                info = os.fstat(dir_fd)
                if (info.st_uid != self.uid or stat.S_IMODE(info.st_mode) != 0o700
                        or (root_stat.st_dev != info.st_dev)):
                    raise ValueError("private consent directory is not protected")
            finally:
                os.close(dir_fd)
        finally:
            os.close(fd)


    def _open_store_directory(self) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            root_fd = os.open(self.root, flags)
            root_info = os.fstat(root_fd)
            if (self._root_identity != (root_info.st_dev, root_info.st_ino)
                    or root_info.st_uid != self.uid):
                raise AuthorityDenied("consent.store", "selected root journal identity changed")
            directory_fd = os.open(self.directory_name, flags, dir_fd=root_fd)
            info = os.fstat(directory_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o700
                    or info.st_dev != root_info.st_dev):
                os.close(directory_fd)
                raise AuthorityDenied("consent.store", "private consent directory is no longer protected")
            return directory_fd
        except OSError:
            raise AuthorityDenied("consent.store", "protected consent directory cannot be opened safely") from None
        finally:
            if "root_fd" in locals():
                os.close(root_fd)

    def load(self) -> dict[str, dict[str, Any]]:
        directory_fd = self._open_store_directory()
        try:
            try:
                fd = os.open(_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=directory_fd)
            except FileNotFoundError:
                return {}
            except OSError:
                raise AuthorityDenied("consent.store", "private consent registry cannot be opened safely") from None
        finally:
            os.close(directory_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != self.uid
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > _MAX_RECORD):
                raise AuthorityDenied("consent.store", "private consent registry ownership or mode is invalid")
            chunks: list[bytes] = []
            while True:
                block = os.read(fd, 65536)
                if not block:
                    break
                chunks.append(block)
            raw = b"".join(chunks)
            if not raw:
                return {}
            result = _read_json(raw)
            return result.get("profiles", {})
        finally:
            os.close(fd)

    def save(self, profiles: Mapping[str, Any]) -> None:
        data = _canonical({"schema": 1, "profiles": profiles})
        if len(data) > _MAX_RECORD:
            raise AuthorityDenied("consent.store", "private consent registry has reached its bound")
        directory_fd = self._open_store_directory()
        try:
            fd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
                         dir_fd=directory_fd)
            try:
                os.fchmod(fd, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                temp = ".registry-" + secrets.token_hex(16)
                out = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                              0o600, dir_fd=directory_fd)
                try:
                    os.fchmod(out, 0o600)
                    offset = 0
                    while offset < len(data):
                        offset += os.write(out, data[offset:])
                    os.fsync(out)
                finally:
                    os.close(out)
                os.rename(temp, _FILE, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)
