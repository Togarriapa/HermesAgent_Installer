"""Durable root-signed source choices from the normal setup TTY.

These signed rows preserve installer intent only. Runtime grants, memory
capture consent and public-input permissions are still minted by their own
active registries after the publisher adopts the choice.
"""
from __future__ import annotations

import hashlib
import fcntl
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Mapping

from .root_private_input_consent import _ProtectedStore
from .types import AuthorityDenied

_SEAL = object()
_DOMAIN_PURPOSES = frozenset({
    "memory-service-enablement", "memory-capture-configuration", "private-input-routes",
    "public-free-web-read", "existing-model-selection", "native-policy-preparation",
    "application-qualification",
})
_RECORD_FIELDS = frozenset({
    "schema", "selection_handle", "purpose", "key_id", "release_deployment_receipt_sha256",
    "setup_session_handle", "transaction_handle", "plan_id", "prepared_generation",
    "principal_selection_handle", "namespace_selection_handle",
    "private_profile_selection_handle", "source_member_receipt_handles",
    "choice_payload", "choice_payload_sha256", "choice_epoch", "revocation_epoch",
    "issued_at_unix", "setup_deadline_unix", "adoption_publication_receipt_handle",
    "signature",
})


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupChoiceSnapshot:
    """Current signed setup preference, with no effect authority."""

    selection_handle: str
    purpose: str
    key_id: str
    setup_session_handle: str
    transaction_handle: str
    plan_id: str
    prepared_generation: str
    principal_selection_handle: str
    namespace_selection_handle: str
    private_profile_selection_handle: str | None
    source_member_receipt_handles: tuple[str, ...]
    choice_payload: Mapping[str, Any] = field(repr=False)
    choice_payload_sha256: str
    signed_record_sha256: str
    release_deployment_receipt_sha256: str
    choice_epoch: int
    revocation_epoch: int
    issued_at_unix: float
    setup_deadline_unix: float
    adoption_publication_receipt_handle: str | None
    _registry_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._registry_seal is not _SEAL:
            raise TypeError("setup choice snapshots are issued by the root choice registry")
        object.__setattr__(self, "source_member_receipt_handles", tuple(self.source_member_receipt_handles))
        object.__setattr__(self, "choice_payload", MappingProxyType(dict(self.choice_payload)))

    def __repr__(self) -> str:
        return "RootSetupChoiceSnapshot(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootAdoptedSetupChoiceSelection:
    """Short current projection of a durable choice already adopted by policy.

    This carries configuration intent only. It is not a source, effect, or
    permission receipt; callers must mint their own bounded purpose receipt.
    """

    selection_handle: str
    purpose: str
    consent_id: str | None
    setup_session_handle: str
    transaction_handle: str
    plan_id: str
    prepared_generation: str
    principal_selection_handle: str
    namespace_selection_handle: str
    private_profile_selection_handle: str | None
    setup_deadline_unix: float
    signed_record_sha256: str
    source_choice_row_sha256: str
    choice_epoch: int
    revocation_epoch: int
    key_id: str
    release_deployment_receipt_sha256: str
    active_publication_receipt_handle: str
    service_generation_digest: str
    choice_payload_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    choice_payload: Mapping[str, Any] = field(repr=False)
    _registry_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._registry_seal is not _SEAL:
            raise TypeError("adopted setup choices are issued by the root choice registry")
        object.__setattr__(self, "choice_payload", MappingProxyType(dict(self.choice_payload)))

    def __repr__(self) -> str:
        return "RootAdoptedSetupChoiceSelection(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootAdoptedMemoryServiceEnablementChoice:
    """Current source proof for the separately adopted memory start choice.

    This is a fresh configuration snapshot, not a process-start grant. It is
    purpose-specific so lifecycle consumers cannot reinterpret a generic
    setup-choice payload as consent for capture, egress, or spending.
    """

    selection_handle: str
    choice_handle: str
    choice_observation_id: str
    principal_id: str
    profile_id: str
    namespace_id: str
    provider: str
    backend_variant: str
    enabled: bool
    principal_selection_handle: str
    namespace_selection_handle: str
    private_profile_selection_handle: str
    controller_binding_handle: str
    policy_revision: str
    source_selection_digest: str
    source_choice_row_sha256: str
    choice_payload_sha256: str
    choice_epoch: int
    revocation_epoch: int
    key_id: str
    release_deployment_receipt_sha256: str
    active_publication_receipt_handle: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float
    _registry_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._registry_seal is not _SEAL:
            raise TypeError("adopted memory enablement choices are issued by the root choice registry")
        required_text = (
            self.selection_handle, self.choice_handle, self.choice_observation_id,
            self.principal_id, self.profile_id, self.namespace_id, self.provider,
            self.backend_variant, self.principal_selection_handle,
            self.namespace_selection_handle, self.private_profile_selection_handle,
            self.controller_binding_handle, self.policy_revision,
            self.source_selection_digest, self.source_choice_row_sha256,
            self.choice_payload_sha256, self.key_id,
            self.release_deployment_receipt_sha256,
            self.active_publication_receipt_handle, self.service_generation_digest,
        )
        digests = (self.source_selection_digest, self.source_choice_row_sha256,
                   self.choice_payload_sha256, self.release_deployment_receipt_sha256,
                   self.service_generation_digest)
        if (any(type(value) is not str or not value for value in required_text)
                or any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in digests)
                or self.enabled is not True
                or type(self.choice_epoch) is not int or self.choice_epoch < 1
                or type(self.revocation_epoch) is not int or self.revocation_epoch < 1
                or type(self.issued_monotonic) not in (int, float)
                or type(self.expires_monotonic) not in (int, float)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or not self.issued_monotonic < self.expires_monotonic
                or self.expires_monotonic - self.issued_monotonic > 30.0):
            raise ValueError("adopted memory enablement choice is invalid or expired")

    def __repr__(self) -> str:
        return "RootAdoptedMemoryServiceEnablementChoice(<root-private>)"


@dataclass(frozen=True, slots=True, repr=False)
class RootSetupChoiceRevocationReceipt:
    """Durable signed transition that revokes one adopted setup preference."""

    schema: int
    revocation_receipt_handle: str
    selection_handle: str
    purpose: str
    consent_id: str | None
    previous_choice_epoch: int
    previous_revocation_epoch: int
    revocation_epoch: int
    source_choice_row_sha256: str
    revocation_observation_handle: str
    displayed_payload_sha256: str
    key_id: str
    release_deployment_receipt_sha256: str
    service_generation_digest: str
    revoked_at_unix: float
    signature: str
    _registry_seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._registry_seal is not _SEAL:
            raise TypeError("choice revocation receipts are issued by the root choice registry")

    def claims(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "revocation_receipt_handle": self.revocation_receipt_handle,
            "selection_handle": self.selection_handle,
            "purpose": self.purpose,
            "consent_id": self.consent_id,
            "previous_choice_epoch": self.previous_choice_epoch,
            "previous_revocation_epoch": self.previous_revocation_epoch,
            "revocation_epoch": self.revocation_epoch,
            "source_choice_row_sha256": self.source_choice_row_sha256,
            "revocation_observation_handle": self.revocation_observation_handle,
            "displayed_payload_sha256": self.displayed_payload_sha256,
            "key_id": self.key_id,
            "release_deployment_receipt_sha256": self.release_deployment_receipt_sha256,
            "service_generation_digest": self.service_generation_digest,
            "revoked_at_unix": self.revoked_at_unix,
        }

    def __repr__(self) -> str:
        return "RootSetupChoiceRevocationReceipt(<root-private>)"


class RootSetupChoiceRegistry:
    """Persist exact root TTY choices using the already selected authority key."""

    def __init__(self, verified_installer_release: Any, current_actor_verifier: Any,
                 root_setup_session_store: Any, root_journal: Any,
                 selected_choice_signer: Any, *, authority_service: Any = None,
                 current_active_publication: Any = None,
                 foreground_tty_observer: Any = None):
        if os.geteuid() != 0:
            raise AuthorityDenied("setup-choice.root", "durable setup choices require the installed root process")
        from .installer_release import VerifiedInstallerReleaseReceipt
        from ..protected_enrollment import RootJournalSelection
        self._runtime_only = authority_service is not None
        if self._runtime_only:
            from .service import AuthorityService
            from .setup_policy_publication import RootSetupPublicationReceipt
            if (type(authority_service) is not AuthorityService
                    or type(current_active_publication) is not RootSetupPublicationReceipt
                    or not callable(getattr(authority_service, "root_setup_choice_signer", None))):
                raise AuthorityDenied("setup-choice.runtime", "runtime choice resolver requires the exact active service and publisher receipt")
            selected_choice_signer = authority_service.root_setup_choice_signer()
            current_actor_verifier = None
            root_setup_session_store = None
        else:
            current_active_publication = None
        if (type(verified_installer_release) is not VerifiedInstallerReleaseReceipt
                or not callable(getattr(verified_installer_release, "verify_current", None))
                or (not self._runtime_only and not callable(getattr(current_actor_verifier, "verify_current", None)))
                or (not self._runtime_only and not callable(getattr(root_setup_session_store, "_handle_for_session", None)))
                or type(root_journal) is not RootJournalSelection
                or not callable(getattr(selected_choice_signer, "sign_choice", None))
                or not callable(getattr(selected_choice_signer, "verify_choice", None))
                or not isinstance(getattr(selected_choice_signer, "key_id", None), str)
                or not selected_choice_signer.key_id):
            raise AuthorityDenied("setup-choice.binding", "held release, session, journal, actor and selected signer are required")
        self.release = verified_installer_release
        self.actor_verifier = current_actor_verifier
        self.sessions = root_setup_session_store
        self.journal = root_journal
        self.signer = selected_choice_signer
        self.service = authority_service
        self.current_active_publication = current_active_publication
        self.foreground_tty_observer = foreground_tty_observer
        self._store = _ProtectedStore(root_journal, "setup-choices", None)
        self._rows: dict[str, dict[str, Any]] = self._store.load()
        self._revocation_store = (
            _ProtectedStore(root_journal, "setup-choice-revocations", None)
            if self._runtime_only else None
        )
        self._revocations: dict[str, dict[str, Any]] = (
            self._revocation_store.load() if self._revocation_store is not None else {}
        )
        self._lock = threading.RLock()
        self._registry_seal = _SEAL
        self._live_choices: dict[str, tuple[Any, Any]] = {}
        if self._runtime_only:
            self._check_runtime_release()
        else:
            self._check_release()
        self._verify_stored_rows()

    @classmethod
    def from_root_setup(cls, verified_installer_release: Any,
                        current_actor_verifier: Any, root_setup_session_store: Any,
                        root_journal: Any, selected_choice_signer: Any) -> "RootSetupChoiceRegistry":
        return cls(verified_installer_release, current_actor_verifier,
                   root_setup_session_store, root_journal, selected_choice_signer)

    @classmethod
    def from_root_runtime(cls, verified_installer_release: Any,
                          current_active_publication: Any, authority_service: Any,
                          root_journal: Any, *,
                          foreground_tty_observer: Any = None) -> "RootSetupChoiceRegistry":
        """Open the same signed choice journal for post-setup currentness checks."""
        registry = cls(verified_installer_release, None, None, root_journal, None,
                       authority_service=authority_service,
                       current_active_publication=current_active_publication,
                       foreground_tty_observer=foreground_tty_observer)
        attach = getattr(authority_service, "attach_root_setup_choice_registry", None)
        if not callable(attach):
            raise AuthorityDenied("setup-choice.runtime", "authority service cannot attach its exact choice registry")
        try:
            attach(registry)
        except Exception:
            raise AuthorityDenied("setup-choice.runtime", "authority service rejected the exact choice registry") from None
        registry._verify_stored_revocations()
        return registry

    def attach_foreground_tty_observer(self, observer: Any) -> None:
        """Attach the one runtime root-TTY source after bindings expose this registry."""
        if not self._runtime_only or self.foreground_tty_observer is not None:
            raise AuthorityDenied("setup-choice.revocation", "runtime TTY observer is already attached or unavailable")
        from .root_runtime_foreground_tty import RootRuntimeForegroundTTYObserver
        if (type(observer) is not RootRuntimeForegroundTTYObserver
                or observer.is_bound_to(self, self.service.root_runtime_bindings) is not True):
            raise AuthorityDenied("setup-choice.revocation", "foreground TTY observer is not this exact runtime composition")
        self.foreground_tty_observer = observer

    def record_observed_choice(self, actual_root_tty_choice: Any,
                               current_setup_selection: Any) -> str | None:
        """Sign a currently retained typed root TTY choice as durable intent."""
        from .bootstrap_runtime_factory import RootSelectedMemoryServiceEnablementChoice
        from .native_policy_preparation import RootNativePolicyConfigurationChoice
        from .bootstrap_runtime_factory import RootSelectedApplicationQualificationChoice
        try:
            from .public_web_selection import RootSelectedPublicWebPermissionChoice
        except ImportError:
            RootSelectedPublicWebPermissionChoice = None  # type: ignore[assignment,misc]
        if type(actual_root_tty_choice) is RootSelectedMemoryServiceEnablementChoice:
            purpose = "memory-service-enablement"
            resolver_name = "resolve_current_memory_service_enablement_choice"
            payload = _memory_choice_payload(actual_root_tty_choice)
            selectors = (actual_root_tty_choice.principal_selection_handle,
                         actual_root_tty_choice.namespace_selection_handle,
                         actual_root_tty_choice.private_profile_selection_handle)
            prepared_generation = actual_root_tty_choice.prepared_generation_id
            profile_id = actual_root_tty_choice.profile_id
            principal_id = actual_root_tty_choice.principal_id
            namespace_id = actual_root_tty_choice.namespace_id
            source_handles_fn = lambda identity: (
                identity.principal.receipt_id, identity.namespace.receipt_handle,
                identity.identity_receipt_handle,
                self._current_private_profile_receipt_handle(current_setup_selection, actual_root_tty_choice))
            disabled = actual_root_tty_choice.enabled is not True
        elif type(actual_root_tty_choice) is RootNativePolicyConfigurationChoice:
            purpose = "native-policy-preparation"
            resolver_name = "resolve_current_native_policy_configuration_choice"
            payload = _dataclass_choice_payload(actual_root_tty_choice, {"_seal"})
            selectors = (actual_root_tty_choice.principal_selection_handle,
                         actual_root_tty_choice.namespace_selection_handle)
            prepared_generation = actual_root_tty_choice.prepared_generation_id
            profile_id = actual_root_tty_choice.service_profile_id
            principal_id = namespace_id = None
            source_handles_fn = lambda identity: (
                identity.principal.receipt_id, identity.namespace.receipt_handle,
                identity.identity_receipt_handle)
            disabled = False
        elif type(actual_root_tty_choice) is RootSelectedApplicationQualificationChoice:
            purpose = "application-qualification"
            resolver_name = "resolve_application_setup_choice"
            payload = _dataclass_choice_payload(actual_root_tty_choice, {"_session_seal"})
            selectors = (actual_root_tty_choice.principal_selection_handle,
                         actual_root_tty_choice.namespace_selection_handle)
            prepared_generation = actual_root_tty_choice.prepared_generation_id
            profile_id = actual_root_tty_choice.target_profile_id
            principal_id = namespace_id = None
            source_handles_fn = lambda identity: (
                identity.principal.receipt_id, identity.namespace.receipt_handle,
                identity.identity_receipt_handle, actual_root_tty_choice.qualification_consent_receipt_handle)
            disabled = False
        elif (RootSelectedPublicWebPermissionChoice is not None
              and type(actual_root_tty_choice) is RootSelectedPublicWebPermissionChoice):
            purpose = "public-free-web-read"
            resolver_name = "resolve_current_public_web_permission_choice"
            payload = _public_web_choice_payload(actual_root_tty_choice)
            selectors = (actual_root_tty_choice.principal_selection_handle,
                         actual_root_tty_choice.namespace_selection_handle)
            prepared_generation = actual_root_tty_choice.prepared_generation_id
            profile_id = actual_root_tty_choice.profile_id
            principal_id = actual_root_tty_choice.principal_id
            namespace_id = actual_root_tty_choice.namespace_id
            source_handles_fn = lambda identity: (
                identity.principal.receipt_id, identity.namespace.receipt_handle,
                identity.identity_receipt_handle,
                *actual_root_tty_choice.target_contract_source_receipt_handles)
            disabled = not actual_root_tty_choice.web_scope_ids
        else:
            raise AuthorityDenied("setup-choice.choice", "unsupported or unretained root TTY choice type")
        self._verify_current_setup(current_setup_selection)
        resolve = getattr(current_setup_selection, resolver_name, None)
        if not callable(resolve):
            raise AuthorityDenied("setup-choice.choice", "current setup session cannot revalidate this TTY choice")
        try:
            choice_handle = getattr(actual_root_tty_choice, "choice_handle",
                                    getattr(actual_root_tty_choice, "selection_handle", None))
            retained = resolve(choice_handle)
        except Exception:
            raise AuthorityDenied("setup-choice.choice", "root TTY choice is stale or no longer retained") from None
        if retained is not actual_root_tty_choice:
            raise AuthorityDenied("setup-choice.choice", "root TTY resolver did not return the exact retained choice")
        if disabled:
            self._revoke_purpose(purpose, profile_id)
            return None
        self._check_release()
        auth = current_setup_selection.verify_current_setup_controller()
        release_identity = self._release_identity_for_selection(current_setup_selection)
        current_identity = self._current_identity_for_selection(current_setup_selection)
        if ((principal_id is not None and getattr(current_identity.principal, "principal_id", None) != principal_id)
                or (namespace_id is not None and getattr(current_identity.namespace, "namespace_id", None) != namespace_id)
                or getattr(current_identity.principal, "receipt_id", None) is None
                or getattr(current_identity.namespace, "receipt_handle", None) is None
                or getattr(current_identity, "identity_receipt_handle", None) is None):
            raise AuthorityDenied("setup-choice.identity", "fresh root setup identity does not match the TTY choice")
        if (current_setup_selection.resolve_adopted_principal_selector().selection_handle != selectors[0]
                or current_setup_selection.resolve_adopted_namespace_selector().selection_handle != selectors[1]):
            raise AuthorityDenied("setup-choice.identity", "stable principal or namespace selector changed")
        if purpose == "memory-service-enablement":
            profile_receipt = self._current_private_profile_receipt_handle(current_setup_selection, actual_root_tty_choice)
        else:
            profile_receipt = None
        now_wall = time.time()
        remaining = actual_root_tty_choice.expires_monotonic - time.monotonic()
        if remaining <= 0:
            raise AuthorityDenied("setup-choice.expired", "root TTY memory choice expired")
        handle = secrets.token_urlsafe(32)
        record = {
            "schema": 1,
            "selection_handle": handle,
            # The signer domain and durable row must agree with the concrete
            # retained TTY choice.  A memory choice, native policy choice and
            # application qualification are different intents and cannot be
            # relabelled into the memory lifecycle purpose.
            "purpose": purpose,
            "key_id": self.signer.key_id,
            "release_deployment_receipt_sha256": release_identity,
            "setup_session_handle": self._setup_session_handle_for_selection(current_setup_selection),
            "transaction_handle": auth.transaction_handle,
            "plan_id": auth.plan_artifact_id,
            "prepared_generation": prepared_generation,
            "principal_selection_handle": selectors[0],
            "namespace_selection_handle": selectors[1],
            "private_profile_selection_handle": selectors[2] if len(selectors) > 2 else None,
            "source_member_receipt_handles": sorted(set(source_handles_fn(current_identity))),
            "choice_payload": payload,
            "choice_payload_sha256": _digest(payload),
            "choice_epoch": 1,
            "revocation_epoch": 1,
            "issued_at_unix": now_wall,
            "setup_deadline_unix": now_wall + min(remaining, 300.0),
            "adoption_publication_receipt_handle": None,
            "signature": "",
        }
        with self._lock:
            previous_epoch = max((row.get("choice_epoch", 0) for row in self._rows.values()
                                  if row.get("purpose") == purpose
                                  and row.get("choice_payload", {}).get("profile_id", row.get("choice_payload", {}).get("service_profile_id", row.get("choice_payload", {}).get("target_profile_id"))) == profile_id),
                                 default=0)
            record["choice_epoch"] = previous_epoch + 1
            record["signature"] = self._sign(record)
            for old_handle, old in tuple(self._rows.items()):
                old_payload = old.get("choice_payload", {})
                old_profile = old_payload.get("profile_id", old_payload.get("service_profile_id", old_payload.get("target_profile_id")))
                if old.get("purpose") == record["purpose"] and old_profile == profile_id:
                    self._revoke_row(old_handle, old)
            self._rows[handle] = record
            self._save()
            self._live_choices[handle] = (current_setup_selection, actual_root_tty_choice)
        return handle

    def resolve_current_setup_choice(self, selection_handle: str,
                                     expected_purpose: str) -> RootSetupChoiceSnapshot:
        if self._runtime_only:
            raise AuthorityDenied("setup-choice.session", "runtime registry cannot resolve live setup choices")
        if expected_purpose not in _DOMAIN_PURPOSES or not isinstance(selection_handle, str):
            raise AuthorityDenied("setup-choice.handle", "purpose or selection handle is invalid")
        with self._lock:
            row = self._rows.get(selection_handle)
            live = self._live_choices.get(selection_handle)
        if row is None or row.get("purpose") != expected_purpose:
            raise AuthorityDenied("setup-choice.stale", "setup choice is absent or has another purpose")
        self._verify_row(row)
        if row["revocation_epoch"] != 1:
            raise AuthorityDenied("setup-choice.revoked", "signed setup choice has been revoked")
        if live is None:
            raise AuthorityDenied("setup-choice.session", "current root setup session has not reattached this choice")
        current_selection, original_choice = live
        self._verify_current_setup(current_selection)
        current_choice = self._resolve_typed_choice(current_selection, original_choice, expected_purpose)
        if current_choice is not original_choice or not _choice_matches_row(row, current_choice):
            raise AuthorityDenied("setup-choice.stale", "root TTY choice or bound selectors changed")
        if (row["release_deployment_receipt_sha256"] != self._release_identity_for_selection(current_selection)
                or row["setup_session_handle"] != self._setup_session_handle_for_selection(current_selection)):
            raise AuthorityDenied("setup-choice.release", "current setup is bound to another held release receipt")
        if time.time() >= row["setup_deadline_unix"]:
            raise AuthorityDenied("setup-choice.expired", "setup choice expired with its original TTY session")
        return RootSetupChoiceSnapshot(
            selection_handle=row["selection_handle"], purpose=row["purpose"], key_id=row["key_id"],
            setup_session_handle=row["setup_session_handle"], transaction_handle=row["transaction_handle"],
            plan_id=row["plan_id"], prepared_generation=row["prepared_generation"],
            principal_selection_handle=row["principal_selection_handle"],
            namespace_selection_handle=row["namespace_selection_handle"],
            private_profile_selection_handle=row["private_profile_selection_handle"],
            source_member_receipt_handles=tuple(row["source_member_receipt_handles"]),
            choice_payload=dict(row["choice_payload"]), choice_payload_sha256=row["choice_payload_sha256"],
            signed_record_sha256=hashlib.sha256(_canonical(row)).hexdigest(),
            release_deployment_receipt_sha256=row["release_deployment_receipt_sha256"],
            choice_epoch=row["choice_epoch"], revocation_epoch=row["revocation_epoch"],
            issued_at_unix=row["issued_at_unix"], setup_deadline_unix=row["setup_deadline_unix"],
            adoption_publication_receipt_handle=row["adoption_publication_receipt_handle"],
            _registry_seal=_SEAL,
        )

    def resolve_current_session_choices(self, current_setup_selection: Any
                                        ) -> tuple[RootSetupChoiceSnapshot, ...]:
        """Enumerate only exact current signed choices for this live setup.

        The publisher/compiler can join the finite retained set to its prepared
        catalog without reading this registry's private row map. A signed row for
        this setup session that is revoked, expired, or not reattached is a hard
        error: omitting it would let the compiler reinterpret stale or withdrawn
        intent as no choice.
        """
        self._verify_current_setup(current_setup_selection)
        session_handle = self._setup_session_handle_for_selection(current_setup_selection)
        with self._lock:
            handles = tuple(sorted(
                handle for handle, row in self._rows.items()
                if row.get("setup_session_handle") == session_handle
                and row.get("purpose") in _DOMAIN_PURPOSES
            ))
        current: list[RootSetupChoiceSnapshot] = []
        for handle in handles:
            row = self._rows.get(handle)
            if row is None:
                continue
            self._verify_row(row)
            if row.get("revocation_epoch") != 1:
                raise AuthorityDenied(
                    "setup-choice.revoked",
                    "current setup session contains a revoked choice; restart selection explicitly",
                )
            snapshot = self.resolve_current_setup_choice(handle, row["purpose"])
            current.append(snapshot)
        return tuple(current)

    def resolve_current_adopted_choice_snapshot(
            self, selection_handle: str, expected_purpose: str
            ) -> RootAdoptedSetupChoiceSelection:
        """Resolve durable adopted intent without requiring a setup-session lease."""
        return self.resolve_current_adopted_choice(
            selection_handle, expected_purpose, self.current_active_publication,
        )

    def resolve_current_memory_service_enablement_choice(
            self, selection_handle: str
            ) -> RootAdoptedMemoryServiceEnablementChoice:
        """Resolve one adopted memory-start choice as a fresh typed source snapshot.

        The source is the exact signed ``memory-service-enablement`` row and
        its active publisher adoption. This resolver does not consult or
        revive the expired setup TTY session; every call rechecks the root
        journal, signer, active publication, revocation epoch, and current
        principal/profile binding through ``resolve_current_adopted_choice``.
        """
        if not self._runtime_only:
            raise AuthorityDenied(
                "setup-choice.memory-enablement",
                "runtime adopted memory enablement requires a post-compose registry",
            )
        current = self.resolve_current_adopted_choice_snapshot(
            selection_handle, "memory-service-enablement")
        payload = dict(current.choice_payload)
        expected_fields = {
            "choice_handle", "choice_observation_id", "provider", "backend_variant",
            "enabled", "principal_id", "profile_id", "namespace_id",
            "principal_binding_sha256", "namespace_binding_sha256",
            "private_profile_selection_handle", "controller_binding_handle",
            "policy_revision", "selection_digest",
        }
        if set(payload) != expected_fields:
            raise AuthorityDenied(
                "setup-choice.memory-enablement",
                "signed memory enablement payload differs from its closed purpose schema",
            )
        text_fields = expected_fields - {"enabled"}
        if (any(not isinstance(payload.get(name), str) or not payload[name]
                for name in text_fields)
                or payload["enabled"] is not True
                or payload["private_profile_selection_handle"]
                != current.private_profile_selection_handle
                or not current.private_profile_selection_handle
                or not re.fullmatch(r"[0-9a-f]{64}", payload["selection_digest"])
                or not re.fullmatch(r"[0-9a-f]{64}", payload["principal_binding_sha256"])
                or not re.fullmatch(r"[0-9a-f]{64}", payload["namespace_binding_sha256"])
                or payload["choice_handle"] == current.selection_handle
                or (current.consent_id is not None)):
            raise AuthorityDenied(
                "setup-choice.memory-enablement",
                "signed memory enablement source claims are malformed or aliased",
            )
        now = time.monotonic()
        expires = min(now + 30.0, current.expires_monotonic)
        if expires <= now:
            raise AuthorityDenied(
                "setup-choice.memory-enablement",
                "current memory enablement source snapshot has expired",
            )
        return RootAdoptedMemoryServiceEnablementChoice(
            selection_handle=current.selection_handle,
            choice_handle=payload["choice_handle"],
            choice_observation_id=payload["choice_observation_id"],
            principal_id=payload["principal_id"],
            profile_id=payload["profile_id"],
            namespace_id=payload["namespace_id"],
            provider=payload["provider"],
            backend_variant=payload["backend_variant"],
            enabled=True,
            principal_selection_handle=current.principal_selection_handle,
            namespace_selection_handle=current.namespace_selection_handle,
            private_profile_selection_handle=current.private_profile_selection_handle or "",
            controller_binding_handle=payload["controller_binding_handle"],
            policy_revision=payload["policy_revision"],
            source_selection_digest=payload["selection_digest"],
            source_choice_row_sha256=current.source_choice_row_sha256,
            choice_payload_sha256=current.choice_payload_sha256,
            choice_epoch=current.choice_epoch,
            revocation_epoch=current.revocation_epoch,
            key_id=current.key_id,
            release_deployment_receipt_sha256=current.release_deployment_receipt_sha256,
            active_publication_receipt_handle=current.active_publication_receipt_handle,
            service_generation_digest=current.service_generation_digest,
            issued_monotonic=now,
            expires_monotonic=expires,
            _registry_seal=_SEAL,
        )

    def verify_published_adoption_current(self, adoption: Any) -> None:
        """Verify a publisher adoption through its exact signed source row.

        This method intentionally does not call ``adoption.verify_current``;
        that public method delegates back here after the publisher owner wires
        post-setup revocation/currentness.
        """
        from .setup_policy_publication import PublishedSetupChoiceAdoption
        if type(adoption) is not PublishedSetupChoiceAdoption:
            raise AuthorityDenied("setup-choice.adoption", "exact published choice adoption is required")
        adopted_at = getattr(adoption, "adopted_at_unix", None)
        if (type(adopted_at) not in (int, float) or isinstance(adopted_at, bool)
                or not math.isfinite(adopted_at)
                or adopted_at < adoption.issued_at_unix
                or adopted_at > adoption.setup_deadline_unix):
            raise AuthorityDenied("setup-choice.adoption", "published choice adoption is outside its signed setup window")
        if self._runtime_only:
            current = self.resolve_current_adopted_choice_snapshot(
                adoption.selection_handle, adoption.purpose)
        else:
            # During publication the actual setup TTY/session is still live.
            # Validate through that retained source; runtime-mode resolution
            # is reserved for post-setup consumers.
            current = self.resolve_current_setup_choice(
                adoption.selection_handle, adoption.purpose)
        if (current.signed_record_sha256 != adoption.signed_record_sha256
                or current.choice_payload_sha256 != adoption.choice_payload_sha256
                or current.choice_epoch != adoption.choice_epoch
                or current.revocation_epoch != adoption.revocation_epoch
                or current.key_id != adoption.key_id
                or current.release_deployment_receipt_sha256 != adoption.release_deployment_receipt_sha256
                or current.setup_session_handle != adoption.setup_session_handle
                or current.transaction_handle != adoption.transaction_handle
                or current.plan_id != adoption.plan_id
                or current.prepared_generation != adoption.prepared_generation
                or current.principal_selection_handle != adoption.principal_selection_handle
                or current.namespace_selection_handle != adoption.namespace_selection_handle
                or current.private_profile_selection_handle != adoption.private_profile_selection_handle
                or current.setup_deadline_unix != adoption.setup_deadline_unix
                or current.choice_payload.get("principal_id") not in (None, adoption.principal_id)
                or _choice_profile_id_from_payload(current.choice_payload, current.purpose) != adoption.profile_id
                or current.choice_payload.get("namespace_id") not in (None, adoption.namespace_id)):
            raise AuthorityDenied("setup-choice.adoption", "publisher adoption differs from its exact current signed source row")
        if self._runtime_only and (
                current.active_publication_receipt_handle != adoption.publication_receipt_handle
                or current.service_generation_digest != adoption.service_generation_digest):
            raise AuthorityDenied("setup-choice.adoption", "runtime adoption differs from its current active generation")

    def resolve_current_adopted_choice(
            self, selection_handle: str, expected_purpose: str,
            active_publication_receipt: Any
            ) -> RootAdoptedSetupChoiceSelection:
        if not self._runtime_only:
            raise AuthorityDenied("setup-choice.runtime", "adopted choice resolution requires runtime registry mode")
        if (not isinstance(selection_handle, str) or not selection_handle
                or expected_purpose not in _DOMAIN_PURPOSES):
            raise AuthorityDenied("setup-choice.handle", "adopted choice selector is malformed")
        from .setup_policy_publication import (
            PolicyPublicationReceiptResolver, PublishedSetupChoiceAdoption,
            RootSetupPublicationReceipt,
        )
        if type(active_publication_receipt) is not RootSetupPublicationReceipt:
            raise AuthorityDenied("setup-choice.publication", "current typed active publication receipt is required")
        self._check_runtime_release()
        try:
            active = PolicyPublicationReceiptResolver.resolve_current()
            adoption = PolicyPublicationReceiptResolver.resolve_current_choice_adoption(selection_handle)
        except Exception:
            raise AuthorityDenied("setup-choice.publication", "choice is not in the current active publication") from None
        if (type(adoption) is not PublishedSetupChoiceAdoption
                or adoption.selection_handle != selection_handle
                or adoption.purpose != expected_purpose
                or active.receipt_handle != active_publication_receipt.receipt_handle
                or active.publication_sha256 != active_publication_receipt.publication_sha256
                or active.generation_id != active_publication_receipt.generation_id
                or active.service_generation_digest != self.service.service_generation_digest
                or adoption.publication_receipt_handle != active.receipt_handle
                or adoption.service_generation_digest != active.service_generation_digest
                or active_publication_receipt.state != "active-committed"):
            raise AuthorityDenied("setup-choice.publication", "active publication identity or generation changed")
        with self._lock:
            # Reopen the protected journal on every resolution so another
            # root registry instance's durable revoke/reconfiguration is
            # visible immediately; process-local rows are never authority.
            self._rows = self._store.load()
            if self._revocation_store is None:
                raise AuthorityDenied("setup-choice.runtime", "revocation journal is unavailable")
            self._revocations = self._revocation_store.load()
            revocation = self._revocations.get(selection_handle)
            if revocation is not None:
                self._verify_persisted_revocation(selection_handle, revocation)
                raise AuthorityDenied("setup-choice.revoked", "adopted setup choice has a durable revocation")
            raw = self._rows.get(selection_handle)
            row = None if raw is None else json.loads(_canonical(raw))
        if row is None:
            raise AuthorityDenied("setup-choice.stale", "adopted choice source row is absent")
        self._verify_row(row)
        row_sha = hashlib.sha256(_canonical(row)).hexdigest()
        payload = row["choice_payload"]
        adopted_at = getattr(adoption, "adopted_at_unix", None)
        if (row["purpose"] != expected_purpose
                or row_sha != adoption.signed_record_sha256
                or row["choice_payload_sha256"] != adoption.choice_payload_sha256
                or row["choice_epoch"] != adoption.choice_epoch
                or row["revocation_epoch"] != adoption.revocation_epoch
                or row["key_id"] != adoption.key_id
                or row["release_deployment_receipt_sha256"] != adoption.release_deployment_receipt_sha256
                or row["release_deployment_receipt_sha256"] != self.release.deployment_receipt_sha256
                or tuple(row["source_member_receipt_handles"]) != adoption.source_member_receipt_handles
                or row["setup_session_handle"] != adoption.setup_session_handle
                or row["transaction_handle"] != adoption.transaction_handle
                or row["plan_id"] != adoption.plan_id
                or row["prepared_generation"] != adoption.prepared_generation
                or row["principal_selection_handle"] != adoption.principal_selection_handle
                or row["namespace_selection_handle"] != adoption.namespace_selection_handle
                or row["private_profile_selection_handle"] != adoption.private_profile_selection_handle
                or not isinstance(adopted_at, (int, float))
                or isinstance(adopted_at, bool)
                or adopted_at < row["issued_at_unix"]
                or adopted_at > row["setup_deadline_unix"]):
            raise AuthorityDenied("setup-choice.stale", "adopted choice no longer matches its signed source row")
        profile_id = _choice_profile_id_from_payload(payload, expected_purpose)
        principal_id = payload.get("principal_id", adoption.principal_id)
        namespace_id = payload.get("namespace_id", adoption.namespace_id)
        try:
            current_binding = self.service.resolve_current_active_principal_binding(profile_id)
        except Exception:
            raise AuthorityDenied("setup-choice.subject", "active protected principal/profile binding is unavailable") from None
        profile_generation = self.service.profile_generations.get(profile_id)
        policy_revision = self.service.current_authority_policy_revision()
        if (principal_id != adoption.principal_id
                or profile_id != adoption.profile_id
                or namespace_id != adoption.namespace_id
                or current_binding.principal_id != adoption.principal_id
                or current_binding.profile_id != adoption.profile_id
                or current_binding.namespace_id != adoption.namespace_id
                or not isinstance(profile_generation, str) or not profile_generation
                or (expected_purpose == "memory-service-enablement"
                    and payload.get("policy_revision") != policy_revision)
                or (expected_purpose != "memory-service-enablement"
                    and payload.get("policy_revision") is not None
                    and payload.get("policy_revision") != policy_revision)
                or ("profile_generation" in payload
                    and payload.get("profile_generation") != profile_generation)
                or payload.get("principal_binding_sha256", adoption.principal_binding_sha256)
                != adoption.principal_binding_sha256
                or payload.get("namespace_binding_sha256", adoption.namespace_binding_sha256)
                != adoption.namespace_binding_sha256):
            raise AuthorityDenied("setup-choice.subject", "active adoption does not match signed choice selectors")
        consent_id = payload.get("consent_id")
        if (expected_purpose == "public-free-web-read"
                and (not isinstance(consent_id, str)
                     or not re.fullmatch(r"[0-9a-f]{48}", consent_id))):
            raise AuthorityDenied("setup-choice.consent", "signed consent identity is malformed")
        now = time.monotonic()
        return RootAdoptedSetupChoiceSelection(
            selection_handle=selection_handle, purpose=expected_purpose,
            consent_id=consent_id,
            setup_session_handle=row["setup_session_handle"],
            transaction_handle=row["transaction_handle"], plan_id=row["plan_id"],
            prepared_generation=row["prepared_generation"],
            principal_selection_handle=row["principal_selection_handle"],
            namespace_selection_handle=row["namespace_selection_handle"],
            private_profile_selection_handle=row["private_profile_selection_handle"],
            setup_deadline_unix=row["setup_deadline_unix"], signed_record_sha256=row_sha,
            source_choice_row_sha256=row_sha,
            choice_epoch=row["choice_epoch"], revocation_epoch=row["revocation_epoch"],
            key_id=row["key_id"],
            release_deployment_receipt_sha256=row["release_deployment_receipt_sha256"],
            active_publication_receipt_handle=active.receipt_handle,
            service_generation_digest=active.service_generation_digest,
            choice_payload_sha256=row["choice_payload_sha256"],
            issued_monotonic=now, expires_monotonic=now + 30.0,
            choice_payload=payload, _registry_seal=_SEAL,
        )

    def revoke_adopted_choice(self, revocation_observation_handle: str
                              ) -> RootSetupChoiceRevocationReceipt:
        """Persist one foreground root-TTY revocation of a current adopted choice."""
        if not self._runtime_only or self.foreground_tty_observer is None:
            raise AuthorityDenied("setup-choice.revocation", "runtime root TTY revocation source is unavailable")
        from .root_runtime_foreground_tty import RootObservedAdoptedChoiceRevocation
        observer = self.foreground_tty_observer
        if type(revocation_observation_handle) is not str or not re.fullmatch(
                r"[0-9a-f]{64}", revocation_observation_handle):
            raise AuthorityDenied("setup-choice.revocation", "revocation observation handle is malformed")
        # Resolve exactly once by the retained observation's handle. The TTY
        # observer returns its exact sealed selection only through its private
        # currentness join; do not accept a caller-supplied selected choice.
        lookup = getattr(observer, "resolve_observation_selection", None)
        if not callable(lookup):
            raise AuthorityDenied("setup-choice.revocation", "TTY source has no retained selection resolver")
        try:
            selection = lookup(revocation_observation_handle)
            if type(selection) is not RootAdoptedSetupChoiceSelection:
                raise ValueError
            current = self.resolve_current_adopted_choice_snapshot(
                selection.selection_handle, selection.purpose)
            observed = observer.resolve_current_revocation(
                revocation_observation_handle, current)
        except Exception:
            raise AuthorityDenied("setup-choice.revocation", "root TTY revocation is absent, stale, or mismatched") from None
        if type(observed) is not RootObservedAdoptedChoiceRevocation:
            raise AuthorityDenied("setup-choice.revocation", "exact root TTY revocation observation is required")
        with self._lock:
            self._rows = self._store.load()
            self._revocations = self._revocation_store.load()
            prior = self._revocations.get(selection.selection_handle)
            if prior is not None:
                receipt = self._receipt_from_persisted(prior)
                if (receipt.revocation_observation_handle != revocation_observation_handle
                        or observer.verify_consumed_revocation(
                            revocation_observation_handle, current) is not True
                        or self.service.root_choice_revocation_signer().verify_revocation(receipt) is not True):
                    raise AuthorityDenied("setup-choice.revocation", "choice already has another durable revocation")
                return receipt
            row = self._rows.get(selection.selection_handle)
            if row is None:
                raise AuthorityDenied("setup-choice.revocation", "signed source choice row is absent")
            self._verify_row(row)
            row_sha = hashlib.sha256(_canonical(row)).hexdigest()
            if (row_sha != current.source_choice_row_sha256
                    or row["purpose"] != current.purpose
                    or row["choice_epoch"] != current.choice_epoch
                    or row["revocation_epoch"] != current.revocation_epoch):
                raise AuthorityDenied("setup-choice.revocation", "signed source row changed before revocation")
            candidate = RootSetupChoiceRevocationReceipt(
                schema=1, revocation_receipt_handle=secrets.token_hex(32),
                selection_handle=current.selection_handle, purpose=current.purpose,
                consent_id=current.consent_id,
                previous_choice_epoch=current.choice_epoch,
                previous_revocation_epoch=current.revocation_epoch,
                revocation_epoch=current.revocation_epoch + 1,
                source_choice_row_sha256=row_sha,
                revocation_observation_handle=observed.revocation_observation_handle,
                displayed_payload_sha256=observed.displayed_payload_sha256,
                key_id=self.signer.key_id,
                release_deployment_receipt_sha256=current.release_deployment_receipt_sha256,
                service_generation_digest=current.service_generation_digest,
                revoked_at_unix=time.time(), signature="", _registry_seal=_SEAL,
            )
            try:
                signature = self.service.root_choice_revocation_signer().sign_revocation(candidate)
            except Exception:
                raise AuthorityDenied("setup-choice.revocation", "authority rejected the current revocation transition") from None
            receipt = _replace_revocation_signature(candidate, signature)
            # Consume the exact TTY proof before making the durable transition.
            # A storage failure then requires a fresh explicit TTY action and
            # can never leave a reusable confirmation receipt.
            try:
                consumed = observer.consume_current_revocation(
                    revocation_observation_handle, current)
            except Exception:
                raise AuthorityDenied("setup-choice.revocation", "root TTY revocation could not be consumed") from None
            if consumed is not observed:
                raise AuthorityDenied("setup-choice.revocation", "root TTY source changed during revocation")
            self._revocations[selection.selection_handle] = {
                **receipt.claims(), "signature": receipt.signature,
            }
            try:
                _commit_revocation_index_entry(
                    self._revocation_store, selection.selection_handle,
                    self._revocations[selection.selection_handle],
                )
            except Exception:
                self._revocations.pop(selection.selection_handle, None)
                raise AuthorityDenied("setup-choice.revocation", "durable revocation journal could not be committed") from None
            if self.service.root_choice_revocation_signer().verify_revocation(receipt) is not True:
                raise AuthorityDenied("setup-choice.revocation", "committed revocation failed signed membership verification")
            return receipt

    def verify_revocation_transition_request(self, candidate: Any) -> bool:
        """Non-consuming signer admission for an exact, still-current TTY action."""
        if (not self._runtime_only or self.foreground_tty_observer is None
                or type(candidate) is not RootSetupChoiceRevocationReceipt
                or candidate._registry_seal is not _SEAL):
            return False
        try:
            selection = self.resolve_current_adopted_choice_snapshot(
                candidate.selection_handle, candidate.purpose)
            observed = self.foreground_tty_observer.resolve_current_revocation(
                candidate.revocation_observation_handle, selection)
            self._verify_revocation_join(candidate, selection, observed)
            return True
        except Exception:
            return False

    def verify_revocation_receipt_membership(self, receipt: Any) -> bool:
        """Check the exact protected committed receipt without recursively signing."""
        if (not self._runtime_only or type(receipt) is not RootSetupChoiceRevocationReceipt
                or receipt._registry_seal is not _SEAL):
            return False
        try:
            with self._lock:
                self._rows = self._store.load()
                self._revocations = self._revocation_store.load()
                stored = self._revocations.get(receipt.selection_handle)
                row = self._rows.get(receipt.selection_handle)
                if (stored is None or row is None
                        or stored != {**receipt.claims(), "signature": receipt.signature}):
                    return False
                self._verify_row(row)
                if (hashlib.sha256(_canonical(row)).hexdigest() != receipt.source_choice_row_sha256
                        or row["purpose"] != receipt.purpose
                        or row["choice_epoch"] != receipt.previous_choice_epoch
                        or row["revocation_epoch"] != receipt.previous_revocation_epoch
                        or receipt.revocation_epoch != receipt.previous_revocation_epoch + 1
                        or row["key_id"] != receipt.key_id
                        or row["release_deployment_receipt_sha256"] != receipt.release_deployment_receipt_sha256
                        or receipt.release_deployment_receipt_sha256 != self.release.deployment_receipt_sha256
                        or receipt.service_generation_digest != self.service.service_generation_digest
                        or row["choice_payload"].get("consent_id") != receipt.consent_id):
                    return False
            self._check_runtime_release()
            # Confirm the same signed intent is still in the active publisher
            # descriptor. Its choice is revoked for use, while the active
            # deployment/source generation remains the owner of the record.
            from .setup_policy_publication import PolicyPublicationReceiptResolver, PublishedSetupChoiceAdoption
            adoption = PolicyPublicationReceiptResolver.resolve_current_choice_adoption(
                receipt.selection_handle)
            return bool(
                type(adoption) is PublishedSetupChoiceAdoption
                and adoption.purpose == receipt.purpose
                and adoption.signed_record_sha256 == receipt.source_choice_row_sha256
                and adoption.choice_epoch == receipt.previous_choice_epoch
                and adoption.revocation_epoch == receipt.previous_revocation_epoch
                and adoption.service_generation_digest == receipt.service_generation_digest
                and adoption.release_deployment_receipt_sha256 == receipt.release_deployment_receipt_sha256
            )
        except Exception:
            return False

    def _verify_revocation_join(self, receipt: RootSetupChoiceRevocationReceipt,
                                selection: RootAdoptedSetupChoiceSelection,
                                observed: Any) -> None:
        fields = (
            (receipt.selection_handle, selection.selection_handle),
            (receipt.purpose, selection.purpose),
            (receipt.consent_id, selection.consent_id),
            (receipt.previous_choice_epoch, selection.choice_epoch),
            (receipt.previous_revocation_epoch, selection.revocation_epoch),
            (receipt.source_choice_row_sha256, selection.source_choice_row_sha256),
            (receipt.key_id, selection.key_id),
            (receipt.release_deployment_receipt_sha256, selection.release_deployment_receipt_sha256),
            (receipt.service_generation_digest, selection.service_generation_digest),
            (receipt.revocation_observation_handle, observed.revocation_observation_handle),
            (receipt.displayed_payload_sha256, observed.displayed_payload_sha256),
            (observed.selection_handle, selection.selection_handle),
            (observed.purpose, selection.purpose),
            (observed.consent_id, selection.consent_id),
            (observed.source_choice_row_sha256, selection.source_choice_row_sha256),
            (observed.choice_epoch, selection.choice_epoch),
            (observed.revocation_epoch, selection.revocation_epoch),
            (observed.active_publication_receipt_handle, selection.active_publication_receipt_handle),
            (observed.service_generation_digest, selection.service_generation_digest),
        )
        if (any(actual != expected for actual, expected in fields)
                or type(receipt.revocation_epoch) is not int
                or receipt.revocation_epoch != receipt.previous_revocation_epoch + 1
                or receipt.revoked_at_unix <= 0
                or not math.isfinite(receipt.revoked_at_unix)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.revocation_receipt_handle)):
            raise AuthorityDenied("setup-choice.revocation", "revocation receipt does not bind the exact current TTY action")

    def _receipt_from_persisted(self, value: Any) -> RootSetupChoiceRevocationReceipt:
        expected = {
            "schema", "revocation_receipt_handle", "selection_handle", "purpose", "consent_id",
            "previous_choice_epoch", "previous_revocation_epoch", "revocation_epoch",
            "source_choice_row_sha256", "revocation_observation_handle", "displayed_payload_sha256",
            "key_id", "release_deployment_receipt_sha256", "service_generation_digest",
            "revoked_at_unix", "signature",
        }
        if type(value) is not dict or set(value) != expected:
            raise AuthorityDenied("setup-choice.revocation", "persisted revocation fields are malformed")
        try:
            fields = dict(value)
            fields["_registry_seal"] = _SEAL
            receipt = RootSetupChoiceRevocationReceipt(**fields)
        except Exception:
            raise AuthorityDenied("setup-choice.revocation", "persisted revocation receipt is malformed") from None
        if (not re.fullmatch(r"[0-9a-f]{64}", receipt.revocation_receipt_handle)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.selection_handle)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.source_choice_row_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.revocation_observation_handle)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.displayed_payload_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.release_deployment_receipt_sha256)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.service_generation_digest)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt.signature)):
            raise AuthorityDenied("setup-choice.revocation", "persisted revocation receipt is malformed")
        return receipt

    def _verify_persisted_revocation(self, selection_handle: str, value: Any) -> None:
        receipt = self._receipt_from_persisted(value)
        if receipt.selection_handle != selection_handle:
            raise AuthorityDenied("setup-choice.revocation", "revocation journal key does not match its receipt")
        try:
            valid = self.service.root_choice_revocation_signer().verify_revocation(receipt)
        except Exception:
            valid = False
        if valid is not True:
            raise AuthorityDenied("setup-choice.revocation", "durable revocation signature or membership is invalid")

    def reattach_current_setup_selection(self, selection_handle: str,
                                         current_setup_selection: Any) -> None:
        """Rebind a persisted intent only to the exact freshly resumed TTY choice."""
        with self._lock:
            row = self._rows.get(selection_handle)
        if row is None:
            raise AuthorityDenied("setup-choice.stale", "persisted setup choice is absent")
        self._verify_row(row)
        if row["revocation_epoch"] != 1:
            raise AuthorityDenied("setup-choice.revoked", "revoked setup choice cannot be reattached")
        self._verify_current_setup(current_setup_selection)
        payload = row["choice_payload"]
        choice = self._resolve_persisted_choice(current_setup_selection, row)
        if (not _choice_matches_row(row, choice)
                or getattr(choice, "setup_session_id", None) != row["setup_session_handle"]
                or getattr(choice, "transaction_handle", None) != row["transaction_handle"]
                or row["release_deployment_receipt_sha256"] != self._release_identity_for_selection(current_setup_selection)
                or row["setup_session_handle"] != self._setup_session_handle_for_selection(current_setup_selection)):
            raise AuthorityDenied("setup-choice.stale", "resumed setup choice does not match the signed record")
        with self._lock:
            self._live_choices[selection_handle] = (current_setup_selection, choice)

    def revoke_choice(self, selection_handle: str) -> int:
        with self._lock:
            row = self._rows.get(selection_handle)
            if row is None:
                raise AuthorityDenied("setup-choice.stale", "setup choice is absent")
            self._revoke_row(selection_handle, row)
            self._live_choices.pop(selection_handle, None)
            self._save()
            return row["revocation_epoch"]

    def revoke_current_profile_purpose(self, current_setup_selection: Any,
                                       purpose: str, profile_id: str) -> int:
        """Durably clear one purpose for a profile selected in this live setup.

        This is a deny-only operation. Callers must still pass the exact sealed
        setup facade; it cannot create or refresh a choice.
        """
        if (purpose not in _DOMAIN_PURPOSES or not isinstance(profile_id, str)
                or not profile_id or any(ord(char) < 0x20 for char in profile_id)):
            raise AuthorityDenied("setup-choice.revoke", "purpose or profile selector is malformed")
        self._verify_current_setup(current_setup_selection)
        self._check_release()
        session_handle = self._setup_session_handle_for_selection(current_setup_selection)
        revoked = 0
        with self._lock:
            for handle, row in self._rows.items():
                payload = row.get("choice_payload", {})
                candidate_profile = _choice_profile_id_from_payload(payload, row.get("purpose", ""))
                if (row.get("setup_session_handle") == session_handle
                        and row.get("purpose") == purpose
                        and candidate_profile == profile_id
                        and row.get("revocation_epoch") == 1):
                    self._revoke_row(handle, row)
                    self._live_choices.pop(handle, None)
                    revoked += 1
            self._save()
        return revoked

    def adopt_published_choice(self, selection_handle: str,
                               actual_active_publication_receipt: Any) -> str:
        """Verify one publisher-retained adoption of this exact signed choice.

        The active publisher owns durable adoption state. This method is a
        non-mutating join: changing this signed setup row would change its
        signed-record digest and invalidate the publisher's proof.
        """
        from .setup_policy_publication import PublishedSetupChoiceAdoption, _SEAL as _PUBLISHER_SEAL

        if (not isinstance(selection_handle, str)
                or type(actual_active_publication_receipt) is not PublishedSetupChoiceAdoption
                or actual_active_publication_receipt._seal is not _PUBLISHER_SEAL
                or actual_active_publication_receipt.selection_handle != selection_handle):
            raise AuthorityDenied("setup-choice.adoption", "exact publisher choice adoption is required")
        receipt = actual_active_publication_receipt
        # Check the active publisher projection and its exact signed source
        # row. Adoption time is a historical admission boundary; setup expiry
        # after a timely publication does not expire runtime configuration.
        try:
            receipt.verify_current(self)
        except Exception:
            raise AuthorityDenied("setup-choice.adoption", "publisher adoption is not current") from None
        with self._lock:
            row = self._rows.get(selection_handle)
        if row is None:
            raise AuthorityDenied("setup-choice.adoption", "signed setup choice is absent")
        self._verify_row(row)
        if (not isinstance(row, Mapping) or set(row) != _RECORD_FIELDS
                or row.get("selection_handle") != selection_handle
                or row.get("choice_payload_sha256") != _digest(row.get("choice_payload"))
                or type(row.get("choice_epoch")) is not int
                or type(row.get("revocation_epoch")) is not int):
            raise AuthorityDenied("setup-choice.record", "published setup choice row is malformed")
        adopted_at = getattr(receipt, "adopted_at_unix", None)
        if (type(adopted_at) not in (int, float) or isinstance(adopted_at, bool)
                or not math.isfinite(adopted_at)
                or adopted_at < row["issued_at_unix"]
                or adopted_at > row["setup_deadline_unix"]):
            raise AuthorityDenied("setup-choice.expired", "setup intent was not adopted within its original deadline")
        payload = row["choice_payload"]
        profile_id = _choice_profile_id_from_payload(payload, row["purpose"])
        principal_id = payload.get("principal_id")
        namespace_id = payload.get("namespace_id")
        claims = {
            "selection_handle": selection_handle,
            "purpose": row["purpose"],
            "key_id": row["key_id"],
            "signed_record_sha256": hashlib.sha256(_canonical(row)).hexdigest(),
            "choice_payload_sha256": row["choice_payload_sha256"],
            "choice_epoch": row["choice_epoch"],
            "revocation_epoch": row["revocation_epoch"],
            "issued_at_unix": row["issued_at_unix"],
            "setup_deadline_unix": row["setup_deadline_unix"],
            "release_deployment_receipt_sha256": row["release_deployment_receipt_sha256"],
            "setup_session_handle": row["setup_session_handle"],
            "transaction_handle": row["transaction_handle"],
            "plan_id": row["plan_id"],
            "prepared_generation": row["prepared_generation"],
            "principal_selection_handle": row["principal_selection_handle"],
            "namespace_selection_handle": row["namespace_selection_handle"],
            "private_profile_selection_handle": row["private_profile_selection_handle"],
            "source_member_receipt_handles": tuple(row["source_member_receipt_handles"]),
            "principal_id": receipt.principal_id if principal_id is None else principal_id,
            "profile_id": profile_id,
            "namespace_id": receipt.namespace_id if namespace_id is None else namespace_id,
            "principal_binding_sha256": payload.get("principal_binding_sha256"),
            "namespace_binding_sha256": payload.get("namespace_binding_sha256"),
        }
        if (any(getattr(receipt, key, None) != value for key, value in claims.items())
                or receipt.publication_receipt_handle == ""
                or receipt.publication_sha256 == ""
                or receipt.generation_id == ""
                or receipt.service_generation_digest == ""
                or receipt.selection_catalog_sha256 == ""):
            raise AuthorityDenied("setup-choice.adoption", "publisher receipt does not join the exact current signed choice")
        return receipt.publication_receipt_handle

    def _verify_current_setup(self, selection: Any) -> None:
        if not callable(getattr(selection, "verify_current_setup_controller", None)):
            raise AuthorityDenied("setup-choice.session", "current root setup selection is not typed")
        try:
            auth = selection.verify_current_setup_controller()
            self.release.verify_current()
            self.actor_verifier.verify_current(self.release)
        except Exception:
            raise AuthorityDenied("setup-choice.session", "root actor, release or setup session is stale") from None
        if (getattr(auth, "operator_uid", None) != 0
                or not getattr(auth, "setup_session_id", None)
                or not getattr(auth, "transaction_handle", None)):
            raise AuthorityDenied("setup-choice.session", "setup session is not root-controlled")

    def _check_release(self) -> None:
        try:
            self.release.verify_current()
            self.actor_verifier.verify_current(self.release)
        except Exception:
            raise AuthorityDenied("setup-choice.release", "held installer release or root actor is stale") from None

    def _check_runtime_release(self) -> None:
        if not self._runtime_only:
            raise AuthorityDenied("setup-choice.runtime", "runtime release check requires runtime registry mode")
        try:
            self.release.verify_current()
            if (self.current_active_publication is None
                    or getattr(self.current_active_publication, "state", None) != "active-committed"
                    or not isinstance(self.release.deployment_receipt_sha256, str)
                    or len(self.release.deployment_receipt_sha256) != 64):
                raise ValueError("active publication or held release identity is unavailable")
        except Exception:
            raise AuthorityDenied("setup-choice.release", "installed release is no longer current") from None

    def _verify_stored_revocations(self) -> None:
        if not self._runtime_only or self._revocation_store is None:
            return
        with self._lock:
            self._revocations = self._revocation_store.load()
            self._rows = self._store.load()
            if not isinstance(self._revocations, dict):
                raise AuthorityDenied("setup-choice.revocation", "protected revocation index is malformed")
            for selection_handle, receipt in self._revocations.items():
                if not isinstance(selection_handle, str):
                    raise AuthorityDenied("setup-choice.revocation", "protected revocation index key is malformed")
                parsed = self._receipt_from_persisted(receipt)
                if parsed.selection_handle != selection_handle:
                    raise AuthorityDenied("setup-choice.revocation", "protected revocation key does not match receipt")
                self._verify_persisted_revocation(selection_handle, receipt)

    def _release_identity_for_selection(self, selection: Any) -> str:
        resolver = getattr(selection, "resolve_held_installer_release_receipt", None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.release", "current setup has no held installer release resolver")
        try:
            value = resolver()
        except Exception:
            raise AuthorityDenied("setup-choice.release", "held installer release receipt is not current") from None
        if value is not self.release:
            raise AuthorityDenied("setup-choice.release", "current setup resolved another held release receipt")
        identity = getattr(value, "deployment_receipt_sha256", None)
        if not isinstance(identity, str) or len(identity) != 64 or any(c not in "0123456789abcdef" for c in identity):
            raise AuthorityDenied("setup-choice.release", "held deployment receipt identity is malformed")
        return identity

    def _setup_session_handle_for_selection(self, selection: Any) -> str:
        resolver = getattr(selection, "resolve_current_setup_session_handle", None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.session", "current setup has no typed session handle resolver")
        try:
            value = resolver()
        except Exception:
            raise AuthorityDenied("setup-choice.session", "current setup session handle is stale") from None
        from .bootstrap_enrollment import RootSetupSessionHandle
        if type(value) is not RootSetupSessionHandle or not re.fullmatch(r"[0-9a-f]{64}", value.session_id):
            raise AuthorityDenied("setup-choice.session", "current setup session handle is malformed")
        return value.session_id

    def _current_identity_for_selection(self, selection: Any) -> Any:
        resolver = getattr(selection, "resolve_current_setup_identity", None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.identity", "current setup cannot refresh its principal/namespace identity")
        try:
            return resolver()
        except Exception:
            raise AuthorityDenied("setup-choice.identity", "current setup identity snapshot is unavailable") from None

    def _resolve_typed_choice(self, selection: Any, choice: Any, purpose: str) -> Any:
        from .bootstrap_runtime_factory import RootSelectedMemoryServiceEnablementChoice, RootSelectedApplicationQualificationChoice
        from .native_policy_preparation import RootNativePolicyConfigurationChoice
        try:
            from .public_web_selection import RootSelectedPublicWebPermissionChoice
        except ImportError:
            RootSelectedPublicWebPermissionChoice = None  # type: ignore[assignment,misc]
        if type(choice) is RootSelectedMemoryServiceEnablementChoice and purpose == "memory-service-enablement":
            name, handle = "resolve_current_memory_service_enablement_choice", choice.choice_handle
        elif type(choice) is RootNativePolicyConfigurationChoice and purpose == "native-policy-preparation":
            name, handle = "resolve_current_native_policy_configuration_choice", choice.choice_handle
        elif type(choice) is RootSelectedApplicationQualificationChoice and purpose == "application-qualification":
            name, handle = "resolve_application_setup_choice", choice.selection_handle
        elif (RootSelectedPublicWebPermissionChoice is not None
              and type(choice) is RootSelectedPublicWebPermissionChoice
              and purpose == "public-free-web-read"):
            name, handle = "resolve_current_public_web_permission_choice", choice.choice_handle
        else:
            raise AuthorityDenied("setup-choice.purpose", "choice type is not admitted for this exact purpose")
        resolver = getattr(selection, name, None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.session", "current setup has no typed resolver for this choice")
        try:
            retained = resolver(handle)
        except Exception:
            raise AuthorityDenied("setup-choice.session", "root TTY choice is no longer current") from None
        return retained

    def _resolve_persisted_choice(self, selection: Any, row: Mapping[str, Any]) -> Any:
        payload = row["choice_payload"]
        purpose = row["purpose"]
        if purpose == "memory-service-enablement":
            handle = payload.get("choice_handle")
        elif purpose == "native-policy-preparation":
            handle = payload.get("choice_handle")
        elif purpose == "application-qualification":
            handle = payload.get("selection_handle")
        elif purpose == "public-free-web-read":
            handle = payload.get("choice_handle")
        else:
            raise AuthorityDenied("setup-choice.purpose", "persisted purpose has no typed setup producer")
        from .bootstrap_runtime_factory import RootSelectedMemoryServiceEnablementChoice, RootSelectedApplicationQualificationChoice
        from .native_policy_preparation import RootNativePolicyConfigurationChoice
        try:
            from .public_web_selection import RootSelectedPublicWebPermissionChoice
        except ImportError:
            RootSelectedPublicWebPermissionChoice = None  # type: ignore[assignment,misc]
        if purpose == "public-free-web-read" and RootSelectedPublicWebPermissionChoice is None:
            raise AuthorityDenied("setup-choice.purpose", "public web TTY choice producer is unavailable")
        expected = {"memory-service-enablement": RootSelectedMemoryServiceEnablementChoice,
                    "native-policy-preparation": RootNativePolicyConfigurationChoice,
                    "application-qualification": RootSelectedApplicationQualificationChoice,
                    **({"public-free-web-read": RootSelectedPublicWebPermissionChoice}
                       if RootSelectedPublicWebPermissionChoice is not None else {})}[purpose]
        if purpose == "memory-service-enablement":
            name = "resolve_current_memory_service_enablement_choice"
        elif purpose == "native-policy-preparation":
            name = "resolve_current_native_policy_configuration_choice"
        elif purpose == "public-free-web-read":
            name = "resolve_current_public_web_permission_choice"
        else:
            name = "resolve_application_setup_choice"
        resolver = getattr(selection, name, None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.session", "resumed setup has no typed purpose resolver")
        try:
            choice = resolver(handle)
        except Exception:
            raise AuthorityDenied("setup-choice.session", "persisted choice is not retained by the resumed session") from None
        if type(choice) is not expected:
            raise AuthorityDenied("setup-choice.session", "purpose resolver returned another choice type")
        return choice

    def _current_private_profile_matches(self, selection: Any, choice: Any) -> bool:
        resolver = getattr(selection, "resolve_current_private_profile", None)
        if not callable(resolver):
            return False
        try:
            current = resolver(choice.private_profile_selection_handle,
                               purpose="memory-service-enablement")
        except Exception:
            return False
        return (getattr(current, "selection_handle", None) == choice.private_profile_selection_handle
                and getattr(current, "profile_id", None) == choice.profile_id
                and getattr(current, "receipt_handle", None) == choice.private_profile_selection_receipt_handle)

    def _current_private_profile_receipt_handle(self, selection: Any, choice: Any) -> str:
        resolver = getattr(selection, "resolve_current_private_profile", None)
        if not callable(resolver):
            raise AuthorityDenied("setup-choice.profile", "current private profile selector is unavailable")
        try:
            current = resolver(choice.private_profile_selection_handle,
                               purpose="memory-service-enablement")
        except Exception:
            raise AuthorityDenied("setup-choice.profile", "current private profile selection is stale") from None
        if (getattr(current, "selection_handle", None) != choice.private_profile_selection_handle
                or getattr(current, "profile_id", None) != choice.profile_id):
            raise AuthorityDenied("setup-choice.profile", "current private profile selector changed")
        receipt = getattr(current, "receipt_handle", None)
        if not isinstance(receipt, str) or not receipt:
            raise AuthorityDenied("setup-choice.profile", "current private profile receipt handle is malformed")
        return receipt

    def _sign(self, row: Mapping[str, Any]) -> str:
        unsigned = {key: value for key, value in row.items() if key != "signature"}
        signature = self.signer.sign_choice(str(row["purpose"]), _canonical(unsigned))
        if not isinstance(signature, str) or len(signature) != 64:
            raise AuthorityDenied("setup-choice.signature", "existing root key signer returned an invalid signature")
        return signature

    def _verify_row(self, row: Mapping[str, Any]) -> None:
        if not isinstance(row, Mapping) or set(row) != _RECORD_FIELDS:
            raise AuthorityDenied("setup-choice.record", "persisted setup choice fields are invalid")
        if (row["schema"] != 1 or row["purpose"] not in _DOMAIN_PURPOSES
                or row["key_id"] != self.signer.key_id
                or not isinstance(row["release_deployment_receipt_sha256"], str)
                or len(row["release_deployment_receipt_sha256"]) != 64
                or any(c not in "0123456789abcdef" for c in row["release_deployment_receipt_sha256"])
                or row["selection_handle"] == ""
                or row["choice_payload_sha256"] != _digest(row["choice_payload"])
                or type(row["choice_epoch"]) is not int or row["choice_epoch"] < 1
                or type(row["revocation_epoch"]) is not int or row["revocation_epoch"] < 1
                or not isinstance(row["source_member_receipt_handles"], list)
                or row["source_member_receipt_handles"] != sorted(set(row["source_member_receipt_handles"]))
                or row["adoption_publication_receipt_handle"] is not None):
            raise AuthorityDenied("setup-choice.record", "persisted setup choice is malformed or not adoptable")
        unsigned = {key: value for key, value in row.items() if key != "signature"}
        try:
            valid = self.signer.verify_choice(row["purpose"], _canonical(unsigned), row["signature"])
        except Exception:
            valid = False
        if valid is not True:
            raise AuthorityDenied("setup-choice.signature", "persisted setup choice signature is invalid")

    def _verify_stored_rows(self) -> None:
        if any(not isinstance(handle, str) or row.get("selection_handle") != handle
               for handle, row in self._rows.items()):
            raise AuthorityDenied("setup-choice.store", "setup choice store keys are malformed")
        for row in self._rows.values():
            self._verify_row(row)

    def _revoke_row(self, handle: str, row: dict[str, Any]) -> None:
        row["revocation_epoch"] += 1
        row["choice_epoch"] += 1
        row["signature"] = self._sign(row)

    def _revoke_purpose(self, purpose: str, profile_id: str) -> None:
        with self._lock:
            for handle, row in self._rows.items():
                payload = row.get("choice_payload", {})
                candidate_profile = payload.get("profile_id", payload.get("service_profile_id", payload.get("target_profile_id")))
                if row.get("purpose") == purpose and candidate_profile == profile_id:
                    self._revoke_row(handle, row)
                    self._live_choices.pop(handle, None)
            self._save()

    def _save(self) -> None:
        self._store.save(self._rows)


def _memory_choice_payload(choice: Any) -> dict[str, Any]:
    return {
        "choice_handle": choice.choice_handle,
        "choice_observation_id": choice.choice_observation_id,
        "provider": choice.provider,
        "backend_variant": choice.backend_variant,
        "enabled": choice.enabled,
        "principal_id": choice.principal_id,
        "profile_id": choice.profile_id,
        "namespace_id": choice.namespace_id,
        "principal_binding_sha256": choice.principal_binding_sha256,
        "namespace_binding_sha256": choice.namespace_binding_sha256,
        "private_profile_selection_handle": choice.private_profile_selection_handle,
        "controller_binding_handle": choice.controller_binding_handle,
        "policy_revision": choice.policy_revision,
        "selection_digest": choice.selection_digest,
    }


def _replace_revocation_signature(
        receipt: RootSetupChoiceRevocationReceipt, signature: str
        ) -> RootSetupChoiceRevocationReceipt:
    from dataclasses import replace
    if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
        raise AuthorityDenied("setup-choice.revocation", "root key signer returned an invalid signature")
    return replace(receipt, signature=signature)


def _commit_revocation_index_entry(store: Any, selection_handle: str,
                                  entry: Mapping[str, Any]) -> None:
    """CAS one revocation under the root journal's cross-process file lock."""
    if (not isinstance(selection_handle, str) or not selection_handle
            or not isinstance(entry, Mapping)):
        raise AuthorityDenied("setup-choice.revocation", "revocation journal update is malformed")
    directory_fd = store._open_store_directory()
    try:
        lock_fd = os.open(".lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                          0o600, dir_fd=directory_fd)
        try:
            info = os.fstat(lock_fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise AuthorityDenied("setup-choice.revocation", "root revocation lock is not protected")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            current = store.load()
            if selection_handle in current:
                raise AuthorityDenied("setup-choice.revocation", "choice already has a committed revocation")
            updated = dict(current)
            updated[selection_handle] = dict(entry)
            data = _canonical({"schema": 1, "profiles": updated})
            if len(data) > 1_048_576:
                raise AuthorityDenied("setup-choice.revocation", "revocation journal reached its protected bound")
            temp_name = ".revocations-" + secrets.token_hex(16)
            try:
                out_fd = os.open(temp_name, os.O_CREAT | os.O_EXCL | os.O_WRONLY
                                 | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory_fd)
                try:
                    os.fchmod(out_fd, 0o600)
                    offset = 0
                    while offset < len(data):
                        offset += os.write(out_fd, data[offset:])
                    os.fsync(out_fd)
                finally:
                    os.close(out_fd)
                os.rename(temp_name, store.file.name,
                          src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
                os.fsync(directory_fd)
            finally:
                try:
                    os.unlink(temp_name, dir_fd=directory_fd)
                except FileNotFoundError:
                    pass
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory_fd)


def _choice_profile_id(choice: Any, purpose: str) -> str | None:
    if purpose == "memory-service-enablement":
        return getattr(choice, "profile_id", None)
    if purpose == "public-free-web-read":
        return getattr(choice, "profile_id", None)
    if purpose == "native-policy-preparation":
        return getattr(choice, "service_profile_id", None)
    if purpose == "application-qualification":
        return getattr(choice, "target_profile_id", None)
    if purpose == "existing-model-selection":
        return getattr(choice, "target_profile_id", None)
    return None


def _choice_profile_id_from_payload(payload: Mapping[str, Any], purpose: str) -> str | None:
    """Read the purpose-specific profile field from the canonical signed row."""
    field_by_purpose = {
        "memory-service-enablement": "profile_id",
        "public-free-web-read": "profile_id",
        "native-policy-preparation": "service_profile_id",
        "application-qualification": "target_profile_id",
        "existing-model-selection": "target_profile_id",
    }
    field = field_by_purpose.get(purpose)
    value = payload.get(field) if field is not None else None
    return value if isinstance(value, str) and value else None


def _public_web_choice_payload(choice: Any) -> dict[str, Any]:
    """Preserve exact v142 scope bytes in the durable signed choice record."""
    payload = _dataclass_choice_payload(
        choice, {"_issuer_token", "scope_payloads"})
    scope_ids = payload.get("web_scope_ids")
    scope_bytes = getattr(choice, "scope_payloads", None)
    digests = payload.get("scope_payload_sha256s")
    if (not isinstance(scope_ids, list) or not scope_ids
            or scope_ids != sorted(set(scope_ids))
            or not isinstance(scope_bytes, tuple) or len(scope_bytes) != len(scope_ids)
            or not isinstance(digests, list) or len(digests) != len(scope_ids)):
        raise AuthorityDenied("setup-choice.public-scope", "public scope choice is empty or malformed")
    decoded: list[dict[str, Any]] = []
    for scope_id, raw, expected_digest in zip(scope_ids, scope_bytes, digests):
        if type(raw) is not bytes or hashlib.sha256(raw).hexdigest() != expected_digest:
            raise AuthorityDenied("setup-choice.public-scope", "public scope bytes or digest are invalid")
        try:
            row = json.loads(raw.decode("utf-8", "strict"))
        except Exception:
            raise AuthorityDenied("setup-choice.public-scope", "public scope payload is invalid JSON") from None
        if (type(row) is not dict or row.get("enrollment_id") != scope_id
                or _canonical(row) != raw):
            raise AuthorityDenied("setup-choice.public-scope", "public scope bytes are not canonical or do not match the ID")
        decoded.append(row)
    payload["scope_payloads"] = decoded
    _validate_public_choice_parallel_fields(choice, len(scope_ids))
    return payload


def _validate_public_choice_parallel_fields(choice: Any, count: int) -> None:
    names = (
        "target_selection_handles", "scope_payload_sha256s",
        "configuration_observation_handles", "configuration_sha256s",
        "target_contract_artifact_ids", "target_contract_sha256s",
        "target_contract_source_receipt_handles",
    )
    for name in names:
        values = getattr(choice, name, None)
        if (not isinstance(values, tuple) or len(values) != count
                or not all(isinstance(value, str) and value for value in values)):
            raise AuthorityDenied("setup-choice.public-scope", f"public scope provenance {name} is malformed")
    if (tuple(sorted(set(choice.target_selection_handles))) != choice.target_selection_handles
            or len(set(choice.target_selection_handles)) != count):
        raise AuthorityDenied("setup-choice.public-scope", "target selection handles are not canonical")


def _memory_choice_matches(row: Mapping[str, Any], choice: Any) -> bool:
    return (row["purpose"] == "memory-service-enablement"
            and row["choice_payload"] == _memory_choice_payload(choice)
            and row["prepared_generation"] == choice.prepared_generation_id
            and row["principal_selection_handle"] == choice.principal_selection_handle
            and row["namespace_selection_handle"] == choice.namespace_selection_handle)


def _choice_matches_row(row: Mapping[str, Any], choice: Any) -> bool:
    purpose = row["purpose"]
    if purpose == "memory-service-enablement":
        return _memory_choice_matches(row, choice)
    if purpose == "public-free-web-read":
        if (f"{type(choice).__module__}.{type(choice).__qualname__}"
                != "hermes_installer.authority.public_web_selection.RootSelectedPublicWebPermissionChoice"):
            return False
        try:
            payload = _public_web_choice_payload(choice)
        except AuthorityDenied:
            return False
        return (row["choice_payload"] == payload
                and row["prepared_generation"] == choice.prepared_generation_id
                and row["principal_selection_handle"] == choice.principal_selection_handle
                and row["namespace_selection_handle"] == choice.namespace_selection_handle)
    expected = {
        "native-policy-preparation": "native_policy_preparation.RootNativePolicyConfigurationChoice",
        "application-qualification": "bootstrap_runtime_factory.RootSelectedApplicationQualificationChoice",
    }.get(purpose)
    if expected is None or f"{type(choice).__module__}.{type(choice).__qualname__}" != expected:
        return False
    excluded = {"_seal"} if purpose == "native-policy-preparation" else {"_session_seal"}
    payload = _dataclass_choice_payload(choice, excluded)
    return (row["choice_payload"] == payload
            and row["prepared_generation"] == getattr(choice, "prepared_generation_id", None)
            and row["principal_selection_handle"] == getattr(choice, "principal_selection_handle", None)
            and row["namespace_selection_handle"] == getattr(choice, "namespace_selection_handle", None))


def _dataclass_choice_payload(choice: Any, excluded: set[str]) -> dict[str, Any]:
    from dataclasses import fields
    result: dict[str, Any] = {}
    for item in fields(choice):
        if item.name in excluded or item.name.startswith("_"):
            continue
        value = getattr(choice, item.name)
        if isinstance(value, tuple):
            value = list(value)
        if value is None or isinstance(value, (str, int, float, bool, list, dict)):
            result[item.name] = value
        else:
            raise AuthorityDenied("setup-choice.payload", "typed TTY choice contains unsupported durable payload data")
    return result


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()
