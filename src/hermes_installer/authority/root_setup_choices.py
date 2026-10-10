"""Durable root-signed source choices from the normal setup TTY.

These signed rows preserve installer intent only. Runtime grants, memory
capture consent and public-input permissions are still minted by their own
active registries after the publisher adopts the choice.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
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


class RootSetupChoiceRegistry:
    """Persist exact root TTY choices using the already selected authority key."""

    def __init__(self, verified_installer_release: Any, current_actor_verifier: Any,
                 root_setup_session_store: Any, root_journal: Any,
                 selected_choice_signer: Any):
        if os.geteuid() != 0:
            raise AuthorityDenied("setup-choice.root", "durable setup choices require the installed root process")
        from .installer_release import VerifiedInstallerReleaseReceipt
        from ..protected_enrollment import RootJournalSelection
        if (type(verified_installer_release) is not VerifiedInstallerReleaseReceipt
                or not callable(getattr(verified_installer_release, "verify_current", None))
                or not callable(getattr(current_actor_verifier, "verify_current", None))
                or not callable(getattr(root_setup_session_store, "_handle_for_session", None))
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
        self._store = _ProtectedStore(root_journal, "setup-choices", None)
        self._rows: dict[str, dict[str, Any]] = self._store.load()
        self._lock = threading.RLock()
        self._registry_seal = _SEAL
        self._live_choices: dict[str, tuple[Any, Any]] = {}
        self._check_release()
        self._verify_stored_rows()

    @classmethod
    def from_root_setup(cls, verified_installer_release: Any,
                        current_actor_verifier: Any, root_setup_session_store: Any,
                        root_journal: Any, selected_choice_signer: Any) -> "RootSetupChoiceRegistry":
        return cls(verified_installer_release, current_actor_verifier,
                   root_setup_session_store, root_journal, selected_choice_signer)

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
        catalog without reading this registry's private row map. Stale, expired,
        revoked, or not-yet-reattached choices are omitted; malformed stored
        signatures still fail closed through `_verify_row`.
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
                continue
            try:
                snapshot = self.resolve_current_setup_choice(handle, row["purpose"])
            except AuthorityDenied:
                continue
            current.append(snapshot)
        return tuple(current)

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
        # Check the independent active publisher proof first. It binds this
        # setup choice to the current published generation and remains valid
        # after the setup TTY lease expires; no setup lease is renewed here.
        try:
            current = receipt.verify_current()
        except Exception:
            raise AuthorityDenied("setup-choice.adoption", "publisher adoption is not current") from None
        if current is not receipt:
            raise AuthorityDenied("setup-choice.adoption", "publisher adoption resolver returned another receipt")
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
        if time.time() >= row["setup_deadline_unix"]:
            raise AuthorityDenied("setup-choice.expired", "expired setup intent cannot be adopted")
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
