"""One-use root foreground-TTY observations for adopted choice revocation.

The observer preserves operator intent only. Durable mutation remains the
existing RootSetupChoiceRegistry/AuthorityService signing facade's job.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

_SEAL = object()
_TTL = 30.0


class RootRuntimeForegroundTTYDenied(PermissionError):
    """A runtime root TTY action is absent, stale, or belongs to another choice."""


@dataclass(frozen=True, slots=True, repr=False)
class RootObservedAdoptedChoiceRevocation:
    schema: int
    revocation_observation_handle: str
    selection_handle: str
    purpose: str
    consent_id: str | None
    source_choice_row_sha256: str
    choice_epoch: int
    revocation_epoch: int
    active_publication_receipt_handle: str
    service_generation_digest: str
    principal_id: str
    profile_id: str
    namespace_id: str
    owner_generation: str
    displayed_payload_sha256: str
    root_actor_observation_handle: str
    tty_controller_observation_handle: str
    action: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if self._seal is not _SEAL or self.schema != 1 or self.action != "revoke-adopted-choice":
            raise TypeError("runtime revocation observations are issued by the foreground root TTY")
        for name in ("selection_handle", "purpose", "source_choice_row_sha256",
                     "active_publication_receipt_handle", "service_generation_digest",
                     "principal_id", "profile_id", "namespace_id", "owner_generation",
                     "displayed_payload_sha256", "root_actor_observation_handle",
                     "tty_controller_observation_handle"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError("runtime revocation observation has a missing binding")
        if (self.consent_id is not None and (type(self.consent_id) is not str
                or not self.consent_id)
                or type(self.choice_epoch) is not int or type(self.revocation_epoch) is not int
                or self.choice_epoch < 1 or self.revocation_epoch < 0
                or not (self.issued_monotonic <= time.monotonic() < self.expires_monotonic)
                or self.expires_monotonic - self.issued_monotonic > _TTL):
            raise ValueError("runtime revocation observation is malformed or expired")

    def __repr__(self) -> str:
        return "RootObservedAdoptedChoiceRevocation(<root-private>)"


class RootRuntimeForegroundTTYObserver:
    """Retain genuine root actor + foreground controlling-TTY action proofs."""

    def __init__(self, *, verified_installer_release: Any,
                 current_installed_actor_verifier: Any, active_bindings: Any,
                 root_journal: Any) -> None:
        from .installer_release import VerifiedInstallerReleaseReceipt, RootActorObservation
        from .runtime_bindings import RootRuntimeBindings
        from ..protected_enrollment import RootJournalSelection
        if (os.geteuid() != 0 or type(verified_installer_release) is not VerifiedInstallerReleaseReceipt
                or type(current_installed_actor_verifier) is not RootActorObservation
                or type(active_bindings) is not RootRuntimeBindings
                or type(root_journal) is not RootJournalSelection):
            raise RootRuntimeForegroundTTYDenied("installed root actor, release, active bindings, and journal are required")
        verified_installer_release.verify_current()
        current_installed_actor_verifier.verify_current(verified_installer_release)
        if getattr(active_bindings, "root_setup_choice_registry", None) is None:
            raise RootRuntimeForegroundTTYDenied("runtime adopted-choice resolver is unavailable")
        self._release = verified_installer_release
        self._actor = current_installed_actor_verifier
        self._bindings = active_bindings
        self._journal = root_journal
        self._registry = active_bindings.root_setup_choice_registry
        self._records: dict[str, tuple[RootObservedAdoptedChoiceRevocation, Any]] = {}
        self._consumed: set[str] = set()

    @classmethod
    def from_root_runtime(cls, *, verified_installer_release: Any,
                          current_installed_actor_verifier: Any,
                          active_bindings: Any, root_journal: Any
                          ) -> "RootRuntimeForegroundTTYObserver":
        return cls(verified_installer_release=verified_installer_release,
                   current_installed_actor_verifier=current_installed_actor_verifier,
                   active_bindings=active_bindings, root_journal=root_journal)

    def observe_adopted_choice_revocation(self, adopted_choice_selection: Any
                                          ) -> RootObservedAdoptedChoiceRevocation:
        selection = self._resolve_exact(adopted_choice_selection)
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            self._check_runtime_identity()
            _verify_root_tty_proof(proof)
            tty_handle = _tty_digest(proof)
            actor_handle = _actor_digest(self._actor)
            payload = _display_payload(selection)
            digest = hashlib.sha256(_canonical(payload)).hexdigest()
            os.write(2, ("\nDurable adopted-choice revocation\n" +
                json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) +
                "\nThis permanently revokes the current choice for this profile. "
                "Type REVOKE to proceed; blank or any other response denies: ").encode("utf-8"))
            from .public_web_selection import _read_tty_line
            if _read_tty_line(proof.stdin_fd, max_bytes=64) != b"REVOKE":
                raise RootRuntimeForegroundTTYDenied("adopted choice revocation was not confirmed")
            _verify_root_tty_proof(proof)
            self._check_runtime_identity()
            current = self._resolve_exact(selection)
            if not _same_selection(current, selection):
                raise RootRuntimeForegroundTTYDenied("adopted choice changed during TTY action")
            now = time.monotonic()
            record = RootObservedAdoptedChoiceRevocation(
                schema=1, revocation_observation_handle=secrets.token_hex(32),
                selection_handle=selection.selection_handle, purpose=selection.purpose,
                consent_id=selection.consent_id,
                source_choice_row_sha256=selection.source_choice_row_sha256,
                choice_epoch=selection.choice_epoch, revocation_epoch=selection.revocation_epoch,
                active_publication_receipt_handle=selection.active_publication_receipt_handle,
                service_generation_digest=selection.service_generation_digest,
                principal_id=_subject(selection, "principal_id"),
                profile_id=_subject(selection, "profile_id"),
                namespace_id=_subject(selection, "namespace_id"),
                owner_generation=_owner_generation(selection),
                displayed_payload_sha256=digest, root_actor_observation_handle=actor_handle,
                tty_controller_observation_handle=tty_handle, action="revoke-adopted-choice",
                issued_monotonic=now, expires_monotonic=now + _TTL, _seal=_SEAL,
            )
            self._records[record.revocation_observation_handle] = (record, selection)
            return record
        except RootRuntimeForegroundTTYDenied:
            raise
        except Exception:
            raise RootRuntimeForegroundTTYDenied("current root TTY, actor, or adopted choice is unavailable") from None
        finally:
            proof.close()

    def resolve_current_revocation(self, observation_handle: str,
                                   expected_selection: Any) -> RootObservedAdoptedChoiceRevocation:
        record = self._lookup(observation_handle, expected_selection, require_unconsumed=True)
        self._check_runtime_identity()
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            if _tty_digest(proof) != record.tty_controller_observation_handle:
                raise RootRuntimeForegroundTTYDenied("foreground controlling TTY changed")
        finally:
            proof.close()
        return record

    def consume_current_revocation(self, observation_handle: str,
                                   expected_selection: Any) -> RootObservedAdoptedChoiceRevocation:
        record = self.resolve_current_revocation(observation_handle, expected_selection)
        self._consumed.add(observation_handle)
        return record

    def resolve_observation_selection(self, observation_handle: str) -> Any:
        """Return the exact retained adopted selection for signer-side lookup.

        Callers provide only the opaque observation handle. The observer
        rechecks current installed-root identity, current source row/epoch,
        original TTY controller, TTL, and one-use state before returning the
        same sealed selection object retained when the operator acted.
        """
        pair = self._records.get(observation_handle)
        if pair is None:
            raise RootRuntimeForegroundTTYDenied("revocation observation is absent")
        record, selection = pair
        self._lookup(observation_handle, selection, require_unconsumed=True)
        self._check_runtime_identity()
        from ..root_setup import _capture_root_tty_proof, _verify_root_tty_proof
        proof = _capture_root_tty_proof()
        try:
            _verify_root_tty_proof(proof)
            if (_tty_digest(proof) != record.tty_controller_observation_handle
                    or _actor_digest(self._actor) != record.root_actor_observation_handle):
                raise RootRuntimeForegroundTTYDenied("root actor or foreground TTY changed")
        finally:
            proof.close()
        # Return the exact identity held at capture, never a newly projected
        # object supplied by the caller.
        return selection

    def is_bound_to(self, registry: Any, bindings: Any) -> bool:
        """Check exact composition identity without exposing private members."""
        return (type(self) is RootRuntimeForegroundTTYObserver
                and self._registry is registry and self._bindings is bindings)

    def verify_consumed_revocation(self, observation_handle: str,
                                   expected_selection: Any) -> bool:
        if observation_handle not in self._consumed:
            return False
        try:
            self._lookup(observation_handle, expected_selection, require_unconsumed=False)
            self._check_runtime_identity()
            return True
        except Exception:
            return False

    def _lookup(self, handle: str, expected: Any, *, require_unconsumed: bool
                ) -> RootObservedAdoptedChoiceRevocation:
        pair = self._records.get(handle)
        if (pair is None or (require_unconsumed and handle in self._consumed)
                or type(pair[0]) is not RootObservedAdoptedChoiceRevocation
                or pair[0]._seal is not _SEAL or pair[1] is not expected):
            raise RootRuntimeForegroundTTYDenied("revocation observation is absent, consumed, or mismatched")
        record = pair[0]
        if not (record.issued_monotonic <= time.monotonic() < record.expires_monotonic):
            raise RootRuntimeForegroundTTYDenied("revocation observation expired")
        current = self._resolve_exact(expected)
        if not _same_selection(current, expected):
            raise RootRuntimeForegroundTTYDenied("adopted choice source row, owner, or epoch changed")
        return record

    def _resolve_exact(self, selection: Any) -> Any:
        from .root_setup_choices import RootAdoptedSetupChoiceSelection
        if type(selection) is not RootAdoptedSetupChoiceSelection:
            raise RootRuntimeForegroundTTYDenied("exact adopted choice projection is required")
        resolver = getattr(self._registry, "resolve_current_adopted_choice_snapshot", None)
        if not callable(resolver):
            raise RootRuntimeForegroundTTYDenied("runtime adopted choice resolver is unavailable")
        current = resolver(selection.selection_handle, selection.purpose)
        if type(current) is not RootAdoptedSetupChoiceSelection or not _same_selection(current, selection):
            raise RootRuntimeForegroundTTYDenied("adopted choice is no longer current")
        return current

    def _check_runtime_identity(self) -> None:
        self._release.verify_current()
        self._actor.verify_current(self._release)
        service = getattr(self._registry, "service", None)
        if (os.geteuid() != 0
                or not isinstance(getattr(self._bindings, "service_generation_digest", None), str)
                or getattr(service, "service_generation_digest", None)
                    != self._bindings.service_generation_digest):
            raise RootRuntimeForegroundTTYDenied("installed root runtime identity changed")


def _same_selection(left: Any, right: Any) -> bool:
    names = ("selection_handle", "purpose", "consent_id", "source_choice_row_sha256",
             "choice_epoch", "revocation_epoch", "active_publication_receipt_handle",
             "service_generation_digest", "principal_selection_handle",
             "namespace_selection_handle", "choice_payload_sha256")
    return all(getattr(left, name, None) == getattr(right, name, None) for name in names)


def _subject(selection: Any, name: str) -> str:
    payload = getattr(selection, "choice_payload", {})
    value = payload.get(name)
    if not isinstance(value, str) or not value:
        raise RootRuntimeForegroundTTYDenied("signed choice does not bind the required subject")
    return value


def _owner_generation(selection: Any) -> str:
    payload = getattr(selection, "choice_payload", {})
    value = payload.get("owner_generation", payload.get(
        "profile_generation", getattr(selection, "prepared_generation", None)))
    if not isinstance(value, str) or not value:
        raise RootRuntimeForegroundTTYDenied("signed choice does not bind its owner generation")
    return value


def _display_payload(selection: Any) -> dict[str, Any]:
    return {"purpose": selection.purpose, "profile_id": _subject(selection, "profile_id"),
            "namespace_id": _subject(selection, "namespace_id"),
            "principal_id": _subject(selection, "principal_id"),
            "owner_generation": _owner_generation(selection),
            "selection_handle": selection.selection_handle,
            "consent_id": selection.consent_id,
            "source_choice_row_sha256": selection.source_choice_row_sha256,
            "choice_epoch": selection.choice_epoch,
            "revocation_epoch": selection.revocation_epoch,
            "active_publication_receipt_handle": selection.active_publication_receipt_handle,
            "service_generation_digest": selection.service_generation_digest}


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _tty_digest(proof: Any) -> str:
    return "tty-" + hashlib.sha256(_canonical({
        "pid": proof.controller_pid, "start_ticks": proof.controller_start_ticks,
        "uid": proof.controller_uid, "gid": proof.controller_gid,
        "session": proof.session_id, "process_group": proof.process_group_id,
        "device": proof.tty_device, "inode": proof.tty_inode,
        "rdevice": proof.tty_rdevice,
    })).hexdigest()


def _actor_digest(actor: Any) -> str:
    return "actor-" + hashlib.sha256(_canonical({
        "pid": actor.pid, "uid": actor.uid, "gid": actor.gid,
        "start_time": actor.start_time,
        "release_commit": getattr(actor, "release_commit", None),
    })).hexdigest()
