"""Root-only AuthorityService receipts for selected HTTP and audio ingress.

The adapter does not turn a token, URL, PCM buffer, or caller-supplied receipt
into authority. It accepts only values produced at the selected root listener
or capture seam, binds them to a current resource-controller proof, and asks
the attached resource event issuer for the short-lived signed parent context.
Receipt handles are retained only in the AuthorityService root registry.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from dataclasses import replace
from typing import Any, Mapping

from hermes_installer.authority.channel_provenance import AuthenticatedSubjectReceipt
from hermes_installer.authority.source_observers import SourceReceiptHandle
from hermes_installer.authority.types import HostContext, SourceReceipt, canonical_digest
from hermes_installer.components.plugin_channel_provenance import HttpIngressSelection


class NativeInputReceiptDenied(PermissionError):
    """The selected native-input receipt could not be issued or resolved."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class AuthorityServiceNativeInputReceiptIssuer:
    """Issue actual signed parent receipts from listener/session observations.

    ``producer_capability`` and ``controller_proof`` are root-only objects from
    the source producer registration and retained ingress custody resolver.
    They are never accepted per call. The issuer calls the event issuer's
    selected-context seam immediately before each receipt mint, so stale
    controller selection or AuthorityService context fails closed.
    """

    def __init__(self, service: Any, event_issuer: Any, *, producer_capability: object,
                 controller_proof: object, selection: HttpIngressSelection,
                 selection_handle: object,
                 monotonic=time.monotonic):
        if (service is None or producer_capability is None or controller_proof is None
                or not isinstance(selection, HttpIngressSelection) or selection_handle is None
                or not callable(getattr(event_issuer, "prepare_source_parent_context", None))
                or not callable(getattr(service, "issue_source_receipt", None))
                or not isinstance(getattr(service, "_source_receipt_handles", None), dict)
                or not hasattr(service, "_lock")):
            raise TypeError("selected root issuer, AuthorityService receipt store and controller proof are required")
        self.service, self.event_issuer = service, event_issuer
        self.producer_capability, self.controller_proof = producer_capability, controller_proof
        self.selection, self.selection_handle, self.monotonic = selection, selection_handle, monotonic
        self._subjects: dict[str, tuple[AuthenticatedSubjectReceipt | None, SourceReceiptHandle, str, float]] = {}
        self._lock = threading.RLock()

    def issue_subject_source_receipt(self, *, selection: HttpIngressSelection,
                                     session_id: str, subject_digest: str,
                                     token_fingerprint: str,
                                     source_payload: Mapping[str, Any],
                                     expires_monotonic: float) -> SourceReceiptHandle:
        if (selection is not self.selection or not _safe_id(session_id)
                or not _sha(subject_digest) or not _sha(token_fingerprint)
                or not isinstance(source_payload, Mapping)
                or type(expires_monotonic) not in (int, float)
                or expires_monotonic <= self.monotonic()):
            raise NativeInputReceiptDenied("JWT observation does not match the selected root enrollment")
        expected = {"schema": 1, "selection_id": selection.id,
                    "session_id": session_id, "subject_digest": subject_digest,
                    "token_fingerprint": token_fingerprint,
                    "profile_id": selection.profile_id}
        if dict(source_payload) != expected:
            raise NativeInputReceiptDenied("JWT receipt payload differs from verified claims")
        receipt_handle = self._issue_receipt(
            payload=_canonical(expected),
            origin_suffix=f"jwt-subject:{session_id}:{token_fingerprint}",
            ttl_seconds=min(60, max(1, int(expires_monotonic - self.monotonic()))),
        )
        receipt = self._resolve(receipt_handle)
        if (receipt.payload_digest != canonical_digest(expected)
                or receipt.source_kind != "native-input"
                or receipt.profile_id != selection.profile_id):
            self._revoke(receipt_handle)
            raise NativeInputReceiptDenied("AuthorityService receipt does not bind the JWT observation")
        # The caller (JWT authority) will install the corresponding session
        # object. Retain its direct handle here for the following request join.
        with self._lock:
            self._prune_subjects_locked()
            if session_id not in self._subjects and len(self._subjects) >= 1024:
                self._revoke(receipt_handle)
                raise NativeInputReceiptDenied("root JWT subject receipt table is full")
            previous = self._subjects.get(session_id)
            if previous is not None:
                self._revoke(previous[1])
            self._subjects[session_id] = (None, receipt_handle, subject_digest, float(expires_monotonic))
        return receipt_handle

    def bind_subject_session(self, session_id: str,
                             subject: AuthenticatedSubjectReceipt) -> None:
        """Bind the root verifier's returned opaque session to its signed receipt."""
        if not _safe_id(session_id) or type(subject) is not AuthenticatedSubjectReceipt:
            raise NativeInputReceiptDenied("authenticated subject session is malformed")
        with self._lock:
            row = self._subjects.get(session_id)
            if (row is None or row[1] != subject.receipt_handle
                    or row[2] != subject.subject_digest
                    or subject.expires_monotonic > row[3]):
                raise NativeInputReceiptDenied("JWT session has no matching signed root receipt")
            self._subjects[session_id] = (subject, row[1], row[2], row[3])

    def issue_request_source_receipt(self, selection_handle: object, session_handle: str,
                                     subject_receipt_handle: str, body: bytes) -> SourceReceiptHandle:
        if (selection_handle is not self.selection_handle
                or not _safe_id(session_handle)
                or not isinstance(subject_receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", subject_receipt_handle)
                or not isinstance(body, bytes) or not 1 <= len(body) <= self.selection.max_body_bytes):
            raise NativeInputReceiptDenied("request observation is malformed or outside selected bounds")
        with self._lock:
            self._prune_subjects_locked()
            session = next((row for row in self._subjects.values()
                            if row[0] is not None and row[0].session_handle == session_handle
                            and row[1] == subject_receipt_handle), None)
        if session is None or session[0].expires_monotonic <= self.monotonic():
            raise NativeInputReceiptDenied("request has no current selected JWT subject receipt")
        parent = self._resolve(session[1])
        if (parent.source_kind != "native-input"
                or parent.profile_id != self.selection.profile_id):
            raise NativeInputReceiptDenied("JWT parent receipt is stale or request body was confused with it")
        handle = self._issue_receipt(
            payload=body,
            origin_suffix=f"http-request:{session_handle}:{hashlib.sha256(body).hexdigest()}",
            ttl_seconds=min(30, max(1, int(session[0].expires_monotonic - self.monotonic()))),
            parent_receipts=(parent,),
        )
        request = self._resolve(handle)
        if (request.payload_digest != hashlib.sha256(body).hexdigest()
                or request.parent_receipt_ids != (parent.receipt_id,)):
            self._revoke(handle)
            raise NativeInputReceiptDenied("AuthorityService request receipt has incorrect ancestry")
        return handle

    def _issue_receipt(self, *, payload: bytes, origin_suffix: str, ttl_seconds: int,
                       parent_receipts: tuple[SourceReceipt, ...] = ()) -> SourceReceiptHandle:
        context = self.event_issuer.prepare_source_parent_context(
            self.producer_capability, self.controller_proof, source_payload=payload)
        if type(context) is not HostContext:
            raise NativeInputReceiptDenied("resource issuer did not provide a signed selected parent context")
        self.service._verify_context_signature(context)
        self.service._assert_current_context(context, self.service._binding(context.uid), context.uid)
        if parent_receipts:
            context = replace(context, source_receipts=parent_receipts,
                              monotonic_expires_at=min(context.monotonic_expires_at,
                                                       *(row.monotonic_expires_at for row in parent_receipts)),
                              signature="pending")
            context = HostContext.from_wire(self.service._signed_context(
                context, self.service._sign(context.claims())))
            if context.monotonic_expires_at <= self.monotonic():
                raise NativeInputReceiptDenied("selected source parent lease has expired")
        receipt = self.service.issue_source_receipt(
            context, source_kind="native-input",
            origin_id=f"{self.selection.source_issuer_id}:{origin_suffix}"[:256],
            payload=payload, ttl_seconds=ttl_seconds)
        handle = SourceReceiptHandle(__import__("secrets").token_urlsafe(32))
        with self.service._lock:
            if handle in self.service._source_receipt_handles:
                raise NativeInputReceiptDenied("AuthorityService receipt handle collision")
            self.service._source_receipt_handles[str(handle)] = receipt
        return handle

    def _resolve(self, handle: SourceReceiptHandle) -> SourceReceipt:
        with self.service._lock:
            receipt = self.service._source_receipt_handles.get(str(handle))
        if type(receipt) is not SourceReceipt:
            raise NativeInputReceiptDenied("source receipt is not retained by AuthorityService")
        self.service._verify_source_receipt(receipt, self.service._binding(receipt.uid))
        if (receipt.profile_id != self.selection.profile_id
                or receipt.process_generation != self.service.profile_generations.get(
                    self.selection.profile_id, "unversioned")
                or receipt.monotonic_expires_at <= self.monotonic()):
            raise NativeInputReceiptDenied("source receipt is stale or from another selected profile")
        return receipt

    def _revoke(self, handle: SourceReceiptHandle) -> None:
        with self.service._lock:
            self.service._source_receipt_handles.pop(str(handle), None)

    def _prune_subjects_locked(self) -> None:
        now = self.monotonic()
        expired = [key for key, row in self._subjects.items() if row[3] <= now]
        for key in expired:
            row = self._subjects.pop(key)
            self._revoke(row[1])


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and all(ord(c) >= 0x21 for c in value)


def _sha(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None
