from __future__ import annotations

import hashlib
import threading
import time
from dataclasses import replace

import pytest

from hermes_installer.authority.channel_provenance import AuthenticatedSubjectReceipt
from hermes_installer.authority.native_input_sessions import (
    AuthorityServiceNativeInputReceiptIssuer, NativeInputReceiptDenied,
)
from hermes_installer.authority.source_observers import SourceReceiptHandle
from hermes_installer.authority.types import HostContext, Sensitivity, SourceReceipt, canonical_digest
from hermes_installer.components.plugin_channel_provenance import HttpIngressSelection


class _Binding:
    uid = 501
    principal_id = "principal-001"
    profile_id = "profile-001"


class _AuthorityFixture:
    def __init__(self):
        self._lock = threading.RLock()
        self._source_receipt_handles = {}
        self.bindings_by_uid = {501: _Binding()}
        self.profile_generations = {"profile-001": "generation-001"}
        self.monotonic = time.monotonic

    def _verify_context_signature(self, context):
        assert context.signature == "context-signature"

    def _assert_current_context(self, context, binding, uid):
        assert binding is self.bindings_by_uid[uid]

    def _policy_revision(self):
        return "policy-1"

    def _binding(self, uid):
        return self.bindings_by_uid[uid]

    def _sign(self, claims):
        return "receipt-signature"

    def _signed_context(self, context, signature):
        return replace(context, signature="context-signature").to_wire()

    def issue_source_receipt(self, context, *, source_kind, origin_id, payload, ttl_seconds):
        now = self.monotonic()
        row = SourceReceipt(
            receipt_id=f"receipt-{len(self._source_receipt_handles) + 1}",
            issuer_id="host-authority", source_kind=source_kind,
            principal_id=context.principal_id, profile_id=context.profile_id,
            namespace_id=context.namespace_id, uid=context.uid, origin_id=origin_id,
            process_generation="generation-001", payload_digest=canonical_digest(payload),
            sensitivity=Sensitivity.PRIVATE, parent_lineage_hash=context.lineage_hash,
            policy_revision="policy-1", recipient_ceiling=frozenset(),
            issued_at_monotonic=now, monotonic_expires_at=min(now + ttl_seconds,
                context.monotonic_expires_at), signature="receipt-signature",
            enrollment_id="enrollment-1", native_process_identity="root-selected-process",
            parent_receipt_ids=tuple(sorted(item.receipt_id for item in context.source_receipts)),
            nonce=f"nonce-{len(self._source_receipt_handles) + 1}",
        )
        handle = SourceReceiptHandle(f"h{len(self._source_receipt_handles) + 1}".ljust(43, "x"))
        self._source_receipt_handles[str(handle)] = row
        return row

    def _verify_source_receipt(self, receipt, binding):
        assert binding is self.bindings_by_uid[receipt.uid]
        assert receipt.signature == "receipt-signature"


def _selection():
    return HttpIngressSelection("http-selection", "http-channel", 1, "profile-001", "role-001",
        "issuer-001", "listener-001", "jwt-verifier-001", "session-policy-001",
        "http-body-v1", 4096, 30)


def _context():
    now = time.monotonic()
    return HostContext(
        principal_id="principal-001", profile_id="profile-001", namespace_id="namespace-001",
        uid=501, purpose="resource-source:http-channel", intent_id="intent-1", trace_id="trace-1",
        sensitivity=Sensitivity.PRIVATE, lineage_hash="a"*64, policy_revision="policy-1",
        capabilities=frozenset(), issued_at_monotonic=now, monotonic_expires_at=now+60,
        nonce="nonce-1", grant_id="grant-1", signature="context-signature",
        final_payload_digest="b"*64,
    )


class _EventIssuer:
    def __init__(self):
        self.payloads = []

    def prepare_source_parent_context(self, capability, controller_proof, *, source_payload):
        assert capability is CAPABILITY and controller_proof is CONTROLLER
        self.payloads.append(source_payload)
        return _context()


CAPABILITY = object()
CONTROLLER = object()


def _issuer():
    service, event = _AuthorityFixture(), _EventIssuer()
    selected = _selection()
    issuer = AuthorityServiceNativeInputReceiptIssuer(
        service, event, producer_capability=CAPABILITY, controller_proof=CONTROLLER,
        selection=selected, selection_handle=object())
    return issuer, service, event, selected


def test_jwt_and_raw_request_receipts_are_signed_selected_and_parent_linked():
    issuer, service, event, selected = _issuer()
    sid, digest, fingerprint = "session-opaque-123", "a"*64, "b"*64
    payload = {"schema": 1, "selection_id": selected.id, "session_id": sid,
               "subject_digest": digest, "token_fingerprint": fingerprint,
               "profile_id": selected.profile_id}
    subject_handle = issuer.issue_subject_source_receipt(
        selection=selected, session_id=sid, subject_digest=digest,
        token_fingerprint=fingerprint, source_payload=payload,
        expires_monotonic=time.monotonic()+50)
    subject = AuthenticatedSubjectReceipt(str(subject_handle), "root-session-handle-123", digest,
                                          time.monotonic()+40, selected.jwt_verifier_enrollment_id)
    issuer.bind_subject_session(sid, subject)
    body = b'{"schema":1,"event":"fixture"}'
    request_handle = issuer.issue_request_source_receipt(
        issuer.selection_handle, subject.session_handle, str(subject_handle), body)
    parent = service._source_receipt_handles[str(subject_handle)]
    request = service._source_receipt_handles[str(request_handle)]
    assert event.payloads == [canonical_payload(payload), body]
    assert request.payload_digest == hashlib.sha256(body).hexdigest()
    assert request.parent_receipt_ids == (parent.receipt_id,)
    assert request.source_kind == parent.source_kind == "native-input"


def canonical_payload(value):
    import json
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def test_request_receipt_rejects_unbound_session_handle_or_changed_selection():
    issuer, _service, _event, _selected = _issuer()
    with pytest.raises(NativeInputReceiptDenied, match="current selected JWT"):
        issuer.issue_request_source_receipt(issuer.selection_handle, "session-without-proof",
                                            "R"*43, b"{}")
    with pytest.raises(NativeInputReceiptDenied, match="selected bounds"):
        issuer.issue_request_source_receipt(issuer.selection_handle, "session-without-proof",
                                            "R"*43, b"x"*4097)


def test_root_context_provider_is_required_and_must_return_signed_context():
    service, selected = _AuthorityFixture(), _selection()
    class MissingIssuer:
        pass
    with pytest.raises(TypeError, match="selected root issuer"):
        AuthorityServiceNativeInputReceiptIssuer(service, MissingIssuer(),
            producer_capability=CAPABILITY, controller_proof=CONTROLLER,
            selection=selected, selection_handle=object())
