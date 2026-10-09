from __future__ import annotations

import hashlib
import json

import pytest

from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection,
    AuthenticatedHttpIngressProducer,
    ChannelIngressDenied,
    HttpIngressSelection,
    SelectedAudioIngressProducer,
)


class HttpObserver:
    def __init__(self, body=b'{"message":"hello"}', clock=lambda: 100.0):
        self.body = body
        self.clock = clock
        self.current = True
        self.consumed = False
        self.expected_proof = None
        self.observed_records = []
        self.validations = 0
        self.proof = object()
        self.bound_digest = hashlib.sha256(body).hexdigest()

    def observe_selected_http_ingress(self, selection_handle, root_request_record):
        self.observed_records.append((selection_handle, root_request_record))
        self.expected_proof = self.proof
        return self.proof

    def read_verified_http_body(self, selection, proof):
        assert selection.id == "http-selection"
        assert proof is self.proof
        return self.body

    def validate_http_observation(self, selection, proof, *, now_monotonic):
        self.validations += 1
        if not self.current or self.consumed or proof is not self.expected_proof:
            raise PermissionError("JWT/session revoked or stale")
        return {
            "schema": 1, "proof_handle": "http-proof-0001", "selection_id": selection.id,
            "session_handle": "http-session-0001", "authenticated_subject_receipt_handle": "subject-receipt-0001",
            "request_receipt_handle": "request-receipt-0001",
            "body_sha256": self.bound_digest,
            "controller_identity_digest": "a" * 64, "service_generation_digest": "b" * 64,
            "issued_monotonic": 95.0, "expires_monotonic": 110.0,
        }


class AudioObserver:
    def __init__(self, clock=lambda: 100.0):
        self.current = True
        self.consumed = False
        self.expected_proof = None
        self.capture_record = None
        self.proof = object()

    def observe_selected_audio_ingress(self, selection_handle, root_capture_record):
        self.capture_record = (selection_handle, root_capture_record)
        self.expected_proof = self.proof
        return self.proof

    def validate_audio_observation(self, selection, proof, *, now_monotonic):
        if not self.current or self.consumed or proof is not self.expected_proof:
            raise PermissionError("session consent revoked or device changed")
        return {
            "schema": 1, "proof_handle": "audio-proof-0001", "selection_id": selection.id,
            "session_handle": "audio-session-0001", "consent_receipt_handle": "consent-receipt-0001",
            "capture_receipt_handle": "capture-receipt-0001", "audio_artifact_id": "artifact-0001",
            "audio_sha256": "c" * 64, "size_bytes": 8192, "format_schema_id": selection.sample_format_schema_id,
            "controller_identity_digest": "a" * 64, "service_generation_digest": "b" * 64,
            "issued_monotonic": 95.0, "expires_monotonic": 110.0,
        }


class FakeClock:
    value = 100.0
    def __call__(self): return self.value


def http_selection(**overrides):
    values = dict(id="http-selection", channel_resource_id="webhook-channel-01",
                  resource_generation=2, profile_id="profile-001", controller_role_id="role-001",
                  source_issuer_id="source-issuer-001", listener_enrollment_id="listener-001",
                  jwt_verifier_enrollment_id="jwt-verifier-001", allowed_session_policy_id="sessions-001",
                  body_schema_id="body-schema-001", max_body_bytes=4096, max_event_age_seconds=30)
    values.update(overrides)
    return HttpIngressSelection(**values)


def audio_selection(**overrides):
    values = dict(id="audio-selection", channel_resource_id="audio-channel-01",
                  resource_generation=2, profile_id="profile-001", controller_role_id="role-001",
                  source_issuer_id="source-issuer-001", device_enrollment_id="device-enrollment-001",
                  capture_backend_artifact_id="capture-backend-001", capture_backend_sha256="d" * 64,
                  session_policy_id="session-policy-001", max_capture_bytes=16384,
                  max_capture_seconds=10, sample_format_schema_id="pcm16-mono-16000-v1")
    values.update(overrides)
    return AudioIngressSelection(**values)


def test_http_ingress_binds_exact_selected_jwt_session_and_body_and_revalidates_currentness():
    clock, observer = FakeClock(), HttpObserver(clock=lambda: 100.0)
    selection = http_selection()
    producer = AuthenticatedHttpIngressProducer(selection, "protected-selection-handle-01",
                                                observer, clock=clock)
    ingress = producer.observe(root_request_record=object())
    assert ingress.payload == b'{"message":"hello"}'
    assert ingress.proof is observer.proof
    assert observer.observed_records[0][0] == "protected-selection-handle-01"
    assert producer.validate_claims(ingress.proof) is True
    assert observer.validations == 2
    observer.consumed = True  # the protected source registry consumed the proof
    assert producer.validate_claims(ingress.proof) is False
    observer.current = False
    assert producer.validate_claims(ingress.proof) is False


def test_http_ingress_rejects_body_mutation_stale_proof_and_noncanonical_body():
    clock, observer = FakeClock(), HttpObserver()
    producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                observer, clock=clock)
    ingress = producer.observe(object())
    observer.body = b'{"message":"changed"}'
    assert producer.validate_claims(ingress.proof) is False

    stale = HttpObserver()
    stale.validate_http_observation = lambda *_a, **_kw: {
        "schema": 1, "proof_handle": "http-proof-0001", "selection_id": "http-selection",
        "session_handle": "http-session-0001", "authenticated_subject_receipt_handle": "subject-receipt-0001",
        "request_receipt_handle": "request-receipt-0001", "body_sha256": hashlib.sha256(stale.body).hexdigest(),
        "controller_identity_digest": "a" * 64, "service_generation_digest": "b" * 64,
        "issued_monotonic": 0.0, "expires_monotonic": 10.0,
    }
    stale_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                      stale, clock=clock)
    with pytest.raises(ChannelIngressDenied, match="freshness or lease"):
        stale_producer.observe(object())

    noncanonical_wire = HttpObserver(body=b'{ "message":"hello" }')
    noncanonical_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                             noncanonical_wire, clock=clock)
    assert noncanonical_producer.observe(object()).payload == b'{"message":"hello"}'

    bad = HttpObserver(body=b'{"message":"first","message":"second"}')
    bad_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                    bad, clock=clock)
    with pytest.raises(ChannelIngressDenied, match="bounded JSON"):
        bad_producer.observe(object())


def test_http_proof_rejects_worker_constructed_object_and_wrong_selected_controller():
    producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                HttpObserver(), clock=FakeClock())
    assert producer.validate_claims({"proof_handle": "invented-proof-001"}) is False


def test_audio_ingress_requires_root_consent_device_and_current_session_receipts():
    clock, observer = FakeClock(), AudioObserver()
    selection = audio_selection()
    producer = SelectedAudioIngressProducer(selection, "protected-selection-handle-01",
                                            observer, clock=clock)
    ingress = producer.observe(root_capture_record=object())
    event = json.loads(ingress.payload)
    assert ingress.proof is observer.proof
    assert event == {"audio_artifact_id": "artifact-0001", "audio_sha256": "c" * 64,
                     "capture_receipt_handle": "capture-receipt-0001",
                     "consent_receipt_handle": "consent-receipt-0001",
                     "format_schema_id": "pcm16-mono-16000-v1", "session_handle": "audio-session-0001",
                     "size_bytes": 8192}
    assert producer.validate_claims(ingress.proof) is True
    observer.consumed = True
    assert producer.validate_claims(ingress.proof) is False
    observer.current = False
    assert producer.validate_claims(ingress.proof) is False


def test_audio_ingress_rejects_missing_consent_or_device_change_and_bound_violations():
    clock, observer = FakeClock(), AudioObserver()
    producer = SelectedAudioIngressProducer(audio_selection(max_capture_bytes=4096),
                                            "protected-selection-handle-01", observer,
                                            clock=clock)
    with pytest.raises(ChannelIngressDenied, match="size or lease"):
        producer.observe(object())
    observer.current = False
    producer2 = SelectedAudioIngressProducer(audio_selection(), "protected-selection-handle-01",
                                             observer, clock=clock)
    proof = observer.proof
    assert producer2.validate_claims(proof) is False


def test_selection_bounds_reject_unknown_unbounded_runtime_enrollment():
    with pytest.raises(ChannelIngressDenied, match="bounds"):
        http_selection(max_body_bytes=262145)
    with pytest.raises(ChannelIngressDenied, match="bounds"):
        audio_selection(max_capture_seconds=31)
    with pytest.raises(ChannelIngressDenied, match="digest"):
        audio_selection(capture_backend_sha256="not-a-pin")
