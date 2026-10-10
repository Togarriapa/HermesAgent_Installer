from __future__ import annotations

import hashlib
import json

import pytest

from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection,
    AuthenticatedHttpIngressProducer,
    ChannelIngressDenied,
    HttpIngressSelection,
    ObservedChannelIngress,
    SelectedAudioIngressProducer,
)


class HttpObserver:
    def __init__(self, body=b'{"text":"hello"}', clock=lambda: 100.0):
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
            "request_receipt_handle": "request-receipt-0001", "request_id":"request-id-0001",
            "session_id":"session-id-0001", "subject_id":"subject-id-0001", "text":"hello",
            "raw_body_size_bytes":len(self.body),
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
            "session_id":"audio-session-0001",
            "capture_receipt_handle": "capture-receipt-0001", "audio_artifact_id": "artifact-0001",
            "audio_artifact_receipt_handle":"artifact-receipt-0001",
            "audio_sha256": "c" * 64, "size_bytes": 8192, "format_schema_id": selection.sample_format_schema_id,
            "capture_id":"capture-id-0001", "duration_milliseconds":256,
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
    assert json.loads(ingress.payload)["text"] == "hello"
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
    observer.body = b'{"text":"changed"}'
    assert producer.validate_claims(ingress.proof) is False

    stale = HttpObserver()
    stale.validate_http_observation = lambda *_a, **_kw: {
        "schema": 1, "proof_handle": "http-proof-0001", "selection_id": "http-selection",
        "session_handle": "http-session-0001", "authenticated_subject_receipt_handle": "subject-receipt-0001",
        "request_receipt_handle": "request-receipt-0001", "request_id":"request-id-0001",
        "session_id":"session-id-0001", "subject_id":"subject-id-0001", "text":"hello",
        "raw_body_size_bytes":len(stale.body), "body_sha256": hashlib.sha256(stale.body).hexdigest(),
        "controller_identity_digest": "a" * 64, "service_generation_digest": "b" * 64,
        "issued_monotonic": 0.0, "expires_monotonic": 10.0,
    }
    stale_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                      stale, clock=clock)
    with pytest.raises(ChannelIngressDenied, match="freshness or lease"):
        stale_producer.observe(object())

    noncanonical_wire = HttpObserver(body=b'{ "text":"hello" }')
    noncanonical_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                             noncanonical_wire, clock=clock)
    assert json.loads(noncanonical_producer.observe(object()).payload)["text"] == "hello"

    bad = HttpObserver(body=b'{"text":"first","text":"second"}')
    bad_producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                    bad, clock=clock)
    with pytest.raises(ChannelIngressDenied, match="bounded JSON"):
        bad_producer.observe(object())


def test_http_proof_rejects_worker_constructed_object_and_wrong_selected_controller():
    producer = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                                HttpObserver(), clock=FakeClock())
    assert producer.validate_claims({"proof_handle": "invented-proof-001"}) is False


def test_event_issuer_observation_seam_consumes_only_exact_http_and_audio_records_once():
    class Custody:
        controller_role_id = "role-001"
        source_issuer_id = "source-issuer-001"
        resource_generation = "2"
        def revalidate(self): return True

    clock = FakeClock()
    http = AuthenticatedHttpIngressProducer(http_selection(), "protected-selection-handle-01",
                                             HttpObserver(), clock=clock)
    request = http.observe(object())
    result = http.consume_verified_raw_observation(request, Custody())
    assert result["raw_payload"] == b'{"text":"hello"}'
    assert result["event_data"]["text"] == "hello"
    assert len(result["event_id"]) >= 32 and len(result["replay_key_sha256"]) == 64
    with pytest.raises(ChannelIngressDenied, match="unknown, replayed"):
        http.consume_verified_raw_observation(request, Custody())

    audio = SelectedAudioIngressProducer(audio_selection(), "protected-selection-handle-01",
                                          AudioObserver(), clock=clock)
    capture = audio.observe(object())
    result = audio.consume_verified_raw_observation(capture, Custody())
    assert result["raw_payload"] == capture.payload  # metadata only; PCM remains in the sealed artifact
    assert result["event_data"]["audio_sha256"] == "c" * 64
    with pytest.raises(ChannelIngressDenied, match="unknown, replayed"):
        audio.consume_verified_raw_observation(capture, Custody())

    forged = ObservedChannelIngress(object(), b"{}")
    with pytest.raises(ChannelIngressDenied, match="unknown, replayed"):
        audio.consume_verified_raw_observation(forged, Custody())


def test_audio_ingress_requires_root_consent_device_and_current_session_receipts():
    clock, observer = FakeClock(), AudioObserver()
    selection = audio_selection()
    producer = SelectedAudioIngressProducer(selection, "protected-selection-handle-01",
                                            observer, clock=clock)
    ingress = producer.observe(root_capture_record=object())
    event = json.loads(ingress.payload)
    assert ingress.proof is observer.proof
    assert event == {"session_id":"audio-session-0001", "capture_id":"capture-id-0001",
            "audio_artifact_receipt_handle":"artifact-receipt-0001", "audio_sha256":"c"*64,
        "audio_size_bytes":8192, "format":"pcm-s16le-mono", "sample_rate_hz":16000,
        "duration_milliseconds":256}
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
        audio_selection(max_capture_seconds=61)
    with pytest.raises(ChannelIngressDenied, match="digest"):
        audio_selection(capture_backend_sha256="not-a-pin")


def test_concrete_root_http_observer_binds_listener_jwt_current_session_and_body():
    from hermes_installer.authority.channel_provenance import (
        AuthenticatedHttpRequest, AuthenticatedSubjectReceipt, RootSelectedHttpIngressObserver,
    )
    clock = FakeClock()
    body = b'{"text":"selected"}'
    request = AuthenticatedHttpRequest("listener-001", "http-selection", "POST", "ingress-event",
        "application/json", "session-id-001", b"synthetic-jwt", body, "request-receipt-001", "request-id-001")
    class Listener:
        def take_authenticated_request(self, handle, record):
            assert handle is selection_handle and record is selected_request
            return request
    subject = AuthenticatedSubjectReceipt("subject-receipt-001", "session-handle-001", "e"*64,
                                         130.0, "jwt-verifier-001")
    class Verifier:
        current = True
        def verify_selected_jwt(self, selection, token, session_id):
            assert selection is selected and token == b"synthetic-jwt" and session_id == "session-id-001"
            return subject
        def current_selected_subject(self, selection, receipt):
            if not self.current or receipt is not subject: raise PermissionError("revoked")
            return subject
    selected = http_selection()
    selection_handle, selected_request = object(), object()
    observer = RootSelectedHttpIngressObserver(selected, selection_handle, Listener(), Verifier(),
        controller_identity_digest="a"*64, service_generation_digest="b"*64,
        route_id="ingress-event", body_schema_validator=lambda schema, payload: schema == selected.body_schema_id
        and json.loads(payload) == {"text":"selected"}, monotonic=clock)
    producer = AuthenticatedHttpIngressProducer(selected, selection_handle, observer, clock=clock)
    ingress = producer.observe(selected_request)
    assert json.loads(ingress.payload) == {"text":"selected", "session_id":"session-id-001",
        "request_id":"request-id-001", "subject_id":"e"*64,
        "raw_body_sha256":hashlib.sha256(body).hexdigest(), "raw_body_size_bytes":len(body)}
    assert producer.validate_claims(ingress.proof)
    assert observer.consume_source_receipts(ingress) == ()
    observer.consume(ingress.proof)
    assert not producer.validate_claims(ingress.proof)


def test_concrete_root_audio_observer_requires_current_device_consent_receipt():
    from hermes_installer.authority.channel_provenance import (
        RootSelectedAudioIngressObserver, SelectedAudioCaptureReceipt,
    )
    clock = FakeClock()
    selected = audio_selection()
    selection_handle, root_capture = object(), object()
    receipt = SelectedAudioCaptureReceipt(selected.id, selected.device_enrollment_id,
        selected.capture_backend_artifact_id, selected.capture_backend_sha256,
        "audio-session-001", "consent-receipt-001", "capture-receipt-001", "artifact-receipt-001",
        "capture-id-001", "artifact-001",
        "c"*64, 8192, selected.sample_format_schema_id, 130.0)
    class CaptureAuthority:
        current = True
        def take_selected_capture(self, handle, record):
            assert handle is selection_handle and record is root_capture
            return receipt
        def current_selected_capture(self, handle, observed):
            if not self.current or observed is not receipt: raise PermissionError("consent revoked")
            return receipt
    root = RootSelectedAudioIngressObserver(selected, selection_handle, CaptureAuthority(),
        controller_identity_digest="a"*64, service_generation_digest="b"*64, monotonic=clock)
    producer = SelectedAudioIngressProducer(selected, selection_handle, root, clock=clock)
    ingress = producer.observe(root_capture)
    assert json.loads(ingress.payload)["audio_artifact_receipt_handle"] == "artifact-receipt-001"
    assert producer.validate_claims(ingress.proof)
    assert root.consume_source_receipts(ingress) == ()
    root.consume(ingress.proof)
    assert not producer.validate_claims(ingress.proof)
