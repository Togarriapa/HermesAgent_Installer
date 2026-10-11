"""Root-side HTTP/audio ingress observers for RB-T08 v40.

The authority process constructs these observers from the selected listener,
JWT/session verifier, microphone consent/device authority, and sealed artifact
store. Native workers never construct request/capture records or observer
instances. This module does not open sockets or devices itself; those effects
remain behind the enrolled root services.
"""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from hermes_installer.components.plugin_channel_provenance import (
    AudioIngressSelection, ChannelIngressDenied, HttpIngressSelection, ObservedChannelIngress,
    _canonical_body,
)
from .types import SourceReceipt


@dataclass(frozen=True, slots=True)
class AuthenticatedHttpRequest:
    """Short-lived record created only by the root selected listener."""
    listener_enrollment_id: str
    selection_id: str
    method: str
    route_id: str
    content_type: str
    session_id: str
    access_jwt: bytes = field(repr=False)
    body: bytes = field(repr=False)
    request_receipt_handle: str
    request_id: str


@dataclass(frozen=True, slots=True)
class AuthenticatedSubjectReceipt:
    """Result of actual signature, issuer/audience, policy and session checks."""
    receipt_handle: str
    session_handle: str
    subject_digest: str
    expires_monotonic: float
    verifier_enrollment_id: str


class SelectedHttpListener(Protocol):
    def take_authenticated_request(self, selection_handle: object,
                                   request_record: object) -> AuthenticatedHttpRequest: ...


class SelectedHttpIdentityVerifier(Protocol):
    def verify_selected_jwt(self, selection: HttpIngressSelection, token: bytes,
                            session_id: str) -> AuthenticatedSubjectReceipt: ...
    def current_selected_subject(self, selection: HttpIngressSelection,
                                 receipt: AuthenticatedSubjectReceipt) -> AuthenticatedSubjectReceipt: ...


@dataclass(frozen=True, slots=True)
class _HttpProof:
    proof_handle: str
    selection_id: str
    request_receipt_handle: str
    request_id: str
    session_id: str
    body: bytes = field(repr=False)
    subject: AuthenticatedSubjectReceipt = field(repr=False)
    body_digest: str
    controller_identity_digest: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float


class RootSelectedHttpIngressObserver:
    """Per-enrollment root observer that binds listener, JWT, session and body."""
    def __init__(self, selection: HttpIngressSelection, selection_handle: object,
                 listener: SelectedHttpListener, identity_verifier: SelectedHttpIdentityVerifier,
                 *, controller_identity_digest: str, service_generation_digest: str,
                 route_id: str, body_schema_validator, monotonic=time.monotonic,
                 source_receipt_resolver=None, source_receipt_validator=None):
        if not isinstance(selection, HttpIngressSelection):
            raise TypeError("selected HTTP ingress enrollment is required")
        for name in ("take_authenticated_request",):
            if not callable(getattr(listener, name, None)):
                raise TypeError("root selected HTTP listener is required")
        for name in ("verify_selected_jwt", "current_selected_subject"):
            if not callable(getattr(identity_verifier, name, None)):
                raise TypeError("root JWT and current-session verifier is required")
        if (len(controller_identity_digest) != 64 or len(service_generation_digest) != 64
                or not callable(body_schema_validator) or not route_id):
            raise ValueError("root HTTP controller, generation, route and body schema binding are required")
        self.selection, self.selection_handle = selection, selection_handle
        self.listener, self.identity_verifier = listener, identity_verifier
        self.controller_identity_digest = controller_identity_digest
        self.service_generation_digest = service_generation_digest
        self.route_id, self.body_schema_validator = route_id, body_schema_validator
        self.source_receipt_resolver = source_receipt_resolver
        self.source_receipt_validator = source_receipt_validator
        self.monotonic = monotonic
        self._proofs: dict[str, _HttpProof] = {}
        self._resolved_receipt_proofs: set[str] = set()

    def observe_selected_http_ingress(self, selection_handle: object,
                                      root_request_record: object) -> object:
        if selection_handle is not self.selection_handle:
            raise ChannelIngressDenied("HTTP selection handle is not the current root selection")
        request = self.listener.take_authenticated_request(selection_handle, root_request_record)
        if (not isinstance(request, AuthenticatedHttpRequest)
                or request.listener_enrollment_id != self.selection.listener_enrollment_id
                or request.selection_id != self.selection.id or request.method != "POST"
                or request.route_id != self.route_id or request.content_type != "application/json"):
            raise ChannelIngressDenied("HTTP request is outside the selected authenticated listener route")
        if (not isinstance(request.session_id, str) or not request.session_id
                or not isinstance(request.access_jwt, bytes)
                or not 1 <= len(request.access_jwt) <= 16 * 1024
                or not isinstance(request.request_receipt_handle, str)):
            raise ChannelIngressDenied("root HTTP request lacks a bounded authenticated request")
        canonical, digest = _canonical_body(request.body, self.selection.max_body_bytes)
        if not self.body_schema_validator(self.selection.body_schema_id, canonical):
            raise ChannelIngressDenied("HTTP request body does not match the selected finite schema")
        subject = self.identity_verifier.verify_selected_jwt(
            self.selection, request.access_jwt, request.session_id)
        if (not isinstance(subject, AuthenticatedSubjectReceipt)
                or subject.verifier_enrollment_id != self.selection.jwt_verifier_enrollment_id
                or not subject.receipt_handle or not subject.session_handle
                or len(subject.subject_digest) != 64
                or any(c not in "0123456789abcdef" for c in subject.subject_digest)
                or subject.expires_monotonic <= self.monotonic()):
            raise ChannelIngressDenied("root JWT verifier did not issue a current selected subject receipt")
        now = self.monotonic()
        proof = _HttpProof(secrets.token_urlsafe(32), self.selection.id,
                           request.request_receipt_handle, request.request_id, request.session_id,
                           request.body, subject,
                           digest, self.controller_identity_digest, self.service_generation_digest,
                           now, min(now + 30.0, subject.expires_monotonic))
        self._proofs[proof.proof_handle] = proof
        return proof

    def validate_http_observation(self, selection: HttpIngressSelection,
                                  proof: object, *, now_monotonic: float) -> Mapping[str, Any]:
        if selection is not self.selection or not isinstance(proof, _HttpProof):
            raise ChannelIngressDenied("HTTP proof is not from this root-selected observer")
        current = self._proofs.get(proof.proof_handle)
        if current is not proof or proof.selection_id != selection.id:
            raise ChannelIngressDenied("HTTP root proof is unknown, consumed or replayed")
        subject = self.identity_verifier.current_selected_subject(selection, proof.subject)
        if subject is not proof.subject or not proof.issued_monotonic <= now_monotonic < proof.expires_monotonic:
            raise ChannelIngressDenied("HTTP JWT subject or selected session is no longer current")
        body_obj = json.loads(proof.body)
        if (set(body_obj) != {"text"} or not isinstance(body_obj["text"], str)
                or not 1 <= len(body_obj["text"]) <= 65536):
            raise ChannelIngressDenied("HTTP event body differs from the selected {text} schema")
        return {"schema": 1, "proof_handle": proof.proof_handle, "selection_id": proof.selection_id,
                "session_handle": proof.subject.session_handle,
                "authenticated_subject_receipt_handle": proof.subject.receipt_handle,
                "request_receipt_handle": proof.request_receipt_handle,
                "request_id": proof.request_id, "session_id": proof.session_id,
                "subject_id": proof.subject.subject_digest, "text": body_obj["text"],
                "raw_body_size_bytes": len(proof.body),
                "body_sha256": proof.body_digest,
                "controller_identity_digest": proof.controller_identity_digest,
                "service_generation_digest": proof.service_generation_digest,
                "issued_monotonic": proof.issued_monotonic,
                "expires_monotonic": proof.expires_monotonic}

    def read_verified_http_body(self, selection: HttpIngressSelection, proof: object) -> bytes:
        self.validate_http_observation(selection, proof, now_monotonic=self.monotonic())
        assert isinstance(proof, _HttpProof)
        return proof.body

    def consume(self, proof: object) -> None:
        if type(proof) is ObservedChannelIngress:
            proof = proof.proof
        if isinstance(proof, _HttpProof):
            self._proofs.pop(proof.proof_handle, None)
            self._resolved_receipt_proofs.discard(proof.proof_handle)

    def consume_source_receipts(self, proof: object) -> tuple[SourceReceipt, ...]:
        """Consume the retained transport proof; initial ingress has no parent receipt."""
        if type(proof) is ObservedChannelIngress:
            observation = proof
            proof = observation.proof
            claims = self.validate_http_observation(self.selection, proof,
                                                    now_monotonic=self.monotonic())
            try:
                event = json.loads(observation.payload)
            except Exception:
                raise ChannelIngressDenied("HTTP source event payload is malformed") from None
            expected = {"text": claims["text"], "session_id": claims["session_id"],
                        "request_id": claims["request_id"], "subject_id": claims["subject_id"],
                        "raw_body_sha256": claims["body_sha256"],
                        "raw_body_size_bytes": claims["raw_body_size_bytes"]}
            if event != expected:
                raise ChannelIngressDenied("HTTP source event payload differs from retained request")
        if not isinstance(proof, _HttpProof) or proof.proof_handle in self._resolved_receipt_proofs:
            raise ChannelIngressDenied("HTTP source proof is unavailable or was already consumed")
        self.validate_http_observation(self.selection, proof, now_monotonic=self.monotonic())
        self._resolved_receipt_proofs.add(proof.proof_handle)
        return ()


@dataclass(frozen=True, slots=True)
class SelectedAudioCaptureReceipt:
    """Root capture workflow result; contains handles/metadata, never PCM/path."""
    selection_id: str
    device_enrollment_id: str
    capture_backend_artifact_id: str
    capture_backend_sha256: str
    session_handle: str
    consent_receipt_handle: str
    capture_receipt_handle: str
    audio_artifact_receipt_handle: str
    capture_id: str
    audio_artifact_id: str
    audio_sha256: str
    size_bytes: int
    format_schema_id: str
    expires_monotonic: float


class RootAudioCaptureAuthority(Protocol):
    def take_selected_capture(self, selection_handle: object,
                              root_capture_record: object) -> SelectedAudioCaptureReceipt: ...
    def current_selected_capture(self, selection_handle: object,
                                 receipt: SelectedAudioCaptureReceipt) -> SelectedAudioCaptureReceipt: ...


@dataclass(frozen=True, slots=True)
class _AudioProof:
    proof_handle: str
    selection_id: str
    receipt: SelectedAudioCaptureReceipt = field(repr=False)
    controller_identity_digest: str
    service_generation_digest: str
    issued_monotonic: float
    expires_monotonic: float


class RootSelectedAudioIngressObserver:
    """Root observer joining consent, current device session and sealed PCM receipt."""
    def __init__(self, selection: AudioIngressSelection, selection_handle: object,
                 capture_authority: RootAudioCaptureAuthority, *,
                 controller_identity_digest: str, service_generation_digest: str,
                 monotonic=time.monotonic, source_receipt_resolver=None,
                 source_receipt_validator=None):
        if not isinstance(selection, AudioIngressSelection):
            raise TypeError("selected audio ingress enrollment is required")
        for name in ("take_selected_capture", "current_selected_capture"):
            if not callable(getattr(capture_authority, name, None)):
                raise TypeError("root selected device, consent and artifact capture authority is required")
        if len(controller_identity_digest) != 64 or len(service_generation_digest) != 64:
            raise ValueError("root audio controller and service generation digests are required")
        self.selection, self.selection_handle = selection, selection_handle
        self.capture_authority = capture_authority
        self.controller_identity_digest = controller_identity_digest
        self.service_generation_digest = service_generation_digest
        self.source_receipt_resolver = source_receipt_resolver
        self.source_receipt_validator = source_receipt_validator
        self.monotonic = monotonic
        self._proofs: dict[str, _AudioProof] = {}
        self._resolved_receipt_proofs: set[str] = set()

    def observe_selected_audio_ingress(self, selection_handle: object,
                                      root_capture_record: object) -> object:
        if selection_handle is not self.selection_handle:
            raise ChannelIngressDenied("audio selection handle is not the current root selection")
        receipt = self.capture_authority.take_selected_capture(selection_handle, root_capture_record)
        self._validate_receipt(receipt)
        now = self.monotonic()
        proof = _AudioProof(secrets.token_urlsafe(32), self.selection.id, receipt,
                            self.controller_identity_digest, self.service_generation_digest,
                            now, min(now + 30.0, receipt.expires_monotonic))
        self._proofs[proof.proof_handle] = proof
        return proof

    def validate_audio_observation(self, selection: AudioIngressSelection,
                                   proof: object, *, now_monotonic: float) -> Mapping[str, Any]:
        if selection is not self.selection or not isinstance(proof, _AudioProof):
            raise ChannelIngressDenied("audio proof is not from this root-selected observer")
        current = self._proofs.get(proof.proof_handle)
        if (current is not proof or proof.selection_id != selection.id
                or not proof.issued_monotonic <= now_monotonic < proof.expires_monotonic):
            raise ChannelIngressDenied("audio root proof is unknown, consumed, expired or replayed")
        receipt = self.capture_authority.current_selected_capture(self.selection_handle, proof.receipt)
        if receipt is not proof.receipt:
            raise ChannelIngressDenied("audio consent, device or selected session is no longer current")
        self._validate_receipt(receipt)
        duration_milliseconds = receipt.size_bytes * 1000 // (16000 * 2)
        if receipt.size_bytes % 32 or not 1 <= duration_milliseconds <= 60000:
            raise ChannelIngressDenied("audio capture size does not encode a complete bounded 16 kHz PCM frame")
        return {"schema": 1, "proof_handle": proof.proof_handle, "selection_id": proof.selection_id,
                "session_handle": receipt.session_handle,
                "consent_receipt_handle": receipt.consent_receipt_handle,
                "capture_receipt_handle": receipt.capture_receipt_handle,
                "audio_artifact_id": receipt.audio_artifact_id,
                "audio_artifact_receipt_handle": receipt.audio_artifact_receipt_handle,
                "audio_sha256": receipt.audio_sha256,
                "size_bytes": receipt.size_bytes, "format_schema_id": receipt.format_schema_id,
                "session_id": receipt.session_handle, "capture_id": receipt.capture_id,
                "duration_milliseconds": duration_milliseconds,
                "controller_identity_digest": proof.controller_identity_digest,
                "service_generation_digest": proof.service_generation_digest,
                "issued_monotonic": proof.issued_monotonic, "expires_monotonic": proof.expires_monotonic}

    def consume(self, proof: object) -> None:
        if type(proof) is ObservedChannelIngress:
            proof = proof.proof
        if isinstance(proof, _AudioProof):
            self._proofs.pop(proof.proof_handle, None)
            self._resolved_receipt_proofs.discard(proof.proof_handle)

    def consume_source_receipts(self, proof: object) -> tuple[SourceReceipt, ...]:
        """Consume actual root-retained device/consent proofs; no synthetic parents."""
        if type(proof) is ObservedChannelIngress:
            observation = proof
            proof = observation.proof
            claims = self.validate_audio_observation(self.selection, proof,
                                                     now_monotonic=self.monotonic())
            try:
                event = json.loads(observation.payload)
            except Exception:
                raise ChannelIngressDenied("audio source event payload is malformed") from None
            expected = {"session_id": claims["session_handle"], "capture_id": claims["capture_id"],
                        "audio_artifact_receipt_handle": claims["audio_artifact_receipt_handle"],
                        "audio_sha256": claims["audio_sha256"], "audio_size_bytes": claims["size_bytes"],
                        "format": "pcm-s16le-mono", "sample_rate_hz": 16000,
                        "duration_milliseconds": claims["duration_milliseconds"]}
            if event != expected:
                raise ChannelIngressDenied("audio source event payload differs from retained capture")
        if not isinstance(proof, _AudioProof) or proof.proof_handle in self._resolved_receipt_proofs:
            raise ChannelIngressDenied("audio source proof is unavailable or was already consumed")
        self.validate_audio_observation(self.selection, proof, now_monotonic=self.monotonic())
        self._resolved_receipt_proofs.add(proof.proof_handle)
        return ()

    def _validate_receipt(self, receipt: object) -> None:
        if (not isinstance(receipt, SelectedAudioCaptureReceipt)
                or receipt.selection_id != self.selection.id
                or receipt.device_enrollment_id != self.selection.device_enrollment_id
                or receipt.capture_backend_artifact_id != self.selection.capture_backend_artifact_id
                or receipt.capture_backend_sha256 != self.selection.capture_backend_sha256
                or receipt.format_schema_id != self.selection.sample_format_schema_id
                or type(receipt.size_bytes) is not int
                or not 1 <= receipt.size_bytes <= self.selection.max_capture_bytes
                or not isinstance(receipt.session_handle, str) or not receipt.session_handle
                or not isinstance(receipt.consent_receipt_handle, str) or not receipt.consent_receipt_handle
                or not isinstance(receipt.capture_receipt_handle, str) or not receipt.capture_receipt_handle
                or not isinstance(receipt.audio_artifact_id, str) or not receipt.audio_artifact_id
                or not isinstance(receipt.audio_sha256, str) or len(receipt.audio_sha256) != 64
                or any(c not in "0123456789abcdef" for c in receipt.audio_sha256)
                or not isinstance(receipt.expires_monotonic, (int, float))
                or receipt.expires_monotonic <= self.monotonic()):
            raise ChannelIngressDenied("root audio capture receipt does not match selected device/session policy")
