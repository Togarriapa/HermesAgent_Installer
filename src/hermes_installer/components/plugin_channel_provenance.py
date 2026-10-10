"""Root-observed provenance adapters for authenticated HTTP and selected audio.

This code never creates transport proofs. The injected root observer authenticates
HTTP JWT/session/body state or checks actual device/session consent and capture,
then returns its private one-use proof. This layer verifies exact v40 claims,
bounds the payload, and revalidates currentness whenever the source issuer calls
``validate_claims``. No worker authorization booleans or channel cross-adaptation.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import math
import secrets
import time
from typing import Any, Mapping, Protocol


class ChannelIngressDenied(PermissionError):
    """The selected transport proof is missing, stale or mismatched."""


_MAX_BODY_BYTES = 256 * 1024
_MAX_AUDIO_BYTES = 32 * 1024 * 1024
_MAX_AUDIO_SECONDS = 60
_MAX_PROOF_LEASE = 60.0
_OPAQUE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.")
_HEX = frozenset("0123456789abcdef")


def _opaque(value: object, label: str) -> str:
    if (not isinstance(value, str) or not 8 <= len(value) <= 128
            or any(char not in _OPAQUE_CHARS for char in value)):
        raise ChannelIngressDenied(f"{label} is malformed")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(c not in _HEX for c in value):
        raise ChannelIngressDenied(f"{label} must be a lowercase SHA-256 digest")
    return value


def _monotonic(value: object, label: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ChannelIngressDenied(f"{label} is invalid")
    return float(value)


def _canonical_body(body: object, maximum: int) -> tuple[bytes, str]:
    if not isinstance(body, bytes) or not body or len(body) > maximum:
        raise ChannelIngressDenied("authenticated HTTP body is empty or oversized")
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    try:
        value = json.loads(body, object_pairs_hook=unique_pairs,
                           parse_constant=lambda _x: (_ for _ in ()).throw(ValueError()))
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                               ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError):
        raise ChannelIngressDenied("authenticated HTTP body is not bounded JSON") from None
    if not isinstance(value, dict):
        raise ChannelIngressDenied("authenticated HTTP body must be a JSON object")
    # The selected request proof binds the original wire bytes. The event issuer
    # receives a separately canonicalized object for source-receipt signing.
    return canonical, hashlib.sha256(body).hexdigest()


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError):
        raise ChannelIngressDenied("source event is not canonical JSON") from None


@dataclass(frozen=True, slots=True)
class HttpIngressSelection:
    """Root-selected HTTP enrollment fields from RB-T08 v40."""
    id: str
    channel_resource_id: str
    resource_generation: int
    profile_id: str
    controller_role_id: str
    source_issuer_id: str
    listener_enrollment_id: str
    jwt_verifier_enrollment_id: str
    allowed_session_policy_id: str
    body_schema_id: str
    max_body_bytes: int
    max_event_age_seconds: int

    def __post_init__(self) -> None:
        for key in ("id", "channel_resource_id", "profile_id", "controller_role_id",
                    "source_issuer_id", "listener_enrollment_id", "jwt_verifier_enrollment_id",
                    "allowed_session_policy_id", "body_schema_id"):
            _opaque(getattr(self, key), f"HTTP selection {key}")
        if (type(self.resource_generation) is not int or self.resource_generation < 1
                or type(self.max_body_bytes) is not int or not 1 <= self.max_body_bytes <= _MAX_BODY_BYTES
                or type(self.max_event_age_seconds) is not int or not 1 <= self.max_event_age_seconds <= 300):
            raise ChannelIngressDenied("HTTP ingress selection bounds are malformed")


@dataclass(frozen=True, slots=True)
class AudioIngressSelection:
    """Root-selected audio enrollment fields from RB-T08 v40."""
    id: str
    channel_resource_id: str
    resource_generation: int
    profile_id: str
    controller_role_id: str
    source_issuer_id: str
    device_enrollment_id: str
    capture_backend_artifact_id: str
    capture_backend_sha256: str
    session_policy_id: str
    max_capture_bytes: int
    max_capture_seconds: int
    sample_format_schema_id: str

    def __post_init__(self) -> None:
        for key in ("id", "channel_resource_id", "profile_id", "controller_role_id",
                    "source_issuer_id", "device_enrollment_id", "capture_backend_artifact_id",
                    "session_policy_id", "sample_format_schema_id"):
            _opaque(getattr(self, key), f"audio selection {key}")
        _digest(self.capture_backend_sha256, "capture backend digest")
        if (type(self.resource_generation) is not int or self.resource_generation < 1
                or type(self.max_capture_bytes) is not int or not 1 <= self.max_capture_bytes <= _MAX_AUDIO_BYTES
                or type(self.max_capture_seconds) is not int or not 1 <= self.max_capture_seconds <= _MAX_AUDIO_SECONDS):
            raise ChannelIngressDenied("audio ingress selection bounds are malformed")


@dataclass(frozen=True, slots=True)
class ObservedChannelIngress:
    """Private observer proof paired with the exact canonical event payload."""
    proof: object = field(repr=False)
    payload: bytes = field(repr=False)


class RootHttpIngressObserver(Protocol):
    """Root-selected listener and actual JWT/principal/session verifier."""
    def observe_selected_http_ingress(self, selection_handle: object,
                                     root_request_record: object) -> object: ...
    def validate_http_observation(self, selection: HttpIngressSelection,
                                  proof: object, *, now_monotonic: float) -> Mapping[str, Any]: ...
    def read_verified_http_body(self, selection: HttpIngressSelection, proof: object) -> bytes: ...


class RootAudioIngressObserver(Protocol):
    """Root-selected real device/session/consent/capture observer."""
    def observe_selected_audio_ingress(self, selection_handle: object,
                                      root_capture_record: object) -> object: ...
    def validate_audio_observation(self, selection: AudioIngressSelection,
                                   proof: object, *, now_monotonic: float) -> Mapping[str, Any]: ...


class _Producer:
    source_kind = "native-input"

    def __init__(self):
        pass


class AuthenticatedHttpIngressProducer(_Producer):
    """Source issuer callbacks for selected authenticated HTTP ingress."""
    def __init__(self, selection: HttpIngressSelection, selection_handle: object,
                 observer: RootHttpIngressObserver,
                 *, clock=time.monotonic):
        super().__init__()
        if not isinstance(selection, HttpIngressSelection):
            raise TypeError("root-selected HTTP ingress enrollment is required")
        if not all(callable(getattr(observer, name, None)) for name in (
            "observe_selected_http_ingress", "validate_http_observation", "read_verified_http_body"
        )):
            raise TypeError("root HTTP listener/JWT/session/body verifier is required")
        self.selection, self.selection_handle, self.observer, self._clock = selection, selection_handle, observer, clock
        self._pending: dict[int, ObservedChannelIngress] = {}

    @property
    def observer_enrollment_id(self) -> str:
        return self.selection.source_issuer_id

    @property
    def protected_selection_handle(self) -> object:
        """Opaque host selection handle for root-side selected listeners only."""
        return self.selection_handle

    def proof_claims(self, proof: object) -> Mapping[str, Any]:
        """Return strictly validated root claims; intended for host adapters."""
        return self._validate(proof)

    def observe(self, root_request_record: object) -> ObservedChannelIngress:
        proof = self.observer.observe_selected_http_ingress(self.selection_handle, root_request_record)
        claims = self._validate(proof)
        body = self.observer.read_verified_http_body(self.selection, proof)
        canonical, digest = _canonical_body(body, self.selection.max_body_bytes)
        if not hmac.compare_digest(digest, claims["body_sha256"]):
            raise ChannelIngressDenied("HTTP body differs from root-authenticated request receipt")
        event = {"text": claims["text"], "session_id": claims["session_id"],
                 "request_id": claims["request_id"], "subject_id": claims["subject_id"],
                 "raw_body_sha256": claims["body_sha256"],
                 "raw_body_size_bytes": claims["raw_body_size_bytes"]}
        observed = ObservedChannelIngress(proof, _canonical_json(event))
        self._pending[id(observed)] = observed
        return observed

    def consume_verified_raw_observation(self, raw_observation: object,
                                         controller_proof: object) -> Mapping[str, Any]:
        """Return exact root-observed HTTP bytes once for the event issuer.

        The issuer seals the returned fields into its own private validated
        observation. This adapter only consumes an object identity minted by
        ``observe`` and revalidates the bound controller and JWT/session proof.
        """
        if (type(raw_observation) is not ObservedChannelIngress
                or self._pending.get(id(raw_observation)) is not raw_observation):
            raise ChannelIngressDenied("HTTP raw observation is unknown, replayed or caller-constructed")
        proof = raw_observation.proof
        claims = self._validate(proof)
        if (not callable(getattr(controller_proof, "revalidate", None))
                or controller_proof.revalidate() is not True
                or controller_proof.controller_role_id != self.selection.controller_role_id
                or controller_proof.source_issuer_id != self.selection.source_issuer_id
                or controller_proof.resource_generation != str(self.selection.resource_generation)):
            raise ChannelIngressDenied("HTTP observation is not bound to the current selected controller")
        body = self.observer.read_verified_http_body(self.selection, proof)
        canonical, digest = _canonical_body(body, self.selection.max_body_bytes)
        if (not hmac.compare_digest(digest, claims["body_sha256"])
                or raw_observation.payload != _canonical_json({
                    "text": claims["text"], "session_id": claims["session_id"],
                    "request_id": claims["request_id"], "subject_id": claims["subject_id"],
                    "raw_body_sha256": digest, "raw_body_size_bytes": len(body)})):
            raise ChannelIngressDenied("HTTP source event differs from its exact root request")
        body_value = json.loads(canonical)
        event_data = {"text": body_value["text"], "session_id": claims["session_id"],
                      "request_id": claims["request_id"], "subject_id": claims["subject_id"],
                      "raw_body_sha256": digest, "raw_body_size_bytes": len(body)}
        del self._pending[id(raw_observation)]
        event_id = secrets.token_urlsafe(32)
        replay = hashlib.sha256(_canonical_json({"selection_id": self.selection.id,
            "session_id": claims["session_id"], "request_id": claims["request_id"],
            "body_sha256": digest})).hexdigest()
        return {"raw_observation_handle": secrets.token_urlsafe(32), "raw_payload": body,
                "event_id": event_id, "replay_key_sha256": replay,
                "observed_monotonic": claims["issued_monotonic"], "event_data": event_data}

    def release_verified_raw_observation(self, raw_observation: object) -> None:
        if type(raw_observation) is ObservedChannelIngress:
            self._pending.pop(id(raw_observation), None)

    def validate_claims(self, proof: object) -> bool:
        try:
            self._validate(proof)
            return True
        except Exception:
            return False

    def _validate(self, proof: object) -> dict[str, Any]:
        try:
            raw = self.observer.validate_http_observation(
                self.selection, proof, now_monotonic=float(self._clock()))
        except (PermissionError, ValueError, TypeError, RuntimeError):
            raise ChannelIngressDenied("HTTP JWT/principal/session is no longer current") from None
        fields = {"schema", "proof_handle", "selection_id", "session_handle",
                  "authenticated_subject_receipt_handle", "request_receipt_handle", "request_id",
                  "session_id", "subject_id", "text", "raw_body_size_bytes", "body_sha256",
                  "controller_identity_digest", "service_generation_digest", "issued_monotonic",
                  "expires_monotonic"}
        if not isinstance(raw, Mapping) or set(raw) != fields or type(raw["schema"]) is not int or raw["schema"] != 1:
            raise ChannelIngressDenied("HTTP observer claims differ from the exact RB-T08 v40 proof schema")
        now = float(self._clock())
        issued, expires = (_monotonic(raw["issued_monotonic"], "HTTP issue time"),
                           _monotonic(raw["expires_monotonic"], "HTTP expiry"))
        if (raw["selection_id"] != self.selection.id or not issued <= now < expires
                or now - issued > self.selection.max_event_age_seconds
                or expires - issued > _MAX_PROOF_LEASE):
            raise ChannelIngressDenied("HTTP selection, session freshness or lease is invalid")
        body, digest = _canonical_body(
            self.observer.read_verified_http_body(self.selection, proof), self.selection.max_body_bytes)
        body_value = json.loads(body)
        if not hmac.compare_digest(digest, _digest(raw["body_sha256"], "HTTP body digest")):
            raise ChannelIngressDenied("HTTP body changed after the authenticated request observation")
        if (set(body_value) != {"text"} or not isinstance(body_value["text"], str)
                or not 1 <= len(body_value["text"]) <= 65536 or raw["text"] != body_value["text"]
                or not isinstance(raw["raw_body_size_bytes"], int)
                or not 1 <= raw["raw_body_size_bytes"] <= self.selection.max_body_bytes):
            raise ChannelIngressDenied("HTTP event differs from the pinned text-only request schema")
        return {"proof_handle": _opaque(raw["proof_handle"], "HTTP proof handle"),
                "selection_id": self.selection.id,
                "session_handle": _opaque(raw["session_handle"], "HTTP session handle"),
                "authenticated_subject_receipt_handle": _opaque(
                    raw["authenticated_subject_receipt_handle"], "authenticated subject receipt"),
                "request_receipt_handle": _opaque(raw["request_receipt_handle"], "request proof"),
                "request_id": _opaque(raw["request_id"], "request ID"),
                "session_id": _opaque(raw["session_id"], "session ID"),
                "subject_id": _opaque(raw["subject_id"], "subject ID"), "text": body_value["text"],
                "raw_body_size_bytes": raw["raw_body_size_bytes"],
                "body_sha256": digest,
                "controller_identity_digest": _digest(raw["controller_identity_digest"], "controller identity digest"),
                "service_generation_digest": _digest(raw["service_generation_digest"], "service generation digest"),
                "issued_monotonic": issued, "expires_monotonic": expires}


class SelectedAudioIngressProducer(_Producer):
    """Source issuer callbacks for consented, bounded root-selected audio capture."""
    def __init__(self, selection: AudioIngressSelection, selection_handle: object,
                 observer: RootAudioIngressObserver,
                 *, clock=time.monotonic):
        super().__init__()
        if not isinstance(selection, AudioIngressSelection):
            raise TypeError("root-selected audio ingress enrollment is required")
        if not all(callable(getattr(observer, name, None)) for name in (
            "observe_selected_audio_ingress", "validate_audio_observation"
        )):
            raise TypeError("root audio device/session/consent/capture observer is required")
        self.selection, self.selection_handle, self.observer, self._clock = selection, selection_handle, observer, clock
        self._pending: dict[int, ObservedChannelIngress] = {}

    @property
    def observer_enrollment_id(self) -> str:
        return self.selection.source_issuer_id

    @property
    def protected_selection_handle(self) -> object:
        """Opaque host selection handle for root-side selected capture only."""
        return self.selection_handle

    def proof_claims(self, proof: object) -> Mapping[str, Any]:
        """Return strictly validated root claims; intended for host adapters."""
        return self._validate(proof)

    def observe(self, root_capture_record: object) -> ObservedChannelIngress:
        proof = self.observer.observe_selected_audio_ingress(self.selection_handle, root_capture_record)
        claims = self._validate(proof)
        # Audio bytes remain in the root-owned artifact store and are never
        # copied into the source event or exposed to the plugin/model.
        payload = _canonical_json({"session_id": claims["session_handle"], "capture_id": claims["capture_id"],
                                   "audio_artifact_receipt_handle": claims["audio_artifact_receipt_handle"],
                                   "audio_sha256": claims["audio_sha256"],
                                   "audio_size_bytes": claims["size_bytes"],
                                   "format": "pcm-s16le-mono", "sample_rate_hz": 16000,
                                   "duration_milliseconds": claims["duration_milliseconds"]})
        observed = ObservedChannelIngress(proof, payload)
        self._pending[id(observed)] = observed
        return observed

    def consume_verified_raw_observation(self, raw_observation: object,
                                         controller_proof: object) -> Mapping[str, Any]:
        """Consume selected audio metadata; PCM stays in its sealed artifact."""
        if (type(raw_observation) is not ObservedChannelIngress
                or self._pending.get(id(raw_observation)) is not raw_observation):
            raise ChannelIngressDenied("audio raw observation is unknown, replayed or caller-constructed")
        claims = self._validate(raw_observation.proof)
        if (not callable(getattr(controller_proof, "revalidate", None))
                or controller_proof.revalidate() is not True
                or controller_proof.controller_role_id != self.selection.controller_role_id
                or controller_proof.source_issuer_id != self.selection.source_issuer_id
                or controller_proof.resource_generation != str(self.selection.resource_generation)):
            raise ChannelIngressDenied("audio observation is not bound to the current selected controller")
        event_data = {"session_id": claims["session_handle"], "capture_id": claims["capture_id"],
                      "audio_artifact_receipt_handle": claims["audio_artifact_receipt_handle"],
                      "audio_sha256": claims["audio_sha256"], "audio_size_bytes": claims["size_bytes"],
                      "format": "pcm-s16le-mono", "sample_rate_hz": 16000,
                      "duration_milliseconds": claims["duration_milliseconds"]}
        if raw_observation.payload != _canonical_json(event_data):
            raise ChannelIngressDenied("audio event differs from its root capture receipt")
        del self._pending[id(raw_observation)]
        event_id = secrets.token_urlsafe(32)
        replay = hashlib.sha256(_canonical_json({"selection_id": self.selection.id,
            "session_id": claims["session_handle"], "capture_id": claims["capture_id"],
            "audio_sha256": claims["audio_sha256"]})).hexdigest()
        return {"raw_observation_handle": secrets.token_urlsafe(32),
                "raw_payload": raw_observation.payload, "event_id": event_id,
                "replay_key_sha256": replay, "observed_monotonic": claims["issued_monotonic"],
                "event_data": event_data}

    def release_verified_raw_observation(self, raw_observation: object) -> None:
        if type(raw_observation) is ObservedChannelIngress:
            self._pending.pop(id(raw_observation), None)

    def validate_claims(self, proof: object) -> bool:
        try:
            self._validate(proof)
            return True
        except Exception:
            return False

    def _validate(self, proof: object) -> dict[str, Any]:
        try:
            raw = self.observer.validate_audio_observation(
                self.selection, proof, now_monotonic=float(self._clock()))
        except (PermissionError, ValueError, TypeError, RuntimeError):
            raise ChannelIngressDenied("audio device/session permission or capture is no longer current") from None
        fields = {"schema", "proof_handle", "selection_id", "session_handle", "session_id", "consent_receipt_handle",
                  "capture_receipt_handle", "audio_artifact_id", "audio_sha256", "size_bytes",
                  "audio_artifact_receipt_handle", "capture_id", "duration_milliseconds",
                  "format_schema_id", "controller_identity_digest", "service_generation_digest",
                  "issued_monotonic", "expires_monotonic"}
        if not isinstance(raw, Mapping) or set(raw) != fields or type(raw["schema"]) is not int or raw["schema"] != 1:
            raise ChannelIngressDenied("audio observer claims differ from the exact RB-T08 v40 proof schema")
        now = float(self._clock())
        issued, expires = (_monotonic(raw["issued_monotonic"], "audio issue time"),
                           _monotonic(raw["expires_monotonic"], "audio expiry"))
        if (raw["selection_id"] != self.selection.id or raw["format_schema_id"] != self.selection.sample_format_schema_id
                or type(raw["size_bytes"]) is not int or not 1 <= raw["size_bytes"] <= self.selection.max_capture_bytes
                or raw["size_bytes"] % 32 != 0
                or not issued <= now < expires or expires - issued > _MAX_PROOF_LEASE):
            raise ChannelIngressDenied("audio selection, sample format, size or lease is invalid")
        duration = raw["size_bytes"] // 32
        if (type(raw["duration_milliseconds"]) is not int or raw["duration_milliseconds"] != duration
                or not 1 <= duration <= min(60000, self.selection.max_capture_seconds * 1000)):
            raise ChannelIngressDenied("audio duration differs from bounded sealed PCM byte count")
        return {"proof_handle": _opaque(raw["proof_handle"], "audio proof handle"),
                "selection_id": self.selection.id,
                "session_handle": _opaque(raw["session_handle"], "audio session handle"),
                "consent_receipt_handle": _opaque(raw["consent_receipt_handle"], "audio consent receipt"),
                "capture_receipt_handle": _opaque(raw["capture_receipt_handle"], "audio capture receipt"),
                "audio_artifact_id": _opaque(raw["audio_artifact_id"], "audio artifact ID"),
                "audio_artifact_receipt_handle": _opaque(raw["audio_artifact_receipt_handle"],
                                                          "audio artifact receipt handle"),
                "capture_id": _opaque(raw["capture_id"], "capture ID"),
                "duration_milliseconds": raw["duration_milliseconds"],
                "audio_sha256": _digest(raw["audio_sha256"], "audio content digest"),
                "size_bytes": raw["size_bytes"], "format_schema_id": raw["format_schema_id"],
                "controller_identity_digest": _digest(raw["controller_identity_digest"], "controller identity digest"),
                "service_generation_digest": _digest(raw["service_generation_digest"], "service generation digest"),
                "issued_monotonic": issued, "expires_monotonic": expires}
