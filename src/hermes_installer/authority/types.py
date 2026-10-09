"""Opaque host-issued principals and one-effect grants (HI03/HI04).

These records are transport values, not local proof. Only the authority service
may sign them and only the protected broker may verify and consume a grant.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class AuthorityDenied(PermissionError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Sensitivity(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    CONFIDENTIAL = "confidential"
    UNKNOWN = "unknown"


_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_AUTHORITY_OPERATIONS = frozenset({
    "provider.dispatch", "mcp.request", "mcp.stdio", "memory.request", "memory.doctor",
    "memory.capture", "memory.search", "memory.export", "memory.delete", "memory.extract",
    "memory.embed", "memory.backup", "memory.restore", "memory.enqueue", "memory.result",
    "host.write", "alert.deliver", "process.start", "process.status", "process.read",
    "process.write", "process.stop", "artifact.fetch", "package.install",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.orchestrator.recruit",
    "source.capture",
})


def _identifier(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AuthorityDenied("claims.invalid", f"{name} is invalid")
    return value


def _digest(value: Any, name: str, *, optional: bool = False) -> str:
    if optional and value == "":
        return ""
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise AuthorityDenied("claims.invalid", f"{name} is invalid")
    return value


def _time(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise AuthorityDenied("claims.invalid", f"{name} is invalid")
    return float(value)


@dataclass(frozen=True, slots=True)
class HostContext:
    """Signed claims derived by the authority from SO_PEERCRED and policy."""

    principal_id: str
    profile_id: str
    namespace_id: str
    uid: int
    purpose: str
    intent_id: str
    trace_id: str
    sensitivity: Sensitivity
    lineage_hash: str
    policy_revision: str
    capabilities: frozenset[str]
    issued_at_monotonic: float
    monotonic_expires_at: float
    nonce: str
    grant_id: str
    signature: str
    source_receipts: tuple["SourceReceipt", ...] = ()
    final_payload_digest: str | None = None
    enrollment_id: str | None = None
    generation: str | None = None
    operation: str | None = None
    native_process_identity: str | None = None

    def __post_init__(self) -> None:
        for name in ("principal_id", "profile_id", "namespace_id", "purpose", "intent_id", "trace_id", "policy_revision", "nonce", "grant_id", "signature"):
            _identifier(getattr(self, name), name)
        if type(self.uid) is not int or self.uid <= 0:
            raise AuthorityDenied("claims.invalid", "uid is invalid")
        if not isinstance(self.sensitivity, Sensitivity):
            raise AuthorityDenied("claims.invalid", "sensitivity is invalid")
        _digest(self.lineage_hash, "lineage_hash")
        if not isinstance(self.capabilities, frozenset) or any(not isinstance(x, str) or not _ID.fullmatch(x) for x in self.capabilities):
            raise AuthorityDenied("claims.invalid", "capabilities are invalid")
        if (not isinstance(self.source_receipts, tuple)
                or any(not isinstance(item, SourceReceipt) for item in self.source_receipts)
                or len(self.source_receipts) > 64):
            raise AuthorityDenied("claims.invalid", "source receipt lineage is invalid")
        if self.final_payload_digest is not None:
            _digest(self.final_payload_digest, "final_payload_digest")
        for name in ("enrollment_id", "generation", "operation", "native_process_identity"):
            value = getattr(self, name)
            if value is not None:
                _identifier(value, name)
        if self.operation is not None and self.operation not in _AUTHORITY_OPERATIONS:
            raise AuthorityDenied("claims.invalid", "operation is not a fixed host effect")
        issued = _time(self.issued_at_monotonic, "issued_at_monotonic")
        expires = _time(self.monotonic_expires_at, "monotonic_expires_at")
        if expires <= issued or expires - issued > 600:
            raise AuthorityDenied("claims.invalid", "context lease exceeds its bound")

    @property
    def effective_sensitivity(self) -> Sensitivity:
        return self.sensitivity

    def claims(self) -> dict[str, Any]:
        claims = {
            "principal_id": self.principal_id, "profile_id": self.profile_id,
            "namespace_id": self.namespace_id, "uid": self.uid,
            "purpose": self.purpose, "intent_id": self.intent_id,
            "trace_id": self.trace_id, "sensitivity": self.sensitivity.value,
            "lineage_hash": self.lineage_hash, "policy_revision": self.policy_revision,
            "capabilities": sorted(self.capabilities),
            "issued_at_monotonic": self.issued_at_monotonic,
            "monotonic_expires_at": self.monotonic_expires_at,
            "nonce": self.nonce, "grant_id": self.grant_id,
        }
        if self.source_receipts:
            claims["source_receipts"] = [item.to_wire() for item in self.source_receipts]
        if self.final_payload_digest is not None:
            claims["final_payload_digest"] = self.final_payload_digest
        for name in ("enrollment_id", "generation", "operation", "native_process_identity"):
            value = getattr(self, name)
            if value is not None:
                claims[name] = value
        return claims

    def to_wire(self) -> dict[str, Any]:
        return {**self.claims(), "signature": self.signature}

    @classmethod
    def from_wire(cls, value: Any) -> "HostContext":
        if not isinstance(value, dict):
            raise AuthorityDenied("claims.invalid", "host context is malformed")
        required = {"principal_id", "profile_id", "namespace_id", "uid", "purpose", "intent_id", "trace_id", "sensitivity", "lineage_hash", "policy_revision", "capabilities", "issued_at_monotonic", "monotonic_expires_at", "nonce", "grant_id", "signature"}
        optional = {"source_receipts", "final_payload_digest", "enrollment_id", "generation",
                    "operation", "native_process_identity"}
        if not required.issubset(value) or set(value) - required - optional or not isinstance(value["capabilities"], list):
            raise AuthorityDenied("claims.invalid", "host context fields are invalid")
        try:
            fields = dict(value)
            receipts = fields.pop("source_receipts", [])
            final_digest = fields.pop("final_payload_digest", None)
            if not isinstance(receipts, list):
                raise ValueError("receipts")
            return cls(**{**fields, "sensitivity": Sensitivity(value["sensitivity"]),
                          "capabilities": frozenset(value["capabilities"]),
                          "source_receipts": tuple(SourceReceipt.from_wire(item) for item in receipts),
                          "final_payload_digest": final_digest})
        except (ValueError, TypeError, KeyError):
            raise AuthorityDenied("claims.invalid", "host context fields are invalid") from None


@dataclass(frozen=True, slots=True)
class SourceReceipt:
    """Signed digest/provenance from a trusted in-process source adapter."""

    receipt_id: str
    issuer_id: str
    source_kind: str
    principal_id: str
    profile_id: str
    namespace_id: str
    uid: int
    origin_id: str
    process_generation: str
    payload_digest: str
    sensitivity: Sensitivity
    parent_lineage_hash: str
    policy_revision: str
    recipient_ceiling: frozenset[str]
    issued_at_monotonic: float
    monotonic_expires_at: float
    signature: str
    enrollment_id: str = ""
    native_process_identity: str = ""
    parent_receipt_ids: tuple[str, ...] = ()
    nonce: str = ""

    def __post_init__(self) -> None:
        for name in ("receipt_id", "issuer_id", "source_kind", "principal_id", "profile_id",
                     "namespace_id", "origin_id", "process_generation", "policy_revision", "signature"):
            _identifier(getattr(self, name), name)
        for name in ("enrollment_id", "native_process_identity", "nonce"):
            _identifier(getattr(self, name), name)
        if type(self.uid) is not int or self.uid <= 0 or not isinstance(self.sensitivity, Sensitivity):
            raise AuthorityDenied("source.invalid", "source receipt identity or sensitivity is invalid")
        _digest(self.payload_digest, "payload_digest")
        _digest(self.parent_lineage_hash, "parent_lineage_hash")
        if (not isinstance(self.recipient_ceiling, frozenset)
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in self.recipient_ceiling)
                or len(self.recipient_ceiling) > 64):
            raise AuthorityDenied("source.invalid", "source receipt recipient ceiling is invalid")
        if (not isinstance(self.parent_receipt_ids, tuple) or len(self.parent_receipt_ids) > 64
                or any(not isinstance(item, str) or not _ID.fullmatch(item) for item in self.parent_receipt_ids)
                or len(set(self.parent_receipt_ids)) != len(self.parent_receipt_ids)):
            raise AuthorityDenied("source.invalid", "source receipt parent closure is invalid")
        issued = _time(self.issued_at_monotonic, "issued_at_monotonic")
        expires = _time(self.monotonic_expires_at, "monotonic_expires_at")
        if expires <= issued or expires - issued > 600:
            raise AuthorityDenied("source.invalid", "source receipt lease exceeds its bound")

    def claims(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id, "issuer_id": self.issuer_id,
            "source_kind": self.source_kind, "principal_id": self.principal_id,
            "profile_id": self.profile_id, "namespace_id": self.namespace_id,
            "uid": self.uid, "origin_id": self.origin_id,
            "process_generation": self.process_generation,
            "payload_digest": self.payload_digest, "sensitivity": self.sensitivity.value,
            "parent_lineage_hash": self.parent_lineage_hash,
            "policy_revision": self.policy_revision,
            "recipient_ceiling": sorted(self.recipient_ceiling),
            "issued_at_monotonic": self.issued_at_monotonic,
            "monotonic_expires_at": self.monotonic_expires_at,
            "enrollment_id": self.enrollment_id,
            "native_process_identity": self.native_process_identity,
            "parent_receipt_ids": list(self.parent_receipt_ids),
            "nonce": self.nonce,
        }

    def to_wire(self) -> dict[str, Any]:
        return {**self.claims(), "signature": self.signature}

    @classmethod
    def from_wire(cls, value: Any) -> "SourceReceipt":
        required = {"receipt_id", "issuer_id", "source_kind", "principal_id", "profile_id",
                    "namespace_id", "uid", "origin_id", "process_generation", "payload_digest",
                    "sensitivity", "parent_lineage_hash", "policy_revision", "recipient_ceiling",
                    "issued_at_monotonic", "monotonic_expires_at", "signature", "enrollment_id",
                    "native_process_identity", "parent_receipt_ids", "nonce"}
        if not isinstance(value, dict) or set(value) != required or not isinstance(value["recipient_ceiling"], list):
            raise AuthorityDenied("source.invalid", "source receipt fields are invalid")
        if not isinstance(value["parent_receipt_ids"], list):
            raise AuthorityDenied("source.invalid", "source receipt parent closure is invalid")
        try:
            return cls(**{**value, "sensitivity": Sensitivity(value["sensitivity"]),
                          "recipient_ceiling": frozenset(value["recipient_ceiling"]),
                          "parent_receipt_ids": tuple(value["parent_receipt_ids"])})
        except (ValueError, TypeError, KeyError):
            raise AuthorityDenied("source.invalid", "source receipt fields are invalid") from None


@dataclass(frozen=True, slots=True)
class EffectAuthorization:
    """Signed, one-use grant bound to one exact effect and request digest."""

    principal_id: str
    profile_id: str
    namespace_id: str
    uid: int
    purpose: str
    sensitivity: Sensitivity
    trace_id: str
    policy_revision: str
    lineage_hash: str
    capability: str
    intent_id: str
    target: str
    recipient: str | None
    request_digest: str
    retry_index: int
    issued_at_monotonic: float
    monotonic_expires_at: float
    grant_id: str
    nonce: str
    context_digest: str
    signature: str
    source_receipts: tuple[SourceReceipt, ...] = ()
    final_payload_digest: str | None = None
    enrollment_id: str | None = None
    generation: str | None = None
    operation: str | None = None
    native_process_identity: str | None = None

    def __post_init__(self) -> None:
        for name in ("principal_id", "profile_id", "namespace_id", "purpose", "trace_id", "policy_revision", "capability", "intent_id", "target", "grant_id", "nonce", "signature"):
            _identifier(getattr(self, name), name)
        if self.recipient is not None:
            _identifier(self.recipient, "recipient")
        if type(self.uid) is not int or self.uid <= 0 or type(self.retry_index) is not int or self.retry_index < 0:
            raise AuthorityDenied("grant.invalid", "effect grant identity is invalid")
        if not isinstance(self.sensitivity, Sensitivity):
            raise AuthorityDenied("grant.invalid", "effect grant sensitivity is invalid")
        _digest(self.lineage_hash, "lineage_hash")
        _digest(self.request_digest, "request_digest")
        _digest(self.context_digest, "context_digest")
        if (not isinstance(self.source_receipts, tuple)
                or any(not isinstance(item, SourceReceipt) for item in self.source_receipts)
                or len(self.source_receipts) > 64):
            raise AuthorityDenied("grant.invalid", "effect grant source receipt lineage is invalid")
        if self.final_payload_digest is not None:
            _digest(self.final_payload_digest, "final_payload_digest")
        for name in ("enrollment_id", "generation", "operation", "native_process_identity"):
            value = getattr(self, name)
            if value is not None:
                _identifier(value, name)
        if self.operation is not None and self.operation not in _AUTHORITY_OPERATIONS:
            raise AuthorityDenied("grant.invalid", "operation is not a fixed host effect")
        issued = _time(self.issued_at_monotonic, "issued_at_monotonic")
        expires = _time(self.monotonic_expires_at, "monotonic_expires_at")
        if expires <= issued or expires - issued > 600:
            raise AuthorityDenied("grant.invalid", "effect grant lease exceeds its bound")

    def claims(self) -> dict[str, Any]:
        claims = {
            "principal_id": self.principal_id, "profile_id": self.profile_id,
            "namespace_id": self.namespace_id, "uid": self.uid,
            "purpose": self.purpose, "sensitivity": self.sensitivity.value,
            "trace_id": self.trace_id, "policy_revision": self.policy_revision,
            "lineage_hash": self.lineage_hash, "capability": self.capability,
            "intent_id": self.intent_id, "target": self.target,
            "recipient": self.recipient, "request_digest": self.request_digest,
            "retry_index": self.retry_index,
            "issued_at_monotonic": self.issued_at_monotonic,
            "monotonic_expires_at": self.monotonic_expires_at,
            "grant_id": self.grant_id, "nonce": self.nonce,
            "context_digest": self.context_digest,
        }
        if self.source_receipts:
            claims["source_receipts"] = [item.to_wire() for item in self.source_receipts]
        if self.final_payload_digest is not None:
            claims["final_payload_digest"] = self.final_payload_digest
        for name in ("enrollment_id", "generation", "operation", "native_process_identity"):
            value = getattr(self, name)
            if value is not None:
                claims[name] = value
        return claims

    def to_wire(self) -> dict[str, Any]:
        return {**self.claims(), "signature": self.signature}

    @classmethod
    def from_wire(cls, value: Any) -> "EffectAuthorization":
        if not isinstance(value, dict):
            raise AuthorityDenied("grant.invalid", "effect grant is malformed")
        required = {"principal_id", "profile_id", "namespace_id", "uid", "purpose", "sensitivity", "trace_id", "policy_revision", "lineage_hash", "capability", "intent_id", "target", "recipient", "request_digest", "retry_index", "issued_at_monotonic", "monotonic_expires_at", "grant_id", "nonce", "context_digest", "signature"}
        optional = {"source_receipts", "final_payload_digest", "enrollment_id", "generation",
                    "operation", "native_process_identity"}
        if not required.issubset(value) or set(value) - required - optional:
            raise AuthorityDenied("grant.invalid", "effect grant fields are invalid")
        try:
            fields = dict(value)
            receipts = fields.pop("source_receipts", [])
            final_digest = fields.pop("final_payload_digest", None)
            if not isinstance(receipts, list):
                raise ValueError("receipts")
            return cls(**{**fields, "sensitivity": Sensitivity(value["sensitivity"]),
                          "source_receipts": tuple(SourceReceipt.from_wire(item) for item in receipts),
                          "final_payload_digest": final_digest})
        except (ValueError, TypeError, KeyError):
            raise AuthorityDenied("grant.invalid", "effect grant fields are invalid") from None


@dataclass(frozen=True, slots=True)
class VerifiedEffectAuthorization:
    """Local receipt that the root authority verified a grant binding."""

    authorization: EffectAuthorization
    operation: str
    verified_at_monotonic: float
    verification_receipt: str


@dataclass(frozen=True, slots=True)
class BrokeredEffectResponse:
    status: int
    body: bytes
    headers: Mapping[str, str]
    receipt_id: str


def canonical_bytes(value: bytes | Mapping[str, Any] | list[Any]) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_digest(value: bytes | Mapping[str, Any] | list[Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()
