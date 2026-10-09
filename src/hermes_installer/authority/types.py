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
    "host.write", "alert.deliver", "plugin.agent-live-wallet.execute",
    "plugin.agent-live-wallet.read", "plugin.agent-sandbox-wallet.execute",
    "plugin.agent-sandbox-wallet.read", "plugin.authentik-authorization.read",
    "plugin.cloudflare-homelab.read", "plugin.cloudflare-homelab.write",
    "plugin.codex.run", "plugin.composio.invoke", "plugin.ebook-toolchain.run",
    "plugin.epic-kanban.delete", "plugin.epic-kanban.read", "plugin.epic-kanban.write",
    "plugin.financial-data-hub.read", "plugin.financial-execution-gateway.execute",
    "plugin.github.admin", "plugin.github.read", "plugin.github.write",
    "plugin.homelab-ops-broker.read", "plugin.homelab-ops-broker.write",
    "plugin.kobo-bridge.deliver", "plugin.kobo-bridge.read",
    "plugin.resource-overlay-store.backup", "plugin.resource-overlay-store.read",
    "plugin.resource-overlay-store.write", "plugin.voice-pipeline.session",
    "plugin.voice-pipeline.stt", "plugin.voice-pipeline.tts", "plugin.web.read",
    "process.start", "process.status", "process.read",
    "process.write", "process.stop", "artifact.fetch", "package.install",
    "process.inspect", "connector.open", "connector.read", "connector.write",
    "connector.close", "native.event.prepare", "native.request.dispatch",
    "resource.cron.run", "resource.channel.route", "resource.webhook.deliver",
    "resource.webhook.run", "resource.channel.run", "resource.bundle.node.run",
    "resource.job.admit", "resource.job.child.admit",
    "resource.orchestrator.recruit",
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
    source_receipt_handle: str | None = None
    producer_context_handle: str | None = None
    tool_call_bindings: tuple["NativeToolCallBinding", ...] = ()


@dataclass(frozen=True, slots=True)
class NativeEventHandle:
    """Opaque short-lived root lookup handle for one native dispatch attempt."""

    native_event_handle: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not isinstance(self.native_event_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.native_event_handle)):
            raise AuthorityDenied("native.handle", "native event handle is malformed")
        expiry = _time(self.expires_monotonic, "native event expiry")
        if expiry <= 0:
            raise AuthorityDenied("native.handle", "native event expiry is invalid")


@dataclass(frozen=True, slots=True)
class NativeInvocationBinding:
    """Root-registered, one-use binding for an observed native tool call."""

    invocation_handle: str
    package_id: str
    profile_id: str
    generation: str
    adapter_id: str
    action_id: str
    arguments_sha256: str
    parent_closure_digest: str
    expires_monotonic: float
    binding_sha256: str

    def __post_init__(self) -> None:
        if (not isinstance(self.invocation_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.invocation_handle)):
            raise AuthorityDenied("native.invocation", "native invocation handle is malformed")
        for name in ("package_id", "profile_id", "generation", "adapter_id", "action_id"):
            value = getattr(self, name)
            if (not isinstance(value, str) or not 1 <= len(value) <= 192
                    or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
                raise AuthorityDenied("native.invocation", f"native invocation {name} is malformed")
        for name in ("arguments_sha256", "parent_closure_digest", "binding_sha256"):
            if not isinstance(getattr(self, name), str) or not re.fullmatch(r"[0-9a-f]{64}", getattr(self, name)):
                raise AuthorityDenied("native.invocation", f"native invocation {name} is malformed")
        if _time(self.expires_monotonic, "native invocation expiry") <= 0:
            raise AuthorityDenied("native.invocation", "native invocation expiry is invalid")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": 1, "invocation_handle": self.invocation_handle,
                "package_id": self.package_id, "profile_id": self.profile_id,
                "generation": self.generation, "adapter_id": self.adapter_id,
                "action_id": self.action_id, "arguments_sha256": self.arguments_sha256,
                "parent_closure_digest": self.parent_closure_digest,
                "expires_monotonic": self.expires_monotonic,
                "binding_sha256": self.binding_sha256}

    @classmethod
    def from_wire(cls, value: Any, *, monotonic: Any) -> "NativeInvocationBinding":
        fields = {"schema", "invocation_handle", "package_id", "profile_id", "generation",
                  "adapter_id", "action_id", "arguments_sha256", "parent_closure_digest",
                  "expires_monotonic", "binding_sha256"}
        if not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1:
            raise AuthorityDenied("native.invocation", "native invocation response fields are invalid")
        try:
            result = cls(**{key: item for key, item in value.items() if key != "schema"})
        except (TypeError, ValueError):
            raise AuthorityDenied("native.invocation", "native invocation response is malformed") from None
        if result.expires_monotonic <= monotonic():
            raise AuthorityDenied("native.invocation", "native invocation binding is expired")
        return result


@dataclass(frozen=True, slots=True)
class NativeInvocationContexts:
    """Bounded same-peer receipt ancestry for a root-registered invocation."""

    invocation_handle: str
    source_receipt_handles: tuple[str, ...]
    parent_closure_digest: str
    arguments_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not isinstance(self.invocation_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.invocation_handle)
                or not isinstance(self.source_receipt_handles, tuple)
                or len(self.source_receipt_handles) > 128
                or any(not isinstance(item, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", item)
                       for item in self.source_receipt_handles)
                or len(set(self.source_receipt_handles)) != len(self.source_receipt_handles)):
            raise AuthorityDenied("native.invocation", "native invocation contexts are malformed")
        for name in ("parent_closure_digest", "arguments_sha256"):
            if not isinstance(getattr(self, name), str) or not re.fullmatch(r"[0-9a-f]{64}", getattr(self, name)):
                raise AuthorityDenied("native.invocation", f"native invocation {name} is malformed")
        if _time(self.expires_monotonic, "native invocation context expiry") <= 0:
            raise AuthorityDenied("native.invocation", "native invocation context expiry is invalid")

    def to_wire(self) -> dict[str, Any]:
        return {"schema": 1, "invocation_handle": self.invocation_handle,
                "source_receipt_handles": list(self.source_receipt_handles),
                "parent_closure_digest": self.parent_closure_digest,
                "arguments_sha256": self.arguments_sha256,
                "expires_monotonic": self.expires_monotonic}

    @classmethod
    def from_wire(cls, value: Any, *, monotonic: Any) -> "NativeInvocationContexts":
        fields = {"schema", "invocation_handle", "source_receipt_handles",
                  "parent_closure_digest", "arguments_sha256", "expires_monotonic"}
        if (not isinstance(value, dict) or set(value) != fields
                or type(value["schema"]) is not int or value["schema"] != 1
                or not isinstance(value["source_receipt_handles"], list)):
            raise AuthorityDenied("native.invocation", "native invocation context response fields are invalid")
        try:
            result = cls(**{**{key: item for key, item in value.items() if key != "schema"},
                           "source_receipt_handles": tuple(value["source_receipt_handles"])})
        except (TypeError, ValueError):
            raise AuthorityDenied("native.invocation", "native invocation context response is malformed") from None
        if result.expires_monotonic <= monotonic():
            raise AuthorityDenied("native.invocation", "native invocation context has expired")
        return result


@dataclass(frozen=True, slots=True)
class NativeToolCallBinding:
    """Root-parsed provider tool call bound to one observed response body."""

    observed_call_handle: str
    provider_tool_call_id: str
    tool_name: str
    arguments_sha256: str

    def __post_init__(self) -> None:
        if (not isinstance(self.observed_call_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.observed_call_handle)):
            raise AuthorityDenied("native.tool-call", "observed native tool call handle is malformed")
        for name in ("provider_tool_call_id", "tool_name"):
            value = getattr(self, name)
            if (not isinstance(value, str) or not 1 <= len(value) <= 256
                    or any(ord(char) < 0x21 or ord(char) > 0x7e for char in value)):
                raise AuthorityDenied("native.tool-call", f"native tool call {name} is malformed")
        if not isinstance(self.arguments_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", self.arguments_sha256):
            raise AuthorityDenied("native.tool-call", "native tool call argument digest is malformed")

    @classmethod
    def from_wire(cls, value: Any) -> "NativeToolCallBinding":
        fields = {"observed_call_handle", "provider_tool_call_id", "tool_name", "arguments_sha256"}
        if not isinstance(value, dict) or set(value) != fields:
            raise AuthorityDenied("native.tool-call", "native tool call response fields are invalid")
        try:
            return cls(**value)
        except (TypeError, ValueError):
            raise AuthorityDenied("native.tool-call", "native tool call response is malformed") from None


@dataclass(frozen=True, slots=True)
class NativeResponseMetadata:
    """Root response metadata released by a one-use peer-bound lookup."""

    producer_context_handle: str
    tool_call_bindings: tuple[NativeToolCallBinding, ...]
    turn_handle: str | None
    final_response_delivery_handle: str | None

    def __post_init__(self) -> None:
        if (not isinstance(self.producer_context_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.producer_context_handle)
                or not isinstance(self.tool_call_bindings, tuple)
                or len(self.tool_call_bindings) > 128
                or any(not isinstance(item, NativeToolCallBinding) for item in self.tool_call_bindings)
                or len({item.observed_call_handle for item in self.tool_call_bindings})
                    != len(self.tool_call_bindings)
                or self.turn_handle is not None
                    and (not isinstance(self.turn_handle, str)
                         or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.turn_handle))
                or self.final_response_delivery_handle is not None
                    and (not isinstance(self.final_response_delivery_handle, str)
                         or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.final_response_delivery_handle))):
            raise AuthorityDenied("native.response.take", "provider response metadata is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {
            "producer_context_handle": self.producer_context_handle,
            "tool_call_bindings": [
                {"observed_call_handle": item.observed_call_handle,
                 "provider_tool_call_id": item.provider_tool_call_id,
                 "tool_name": item.tool_name,
                 "arguments_sha256": item.arguments_sha256}
                for item in self.tool_call_bindings
            ],
            "turn_handle": self.turn_handle,
            "final_response_delivery_handle": self.final_response_delivery_handle,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "NativeResponseMetadata":
        fields = {"producer_context_handle", "tool_call_bindings", "turn_handle",
                  "final_response_delivery_handle"}
        if (not isinstance(value, dict) or set(value) != fields
                or not isinstance(value["tool_call_bindings"], list)
                or len(value["tool_call_bindings"]) > 128):
            raise AuthorityDenied("native.response.take", "provider response metadata fields are invalid")
        return cls(
            value["producer_context_handle"],
            tuple(NativeToolCallBinding.from_wire(item) for item in value["tool_call_bindings"]),
            value["turn_handle"], value["final_response_delivery_handle"],
        )


@dataclass(frozen=True, slots=True)
class RootCompletedNativeTurnPresentation:
    """Opaque completion reference released after a root-verified native turn."""

    schema: int
    receipt_handle: str
    turn_handle: str
    state: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not isinstance(self.receipt_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.receipt_handle)
                or not isinstance(self.turn_handle, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", self.turn_handle)
                or self.state != "completed"
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)):
            raise AuthorityDenied("native.turn.finish", "native turn presentation is malformed")

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema,
            "receipt_handle": self.receipt_handle,
            "turn_handle": self.turn_handle,
            "state": self.state,
            "expires_monotonic": self.expires_monotonic,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "RootCompletedNativeTurnPresentation":
        fields = {"schema", "receipt_handle", "turn_handle", "state", "expires_monotonic"}
        if not isinstance(value, dict) or set(value) != fields:
            raise AuthorityDenied("native.turn.finish", "native turn presentation fields are invalid")
        try:
            return cls(**value)
        except (TypeError, ValueError):
            raise AuthorityDenied("native.turn.finish", "native turn presentation is malformed") from None


def canonical_bytes(value: bytes | Mapping[str, Any] | list[Any]) -> bytes:
    if isinstance(value, bytes):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_digest(value: bytes | Mapping[str, Any] | list[Any]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def strict_json_loads(data: str) -> Any:
    """Decode JSON while rejecting duplicate keys at every object depth."""
    def unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique_pairs)
