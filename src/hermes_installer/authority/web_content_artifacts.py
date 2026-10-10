"""Root-held web response bytes with effect, invocation and transport ancestry.

This registry is deliberately separate from the static ArtifactCatalog and
SourceObserverRegistry. Public web data is untrusted, but its exact bytes and
provenance still need a short-lived, profile-bound root receipt.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import stat
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

from hermes_installer.authority.types import AuthorityDenied, EffectAuthorization, HostContext

_MAX_BYTES = 2_097_152
_LEASE = 30.0
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_OBSERVATION_SEAL = object()
_TRANSPORT_SEAL = object()
_RECEIPT_SEAL = object()


class WebContentArtifactDenied(PermissionError):
    """A web response receipt is absent, stale, or failed a custody check."""


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedWebTransportReceipt:
    handle: str
    status: int
    final_url: str
    peer_ip: str
    tls_peer_sha256: str
    redirect_chain: tuple[str, ...]
    request_sha256: str
    body_sha256: str
    body_size_bytes: int
    media_type: str
    profile_id: str
    owner_generation: str
    issued_monotonic: float
    expires_monotonic: float
    observation_sha256: str
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _TRANSPORT_SEAL or not _HANDLE.fullmatch(self.handle)
                or not _SHA.fullmatch(self.request_sha256) or not _SHA.fullmatch(self.body_sha256)
                or not _SHA.fullmatch(self.tls_peer_sha256) or not _SHA.fullmatch(self.observation_sha256)
                or type(self.status) is not int or not 200 <= self.status < 300
                or type(self.body_size_bytes) is not int or not 1 <= self.body_size_bytes <= _MAX_BYTES
                or not self.redirect_chain or len(self.redirect_chain) > 5
                or any(not isinstance(url, str) or not 1 <= len(url) <= 2048 for url in self.redirect_chain)
                or not self.final_url or self.final_url != self.redirect_chain[-1]
                or not self.peer_ip or not self.profile_id or not self.owner_generation
                or not self.media_type or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic - self.issued_monotonic > _LEASE):
            raise TypeError("web transport receipts are issued only by the root transport registry")


@dataclass(frozen=True, slots=True, repr=False)
class VerifiedRootWebResponseObservation:
    observation_handle: str
    receipt_handle: str
    native_invocation_handle: str
    profile_id: str
    owner_generation: str
    operation_id: str
    final_url: str
    content_type: str
    redirect_chain: tuple[str, ...]
    canonical_request_sha256: str
    parent_source_receipt_handles: tuple[str, ...]
    transport_receipt_handle: str
    body_sha256: str
    body_size_bytes: int
    media_type: str
    issued_monotonic: float
    expires_monotonic: float
    root_effect_receipt_handle: str | None
    _body: bytes = field(repr=False, compare=False)
    _decoded_content: str = field(repr=False, compare=False)
    _context_payload: bytes = field(repr=False, compare=False)
    _context: HostContext = field(repr=False, compare=False)
    _authorization: EffectAuthorization = field(repr=False, compare=False)
    _invocation: Any = field(repr=False, compare=False)
    _transport: VerifiedWebTransportReceipt = field(repr=False, compare=False)
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _OBSERVATION_SEAL or not _HANDLE.fullmatch(self.observation_handle)
                or not _HANDLE.fullmatch(self.receipt_handle)
                or not _HANDLE.fullmatch(self.native_invocation_handle)
                or not _HANDLE.fullmatch(self.transport_receipt_handle)
                or self.root_effect_receipt_handle is not None
                and not _HANDLE.fullmatch(self.root_effect_receipt_handle)
                or not _SHA.fullmatch(self.canonical_request_sha256)
                or not _SHA.fullmatch(self.body_sha256)
                or not self.profile_id or not self.owner_generation or not _SHA.fullmatch(self.operation_id)
                or not isinstance(self.final_url, str) or not self.final_url.startswith("https://")
                or not isinstance(self.content_type, str) or not self.content_type
                or not isinstance(self.redirect_chain, tuple) or not self.redirect_chain
                or any(not isinstance(url, str) or len(url) > 2048 for url in self.redirect_chain)
                or self.redirect_chain[-1] != self.final_url
                or len(self.redirect_chain) > 5
                or not isinstance(self._decoded_content, str)
                or self.body_size_bytes > _MAX_BYTES
                or not self.parent_source_receipt_handles
                or len(set(self.parent_source_receipt_handles)) != len(self.parent_source_receipt_handles)
                or self._body is None or len(self._body) != self.body_size_bytes
                or hashlib.sha256(self._body).hexdigest() != self.body_sha256
                or self.expires_monotonic <= self.issued_monotonic
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic - self.issued_monotonic > _LEASE):
            raise TypeError("web response observations are minted only by the root handler registry")

    def staged_result_fields(self) -> dict[str, Any]:
        """Serialize a provisional receipt handle; resolution stays denied until service completion."""
        return {
            "artifact_id": f"web-content:{self.body_sha256}",
            "sha256": self.body_sha256,
            "size_bytes": self.body_size_bytes,
            "media_type": self.media_type,
            "profile_id": self.profile_id,
            "owner_generation": self.owner_generation,
            "operation_id": self.operation_id,
            "source_receipt_handle": self.receipt_handle,
            "expires_monotonic": self.expires_monotonic,
        }


@dataclass(frozen=True, slots=True, repr=False)
class RootWebContentArtifactReceipt:
    artifact_id: str
    sha256: str
    size_bytes: int
    media_type: str
    profile_id: str
    owner_generation: str
    operation_id: str
    source_receipt_handle: str
    expires_monotonic: float
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _RECEIPT_SEAL
                or self.artifact_id != f"web-content:{self.sha256}"
                or not _SHA.fullmatch(self.sha256)
                or type(self.size_bytes) is not int or not 1 <= self.size_bytes <= _MAX_BYTES
                or not self.media_type or not self.profile_id or not self.owner_generation
                or not _SHA.fullmatch(self.operation_id)
                or not _HANDLE.fullmatch(self.source_receipt_handle)
                or not math.isfinite(self.expires_monotonic)):
            raise TypeError("web content receipts are issued only by the root CAS registry")

    def as_result_fields(self) -> dict[str, Any]:
        if self._seal is not _RECEIPT_SEAL:
            raise WebContentArtifactDenied("web artifact receipt was not minted by the root registry")
        return {name: getattr(self, name) for name in (
            "artifact_id", "sha256", "size_bytes", "media_type", "profile_id",
            "owner_generation", "operation_id", "source_receipt_handle", "expires_monotonic")}


@dataclass(slots=True)
class _Pending:
    observation: VerifiedRootWebResponseObservation
    path: Path
    fd: int
    device: int
    inode: int
    response_status: int | None = None
    effect_receipt_id: str | None = None
    response_sha256: str | None = None


@dataclass(slots=True)
class _Published:
    observation: VerifiedRootWebResponseObservation
    receipt: RootWebContentArtifactReceipt
    path: Path
    fd: int
    device: int
    inode: int
    completion: Any
    response_body: bytes
    artifact_claims: Mapping[str, Any]
    completion_sha256: str
    completion_signature: str


class WebTransportReceiptRegistry:
    """Retains exact direct-TLS transport observations from the root web adapter."""

    def __init__(self, *, monotonic: Callable[[], float] = time.monotonic):
        self.monotonic = monotonic
        self._receipts: dict[str, VerifiedWebTransportReceipt] = {}
        self._lock = threading.RLock()

    def capture(self, capture: Any, *, request_sha256: str, profile_id: str,
                owner_generation: str, expires_monotonic: float) -> VerifiedWebTransportReceipt:
        from hermes_installer.components.plugin_public_https import (
            ScopedWebCapture, _SCOPED_CAPTURE_SEAL, _public_ip,
        )
        if (type(capture) is not ScopedWebCapture or capture._seal is not _SCOPED_CAPTURE_SEAL
                or not _SHA.fullmatch(request_sha256) or not profile_id or not owner_generation
                or expires_monotonic <= self.monotonic()):
            raise WebContentArtifactDenied("transport response is not a current root-captured TLS result")
        receipt = capture.transport_receipt
        body_sha256 = hashlib.sha256(capture.body).hexdigest()
        now = self.monotonic()
        expiry = min(float(expires_monotonic), now + _LEASE)
        if (not 200 <= receipt.status < 300 or not receipt.tls_peer_sha256
                or not _SHA.fullmatch(receipt.tls_peer_sha256)
                or not _public_ip(receipt.peer_ip)
                or receipt.url != capture.final_url
                or receipt.content_sha256 != body_sha256
                or receipt.byte_length != len(capture.body)
                or receipt.redirect_chain != capture.redirect_chain
                or not capture.redirect_chain or capture.redirect_chain[-1] != capture.final_url
                or not 1 <= len(capture.body) <= _MAX_BYTES):
            raise WebContentArtifactDenied("direct TLS receipt does not match captured response bytes")
        identity = {
            "status": receipt.status, "url": capture.final_url, "peer": receipt.peer_ip,
            "tls": receipt.tls_peer_sha256, "redirects": list(capture.redirect_chain),
            "request_sha256": request_sha256, "body_sha256": body_sha256,
            "body_size_bytes": len(capture.body), "media_type": capture.media_type,
            "profile_id": profile_id, "owner_generation": owner_generation,
        }
        canonical = json.dumps(identity, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        handle = secrets.token_urlsafe(32)
        result = VerifiedWebTransportReceipt(
            handle=handle, status=receipt.status, final_url=capture.final_url,
            peer_ip=receipt.peer_ip, tls_peer_sha256=receipt.tls_peer_sha256,
            redirect_chain=tuple(capture.redirect_chain), request_sha256=request_sha256,
            body_sha256=body_sha256, body_size_bytes=len(capture.body),
            media_type=capture.media_type, profile_id=profile_id,
            owner_generation=owner_generation, issued_monotonic=now,
            expires_monotonic=expiry, observation_sha256=hashlib.sha256(canonical).hexdigest(),
            _seal=_TRANSPORT_SEAL,
        )
        with self._lock:
            self._prune_locked()
            if handle in self._receipts:
                raise WebContentArtifactDenied("transport receipt handle collision")
            self._receipts[handle] = result
        return result

    def resolve(self, handle: str) -> VerifiedWebTransportReceipt:
        with self._lock:
            self._prune_locked()
            item = self._receipts.get(handle)
            if item is None or item._seal is not _TRANSPORT_SEAL:
                raise WebContentArtifactDenied("transport receipt is not retained by the root")
            return item

    def revoke(self, handle: str) -> bool:
        with self._lock:
            return self._receipts.pop(handle, None) is not None

    def _prune_locked(self) -> None:
        now = self.monotonic()
        self._receipts = {key: item for key, item in self._receipts.items()
                          if item.expires_monotonic > now}


class RootWebContentArtifactRegistry:
    """One-use staged response observations and root-only immutable content CAS."""

    @classmethod
    def from_authority_service(cls, service: Any, root_journal: Any,
                               web_transport_receipt_registry: WebTransportReceiptRegistry,
                               *, expected_uid: int = 0,
                               monotonic: Callable[[], float] = time.monotonic) -> "RootWebContentArtifactRegistry":
        return cls(service=service, root_journal=root_journal,
                   web_transport_receipt_registry=web_transport_receipt_registry,
                   expected_uid=expected_uid, monotonic=monotonic)

    def __init__(self, *, service: Any, root_journal: Any,
                 web_transport_receipt_registry: WebTransportReceiptRegistry,
                 expected_uid: int = 0, monotonic: Callable[[], float] = time.monotonic):
        if (not callable(getattr(service, "revalidate_effect", None))
                or not callable(getattr(service, "_sign", None))
                or not callable(getattr(service, "_binding", None))
                or not callable(getattr(web_transport_receipt_registry, "capture", None))
                or not callable(getattr(web_transport_receipt_registry, "resolve", None))
                or not isinstance(getattr(root_journal, "path", None), Path)
                or not root_journal.path.is_absolute()
                or type(expected_uid) is not int or os.geteuid() != expected_uid
                or getattr(root_journal, "device", None) is None
                or getattr(root_journal, "inode", None) is None
                or not isinstance(getattr(root_journal, "service_generation_digest", None), str)):
            raise ValueError("root web artifact registry requires selected service and journal custody")
        self.service, self.root_journal = service, root_journal
        self.transport_receipts = web_transport_receipt_registry
        self.expected_uid, self.monotonic = expected_uid, monotonic
        self.root = root_journal.path / "web-content"
        self._pending: dict[str, _Pending] = {}
        self._pending_grants: dict[str, str] = {}
        self._published: dict[str, _Published] = {}
        self._profile_bytes: dict[tuple[str, str], int] = {}
        self._path_refs: dict[Path, int] = {}
        self._lock = threading.RLock()
        self._closed = False
        self._verify_journal()
        self._mkdir(self.root)
        self._clear_stale(self.root)

    def prepare_authorized_response(self, context: HostContext,
                                    authorization: EffectAuthorization,
                                    request_payload: bytes, capture: Any) -> VerifiedRootWebResponseObservation:
        """Stage raw response bytes after binding the real selected invocation and TLS result."""
        from hermes_installer.components.plugin_public_https import (
            ScopedWebCapture, _SCOPED_CAPTURE_SEAL, _decode_public_content,
        )
        if (not isinstance(context, HostContext) or not isinstance(authorization, EffectAuthorization)
                or not isinstance(request_payload, bytes) or not isinstance(capture, ScopedWebCapture)
                or capture._seal is not _SCOPED_CAPTURE_SEAL
                or not 1 <= len(capture.body) <= _MAX_BYTES):
            raise WebContentArtifactDenied("authorized web response observation is malformed")
        request_sha = hashlib.sha256(request_payload).hexdigest()
        if (authorization.capability != "plugin:web" or authorization.operation != "plugin.web.read"
                or authorization.retry_index != 0 or authorization.request_digest != request_sha
                or context.final_payload_digest != request_sha or context.profile_id != authorization.profile_id
                or context.generation != authorization.generation):
            raise WebContentArtifactDenied("web observation differs from the selected effect grant")
        self._verify_current_effect(context, authorization)
        invocation_registry = getattr(self.service, "native_invocation_registry", None)
        resolve_invocation = getattr(invocation_registry, "resolve_invocation_for_effect", None)
        if not callable(resolve_invocation):
            raise WebContentArtifactDenied("selected native invocation resolver is not assembled")
        invocation = resolve_invocation(context, authorization, authorization.operation, request_sha)
        from hermes_installer.authority.native_runtime_observer import RootNativeToolEffectInvocation
        if (type(invocation) is not RootNativeToolEffectInvocation
                or not _HANDLE.fullmatch(getattr(invocation, "invocation_handle", ""))
                or invocation.operation != authorization.operation
                or invocation.request_digest != request_sha
                or invocation.profile_id != context.profile_id
                or invocation.generation != context.generation
                or invocation.service_generation_digest != self.service.service_generation_digest
                or invocation.expires_monotonic <= self.monotonic()
                or not invocation.source_receipt_handles
                or len(set(invocation.source_receipt_handles)) != len(invocation.source_receipt_handles)):
            raise WebContentArtifactDenied("native invocation does not join the current web effect")
        now = self.monotonic()
        expiry = min(now + _LEASE, authorization.monotonic_expires_at,
                     float(invocation.expires_monotonic))
        if expiry <= now:
            raise WebContentArtifactDenied("web invocation expires before artifact capture")
        transport = self.transport_receipts.capture(
            capture, request_sha256=request_sha, profile_id=context.profile_id,
            owner_generation=context.generation, expires_monotonic=expiry,
        )
        operation_id = hashlib.sha256(
            request_payload + b"\0" + capture.final_url.encode("utf-8") + b"\0"
            + b"\0".join(url.encode("utf-8") for url in capture.redirect_chain)
            + b"\0" + bytes.fromhex(transport.body_sha256)
        ).hexdigest()
        observation_handle = secrets.token_urlsafe(32)
        receipt_handle = secrets.token_urlsafe(32)
        profile_hash = hashlib.sha256(context.profile_id.encode("utf-8")).hexdigest()
        path = self.root / profile_hash / "objects" / transport.body_sha256
        key = context.profile_id, context.generation
        with self._lock:
            self._assert_open()
            self._verify_journal()
            self._prune_locked()
            if authorization.grant_id in self._pending_grants:
                self.transport_receipts.revoke(transport.handle)
                raise WebContentArtifactDenied("one web effect grant already has a staged response")
            if self._profile_bytes.get(key, 0) + len(capture.body) > 32 * 1024 * 1024:
                self.transport_receipts.revoke(transport.handle)
                raise WebContentArtifactDenied("profile web-content quota is full")
            self._store_exclusive(path, capture.body)
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            st = os.fstat(fd)
            observation = VerifiedRootWebResponseObservation(
                observation_handle=observation_handle,
                receipt_handle=receipt_handle,
                native_invocation_handle=invocation.invocation_handle,
                profile_id=context.profile_id, owner_generation=context.generation,
                operation_id=operation_id, final_url=capture.final_url,
                content_type=capture.content_type, redirect_chain=tuple(capture.redirect_chain),
                canonical_request_sha256=request_sha,
                parent_source_receipt_handles=tuple(invocation.source_receipt_handles),
                transport_receipt_handle=transport.handle,
                body_sha256=transport.body_sha256, body_size_bytes=len(capture.body),
                media_type=capture.media_type, issued_monotonic=now,
                expires_monotonic=expiry, root_effect_receipt_handle=None,
                _body=capture.body,
                _decoded_content=_decode_public_content(capture.body, capture.content_type),
                _context_payload=request_payload,
                _context=context, _authorization=authorization,
                _invocation=invocation, _transport=transport, _seal=_OBSERVATION_SEAL,
            )
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != self.expected_uid
                    or st.st_gid != self.expected_uid
                    or stat.S_IMODE(st.st_mode) != 0o400
                    or st.st_size != len(capture.body)):
                os.close(fd)
                self.transport_receipts.revoke(transport.handle)
                raise WebContentArtifactDenied("web-content CAS custody failed after write")
            self._pending[observation_handle] = _Pending(observation, path, fd, st.st_dev, st.st_ino)
            self._pending_grants[authorization.grant_id] = observation_handle
            self._path_refs[path] = self._path_refs.get(path, 0) + 1
            self._profile_bytes[key] = self._profile_bytes.get(key, 0) + len(capture.body)
            return observation

    def resolve_staged_effect(self, *, context: HostContext,
                              authorization: EffectAuthorization, operation: str,
                              target: str, request_payload: bytes, response_status: int,
                              response_body: bytes, effect_receipt_id: str
                              ) -> VerifiedRootWebResponseObservation:
        """Resolve one staged response for the service before it mints completion proof."""
        if (operation != "plugin.web.read" or target != authorization.target
                or not isinstance(request_payload, bytes) or not isinstance(response_body, bytes)
                or type(response_status) is not int or not 200 <= response_status < 300
                or not isinstance(effect_receipt_id, str)
                or not hmac.compare_digest(effect_receipt_id, hashlib.sha256(
                    request_payload + b"\0" + response_body).hexdigest())):
            raise WebContentArtifactDenied("completed web effect fields are malformed")
        with self._lock:
            self._assert_open()
            self._verify_journal()
            self._verify_current_effect(context, authorization)
            observation_handle = self._pending_grants.get(authorization.grant_id)
            pending = self._pending.get(observation_handle) if observation_handle else None
            observation = pending.observation if pending is not None else None
            if (observation is None or observation._context is not context
                    or observation._authorization is not authorization
                    or operation != authorization.operation
                    or request_payload != observation._context_payload
                    or target != authorization.target):
                raise WebContentArtifactDenied("staged response does not match the consumed effect grant")
            self._verify_current_invocation(observation)
            self._verify_fd(pending)
            transport = self.transport_receipts.resolve(observation.transport_receipt_handle)
            result = _decode_handler_response(response_body)
            if (not _matches_observed_result(result, observation)
                    or transport.body_sha256 != observation.body_sha256
                    or transport.request_sha256 != observation.canonical_request_sha256
                    or transport.profile_id != observation.profile_id
                    or transport.owner_generation != observation.owner_generation):
                raise WebContentArtifactDenied("response body does not contain the staged artifact receipt")
            body_sha256 = hashlib.sha256(response_body).hexdigest()
            if pending.effect_receipt_id is not None and (
                    pending.effect_receipt_id != effect_receipt_id
                    or pending.response_sha256 != body_sha256
                    or pending.response_status != response_status):
                raise WebContentArtifactDenied("staged effect response was already bound to other bytes")
            pending.response_status = response_status
            pending.effect_receipt_id = effect_receipt_id
            pending.response_sha256 = body_sha256
            return observation

    def finalize_authorized_effect(self, observation: VerifiedRootWebResponseObservation,
                                   completion: Any, response_body: bytes
                                   ) -> RootWebContentArtifactReceipt:
        """Publish only after AuthorityService has authenticated the completed effect."""
        from hermes_installer.authority.service import RootEffectCompletionReceipt
        if (type(observation) is not VerifiedRootWebResponseObservation
                or observation._seal is not _OBSERVATION_SEAL
                or type(completion) is not RootEffectCompletionReceipt
                or not isinstance(response_body, bytes)):
            raise WebContentArtifactDenied("web effect completion is not a root-minted receipt")
        with self._lock:
            self._assert_open()
            observation_handle = observation.observation_handle
            pending = self._pending.get(observation_handle)
            if (pending is None or pending.observation is not observation
                    or pending.effect_receipt_id is None
                    or pending.response_sha256 != hashlib.sha256(response_body).hexdigest()
                    or pending.response_status != completion.response_status
                    or pending.effect_receipt_id != completion.handler_receipt_id):
                raise WebContentArtifactDenied("web response observation is absent or already consumed")
            verify_completion = getattr(self.service, "verify_root_effect_completion", None)
            if not callable(verify_completion):
                raise WebContentArtifactDenied("root effect completion verifier is not assembled")
            try:
                verify_completion(
                    completion, context=observation._context,
                    authorization=observation._authorization,
                    operation=observation._authorization.operation,
                    target=observation._authorization.target,
                    request_payload=observation._context_payload,
                    response_status=completion.response_status,
                    response_body=response_body,
                    handler_receipt_id=completion.handler_receipt_id,
                )
            except Exception:
                raise WebContentArtifactDenied("root effect completion is stale or does not match this response") from None
            if (completion.operation != observation._authorization.operation
                    or completion.target != observation._authorization.target
                    or completion.grant_id != observation._authorization.grant_id
                    or completion.context_digest != observation._authorization.context_digest
                    or completion.uid != observation._context.uid
                    or completion.request_sha256 != observation.canonical_request_sha256
                    or completion.profile_id != observation.profile_id
                    or completion.generation != observation.owner_generation
                    or completion.service_generation_digest != self.service.service_generation_digest
                    or completion.native_invocation_handle != observation.native_invocation_handle
                    or tuple(completion.parent_source_receipt_handles) != observation.parent_source_receipt_handles
                    or completion.parent_source_closure_sha256 != observation._authorization.lineage_hash
                    or completion.response_sha256 != hashlib.sha256(response_body).hexdigest()
                    or completion.response_size_bytes != len(response_body)
                    or completion.response_status < 200 or completion.response_status >= 300
                    or not _HANDLE.fullmatch(completion.receipt_handle)
                    or not isinstance(completion.signature, bytes) or len(completion.signature) != 32
                    or completion.issued_monotonic < observation.issued_monotonic
                    or completion.issued_monotonic > self.monotonic()
                    or completion.expires_monotonic <= self.monotonic()
                    or completion.expires_monotonic > observation.expires_monotonic):
                raise WebContentArtifactDenied("root effect completion does not join the retained invocation")
            self._verify_current_effect(observation._context, observation._authorization)
            self._verify_current_invocation(observation)
            transport = self.transport_receipts.resolve(observation.transport_receipt_handle)
            # The effect result body is retained by the service completion receipt, but the
            # handler row itself is available only in the pending observation's result digest.
            result_body = response_body
            result = _decode_handler_response(result_body)
            if (not _matches_observed_result(result, observation)
                    or transport.body_sha256 != observation.body_sha256
                    or transport.request_sha256 != observation.canonical_request_sha256
                    or transport.profile_id != observation.profile_id
                    or transport.owner_generation != observation.owner_generation
                    or hashlib.sha256(result_body).hexdigest() != completion.response_sha256
                    or len(result_body) != completion.response_size_bytes):
                raise WebContentArtifactDenied("returned web metadata differs from the staged root observation")
            signed_claims = {
                "schema": 1, "domain": "web-content-artifact-v126",
                "receipt_handle": observation.receipt_handle,
                "observation_handle": observation.observation_handle,
                "root_effect_receipt_handle": completion.receipt_handle,
                "native_invocation_handle": observation.native_invocation_handle,
                "profile_id": observation.profile_id, "owner_generation": observation.owner_generation,
                "operation_id": observation.operation_id,
                "canonical_request_sha256": observation.canonical_request_sha256,
                "parent_source_receipt_handles": list(observation.parent_source_receipt_handles),
                "transport_receipt_handle": observation.transport_receipt_handle,
                "transport_observation_sha256": transport.observation_sha256,
                "body_sha256": observation.body_sha256, "body_size_bytes": observation.body_size_bytes,
                "cas_device": pending.device, "cas_inode": pending.inode,
                "issued_monotonic": observation.issued_monotonic,
                "expires_monotonic": observation.expires_monotonic,
                "response_receipt_id": completion.handler_receipt_id,
                "response_sha256": completion.response_sha256,
            }
            signature = self.service._sign(signed_claims)
            receipt = RootWebContentArtifactReceipt(
                artifact_id=f"web-content:{observation.body_sha256}",
                sha256=observation.body_sha256, size_bytes=observation.body_size_bytes,
                media_type=observation.media_type, profile_id=observation.profile_id,
                owner_generation=observation.owner_generation, operation_id=observation.operation_id,
                source_receipt_handle=observation.receipt_handle,
                expires_monotonic=observation.expires_monotonic, _seal=_RECEIPT_SEAL,
            )
            pending_entry = self._pending.pop(observation.observation_handle)
            self._pending_grants.pop(observation._authorization.grant_id, None)
            completion_digest = hashlib.sha256(json.dumps(
                signed_claims, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
            self._published[observation.receipt_handle] = _Published(
                observation, receipt, pending_entry.path, pending_entry.fd,
                pending_entry.device, pending_entry.inode,
                completion, response_body, signed_claims, completion_digest, signature,
            )
            self._path_refs[pending_entry.path] = max(0, self._path_refs.get(pending_entry.path, 1) - 1) + 1
            return receipt

    def resolve_web_content_receipt(self, source_receipt_handle: str, *, profile_id: str,
                                    owner_generation: str, operation_id: str) -> RootWebContentArtifactReceipt:
        if not isinstance(source_receipt_handle, str) or not _HANDLE.fullmatch(source_receipt_handle):
            raise WebContentArtifactDenied("web receipt handle is malformed")
        with self._lock:
            self._assert_open()
            self._verify_journal()
            self._prune_locked()
            entry = self._published.get(source_receipt_handle)
            if entry is None:
                raise WebContentArtifactDenied("web receipt has not completed in this root service")
            receipt, observation = entry.receipt, entry.observation
            if (receipt.profile_id != profile_id or receipt.owner_generation != owner_generation
                    or receipt.operation_id != operation_id):
                raise WebContentArtifactDenied("web receipt belongs to another profile, generation, or operation")
            self._verify_published(entry)
            return receipt

    def read_selected_content(self, receipt_handle: str, verified_current_native_result_binding: Any) -> bytes:
        """Read only for the exact root-retained native invocation that minted the receipt."""
        with self._lock:
            self._assert_open()
            self._verify_journal()
            self._prune_locked()
            entry = self._published.get(receipt_handle)
            if (entry is None or verified_current_native_result_binding is not entry.observation._invocation):
                raise WebContentArtifactDenied("native result binding is not the retained selected invocation")
            self._verify_published(entry)
            os.lseek(entry.fd, 0, os.SEEK_SET)
            data = bytearray()
            while len(data) <= entry.receipt.size_bytes:
                chunk = os.read(entry.fd, min(65536, entry.receipt.size_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if (len(data) != entry.receipt.size_bytes
                    or not hmac.compare_digest(hashlib.sha256(data).hexdigest(), entry.receipt.sha256)):
                raise WebContentArtifactDenied("held web artifact bytes changed")
            return bytes(data)

    def revoke(self, handle: str) -> bool:
        with self._lock:
            entry = self._published.pop(handle, None)
            pending = self._pending.pop(handle, None)
            selected = entry or pending
            if selected is None:
                return False
            self._remove(selected)
            return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for value in (*self._pending.values(), *self._published.values()):
                self._remove(value)
            self._pending.clear()
            self._published.clear()
            self._closed = True

    def _verify_current_effect(self, context: HostContext,
                               authorization: EffectAuthorization) -> None:
        self.service.revalidate_effect(
            context, authorization, operation="plugin.web.read",
            request_digest=authorization.request_digest, retry_index=0,
        )
        binding = self.service._binding(authorization.uid)
        if (authorization.capability != "plugin:web" or authorization.operation != "plugin.web.read"
                or authorization.profile_id != binding.profile_id
                or authorization.generation != self.service.profile_generations.get(binding.profile_id)
                or context.profile_id != binding.profile_id or context.generation != authorization.generation):
            raise WebContentArtifactDenied("web effect grant is stale or outside its enrolled profile")

    def _verify_current_invocation(
            self, observation: VerifiedRootWebResponseObservation) -> None:
        """Revalidate the retained invocation without consuming its one-use effect slot."""
        registry = getattr(self.service, "native_invocation_registry", None)
        resolve_current = getattr(registry, "resolve_current_invocation_for_effect", None)
        if not callable(resolve_current):
            raise WebContentArtifactDenied("non-consuming current invocation resolver is not assembled")
        authorization = observation._authorization
        try:
            current = resolve_current(
                observation._context,
                authorization,
                authorization.operation,
                authorization.target,
                observation.canonical_request_sha256,
                observation.native_invocation_handle,
            )
        except Exception:
            raise WebContentArtifactDenied("native invocation is no longer current") from None
        from hermes_installer.authority.native_runtime_observer import RootNativeToolEffectInvocation
        retained = observation._invocation
        if (type(current) is not RootNativeToolEffectInvocation
                or current != retained
                or current.invocation_handle != observation.native_invocation_handle
                or current.operation != authorization.operation
                or current.request_digest != observation.canonical_request_sha256
                or current.profile_id != observation.profile_id
                or current.generation != observation.owner_generation
                or current.service_generation_digest != self.service.service_generation_digest
                or current.source_receipt_handles != observation.parent_source_receipt_handles
                or current.expires_monotonic <= self.monotonic()):
            raise WebContentArtifactDenied("current native invocation differs from the retained source closure")

    def _verify_published(self, entry: _Published) -> None:
        obs, receipt = entry.observation, entry.receipt
        if (receipt.expires_monotonic <= self.monotonic()
                or self.service.profile_generations.get(receipt.profile_id) != receipt.owner_generation
                or self._pending_or_published_digest(entry) != obs.body_sha256):
            raise WebContentArtifactDenied("web artifact receipt is expired or stale")
        self._verify_current_effect(obs._context, obs._authorization)
        self._verify_current_invocation(obs)
        verify_completion = getattr(self.service, "verify_root_effect_completion", None)
        if not callable(verify_completion):
            raise WebContentArtifactDenied("root effect completion verifier is not assembled")
        try:
            verify_completion(
                entry.completion, context=obs._context,
                authorization=obs._authorization,
                operation=obs._authorization.operation, target=obs._authorization.target,
                request_payload=obs._context_payload,
                response_status=entry.completion.response_status,
                response_body=entry.response_body,
                handler_receipt_id=entry.completion.handler_receipt_id,
            )
            signature = self.service._sign(entry.artifact_claims)
        except Exception:
            raise WebContentArtifactDenied("web artifact completion signature is stale") from None
        if not hmac.compare_digest(signature, entry.completion_signature):
            raise WebContentArtifactDenied("web artifact receipt signature failed")
        transport = self.transport_receipts.resolve(obs.transport_receipt_handle)
        if (transport.observation_sha256 != entry.observation._transport.observation_sha256
                or transport.body_sha256 != receipt.sha256
                or transport.profile_id != receipt.profile_id
                or transport.owner_generation != receipt.owner_generation):
            raise WebContentArtifactDenied("web transport receipt is no longer current")
        self._verify_fd(entry)

    @staticmethod
    def _pending_or_published_digest(entry: _Published) -> str:
        return entry.observation.body_sha256

    def _verify_fd(self, entry: _Published | _Pending) -> None:
        fd = entry.fd
        st = os.fstat(fd)
        if (not stat.S_ISREG(st.st_mode) or st.st_uid != self.expected_uid
                or st.st_gid != self.expected_uid
                or stat.S_IMODE(st.st_mode) not in {0o400, 0o444}
                or (st.st_dev, st.st_ino) != (entry.device, entry.inode)
                or st.st_size != entry.observation.body_size_bytes):
            raise WebContentArtifactDenied("web CAS held descriptor identity or mode changed")
        os.lseek(fd, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            digest.update(chunk)
        os.lseek(fd, 0, os.SEEK_SET)
        if not hmac.compare_digest(digest.hexdigest(), entry.observation.body_sha256):
            raise WebContentArtifactDenied("web CAS held descriptor bytes failed SHA-256")

    def _store_exclusive(self, path: Path, body: bytes) -> None:
        cursor = self.root
        for part in path.parent.relative_to(self.root).parts:
            cursor = cursor / part
            self._mkdir(cursor)
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
        except FileExistsError:
            fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                st = os.fstat(fd)
                existing = bytearray()
                while len(existing) <= len(body):
                    chunk = os.read(fd, min(65536, len(body) + 1 - len(existing)))
                    if not chunk:
                        break
                    existing.extend(chunk)
                if (st.st_uid != self.expected_uid or st.st_gid != self.expected_uid
                        or not stat.S_ISREG(st.st_mode)
                        or stat.S_IMODE(st.st_mode) not in {0o400, 0o444} or bytes(existing) != body):
                    raise WebContentArtifactDenied("existing web CAS object differs from raw source bytes")
            finally:
                os.close(fd)
            return
        try:
            view = memoryview(body)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("short web content CAS write")
                view = view[written:]
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            path.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)

    def _mkdir(self, path: Path) -> None:
        try:
            os.mkdir(path, 0o700)
        except FileExistsError:
            pass
        st = os.stat(path, follow_symlinks=False)
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
                or st.st_uid != self.expected_uid or st.st_gid != self.expected_uid
                or stat.S_IMODE(st.st_mode) != 0o700):
            raise WebContentArtifactDenied("web CAS directory ownership or mode is unsafe")

    def _verify_journal(self) -> None:
        st = self.root_journal.path.stat(follow_symlinks=False)
        if (not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode)
                or st.st_uid != self.expected_uid or st.st_gid != self.expected_uid
                or stat.S_IMODE(st.st_mode) != 0o700
                or (st.st_dev, st.st_ino) != (self.root_journal.device, self.root_journal.inode)
                or self.root_journal.service_generation_digest != self.service.service_generation_digest):
            raise WebContentArtifactDenied("selected root journal is not current")

    def _clear_stale(self, path: Path) -> None:
        """A new authority epoch cannot adopt old monotonic receipt files."""
        with os.scandir(path) as entries:
            for item in entries:
                st = item.stat(follow_symlinks=False)
                child = path / item.name
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    if (st.st_uid != self.expected_uid or st.st_gid != self.expected_uid
                            or stat.S_IMODE(st.st_mode) != 0o700):
                        raise WebContentArtifactDenied("stale web CAS directory is unsafe")
                    self._clear_stale(child)
                    child.rmdir()
                elif (stat.S_ISREG(st.st_mode) and st.st_uid == self.expected_uid
                      and st.st_gid == self.expected_uid
                      and stat.S_IMODE(st.st_mode) in {0o400, 0o444}):
                    child.unlink()
                else:
                    raise WebContentArtifactDenied("stale web CAS contains an unexpected entry")

    def _prune_locked(self) -> None:
        now = self.monotonic()
        for handle, pending in tuple(self._pending.items()):
            if pending.observation.expires_monotonic <= now:
                self._pending.pop(handle, None)
                self._remove(pending)
        for handle, entry in tuple(self._published.items()):
            if entry.receipt.expires_monotonic <= now:
                self._published.pop(handle, None)
                self._remove(entry)
        self.transport_receipts._prune_locked()

    def _remove(self, entry: _Pending | _Published) -> None:
        try:
            os.close(entry.fd)
        except OSError:
            pass
        remaining = max(0, self._path_refs.get(entry.path, 1) - 1)
        if remaining:
            self._path_refs[entry.path] = remaining
        else:
            self._path_refs.pop(entry.path, None)
            try:
                entry.path.unlink(missing_ok=True)
            except OSError:
                pass
        obs = entry.observation
        self._pending_grants.pop(obs._authorization.grant_id, None)
        key = obs.profile_id, obs.owner_generation
        self._profile_bytes[key] = max(0, self._profile_bytes.get(key, 0) - obs.body_size_bytes)
        self.transport_receipts.revoke(obs.transport_receipt_handle)

    def _assert_open(self) -> None:
        if self._closed:
            raise WebContentArtifactDenied("web-content artifact registry is closed")


def _decode_handler_response(payload: bytes) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8", errors="strict"),
                           parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise WebContentArtifactDenied("web handler response is not canonical UTF-8 JSON") from None
    except ValueError:
        raise WebContentArtifactDenied("web handler response contains a non-finite JSON number") from None
    if (not isinstance(value, dict) or value.get("schema") != 1
            or not isinstance(value.get("operation_id"), str)
            or not isinstance(value.get("result"), dict)):
        raise WebContentArtifactDenied("web handler response envelope is malformed")
    canonical = json.dumps(value, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode("utf-8")
    if canonical != payload:
        raise WebContentArtifactDenied("web handler response is not canonical JSON")
    return value


def _matches_observed_result(result: Mapping[str, Any],
                             observation: VerifiedRootWebResponseObservation) -> bool:
    expected_outer = {"schema", "operation_id", "state", "result",
                      "verification_status", "resume_action_id"}
    payload = result.get("result")
    if (set(result) != expected_outer or result.get("schema") != 1
            or result.get("state") != "read-complete"
            or result.get("verification_status") != "verified"
            or result.get("resume_action_id") is not None
            or result.get("operation_id") != observation.operation_id
            or not isinstance(payload, dict)
            or set(payload) != {"url", "content_type", "content", "untrusted_source",
                                "authority", "redirects", "source_receipt"}):
        return False
    return (payload.get("url") == observation.final_url
            and payload.get("content_type") == observation.content_type
            and payload.get("content") == observation._decoded_content
            and payload.get("untrusted_source") is True
            and payload.get("authority") == "none"
            and payload.get("redirects") == list(observation.redirect_chain)
            and payload.get("source_receipt") == observation.staged_result_fields())
