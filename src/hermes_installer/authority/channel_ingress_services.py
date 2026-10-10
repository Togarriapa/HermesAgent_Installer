"""Root-side listener and source-receipt services for HTTP/audio ingress.

All listeners are TLS mutual-authenticated and loopback-only. Authenticated
channel identity and audio sessions come from selected root services; these
classes never accept a caller path, public bind address, auth boolean, or PCM.
"""
from __future__ import annotations

import hashlib
import hmac
import http.server
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Mapping

from .channel_provenance import (
    AuthenticatedHttpRequest, AuthenticatedSubjectReceipt,
    AudioIngressSelection, SelectedAudioCaptureReceipt,
)
from .source_observers import SourceReceiptHandle
from .types import AuthorityDenied, SourceReceipt
from hermes_installer.components.plugin_channel_provenance import HttpIngressSelection

_MAX_HTTP_BODY = 256 * 1024
_MAX_HTTP_HEADER = 16 * 1024
_SESSION_ID = re.compile(r"[A-Za-z0-9_-]{20,128}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_LOOPBACK = frozenset({"127.0.0.1"})


class IngressServiceDenied(PermissionError):
    """The selected root ingress service cannot prove this request."""


class RootIngressDisposition(Enum):
    ACCEPTED = "accepted"
    DENIED = "denied"


@dataclass(frozen=True, slots=True)
class _RequestTicket:
    owner: object = field(repr=False, compare=False)
    nonce: str
    method: str
    path: str
    host: str
    content_type: str
    session_id: str
    access_jwt: bytes = field(repr=False)
    body: bytes = field(repr=False)
    request_receipt_handle: str
    request_id: str
    issued_monotonic: float


class RootHttpRequestReceiptIssuer:
    """Root-private one-use ledger for exact authenticated HTTP request proofs."""
    def issue_request_source_receipt(self, selection_handle: object, session_handle: str,
                                     subject_receipt_handle: str, body: bytes) -> SourceReceiptHandle:
        """Retain a request proof tied to an active selected JWT session."""
        raise NotImplementedError


class RootJWTSubjectReceiptIssuer:
    """Deprecated compatibility protocol; JWT proofs are retained by the verifier."""
    def issue_subject_source_receipt(self, *, selection: HttpIngressSelection,
                                     session_id: str, subject_digest: str,
                                     token_fingerprint: str,
                                     source_payload: Mapping[str, Any],
                                     expires_monotonic: float) -> SourceReceiptHandle:
        raise NotImplementedError


@dataclass(slots=True)
class _RootJWTSession:
    selection_id: str
    session_id: str
    subject_digest: str
    token_fingerprint: str
    receipt: AuthenticatedSubjectReceipt
    source_proof_handle: str
    active: bool = True


class RootSelectedJWTSessionAuthority:
    """Cryptographically verify selected RS256 JWTs and retain short root leases.

    JWKS, issuer/audience, allowed subject digests and current session policy
    are root-selected. The token is never stored; each request verifies it
    again. The opaque handle is a root-retained authentication proof, not a
    standalone SourceReceipt; the final selected resource event signs the
    canonical request envelope. No Cloudflare Desktop session is used.
    """
    def __init__(self, selection: HttpIngressSelection, *, verifier_enrollment_id: str,
                 owner_generation: str, issuer: str, audience: str,
                 jwks: Mapping[str, Mapping[str, Any]], allowed_subject_digests: frozenset[str],
                 receipt_issuer: RootJWTSubjectReceiptIssuer | None = None,
                 source_receipts: AuthoritySourceReceiptResolver | None = None,
                 wall_clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 max_session_seconds: int = 60):
        if (not isinstance(selection, HttpIngressSelection)
                or (source_receipts is not None and not isinstance(source_receipts, AuthoritySourceReceiptResolver))
                or verifier_enrollment_id != selection.jwt_verifier_enrollment_id
                or not isinstance(owner_generation, str) or not owner_generation
                or not issuer.startswith("https://")
                or not audience or not isinstance(jwks, Mapping) or not jwks
                or not isinstance(allowed_subject_digests, frozenset) or not allowed_subject_digests
                or any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in allowed_subject_digests)
                or type(max_session_seconds) is not int or not 1 <= max_session_seconds <= 60):
            raise ValueError("selected HTTP JWT policy and current session resolver are required")
        if source_receipts is not None and source_receipts.profile_id != selection.profile_id:
            raise ValueError("HTTP JWT session resolver differs from selected profile")
        self.selection, self.issuer, self.audience = selection, issuer, audience
        self.verifier_enrollment_id = verifier_enrollment_id
        self.owner_generation = owner_generation
        self.jwks = dict(jwks)
        self.allowed_subject_digests = allowed_subject_digests
        self.receipt_issuer, self.source_receipts = None, None
        self.wall_clock, self.monotonic = wall_clock, monotonic
        self.max_session_seconds = max_session_seconds
        self._sessions: dict[str, _RootJWTSession] = {}
        self._lock = threading.RLock()

    def verify_selected_jwt(self, selection: HttpIngressSelection, token: bytes,
                            session_id: str) -> AuthenticatedSubjectReceipt:
        if (selection is not self.selection or not isinstance(token, bytes)
                or not 1 <= len(token) <= 16 * 1024
                or not isinstance(session_id, str) or not _SESSION_ID.fullmatch(session_id)):
            raise IngressServiceDenied("JWT request differs from the exact selected session policy")
        try:
            import jwt
            token_text = token.decode("ascii", "strict")
            header = jwt.get_unverified_header(token_text)
            if (not isinstance(header, dict) or header.get("alg") != "RS256"
                    or not isinstance(header.get("kid"), str) or header["kid"] not in self.jwks):
                raise ValueError("header")
            jwk = self.jwks[header["kid"]]
            if (not isinstance(jwk, Mapping) or jwk.get("kty") != "RSA"
                    or jwk.get("alg") not in (None, "RS256") or jwk.get("use") not in (None, "sig")):
                raise ValueError("key")
            public_key = jwt.PyJWK.from_dict(dict(jwk), algorithm="RS256").key
            claims = jwt.decode(
                token_text, public_key, algorithms=["RS256"], issuer=self.issuer,
                audience=self.audience, leeway=0,
                options={"require": ["iss", "aud", "exp", "nbf", "iat", "sub", "sid", "jti"],
                         "verify_exp": False, "verify_nbf": False, "verify_iat": False},
            )
            aud = claims.get("aud")
            if claims.get("iss") != self.issuer or not (aud == self.audience or aud == [self.audience]):
                raise ValueError("issuer/audience")
            subject, token_session, jti = claims.get("sub"), claims.get("sid"), claims.get("jti")
            if (not isinstance(subject, str) or not 1 <= len(subject) <= 512
                    or any(ord(ch) < 0x21 for ch in subject)
                    or token_session != session_id or not isinstance(jti, str)
                    or not 8 <= len(jti) <= 256 or any(ord(ch) < 0x21 for ch in jti)):
                raise ValueError("principal")
            times = {name: claims.get(name) for name in ("iat", "nbf", "exp")}
            if any(isinstance(value, bool) or not isinstance(value, (int, float))
                   or not float("-inf") < float(value) < float("inf") for value in times.values()):
                raise ValueError("times")
            now_wall, now_mono = float(self.wall_clock()), float(self.monotonic())
            issued, not_before, expires = (float(times["iat"]), float(times["nbf"]), float(times["exp"]))
            if (not issued <= now_wall < expires or not_before > now_wall
                    or expires <= issued or expires - issued > 600):
                raise ValueError("expiry")
            subject_digest = hashlib.sha256(subject.encode("utf-8")).hexdigest()
            if subject_digest not in self.allowed_subject_digests:
                raise ValueError("subject")
            fingerprint = hashlib.sha256(token).hexdigest()
            lease_expiry = min(now_mono + self.max_session_seconds,
                               now_mono + (expires - now_wall))
        except Exception:
            raise IngressServiceDenied("selected HTTP JWT signature, claims, subject or session was denied") from None

        with self._lock:
            self._sessions = {key: row for key, row in self._sessions.items()
                              if row.active and row.receipt.expires_monotonic > now_mono}
            for row in self._sessions.values():
                if row.selection_id == selection.id and row.session_id == session_id:
                    if row.token_fingerprint == fingerprint and row.subject_digest == subject_digest:
                        return row.receipt
                    row.active = False
            if len(self._sessions) >= 1024:
                raise IngressServiceDenied("selected HTTP auth session table is full")
            source_handle = secrets.token_urlsafe(32)
            session_handle = secrets.token_urlsafe(32)
            while session_handle in self._sessions:
                session_handle = secrets.token_urlsafe(32)
            receipt = AuthenticatedSubjectReceipt(
                source_handle, session_handle, subject_digest, lease_expiry,
                selection.jwt_verifier_enrollment_id)
            self._sessions[session_handle] = _RootJWTSession(
                selection.id, session_id, subject_digest, fingerprint, receipt, source_handle)
            return receipt

    def current_selected_subject(self, selection: HttpIngressSelection,
                                 receipt: AuthenticatedSubjectReceipt) -> AuthenticatedSubjectReceipt:
        if selection is not self.selection or not isinstance(receipt, AuthenticatedSubjectReceipt):
            raise IngressServiceDenied("authenticated subject receipt is not from this selected verifier")
        with self._lock:
            row = self._sessions.get(receipt.session_handle)
            if (row is None or not row.active or row.receipt is not receipt
                    or receipt.expires_monotonic <= self.monotonic()
                    or row.selection_id != selection.id
                    or row.subject_digest not in self.allowed_subject_digests):
                raise IngressServiceDenied("authenticated HTTP session was revoked, expired or changed")
            return receipt

    def revoke_session(self, session_handle: str) -> None:
        """Root-only revocation hook for session close/policy change."""
        with self._lock:
            row = self._sessions.pop(session_handle, None)
            if row is not None:
                row.active = False

class RootLoopbackHttpIngressListener:
    """Bounded mTLS POST listener for one selected HTTP channel.

    Bind port and TLS context are root-loaded enrollment values. The private
    callback runs inside the listener thread and must complete the observer,
    issuer, and registry capture flow before the request receives 202.
    """
    def __init__(self, selection: HttpIngressSelection, *, host: str, port: int,
                 tls_context: ssl.SSLContext, selection_handle: object,
                 route_id: str,
                 identity_verifier: Any, request_receipt_issuer: RootHttpRequestReceiptIssuer | None = None,
                 source_receipt_resolver: "AuthoritySourceReceiptResolver | None" = None,
                 process_request: Callable[[object], RootIngressDisposition],
                 monotonic: Callable[[], float] = time.monotonic,
                 request_timeout_seconds: float = 5.0):
        if not isinstance(selection, HttpIngressSelection):
            raise TypeError("protected HTTP channel selection is required")
        if host != "127.0.0.1":
            raise ValueError("HTTP channel listener may bind only IPv4 loopback")
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("HTTP channel port must be root-selected or ephemeral for fixtures")
        if (not isinstance(tls_context, ssl.SSLContext)
                or tls_context.protocol != ssl.PROTOCOL_TLS_SERVER
                or tls_context.verify_mode != ssl.CERT_REQUIRED
                or tls_context.minimum_version < ssl.TLSVersion.TLSv1_2):
            raise ValueError("HTTP channel requires root-enrolled TLS 1.2+ mutual authentication")
        if (not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", route_id)
                or not callable(process_request)):
            raise ValueError("HTTP channel route and root event processor are required")
        if selection_handle is None:
            raise ValueError("opaque root-selected HTTP enrollment handle is required")
        if (not callable(getattr(identity_verifier, "verify_selected_jwt", None))
                or not callable(getattr(identity_verifier, "current_selected_subject", None))
                or (request_receipt_issuer is not None
                    and not callable(getattr(request_receipt_issuer, "issue_request_source_receipt", None)))):
            raise TypeError("root JWT/session authority is required")
        if not 0.1 <= request_timeout_seconds <= 10:
            raise ValueError("HTTP request deadline must be bounded")
        self.selection, self.host, self.port = selection, host, port
        self.selection_handle = selection_handle
        self.identity_verifier = identity_verifier
        self.request_receipt_issuer = request_receipt_issuer
        # Retained source proof handles are root audit evidence. They are not
        # intermediate AuthorityService SourceReceipts.
        self.source_receipt_resolver = source_receipt_resolver
        self.tls_context, self.route_id = tls_context, route_id
        self.process_request, self.monotonic = process_request, monotonic
        self.request_timeout_seconds = request_timeout_seconds
        self._owner = object()
        self._tickets: dict[str, _RequestTicket] = {}
        self._lock = threading.RLock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        if self._server is None:
            raise IngressServiceDenied("selected HTTP listener is not active")
        return int(self._server.server_address[1])

    def start(self) -> int:
        if self._server is not None:
            return self.bound_port
        listener = self

        class Server(http.server.ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False
            request_queue_size = 8
            _ingress_slot = threading.BoundedSemaphore(1)

            def process_request(self, request, client_address):
                # The selected ingress policy permits one active request. Do
                # not let ThreadingHTTPServer turn a bounded body limit into
                # an unbounded thread/connection allocation surface.
                if not self._ingress_slot.acquire(blocking=False):
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except Exception:
                    self._ingress_slot.release()
                    raise

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self._ingress_slot.release()

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _fmt, *_args):
                return

            def _reply(self, status: int) -> None:
                body = b"accepted\n" if status == 202 else b"denied\n"
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass
                self.close_connection = True

            def do_POST(self) -> None:
                try:
                    if not isinstance(self.connection, ssl.SSLSocket):
                        raise IngressServiceDenied("TLS is required")
                    peer_cert = self.connection.getpeercert(binary_form=True)
                    if (not peer_cert or len(self.requestline) > 4096
                            or self.path != "/" + listener.route_id
                            or sum(len(key) + len(value) + 4 for key, value in self.headers.items()) > _MAX_HTTP_HEADER):
                        raise IngressServiceDenied("selected client certificate or route is missing")
                    expected_host = f"{listener.host}:{listener.bound_port}"
                    if self.headers.get_all("Host", []) != [expected_host]:
                        raise IngressServiceDenied("HTTP Host is not the selected loopback listener")
                    if self.headers.get_all("Transfer-Encoding", []):
                        raise IngressServiceDenied("transfer-encoded request framing is not accepted")
                    auth = self.headers.get_all("Authorization", [])
                    sessions = self.headers.get_all("X-Hermes-Session-ID", [])
                    lengths = self.headers.get_all("Content-Length", [])
                    content_types = self.headers.get_all("Content-Type", [])
                    if (len(auth) != 1 or not auth[0].startswith("Bearer ")
                            or len(sessions) != 1 or not _SESSION_ID.fullmatch(sessions[0])
                            or len(lengths) != 1 or not lengths[0].isascii()
                            or not lengths[0].isdecimal() or len(lengths[0]) > 7
                            or len(content_types) != 1
                            or content_types[0].split(";", 1)[0].strip().casefold() != "application/json"):
                        raise IngressServiceDenied("HTTP auth/session/body headers are malformed")
                    size = int(lengths[0])
                    if not 1 <= size <= min(listener.selection.max_body_bytes, _MAX_HTTP_BODY):
                        raise IngressServiceDenied("HTTP request body exceeds its selected limit")
                    body = listener._read_body(self, size)
                    token = auth[0][7:].encode("ascii", "strict")
                    if not 1 <= len(token) <= 16 * 1024:
                        raise IngressServiceDenied("HTTP bearer token is malformed or oversized")
                    session_receipt = listener.identity_verifier.verify_selected_jwt(
                        listener.selection, token, sessions[0])
                    if (not isinstance(session_receipt, AuthenticatedSubjectReceipt)
                            or session_receipt.verifier_enrollment_id
                            != listener.selection.jwt_verifier_enrollment_id):
                        raise IngressServiceDenied("selected JWT/session verifier did not authenticate this request")
                    # A random one-use root ledger handle binds the exact body
                    # and verified subject/session below. The final event
                    # issuer signs the canonical event; no synthetic parent
                    # SourceReceipt is created here.
                    receipt_handle = secrets.token_urlsafe(32)
                    request_id = secrets.token_urlsafe(24)
                    ticket = listener._create_ticket(
                        method="POST", path=self.path, host=expected_host,
                        content_type="application/json", session_id=sessions[0],
                        access_jwt=token, body=body, request_receipt_handle=receipt_handle,
                        request_id=request_id,
                    )
                    try:
                        disposition = listener.process_request(ticket)
                    finally:
                        listener._finish_ticket(ticket)
                    if disposition is not RootIngressDisposition.ACCEPTED:
                        raise IngressServiceDenied("root ingress proof or event capture was denied")
                    self._reply(202)
                except Exception:
                    self._reply(403)

            def do_GET(self): self._reply(405)
            def do_PUT(self): self._reply(405)
            def do_PATCH(self): self._reply(405)
            def do_DELETE(self): self._reply(405)
            def do_OPTIONS(self): self._reply(405)

        class TLSHTTPServer(Server):
            def get_request(self):
                sock, address = super().get_request()
                sock.settimeout(self.timeout)
                try:
                    return listener.tls_context.wrap_socket(sock, server_side=True), address
                except Exception:
                    sock.close()
                    raise

        server = TLSHTTPServer((self.host, self.port), Handler)
        server.timeout = self.request_timeout_seconds
        self._server = server
        self._thread = threading.Thread(target=server.serve_forever,
                                        name="hermes-selected-http-channel", daemon=True)
        self._thread.start()
        return self.bound_port

    def _read_body(self, handler: http.server.BaseHTTPRequestHandler, size: int) -> bytes:
        """Read exactly one body under an absolute deadline and memory cap."""
        deadline = self.monotonic() + self.request_timeout_seconds
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            budget = deadline - self.monotonic()
            if budget <= 0:
                raise IngressServiceDenied("HTTP request body exceeded its absolute deadline")
            handler.connection.settimeout(budget)
            # read1 performs at most one underlying recv, allowing the
            # deadline to be recomputed even for a slow trickle body.
            chunk = handler.rfile.read1(min(64 * 1024, remaining))
            if not chunk:
                raise IngressServiceDenied("HTTP request body was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if self.monotonic() > deadline:
            raise IngressServiceDenied("HTTP request body exceeded its absolute deadline")
        return b"".join(chunks)

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        with self._lock:
            self._tickets.clear()

    def _create_ticket(self, *, request_receipt_handle: str, **values: Any) -> _RequestTicket:
        if not _HANDLE.fullmatch(request_receipt_handle):
            raise IngressServiceDenied("request proof handle is malformed")
        values.setdefault("request_id", secrets.token_urlsafe(24))
        nonce = secrets.token_urlsafe(32)
        ticket = _RequestTicket(self._owner, nonce, **values, request_receipt_handle=request_receipt_handle,
                                issued_monotonic=self.monotonic())
        with self._lock:
            self._prune_tickets()
            if len(self._tickets) >= 8:
                raise IngressServiceDenied("HTTP ingress queue is at capacity")
            self._tickets[nonce] = ticket
        return ticket

    def take_authenticated_request(self, selection_handle: object,
                                   request_record: object) -> AuthenticatedHttpRequest:
        if (selection_handle is not self.selection_handle or not isinstance(request_record, _RequestTicket)
                or request_record.owner is not self._owner):
            raise IngressServiceDenied("request ticket was not issued by this root listener")
        with self._lock:
            ticket = self._tickets.pop(request_record.nonce, None)
            if ticket is not request_record:
                raise IngressServiceDenied("HTTP request ticket is unknown or replayed")
            if (self.monotonic() - ticket.issued_monotonic > self.request_timeout_seconds
                    or ticket.method != "POST" or ticket.path != "/" + self.route_id
                    or ticket.host != f"{self.host}:{self.bound_port}"):
                self._tickets.pop(ticket.nonce, None)
                raise IngressServiceDenied("HTTP request ticket expired or differs from selection")
            return AuthenticatedHttpRequest(
                self.selection.listener_enrollment_id, self.selection.id, ticket.method,
                self.route_id, ticket.content_type, ticket.session_id, ticket.access_jwt,
                ticket.body, ticket.request_receipt_handle, ticket.request_id,
            )

    def _finish_ticket(self, ticket: object) -> None:
        if isinstance(ticket, _RequestTicket) and ticket.owner is self._owner:
            with self._lock:
                self._tickets.pop(ticket.nonce, None)

    def _prune_tickets(self) -> None:
        now = self.monotonic()
        self._tickets = {key: row for key, row in self._tickets.items()
                         if now - row.issued_monotonic <= self.request_timeout_seconds}


class AuthoritySourceReceiptResolver:
    """Resolve selected observer receipt handles from AuthorityService's store."""
    def __init__(self, service: Any, *, profile_id: str, principal_id: str,
                 uid: int, generation: str, native_process_identity: str):
        if (not isinstance(profile_id, str) or not profile_id or not isinstance(principal_id, str)
                or not principal_id or type(uid) is not int or uid <= 0 or not generation
                or not native_process_identity or not isinstance(getattr(service, "_lock", None), type(threading.RLock()))
                or not isinstance(getattr(service, "_source_receipt_handles", None), dict)
                or not callable(getattr(service, "_verify_source_receipt", None))):
            raise TypeError("root AuthorityService source receipt store and current identity are required")
        bindings = getattr(service, "bindings_by_uid", {})
        binding = bindings.get(uid)
        if (binding is None or binding.profile_id != profile_id or binding.principal_id != principal_id):
            raise AuthorityDenied("source.binding", "receipt resolver identity differs from root profile binding")
        self.service, self.binding = service, binding
        self.profile_id, self.principal_id = profile_id, principal_id
        self.uid, self.generation = uid, generation
        self.native_process_identity = native_process_identity

    def __call__(self, handles: tuple[str, ...]) -> tuple[SourceReceipt, ...]:
        if (not isinstance(handles, tuple) or not handles or len(handles) > 64
                or len(set(handles)) != len(handles)
                or any(not isinstance(handle, str) or not _HANDLE.fullmatch(handle) for handle in handles)):
            raise AuthorityDenied("source.lineage", "selected receipt handles are malformed")
        service = self.service
        now = service.monotonic()
        with service._lock:
            store = service._source_receipt_handles
            service._source_receipt_handles = {
                handle: row for handle, row in store.items() if row.monotonic_expires_at > now
            }
            receipts: dict[str, SourceReceipt] = {}
            by_id = {row.receipt_id: (handle, row)
                     for handle, row in service._source_receipt_handles.items()}
            pending: list[str] = []
            for handle in handles:
                row = service._source_receipt_handles.get(handle)
                if not isinstance(row, SourceReceipt):
                    raise AuthorityDenied("source.lineage", "selected receipt is absent from root authority")
                receipts[row.receipt_id] = row
                pending.extend(row.parent_receipt_ids)
            while pending:
                receipt_id = pending.pop()
                if receipt_id in receipts:
                    continue
                entry = by_id.get(receipt_id)
                if entry is None:
                    raise AuthorityDenied("source.lineage", "signed receipt closure is incomplete")
                _handle, receipt = entry
                receipts[receipt.receipt_id] = receipt
                pending.extend(receipt.parent_receipt_ids)
                if len(receipts) > 64:
                    raise AuthorityDenied("source.lineage", "signed receipt closure exceeds its limit")
            for receipt in receipts.values():
                service._verify_source_receipt(receipt, self.binding)
                if (receipt.profile_id != self.profile_id or receipt.principal_id != self.principal_id
                        or receipt.uid != self.uid or receipt.process_generation != self.generation
                        or receipt.native_process_identity != self.native_process_identity):
                    raise AuthorityDenied("source.lineage", "signed receipt belongs to a stale or different owner")
            return tuple(sorted(receipts.values(), key=lambda row: row.receipt_id))

    def validate(self, receipt: SourceReceipt) -> bool:
        if not isinstance(receipt, SourceReceipt):
            return False
        try:
            rows = self((self._handle_for(receipt),))
            return receipt in rows
        except Exception:
            return False

    def resolve_direct(self, handle: str) -> SourceReceipt:
        """Resolve one direct receipt (not only its transitive parent closure)."""
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise AuthorityDenied("source.lineage", "source receipt handle is malformed")
        service = self.service
        with service._lock:
            receipt = service._source_receipt_handles.get(handle)
        if not isinstance(receipt, SourceReceipt):
            raise AuthorityDenied("source.lineage", "direct source receipt is absent")
        self((handle,))
        return receipt

    def _handle_for(self, receipt: SourceReceipt) -> str:
        with self.service._lock:
            matches = [handle for handle, row in self.service._source_receipt_handles.items()
                       if row is receipt]
        if len(matches) != 1:
            raise AuthorityDenied("source.lineage", "receipt object is not retained by AuthorityService")
        return matches[0]


@dataclass(frozen=True, slots=True)
class RootAudioInputSession:
    """Root-authenticated active input session; no permission booleans."""
    session_handle: str
    profile_id: str
    owner_generation: str
    device_enrollment_id: str
    device_identity_digest: str
    consent_receipt_handle: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootAudioCaptureArtifact:
    """Root catalog entry for one sealed capture; contains no path or PCM."""
    artifact_id: str
    sha256: str
    size_bytes: int
    media_type: str
    profile_id: str
    owner_generation: str
    operation_id: str
    artifact_receipt_handle: str
    capture_receipt_handle: str
    device_enrollment_id: str
    capture_backend_artifact_id: str
    capture_backend_sha256: str
    format_schema_id: str
    expires_monotonic: float


@dataclass(frozen=True, slots=True)
class RootAudioCaptureRequest:
    """Opaque root workflow result selecting a sealed captured artifact."""
    session_handle: str
    artifact_id: str


class RootAudioSessionAuthority:
    """Root auth-session lookup boundary implemented by the selected runtime."""
    def take_capture_workflow_result(self, selection_handle: object,
                                     workflow_result: object) -> RootAudioCaptureRequest:
        """Resolve/consume a root workflow result; never trust caller IDs."""
        raise NotImplementedError

    def current_input_session(self, selection_handle: object,
                              session_handle: str) -> RootAudioInputSession:
        raise NotImplementedError


class RootPrivateAudioArtifactCatalog:
    """Root memory-only artifact catalog interface; paths never leave root."""
    def resolve_capture(self, selection_handle: object, session: RootAudioInputSession,
                        artifact_id: str) -> RootAudioCaptureArtifact:
        raise NotImplementedError
    def current_capture(self, selection_handle: object, session: RootAudioInputSession,
                        artifact: RootAudioCaptureArtifact) -> RootAudioCaptureArtifact:
        raise NotImplementedError
    def read_capture_bytes(self, selection_handle: object, session: RootAudioInputSession,
                           artifact: RootAudioCaptureArtifact, *, maximum_bytes: int) -> bytearray:
        raise NotImplementedError
    def consume_capture(self, selection_handle: object,
                        artifact: RootAudioCaptureArtifact) -> None:
        raise NotImplementedError


class RootAudioCaptureReceiptResolver:
    """Join a live consented device session, private artifact and signed receipts.

    The selected session service is responsible for checking actual device
    identity and current user permission. This class requires its typed live
    session result on every lookup and then verifies the exact artifacts and
    signed receipt closure through the selected root catalogs.
    """
    def __init__(self, selection: AudioIngressSelection, selection_handle: object, *,
                 sessions: RootAudioSessionAuthority,
                 artifacts: RootPrivateAudioArtifactCatalog,
                 owner_generation: str,
                 source_receipts: AuthoritySourceReceiptResolver | None = None,
                 monotonic: Callable[[], float] = time.monotonic):
        if (not isinstance(selection, AudioIngressSelection) or selection_handle is None
                or not isinstance(owner_generation, str) or not owner_generation):
            raise TypeError("root-selected audio device enrollment and opaque handle are required")
        if (not callable(getattr(sessions, "current_input_session", None))
                or not callable(getattr(sessions, "take_capture_workflow_result", None))):
            raise TypeError("root capture workflow-result and current voice-session authority are required")
        if not all(callable(getattr(artifacts, name, None)) for name in
                   ("resolve_capture", "current_capture", "read_capture_bytes", "consume_capture")):
            raise TypeError("root private audio artifact catalog is required")
        self.selection, self.selection_handle = selection, selection_handle
        self.sessions, self.artifacts = sessions, artifacts
        self.owner_generation, self.source_receipts, self.monotonic = owner_generation, source_receipts, monotonic
        self._receipts: dict[str, tuple[RootAudioInputSession, RootAudioCaptureArtifact,
                                        SelectedAudioCaptureReceipt]] = {}

    def take_selected_capture(self, selection_handle: object,
                              root_capture_record: object) -> SelectedAudioCaptureReceipt:
        if selection_handle is not self.selection_handle:
            raise IngressServiceDenied("audio selection handle is not current")
        # The root voice workflow owns the opaque result and consumes it here.
        # In particular, do not accept a public DTO containing caller-chosen
        # session/artifact IDs as proof that a capture happened.
        root_capture_record = self.sessions.take_capture_workflow_result(
            selection_handle, root_capture_record)
        if not isinstance(root_capture_record, RootAudioCaptureRequest):
            raise IngressServiceDenied("root did not resolve a selected audio workflow result")
        session = self._current_session(root_capture_record.session_handle)
        artifact = self.artifacts.resolve_capture(selection_handle, session,
                                                  root_capture_record.artifact_id)
        self._validate_artifact(session, artifact)
        self._resolve_receipt_closure(session, artifact)
        proof_receipt = self._proof_receipt(session, artifact)
        self._receipts[artifact.capture_receipt_handle] = (session, artifact, proof_receipt)
        return proof_receipt

    def current_selected_capture(self, selection_handle: object,
                                 receipt: SelectedAudioCaptureReceipt) -> SelectedAudioCaptureReceipt:
        if selection_handle is not self.selection_handle or not isinstance(receipt, SelectedAudioCaptureReceipt):
            raise IngressServiceDenied("audio proof is not owned by this selected root service")
        stored = self._receipts.get(receipt.capture_receipt_handle)
        if stored is None:
            raise IngressServiceDenied("audio capture receipt is unknown, consumed or replayed")
        session, artifact, proof_receipt = stored
        current_session = self._current_session(session.session_handle)
        current_artifact = self.artifacts.current_capture(selection_handle, current_session, artifact)
        if current_session != session or current_artifact is not artifact:
            raise IngressServiceDenied("audio consent, device session or sealed artifact is no longer current")
        self._validate_artifact(current_session, current_artifact)
        self._resolve_receipt_closure(current_session, current_artifact)
        return proof_receipt

    def read_current_capture(self, selection_handle: object, receipt: SelectedAudioCaptureReceipt,
                             *, maximum_bytes: int) -> bytearray:
        current = self.current_selected_capture(selection_handle, receipt)
        session, artifact, _proof = self._receipts[current.capture_receipt_handle]
        if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= self.selection.max_capture_bytes:
            raise IngressServiceDenied("audio artifact read bound is invalid")
        data = self.artifacts.read_capture_bytes(selection_handle, session, artifact,
                                                 maximum_bytes=maximum_bytes)
        if (not isinstance(data, bytearray) or not data or len(data) != artifact.size_bytes
                or hashlib.sha256(data).hexdigest() != artifact.sha256):
            if isinstance(data, bytearray):
                data[:] = b"\0" * len(data)
            raise IngressServiceDenied("sealed audio artifact bytes differ from the current root receipt")
        return data

    def consume_capture(self, selection_handle: object,
                        receipt: SelectedAudioCaptureReceipt) -> None:
        if selection_handle is not self.selection_handle:
            raise IngressServiceDenied("audio selection handle is not current")
        stored = self._receipts.pop(receipt.capture_receipt_handle, None)
        if stored is None:
            raise IngressServiceDenied("audio capture was already consumed")
        _session, artifact, _proof = stored
        self.artifacts.consume_capture(selection_handle, artifact)

    def _current_session(self, session_handle: str) -> RootAudioInputSession:
        if not isinstance(session_handle, str) or not _HANDLE.fullmatch(session_handle):
            raise IngressServiceDenied("audio session handle is malformed")
        session = self.sessions.current_input_session(self.selection_handle, session_handle)
        if (not isinstance(session, RootAudioInputSession)
                or session.session_handle != session_handle
                or session.profile_id != self.selection.profile_id
                or session.owner_generation != self.owner_generation
                or session.device_enrollment_id != self.selection.device_enrollment_id
                or not re.fullmatch(r"[0-9a-f]{64}", session.device_identity_digest)
                or not 0 < session.expires_monotonic - self.monotonic() <= 60
                or not isinstance(session.consent_receipt_handle, str)
                or not _HANDLE.fullmatch(session.consent_receipt_handle)):
            raise IngressServiceDenied("current audio session lacks selected device or explicit consent")
        return session

    def _validate_artifact(self, session: RootAudioInputSession,
                           artifact: RootAudioCaptureArtifact) -> None:
        if (not isinstance(artifact, RootAudioCaptureArtifact)
                or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", artifact.artifact_id)
                or not re.fullmatch(r"[0-9a-f]{64}", artifact.sha256)
                or type(artifact.size_bytes) is not int
                or not 1 <= artifact.size_bytes <= self.selection.max_capture_bytes
                or self.selection.sample_format_schema_id != "pcm16-mono-16000-v1"
                or artifact.media_type != "audio/pcm;format=s16le;rate=16000;channels=1"
                or artifact.profile_id != session.profile_id
                or artifact.owner_generation != session.owner_generation
                or not artifact.operation_id or not isinstance(artifact.artifact_receipt_handle, str)
                or not _HANDLE.fullmatch(artifact.artifact_receipt_handle)
                or not isinstance(artifact.capture_receipt_handle, str)
                or not _HANDLE.fullmatch(artifact.capture_receipt_handle)
                or artifact.device_enrollment_id != self.selection.device_enrollment_id
                or artifact.capture_backend_artifact_id != self.selection.capture_backend_artifact_id
                or artifact.capture_backend_sha256 != self.selection.capture_backend_sha256
                or artifact.format_schema_id != self.selection.sample_format_schema_id
                or not 0 < artifact.expires_monotonic - self.monotonic() <= 60):
            raise IngressServiceDenied("audio artifact receipt differs from enrolled device, backend or bounds")

    def _resolve_receipt_closure(self, session: RootAudioInputSession,
                                 artifact: RootAudioCaptureArtifact) -> tuple[SourceReceipt, ...]:
        # These are root-retained device/consent/capture proof handles, not
        # package SourceReceipts. The event issuer binds them into the final
        # signed native-input receipt; initial ingress has no parent chain.
        if (not _HANDLE.fullmatch(session.consent_receipt_handle)
                or not _HANDLE.fullmatch(artifact.capture_receipt_handle)
                or not _HANDLE.fullmatch(artifact.artifact_receipt_handle)):
            raise IngressServiceDenied("audio root proof handles are unavailable")
        return ()

    def _proof_receipt(self, session: RootAudioInputSession,
                       artifact: RootAudioCaptureArtifact) -> SelectedAudioCaptureReceipt:
        return SelectedAudioCaptureReceipt(
            self.selection.id, self.selection.device_enrollment_id,
            self.selection.capture_backend_artifact_id, self.selection.capture_backend_sha256,
            session.session_handle, str(session.consent_receipt_handle),
            str(artifact.capture_receipt_handle), str(artifact.artifact_receipt_handle),
            artifact.operation_id, artifact.artifact_id, artifact.sha256,
            artifact.size_bytes, artifact.format_schema_id, artifact.expires_monotonic,
        )
