"""Direct, bounded, one-hop public HTTPS transport for native web retrieval."""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import http.client
import json
import re
from email.message import Message
import socket
import ssl
import threading
import time
from ipaddress import ip_address
from typing import Any, Callable, Mapping
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from hermes_installer.network import BoundedNetwork, HTTPResult, NetworkError
from hermes_installer.components.plugin_local_voice_web import PluginAdapterError, WebResponse, _public_https_url

MAX_RESPONSE_BYTES = 1_000_000
MAX_DEADLINE_SECONDS = 10.0


class PublicHttpsDenied(PermissionError):
    """A direct HTTPS request failed its public destination or transport policy."""


@dataclass(frozen=True, slots=True)
class PublicSourceReceipt:
    url: str
    content_sha256: str
    byte_length: int
    status: int
    peer_ip: str
    tls_peer_sha256: str
    retrieved_at_unix: int
    redirect_chain: tuple[str, ...]
    enrollment_id: str
    generation: str
    receipt_sha256: str


@dataclass(frozen=True, slots=True, repr=False)
class ScopedWebCapture:
    """Exact verified TLS response bytes retained only within the root handler."""

    final_url: str
    media_type: str
    body: bytes = field(repr=False)
    redirect_chain: tuple[str, ...]
    transport_receipt: PublicSourceReceipt
    content_type: str = "application/octet-stream"
    _seal: object = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if (self._seal is not _SCOPED_CAPTURE_SEAL
                or not isinstance(self.body, bytes) or not self.body
                or not isinstance(self.redirect_chain, tuple)
                or not 1 <= len(self.redirect_chain) <= 5
                or not isinstance(self.media_type, str) or not self.media_type
                or not isinstance(self.content_type, str) or not self.content_type
                or self.final_url != self.redirect_chain[-1]):
            raise TypeError("scoped web captures are issued only by the root HTTPS reader")


_SCOPED_CAPTURE_SEAL = object()


@dataclass(frozen=True, slots=True)
class PublicReadTarget:
    hostname: str
    path_prefixes: tuple[str, ...]
    query_keys: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        host = self.hostname.lower().rstrip(".")
        if host != self.hostname or "." not in host or host.endswith((".local", ".internal", ".localhost")):
            raise ValueError("web target hostname must be a canonical public DNS name")
        if not self.path_prefixes or any(
            not isinstance(prefix, str) or not prefix.startswith("/") or "\\" in prefix
            or "/../" in f"{prefix}/" or len(prefix) > 512 for prefix in self.path_prefixes
        ):
            raise ValueError("web target path prefixes must be bounded absolute paths")
        if any(not isinstance(key, str) or not key or len(key) > 64 for key in self.query_keys):
            raise ValueError("web target query key is invalid")


@dataclass(frozen=True, slots=True)
class EnrolledPublicWebScope:
    enrollment_id: str
    target_id: str
    generation: str
    principal_id: str
    profile_id: str
    recipient: str
    targets: tuple[PublicReadTarget, ...]
    request_bytes_limit: int = 256 * 1024
    response_bytes_limit: int = 2 * 1024 * 1024
    deadline_seconds: float = 30.0

    def __post_init__(self) -> None:
        if (not self.enrollment_id or not self.target_id or not self.generation
                or not self.principal_id or not self.profile_id or not self.recipient
                or not self.targets or len(self.targets) > 32):
            raise ValueError("protected web enrollment is incomplete")
        if (type(self.request_bytes_limit) is not int or not 1 <= self.request_bytes_limit <= 262144
                or type(self.response_bytes_limit) is not int or not 1 <= self.response_bytes_limit <= 2_097_152
                or not 0 < self.deadline_seconds <= 30):
            raise ValueError("protected web effect bounds exceed the RB08 maximum")

    @property
    def target(self) -> str:
        return f"plugin:web:{self.target_id}:{self.generation}"

    def authorize_url(self, value: str) -> str:
        url = _public_https_url(value)
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower()
        matching = [target for target in self.targets if target.hostname == host]
        if not matching:
            raise PublicHttpsDenied("URL host is outside the protected task targets")
        path = parsed.path
        decoded_once = unquote(path)
        decoded_twice = unquote(decoded_once)
        if any("\\" in candidate or any(part in {".", ".."} for part in candidate.split("/"))
               for candidate in (path, decoded_once, decoded_twice)):
            raise PublicHttpsDenied("URL path contains traversal or separator encoding")
        if not any(_path_in_prefix(path, decoded_once, decoded_twice, prefix)
                   for target in matching for prefix in target.path_prefixes):
            raise PublicHttpsDenied("URL path is outside the protected task targets")
        sensitive_names = {"access_token", "api_key", "apikey", "authorization", "credential",
                           "password", "secret", "session", "signature", "token"}
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=64)
        if len(pairs) > 32:
            raise PublicHttpsDenied("URL has too many query fields")
        allowed = set().union(*(target.query_keys for target in matching))
        if any(_sensitive_query_name(key) or key not in allowed for key, _ in pairs):
            raise PublicHttpsDenied("URL query is not in the enrolled public-read schema")
        return url


def _sensitive_query_name(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    return any(secret in normalized for secret in (
        "apikey", "authorization", "credential", "password", "secret", "sessionkey",
        "signature", "token",
    ))


def _path_in_prefix(path: str, decoded_once: str, decoded_twice: str, prefix: str) -> bool:
    candidates = (path, decoded_once, decoded_twice)
    for value in candidates:
        if prefix == "/" or value == prefix.rstrip("/"):
            return True
        if value.startswith(prefix if prefix.endswith("/") else prefix + "/"):
            return True
    return False


class DirectPublicHttpsReader:
    """No-proxy direct connection with DNS/IP checks before each HTTP hop.

    Redirects are returned as ordinary 3xx responses. The caller must check
    each destination before making the next request.
    """
    def __init__(self, *, deadline_seconds: float = MAX_DEADLINE_SECONDS,
                 max_response_bytes: int = MAX_RESPONSE_BYTES):
        if not 0.1 <= deadline_seconds <= MAX_DEADLINE_SECONDS:
            raise ValueError("web deadline is outside the fixed maximum")
        if not 1024 <= max_response_bytes <= MAX_RESPONSE_BYTES:
            raise ValueError("web response limit is outside the fixed maximum")
        self.deadline_seconds = deadline_seconds
        self.max_response_bytes = max_response_bytes

    def get_one_hop(self, url: str, *, timeout: float, max_bytes: int,
                    cancelled: Callable[[], bool] | None = None) -> WebResponse:
        canonical = _public_https_url(url)
        if type(timeout) not in {int, float} or not 0 < timeout <= self.deadline_seconds:
            raise PluginAdapterError("web operation deadline is invalid")
        if type(max_bytes) is not int or not 1 <= max_bytes <= self.max_response_bytes:
            raise PluginAdapterError("web response bound is invalid")
        parsed = urlsplit(canonical)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        def request(one_url: str, method: str, headers: dict[str, str], body: bytes | None,
                    socket_timeout: float, byte_limit: int) -> HTTPResult:
            if one_url != canonical or method != "GET" or body is not None:
                raise PublicHttpsDenied("only the exact canonical one-hop GET is allowed")
            return _direct_get(canonical, path, parsed.hostname or "", socket_timeout,
                               min(byte_limit, max_bytes))

        try:
            result = BoundedNetwork(deadline_seconds=min(self.deadline_seconds, float(timeout)),
                                    socket_timeout=min(4.0, float(timeout)),
                                    max_response_bytes=max(1024, max_bytes),
                                    requester=request).request(
                                        canonical, method="GET",
                                        headers={"Accept": "text/html, text/plain, application/json, application/xml;q=0.9"},
                                        cancelled=cancelled)
        except (NetworkError, OSError, TimeoutError, ValueError, PublicHttpsDenied):
            raise PluginAdapterError("direct public HTTPS request failed within its bounds") from None
        body = result.body
        if len(body) > max_bytes:
            raise PluginAdapterError("public response exceeds its byte limit")
        peer_ip = result.headers.pop("X-Hermes-Connected-IP", "")
        tls_digest = result.headers.pop("X-Hermes-TLS-SHA256", "")
        if not _public_ip(peer_ip) or len(tls_digest) != 64:
            raise PluginAdapterError("transport did not return peer and TLS receipt metadata")
        return WebResponse(result.status, result.headers, body, canonical, peer_ip,
                           True, False, tls_digest)


def _direct_get(url: str, path: str, host: str, timeout: float,
                max_bytes: int) -> HTTPResult:
    """Connect to a checked numeric address and verify TLS for the URL host."""
    if not 0.1 <= timeout <= MAX_DEADLINE_SECONDS:
        raise PublicHttpsDenied("socket timeout is outside the fixed range")
    infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    addresses: list[tuple[int, tuple]] = []
    seen: set[tuple[int, str]] = set()
    for family, _socktype, _proto, _canon, sockaddr in infos:
        address = ip_address(sockaddr[0])
        if not address.is_global:
            raise PublicHttpsDenied("public hostname resolves to a private or reserved address")
        key = family, str(address)
        if key not in seen:
            addresses.append((family, sockaddr))
            seen.add(key)
    if not addresses:
        raise PublicHttpsDenied("public hostname has no usable address")
    last_error: Exception | None = None
    for family, sockaddr in addresses[:8]:
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        tls: ssl.SSLSocket | None = None
        try:
            raw.connect(sockaddr)
            connected = ip_address(raw.getpeername()[0])
            if not connected.is_global or connected != ip_address(sockaddr[0]):
                raise PublicHttpsDenied("connected peer differs from checked public address")
            tls = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            certificate = tls.getpeercert(binary_form=True)
            if not certificate:
                raise PublicHttpsDenied("TLS peer did not provide a certificate")
            host_header = f"[{host}]" if ":" in host else host
            request = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
                       "Accept: text/html, text/plain, application/json, application/xml;q=0.9\r\n"
                       "Connection: close\r\nUser-Agent: HermesInstaller-Web/1\r\n\r\n").encode("ascii")
            tls.sendall(request)
            response = http.client.HTTPResponse(tls)
            response.begin()
            body = response.read(max_bytes + 1)
            if len(body) > max_bytes:
                raise PublicHttpsDenied("public response exceeds the byte limit")
            headers = {str(k): str(v) for k, v in response.getheaders()
                       if k.lower() in {"content-type", "content-length", "location", "cache-control"}}
            headers["X-Hermes-Connected-IP"] = str(connected)
            headers["X-Hermes-TLS-SHA256"] = hashlib.sha256(certificate).hexdigest()
            return HTTPResult(int(response.status), headers, body)
        except PublicHttpsDenied:
            raise
        except Exception as exc:
            last_error = exc
        finally:
            if tls is not None:
                tls.close()
            else:
                raw.close()
    raise PublicHttpsDenied(f"connection failed ({type(last_error).__name__ if last_error else 'unknown'})")


def _public_ip(value: str) -> bool:
    try:
        return ip_address(value).is_global
    except ValueError:
        return False


def make_source_receipt(url: str, response: WebResponse, *, body: bytes,
                        retrieved_at_unix: int, redirect_chain: tuple[str, ...],
                        enrollment_id: str, generation: str) -> PublicSourceReceipt:
    if response.final_url != url or not response.tls_verified or response.used_proxy or not _public_ip(response.connected_ip):
        raise PluginAdapterError("source receipt transport claims failed verification")
    if type(retrieved_at_unix) is not int or retrieved_at_unix <= 0 or len(body) > MAX_RESPONSE_BYTES:
        raise PluginAdapterError("source receipt fields are invalid")
    content_digest = hashlib.sha256(body).hexdigest()
    unsigned = {"url": url, "content_sha256": content_digest, "byte_length": len(body),
                "status": response.status, "peer_ip": response.connected_ip,
                "tls_peer_sha256": response.tls_peer_sha256,
                "retrieved_at_unix": retrieved_at_unix, "redirect_chain": redirect_chain,
                "enrollment_id": enrollment_id, "generation": generation}
    receipt_digest = hashlib.sha256(json.dumps(
        unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    return PublicSourceReceipt(**unsigned, receipt_sha256=receipt_digest)


class PluginWebReadEffectHandler:
    """Root-side one-use broker handler for one exact RB08 web enrollment."""
    def __init__(self, enrollment: EnrolledPublicWebScope,
                 reader: DirectPublicHttpsReader, *, artifact_registry: Any | None = None):
        if type(enrollment) is not EnrolledPublicWebScope or type(reader) is not DirectPublicHttpsReader:
            raise TypeError("web handler requires protected enrollment and reviewed direct reader")
        self.enrollment, self.reader = enrollment, reader
        self.artifact_registry = artifact_registry
        self._lock = threading.Lock()

    def __call__(self, *, context: object, authorization: object, payload: bytes,
                 timeout: float, peer_pid: int, cancelled: Callable[[], bool],
                 peer_pidfd: int | None = None) -> Mapping[str, Any]:
        if not self._lock.acquire(blocking=False):
            raise PublicHttpsDenied("selected web target already has an active request")
        try:
            return self._handle(context=context, authorization=authorization, payload=payload,
                                timeout=timeout, peer_pid=peer_pid, cancelled=cancelled,
                                peer_pidfd=peer_pidfd)
        finally:
            self._lock.release()

    def _handle(self, *, context: object, authorization: object, payload: bytes,
                timeout: float, peer_pid: int, cancelled: Callable[[], bool],
                peer_pidfd: int | None = None) -> Mapping[str, Any]:
        del peer_pidfd
        scope = self.enrollment
        if (not callable(cancelled) or cancelled() or type(peer_pid) is not int or peer_pid <= 0
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0 < timeout <= min(30.0, scope.deadline_seconds)):
            raise PublicHttpsDenied("web effect context or deadline is invalid")
        if (getattr(context, "principal_id", None) != scope.principal_id
                or getattr(context, "profile_id", None) != scope.profile_id
                or getattr(authorization, "principal_id", None) != scope.principal_id
                or getattr(authorization, "profile_id", None) != scope.profile_id
                or getattr(authorization, "capability", None) != "plugin:web"
                or getattr(authorization, "target", None) != scope.target
                or getattr(authorization, "recipient", None) != scope.recipient
                or getattr(authorization, "operation", None) != "plugin.web.read"
                or getattr(authorization, "enrollment_id", None) != scope.enrollment_id
                or getattr(authorization, "generation", None) != scope.generation
                or getattr(authorization, "retry_index", None) != 0
                or "plugin:web" not in getattr(context, "capabilities", frozenset())):
            raise PublicHttpsDenied("web effect grant does not match the root enrollment")
        digest = hashlib.sha256(payload).hexdigest()
        if getattr(authorization, "request_digest", None) != digest or len(payload) > scope.request_bytes_limit:
            raise PublicHttpsDenied("web request payload differs from its one-use grant")
        arguments = _decode_plugin_request(payload, scope)
        if self.artifact_registry is None:
            raise PublicHttpsDenied("root web content artifact registry is not assembled")
        capture = retrieve_scoped_capture(
            self.reader, scope, arguments["url"],
            timeout=min(float(timeout), scope.deadline_seconds),
            max_bytes=min(MAX_RESPONSE_BYTES, scope.response_bytes_limit),
            cancelled=cancelled,
        )
        decoded_content = _decode_public_content(capture.body, capture.content_type)
        prepare = getattr(self.artifact_registry, "prepare_authorized_response", None)
        if not callable(prepare):
            raise PublicHttpsDenied("root web content artifact producer is not assembled")
        observation = prepare(context, authorization, payload, capture)
        if (not callable(getattr(observation, "staged_result_fields", None))
                or not isinstance(getattr(observation, "operation_id", None), str)):
            raise PublicHttpsDenied("root web content producer returned an invalid sealed observation")
        operation_id = observation.operation_id
        result = {
            "url": capture.final_url,
            "content_type": capture.content_type,
            "content": decoded_content,
            "untrusted_source": True,
            "authority": "none",
            "redirects": list(capture.redirect_chain),
            "source_receipt": observation.staged_result_fields(),
        }
        result_body = json.dumps(result, sort_keys=True, separators=(",", ":"),
                                  ensure_ascii=False).encode("utf-8")
        body = json.dumps({"schema": 1, "operation_id": operation_id,
                           "state": "read-complete", "result": result,
                           "verification_status": "verified", "resume_action_id": None},
                          sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(body) > scope.response_bytes_limit:
            raise PublicHttpsDenied("web result exceeds its protected response limit")
        receipt_id = hashlib.sha256(payload + b"\0" + body).hexdigest()
        return {"status": 200, "body": body,
                "headers": {"Content-Type": "application/json", "Cache-Control": "no-store"},
                "receipt_id": receipt_id}


def _decode_public_content(body: bytes, content_type: str) -> str:
    """Decode exact captured bytes using only the response's declared charset."""
    if (not isinstance(body, bytes) or not isinstance(content_type, str) or len(content_type) > 512
            or any(char in content_type for char in "\r\n\x00")):
        raise PublicHttpsDenied("public content encoding metadata is invalid")
    message = Message()
    message["content-type"] = content_type
    if not _textual_media_type(message.get_content_type().lower()):
        raise PublicHttpsDenied("public content media type is not textual")
    charset = message.get_content_charset() or "utf-8"
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", charset, re.ASCII):
        raise PublicHttpsDenied("public content charset is invalid")
    try:
        import codecs
        codec = codecs.lookup(charset)
        return body.decode(codec.name, errors="strict")
    except (LookupError, UnicodeError):
        raise PublicHttpsDenied("public content cannot be decoded with its declared charset") from None


def _textual_media_type(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 128 or "/" not in value:
        return False
    major, subtype = value.split("/", 1)
    if major == "text":
        return bool(re.fullmatch(r"[a-z0-9!#$&^_.+-]+", subtype, re.ASCII))
    return (major == "application"
            and (subtype in {"json", "xml"} or subtype.endswith(("+json", "+xml"))
                 and bool(re.fullmatch(r"[a-z0-9!#$&^_.+-]+", subtype, re.ASCII))))


def _decode_plugin_request(payload: bytes, scope: EnrolledPublicWebScope) -> dict[str, Any]:
    if not isinstance(payload, bytes) or not payload or len(payload) > scope.request_bytes_limit:
        raise PublicHttpsDenied("web action payload is outside bounds")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise PublicHttpsDenied("web action payload is malformed") from None
    if not isinstance(value, dict):
        raise PublicHttpsDenied("web action payload must be an object")
    expected = {"schema": 1, "adapter_id": "web", "action_id": "retrieve",
                "enrollment_id": scope.enrollment_id, "generation": scope.generation,
                "arguments": {"url": value.get("arguments", {}).get("url")
                              if isinstance(value.get("arguments"), dict) else None}}
    if value != expected or type(value.get("schema")) is not int:
        raise PublicHttpsDenied("web action is outside the finite enrolled schema")
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode("utf-8")
    if canonical != payload:
        raise PublicHttpsDenied("web action payload is not canonical")
    return value["arguments"]


def retrieve_scoped(reader: DirectPublicHttpsReader, scope: EnrolledPublicWebScope,
                    url: str, *, timeout: float, max_bytes: int,
                    cancelled: Callable[[], bool]) -> dict[str, Any]:
    captured = retrieve_scoped_capture(reader, scope, url, timeout=timeout,
                                       max_bytes=max_bytes, cancelled=cancelled)
    from dataclasses import asdict
    return {"url": captured.final_url, "content_type": captured.media_type,
            "content": captured.body.decode("utf-8", errors="replace"),
            "untrusted_source": True, "authority": "none",
            "redirects": max(0, len(captured.redirect_chain) - 1),
            "source_receipt": asdict(captured.transport_receipt)}


def retrieve_scoped_capture(reader: DirectPublicHttpsReader, scope: EnrolledPublicWebScope,
                            url: str, *, timeout: float, max_bytes: int,
                            cancelled: Callable[[], bool]) -> ScopedWebCapture:
    current = scope.authorize_url(url)
    chain = [current]
    deadline = time.monotonic() + timeout
    for hop in range(5):
        remaining = deadline - time.monotonic()
        if cancelled() or remaining <= 0:
            raise PublicHttpsDenied("web read was cancelled or exceeded its deadline")
        response = reader.get_one_hop(current, timeout=remaining, max_bytes=max_bytes,
                                      cancelled=cancelled)
        if response.used_proxy or not response.tls_verified or not _public_ip(response.connected_ip):
            raise PublicHttpsDenied("web transport failed direct public TLS policy")
        if response.final_url != current or len(response.body) > max_bytes:
            raise PublicHttpsDenied("web transport followed a hidden redirect or exceeded its size limit")
        if response.status in {301, 302, 303, 307, 308}:
            location = next((v for k, v in response.headers.items() if k.lower() == "location"), None)
            if not location or hop == 4:
                raise PublicHttpsDenied("web redirect limit or Location header is invalid")
            current = scope.authorize_url(urljoin(current, location))
            chain.append(current)
            continue
        if not 200 <= response.status < 300:
            raise PublicHttpsDenied(f"public site returned HTTP {response.status}")
        content_type = next((v for k, v in response.headers.items() if k.lower() == "content-type"),
                            "application/octet-stream")
        if (not isinstance(content_type, str) or len(content_type) > 512
                or any(char in content_type for char in "\r\n\x00")):
            raise PublicHttpsDenied("public content type metadata exceeds its bound")
        content_type_message = Message()
        content_type_message["content-type"] = content_type
        media_type = content_type_message.get_content_type().lower()
        if not _textual_media_type(media_type):
            raise PublicHttpsDenied("only textual public content is supported")
        receipt = make_source_receipt(
            current, response, body=response.body, retrieved_at_unix=int(time.time()),
            redirect_chain=tuple(chain), enrollment_id=scope.enrollment_id,
            generation=scope.generation)
        return ScopedWebCapture(current, media_type, response.body, tuple(chain), receipt,
                                content_type, _SCOPED_CAPTURE_SEAL)
    raise PublicHttpsDenied("web redirect limit exceeded")
