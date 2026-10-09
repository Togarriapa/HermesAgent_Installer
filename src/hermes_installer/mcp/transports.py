"""Bounded, secret-conscious transports for the Model Context Protocol.

The transport layer intentionally owns one connection per configured MCP server.
It does not inherit the installer process environment, follow HTTP redirects, or
put credential values in an argument vector.
"""
from __future__ import annotations

import asyncio
import json
import os
import signal
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urlsplit


MAX_MESSAGE_BYTES = 1_048_576
MAX_STDERR_BYTES = 65_536
_SAFE_ENV_KEYS = frozenset({"LANG", "LC_ALL", "TZ", "PATH"})


class TransportError(RuntimeError):
    """A transport failure whose text never includes headers or response bodies."""


def _encode(payload: Mapping[str, Any]) -> bytes:
    try:
        value = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError):
        raise TransportError("MCP message could not be encoded") from None
    if len(value) > MAX_MESSAGE_BYTES:
        raise TransportError("MCP message exceeds the 1 MiB limit")
    return value


def _decode(data: bytes) -> Mapping[str, Any]:
    if len(data) > MAX_MESSAGE_BYTES:
        raise TransportError("MCP response exceeds the 1 MiB limit")
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransportError("MCP response is not valid UTF-8 JSON") from None
    if not isinstance(value, Mapping) or value.get("jsonrpc") != "2.0":
        raise TransportError("MCP response is not a JSON-RPC 2.0 object")
    return value


def _validate_endpoint(endpoint: str) -> None:
    if not isinstance(endpoint, str) or len(endpoint) > 2048:
        raise ValueError("MCP endpoint must be an absolute HTTPS URL")
    parsed = urlsplit(endpoint)
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if parsed.scheme != "https" and not (parsed.scheme == "http" and loopback):
        raise ValueError("MCP endpoint must use HTTPS; HTTP is allowed only on loopback")
    if not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("MCP endpoint must not include user information or a fragment")
    if parsed.port is not None and not 1 <= parsed.port <= 65535:
        raise ValueError("MCP endpoint port is invalid")


@dataclass(frozen=True, slots=True)
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Authenticated requests must not silently replay credentials to a new
        # origin. An explicitly reviewed adapter may choose a final endpoint.
        return None




def _check_dispatch_grant(service_id, context, grant) -> None:
    from ..policy import DispatchAuthorization
    if not isinstance(grant, DispatchAuthorization) or context is None:
        raise TransportError("MCP host authorization is unavailable")
    capability = f"mcp:{service_id}:"
    import time
    if (not grant.capability.startswith(capability)
            or grant.principal_id != context.principal_id
            or grant.profile_id != context.profile_id
            or grant.namespace != context.namespace
            or grant.trace_id != context.trace_id
            or grant.policy_revision != context.policy_revision
            or grant.grant_id != context.grant_id
            or grant.lineage_sha256 != context.provenance[7:]
            or grant.expires_at_monotonic <= time.monotonic()):
        raise TransportError("MCP host authorization is stale or mismatched")

class StreamableHTTPTransport:
    """Origin-bound Streamable HTTP transport with DNS pinning and host grants."""

    requires_dispatch_grant = True

    def __init__(self, endpoint: str, *, service_id: str, credential_handle=None,
                 timeout: float = 9.0, max_response_bytes: int = MAX_MESSAGE_BYTES,
                 monotonic=time.monotonic) -> None:
        _validate_endpoint(endpoint)
        parsed = urlsplit(endpoint)
        if parsed.query:
            raise ValueError("MCP endpoint query strings are not supported")
        if not service_id or not isinstance(service_id, str):
            raise ValueError("reviewed MCP service id is required")
        if not 0 < timeout <= 9 or not 1 <= max_response_bytes <= MAX_MESSAGE_BYTES:
            raise ValueError("MCP transport bounds are invalid")
        self.endpoint, self.service_id = endpoint, service_id
        self.credential_handle = credential_handle
        self.timeout, self.max_response_bytes = timeout, max_response_bytes
        self.monotonic = monotonic
        self._session_id: str | None = None
        self._closed = False
        self._request_lock = asyncio.Lock()
        self._active: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"StreamableHTTPTransport(service_id={self.service_id!r}, endpoint=<bound>, credentials=<redacted>)"

    def _check_grant(self, context, grant) -> None:
        # The host ContextAuthorizer creates grants from trusted context. A user
        # config label or service name never supplies authority on its own.
        from ..policy import DispatchAuthorization
        if not isinstance(grant, DispatchAuthorization) or context is None:
            raise TransportError("MCP host authorization is unavailable")
        capability = f"mcp:{self.service_id}:"
        if (not grant.capability.startswith(capability)
                or grant.principal_id != context.principal_id
                or grant.profile_id != context.profile_id
                or grant.namespace != context.namespace
                or grant.trace_id != context.trace_id
                or grant.policy_revision != context.policy_revision
                or grant.grant_id != context.grant_id
                or grant.lineage_sha256 != context.provenance[7:]
                or grant.expires_at_monotonic <= self.monotonic()):
            raise TransportError("MCP host authorization is stale or mismatched")

    async def request(self, payload: Mapping[str, Any], *, dispatch_context=None,
                      dispatch_authorization=None) -> Mapping[str, Any]:
        if self._closed:
            raise TransportError("MCP HTTP transport is closed")
        self._check_grant(dispatch_context, dispatch_authorization)
        body = _encode(payload)
        method = payload.get("method")
        if method == "notifications/cancelled":
            return await self._post(payload, body, dispatch_context, dispatch_authorization, allow_cancel=True)
        rid = payload.get("id")
        if rid is not None:
            self._active[str(rid)] = (dispatch_context, dispatch_authorization)
        try:
            async with self._request_lock:
                return await self._post(payload, body, dispatch_context, dispatch_authorization)
        finally:
            if rid is not None:
                self._active.pop(str(rid), None)

    async def _headers(self, context, grant) -> dict[str, str]:
        result = {
            "Host": urlsplit(self.endpoint).netloc,
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "Connection": "close",
        }
        if self._session_id:
            result["Mcp-Session-Id"] = self._session_id
        if self.credential_handle is not None:
            provider = getattr(self.credential_handle, "headers_for", None)
            if not callable(provider):
                raise TransportError("MCP credential handle is invalid")
            try:
                supplied = provider(self.service_id, context, grant)
                if asyncio.iscoroutine(supplied):
                    supplied = await supplied
            except Exception:
                raise TransportError("MCP connection credential is unavailable") from None
            if not isinstance(supplied, Mapping):
                raise TransportError("MCP connection credential is invalid")
            for key, value in supplied.items():
                if not isinstance(key, str) or not isinstance(value, str) or "\r" in key + value or "\n" in key + value:
                    raise TransportError("MCP connection credential is invalid")
                if key.lower() in {"host", "content-length", "connection", "mcp-session-id"}:
                    raise TransportError("MCP credential handle attempted to override transport headers")
                result[key] = value
        return result

    def _address_policy(self, context) -> tuple[bool, bool]:
        caps = getattr(context, "capabilities", frozenset())
        allow_private_ha = self.service_id == "home-assistant" and "mcp:home-assistant:private-endpoint" in caps
        allow_loopback_fixture = "mcp:test:loopback" in caps
        return allow_private_ha, allow_loopback_fixture

    async def _resolve_pinned(self, host: str, port: int, context):
        loop = asyncio.get_running_loop()
        infos = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=__import__("socket").SOCK_STREAM),
            timeout=self.timeout,
        )
        if not infos:
            raise TransportError("MCP endpoint hostname did not resolve")
        allow_private, allow_loopback = self._address_policy(context)
        parsed = urlsplit(self.endpoint)
        candidates = []
        for family, socktype, proto, _, sockaddr in infos:
            address = sockaddr[0].split("%", 1)[0]
            try:
                ip = __import__("ipaddress").ip_address(address)
            except ValueError:
                raise TransportError("MCP endpoint resolved to an invalid address") from None
            if ip.is_loopback:
                if not allow_loopback:
                    raise TransportError("MCP loopback endpoint requires host test authorization")
            elif ip.is_private:
                if not allow_private:
                    raise TransportError("MCP private endpoint requires Home Assistant host authorization")
            elif not ip.is_global or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
                raise TransportError("MCP endpoint resolved to a restricted address")
            candidates.append((family, socktype, proto, sockaddr))
        # Reject mixed DNS answers; selecting a public answer from a mixed set
        # would let a later retry choose a private target.
        if len({item[3][0] for item in candidates}) > 8:
            raise TransportError("MCP endpoint returned too many DNS addresses")
        return candidates[0]

    async def _post(self, payload, body, context, grant, *, allow_cancel=False):
        self._check_grant(context, grant)
        parsed = urlsplit(self.endpoint)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        headers = await self._headers(context, grant)
        family, socktype, proto, sockaddr = await self._resolve_pinned(host, port, context)
        loop = asyncio.get_running_loop()
        raw_socket = __import__("socket").socket(family, socktype, proto)
        raw_socket.setblocking(False)
        writer = None
        try:
            await asyncio.wait_for(loop.sock_connect(raw_socket, sockaddr), self.timeout)
            if parsed.scheme == "https":
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(sock=raw_socket, ssl=__import__("ssl").create_default_context(),
                                             server_hostname=host, limit=65_536),
                    self.timeout,
                )
            else:
                # HTTP is reserved for an explicitly host-authorized loopback
                # fixture; private Home Assistant endpoints must use TLS.
                if "mcp:test:loopback" not in getattr(context, "capabilities", frozenset()):
                    raise TransportError("MCP HTTP transport is allowed only for a host-authorized loopback fixture")
                reader, writer = await asyncio.open_connection(sock=raw_socket, limit=65_536)
            path = parsed.path or "/"
            request_head = (
                f"POST {path} HTTP/1.1\r\n"
                + "".join(f"{key}: {value}\r\n" for key, value in headers.items())
                + f"Content-Length: {len(body)}\r\n\r\n"
            ).encode("ascii")
            writer.write(request_head + body)
            await asyncio.wait_for(writer.drain(), self.timeout)
            status_line = await asyncio.wait_for(reader.readline(), self.timeout)
            if len(status_line) > 8192 or not status_line.endswith(b"\r\n"):
                raise TransportError("MCP HTTP status line is invalid")
            try:
                version, status, _reason = status_line.decode("ascii").rstrip().split(" ", 2)
                status = int(status)
            except (UnicodeDecodeError, ValueError):
                raise TransportError("MCP HTTP status line is invalid") from None
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise TransportError("MCP HTTP version is unsupported")
            response_headers: dict[str, str] = {}
            total_header_bytes = len(status_line)
            while True:
                line = await asyncio.wait_for(reader.readline(), self.timeout)
                total_header_bytes += len(line)
                if total_header_bytes > 65_536 or not line.endswith(b"\r\n"):
                    raise TransportError("MCP HTTP headers exceeded their limit")
                if line == b"\r\n":
                    break
                if b":" not in line:
                    raise TransportError("MCP HTTP header is malformed")
                key, value = line.decode("iso-8859-1").split(":", 1)
                name = key.strip().lower()
                if name in response_headers:
                    raise TransportError("MCP HTTP response contains duplicate headers")
                response_headers[name] = value.strip()
            if 300 <= status < 400:
                raise TransportError("MCP HTTP redirects are not followed")
            if status in {401, 403}:
                raise TransportError("MCP authentication was denied or revoked")
            if status not in {200, 202}:
                raise TransportError(f"MCP HTTP request failed with status {status}")
            raw = await self._read_body(reader, response_headers, self.max_response_bytes)
            session_id = response_headers.get("mcp-session-id")
            if session_id:
                if len(session_id) > 512 or any(ord(ch) < 33 or ord(ch) > 126 for ch in session_id):
                    raise TransportError("MCP session identifier is invalid")
                self._session_id = session_id
            if status == 202 and "id" not in payload:
                return {}
            content_type = response_headers.get("content-type", "").split(";", 1)[0].strip().lower()
            if content_type == "application/json":
                return _decode(raw)
            if content_type == "text/event-stream":
                return self._decode_sse(raw, payload.get("id"))
            raise TransportError("MCP server returned an unsupported content type")
        except asyncio.CancelledError:
            raise
        except TransportError:
            raise
        except asyncio.TimeoutError:
            raise TransportError("MCP HTTP request timed out") from None
        except Exception:
            raise TransportError("MCP HTTP connection failed") from None
        finally:
            if writer is not None:
                writer.close()
                try:
                    await asyncio.wait_for(writer.wait_closed(), 0.5)
                except Exception:
                    pass
            else:
                raw_socket.close()

    @staticmethod
    async def _read_body(reader, headers, maximum):
        if "transfer-encoding" in headers:
            if headers["transfer-encoding"].lower() != "chunked" or "content-length" in headers:
                raise TransportError("MCP HTTP body framing is invalid")
            chunks = bytearray()
            for _ in range(4096):
                line = await reader.readline()
                if len(line) > 128 or not line.endswith(b"\r\n"):
                    raise TransportError("MCP HTTP chunk header is invalid")
                try:
                    size = int(line.split(b";", 1)[0].strip(), 16)
                except ValueError:
                    raise TransportError("MCP HTTP chunk size is invalid") from None
                if size == 0:
                    # Bound and consume trailers; they cannot affect the request's origin.
                    trailer_bytes = 0
                    while True:
                        trailer = await reader.readline()
                        trailer_bytes += len(trailer)
                        if trailer_bytes > 8192 or not trailer:
                            raise TransportError("MCP HTTP trailers exceeded their limit")
                        if trailer == b"\r\n":
                            return bytes(chunks)
                if len(chunks) + size > maximum:
                    raise TransportError("MCP response exceeded the configured size limit")
                chunks.extend(await reader.readexactly(size))
                if await reader.readexactly(2) != b"\r\n":
                    raise TransportError("MCP HTTP chunk terminator is invalid")
            raise TransportError("MCP HTTP response exceeded its chunk limit")
        try:
            length = int(headers.get("content-length", "-1"))
        except ValueError:
            raise TransportError("MCP HTTP content length is invalid") from None
        if length < 0 or length > maximum:
            raise TransportError("MCP HTTP body length is missing or over limit")
        return await reader.readexactly(length)

    @staticmethod
    def _decode_sse(raw: bytes, request_id: Any) -> Mapping[str, Any]:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise TransportError("MCP event stream is not UTF-8") from None
        events, result = 0, None
        for event in text.replace("\r\n", "\n").split("\n\n"):
            data = [line[5:].lstrip() for line in event.split("\n") if line.startswith("data:")]
            if not data:
                continue
            events += 1
            if events > 256:
                raise TransportError("MCP event stream exceeded its event limit")
            try:
                value = _decode("\n".join(data).encode("utf-8"))
            except TransportError:
                continue
            if value.get("id") == request_id:
                result = value
        if result is None:
            raise TransportError("MCP event stream contained no correlated response")
        return result

    async def cancel_request(self, request_id: Any, *, dispatch_context=None,
                             dispatch_authorization=None) -> None:
        if self._closed or dispatch_context is None or dispatch_authorization is None:
            return
        try:
            self._check_grant(dispatch_context, dispatch_authorization)
            payload = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                       "params": {"requestId": request_id, "reason": "caller cancelled"}}
            await asyncio.wait_for(self._post(payload, _encode(payload), dispatch_context,
                                              dispatch_authorization, allow_cancel=True), 2.0)
        except Exception:
            return

    async def close(self) -> None:
        self._closed = True
        self._session_id = None
        self._active.clear()
def is_supervised_stdio_handle(handle, service_id: str) -> bool:
    """Accept only a live-capable handle issued by the managed-process supervisor."""
    try:
        from ..managed_process import ManagedProcessHandle
    except ImportError:
        return False
    return (type(handle) is ManagedProcessHandle
            and getattr(getattr(handle, "spec", None), "service_identity", None) == f"mcp:{service_id}")


async def _require_supervised_stdio_handle(handle, service_id: str, context) -> None:
    capabilities = getattr(context, "capabilities", frozenset())
    # Synthetic fixture grants are issued only by isolated contract-test authorities.
    if "mcp:test:stdio" in capabilities:
        return
    if not is_supervised_stdio_handle(handle, service_id):
        raise TransportError("MCP stdio requires a supervisor-issued service handle")
    try:
        await handle._check_live()
    except Exception:
        raise TransportError("MCP stdio process custody is unavailable") from None


class StdioTransport:
    """Adapter over the host-managed child process; this class never spawns a process.

    The supervisor owns executable pinning, isolated cwd/data, explicit environment,
    child custody and forced shutdown. This adapter only frames bounded MCP lines.
    """
    requires_dispatch_grant = True

    def __init__(self, handle, *, service_id: str, timeout: float = 9.0) -> None:
        required = ("read", "write", "wait", "stop")
        if not service_id or not isinstance(service_id, str):
            raise ValueError("reviewed MCP service id is required")
        self.service_id = service_id
        if handle is None or any(not callable(getattr(handle, name, None)) for name in required):
            raise ValueError("MCP stdio requires a host-managed process handle")
        if not 0 < timeout <= 9:
            raise ValueError("MCP per-attempt timeout must be in (0, 9]")
        self._handle = handle
        self.timeout = timeout
        self._closed = False
        self._request_lock = asyncio.Lock()

    def __repr__(self) -> str:
        return "StdioTransport(process=<host-managed>)"

    async def request(self, payload: Mapping[str, Any], *, dispatch_context=None,
                      dispatch_authorization=None) -> Mapping[str, Any]:
        if self._closed:
            raise TransportError("MCP stdio transport is closed")
        _check_dispatch_grant(self.service_id, dispatch_context, dispatch_authorization)
        await _require_supervised_stdio_handle(self._handle, self.service_id, dispatch_context)
        line = _encode(payload) + b"\n"
        async with self._request_lock:
            try:
                await asyncio.wait_for(self._handle.write(line, timeout=self.timeout), self.timeout)
                if "id" not in payload:
                    return {}
                while True:
                    result = await asyncio.wait_for(
                        self._handle.read(maximum_bytes=MAX_MESSAGE_BYTES + 1, timeout=self.timeout),
                        self.timeout,
                    )
                    if not isinstance(result, bytes) or len(result) > MAX_MESSAGE_BYTES:
                        raise TransportError("MCP stdio response exceeded the message limit")
                    if not result:
                        raise TransportError("MCP stdio process exited before responding")
                    if not result.endswith(b"\n"):
                        raise TransportError("MCP stdio response must be one complete JSON line")
                    response = _decode(result.rstrip(b"\r\n"))
                    if response.get("id") == payload.get("id"):
                        return response
            except asyncio.TimeoutError:
                raise TransportError("MCP stdio request timed out") from None
            except TransportError:
                raise
            except Exception:
                raise TransportError("MCP stdio process disconnected") from None

    async def cancel_request(self, request_id: Any, *, dispatch_context=None,
                             dispatch_authorization=None) -> None:
        if self._closed:
            return
        try:
            _check_dispatch_grant(self.service_id, dispatch_context, dispatch_authorization)
            await _require_supervised_stdio_handle(self._handle, self.service_id, dispatch_context)
            await _require_supervised_stdio_handle(self._handle, self.service_id, dispatch_context)
        except TransportError:
            return
        payload = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": request_id, "reason": "caller cancelled"}}
        try:
            await asyncio.wait_for(self._handle.write(_encode(payload) + b"\n", timeout=2.0), 2.0)
        except Exception:
            return

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            await asyncio.wait_for(self._handle.stop("MCP connection closed", timeout=2.0), 2.5)
        except Exception:
            # The host supervisor owns any forced kill and records its evidence.
            raise TransportError("host-managed MCP process shutdown failed") from None
