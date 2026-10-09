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


class StreamableHTTPTransport:
    """MCP Streamable HTTP transport with bounded reads and no redirect replay."""

    def __init__(
        self,
        endpoint: str,
        *,
        headers: Mapping[str, str] | None = None,
        timeout: float = 15.0,
        max_response_bytes: int = MAX_MESSAGE_BYTES,
    ) -> None:
        _validate_endpoint(endpoint)
        if not 0 < timeout <= 120:
            raise ValueError("transport timeout must be in (0, 120]")
        if not 1 <= max_response_bytes <= MAX_MESSAGE_BYTES:
            raise ValueError("response limit must be in (1, 1048576]")
        safe_headers: dict[str, str] = {}
        for key, value in (headers or {}).items():
            if not isinstance(key, str) or not isinstance(value, str) or "\r" in key + value or "\n" in key + value:
                raise ValueError("MCP headers must be valid single-line strings")
            if key.lower() in {"host", "content-length", "connection", "mcp-session-id"}:
                raise ValueError("MCP transport controls its protocol headers")
            safe_headers[key] = value
        self.endpoint = endpoint
        self._headers = safe_headers
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self._session_id: str | None = None
        self._closed = False
        self._opener = urllib.request.build_opener(_NoRedirect())

    def __repr__(self) -> str:
        return f"StreamableHTTPTransport(endpoint={self.endpoint!r}, headers=<redacted>)"

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._closed:
            raise TransportError("MCP HTTP transport is closed")
        body = _encode(payload)
        return await asyncio.to_thread(self._post, payload, body)

    def _post(self, payload: Mapping[str, Any], body: bytes) -> Mapping[str, Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with self._opener.open(request, timeout=self.timeout) as response:
                self._session_id = response.headers.get("Mcp-Session-Id", self._session_id)
                status = response.status
                content_type = response.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
                raw = response.read(self.max_response_bytes + 1)
        except urllib.error.HTTPError as exc:
            # Do not include server body, URL query, request headers or auth details.
            if exc.code in {401, 403}:
                raise TransportError("MCP authentication was denied or revoked") from None
            raise TransportError(f"MCP HTTP request failed with status {exc.code}") from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise TransportError("MCP HTTP transport timed out or disconnected") from None
        if len(raw) > self.max_response_bytes:
            raise TransportError("MCP response exceeded the configured size limit")
        if status == 202 and "id" not in payload:
            return {}
        if content_type == "application/json":
            return _decode(raw)
        if content_type == "text/event-stream":
            return self._decode_sse(raw, payload.get("id"))
        if status == 202 and "id" not in payload:
            return {}
        raise TransportError("MCP server returned an unsupported content type")

    @staticmethod
    def _decode_sse(raw: bytes, request_id: Any) -> Mapping[str, Any]:
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise TransportError("MCP event stream is not UTF-8") from None
        events = 0
        candidate: Mapping[str, Any] | None = None
        for event in text.replace("\r\n", "\n").split("\n\n"):
            data_lines = [line[5:].lstrip() for line in event.split("\n") if line.startswith("data:")]
            if not data_lines:
                continue
            events += 1
            if events > 256:
                raise TransportError("MCP event stream exceeded its event limit")
            try:
                message = _decode("\n".join(data_lines).encode("utf-8"))
            except TransportError:
                continue
            if message.get("id") == request_id:
                candidate = message
        if candidate is None:
            raise TransportError("MCP event stream contained no correlated response")
        return candidate

    async def cancel_request(self, request_id: Any) -> None:
        if self._closed:
            return
        # MCP cancellation is best effort; it is never treated as success and it
        # does not include the original request arguments or credential values.
        payload = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": request_id, "reason": "caller cancelled"}}
        try:
            await asyncio.wait_for(asyncio.to_thread(self._post, payload, _encode(payload)), self.timeout)
        except (TransportError, asyncio.TimeoutError):
            return

    async def close(self) -> None:
        self._closed = True
        self._session_id = None
        self._headers.clear()


class StdioTransport:
    """Adapter over the host-managed child process; this class never spawns a process.

    The supervisor owns executable pinning, isolated cwd/data, explicit environment,
    child custody and forced shutdown. This adapter only frames bounded MCP lines.
    """
    def __init__(self, handle, *, timeout: float = 9.0) -> None:
        required = ("read", "write", "wait", "stop")
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

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        if self._closed:
            raise TransportError("MCP stdio transport is closed")
        line = _encode(payload) + b"\\n"
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
                    if not result.endswith(b"\\n"):
                        raise TransportError("MCP stdio response must be one complete JSON line")
                    response = _decode(result.rstrip(b"\\r\\n"))
                    if response.get("id") == payload.get("id"):
                        return response
            except asyncio.TimeoutError:
                raise TransportError("MCP stdio request timed out") from None
            except TransportError:
                raise
            except Exception:
                raise TransportError("MCP stdio process disconnected") from None

    async def cancel_request(self, request_id: Any) -> None:
        if self._closed:
            return
        payload = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": request_id, "reason": "caller cancelled"}}
        try:
            await asyncio.wait_for(self._handle.write(_encode(payload) + b"\\n", timeout=2.0), 2.0)
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
