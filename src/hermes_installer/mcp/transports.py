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
    """A no-shell MCP stdio client for a pinned, reviewed executable."""

    def __init__(
        self,
        argv: tuple[str, ...],
        *,
        cwd: Path,
        env: Mapping[str, str] | None = None,
        secret_env: Mapping[str, str] | None = None,
        secret_resolver=None,
        timeout: float = 15.0,
    ) -> None:
        if not argv or not Path(argv[0]).is_absolute() or not Path(argv[0]).is_file():
            raise ValueError("MCP stdio executable must be an existing absolute file")
        if any(not isinstance(arg, str) or "\x00" in arg for arg in argv):
            raise ValueError("MCP stdio arguments must be NUL-free strings")
        if any(arg.lower() in {"--token", "--api-key", "--authorization"} for arg in argv):
            raise ValueError("MCP credentials must use secret references, never arguments")
        if not cwd.is_absolute() or not cwd.is_dir():
            raise ValueError("MCP stdio working directory must be an existing absolute directory")
        if not 0 < timeout <= 120:
            raise ValueError("transport timeout must be in (0, 120]")
        values = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"}
        for key, value in (env or {}).items():
            if key not in _SAFE_ENV_KEYS or not isinstance(value, str) or "\x00" in value:
                raise ValueError("MCP stdio environment contains an unreviewed value")
            values[key] = value
        if secret_env and secret_resolver is None:
            raise ValueError("MCP secret references require the host credential resolver")
        for key, reference in (secret_env or {}).items():
            if not key.startswith("MCP_") or not key.replace("_", "").isalnum():
                raise ValueError("MCP secret environment names must use the MCP_ prefix")
            try:
                value = secret_resolver(reference)
            except Exception:
                raise TransportError("MCP credential reference could not be resolved") from None
            if not isinstance(value, str) or not value or "\x00" in value:
                raise TransportError("MCP credential reference is missing or invalid")
            values[key] = value
        self.argv = argv
        self.cwd = str(cwd)
        self._env = values
        self.timeout = timeout
        self._process: asyncio.subprocess.Process | None = None
        self._stderr_task: asyncio.Task | None = None
        self._stderr_bytes = 0
        self._write_lock = asyncio.Lock()
        self._read_lock = asyncio.Lock()
        self._closed = False

    def __repr__(self) -> str:
        return f"StdioTransport(program={Path(self.argv[0]).name!r}, env=<sanitized>)"

    async def _start(self) -> None:
        if self._process is not None and self._process.returncode is None:
            return
        if self._closed:
            raise TransportError("MCP stdio transport is closed")
        try:
            self._process = await asyncio.create_subprocess_exec(
                *self.argv, cwd=self.cwd, env=self._env, stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        except (OSError, ValueError):
            raise TransportError("MCP stdio server could not be started") from None
        self._stderr_bytes = 0
        self._stderr_task = asyncio.create_task(self._drain_stderr(self._process.stderr))

    async def _drain_stderr(self, stream) -> None:
        while True:
            chunk = await stream.read(4096)
            if not chunk:
                return
            self._stderr_bytes = min(MAX_STDERR_BYTES, self._stderr_bytes + len(chunk))
            # stderr is drained to avoid deadlock but never retained or reported.

    async def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        await self._start()
        process = self._process
        assert process and process.stdin and process.stdout
        raw = _encode(payload) + b"\n"
        async with self._write_lock:
            try:
                process.stdin.write(raw)
                await asyncio.wait_for(process.stdin.drain(), self.timeout)
            except (BrokenPipeError, ConnectionError, asyncio.TimeoutError, OSError):
                await self.close()
                raise TransportError("MCP stdio server disconnected while writing") from None
        if "id" not in payload:
            return {}
        async with self._read_lock:
            try:
                while True:
                    line = await asyncio.wait_for(process.stdout.readline(), self.timeout)
                    if not line:
                        raise TransportError("MCP stdio server disconnected")
                    if len(line) > MAX_MESSAGE_BYTES:
                        raise TransportError("MCP stdio response exceeded the 1 MiB limit")
                    message = _decode(line.rstrip(b"\r\n"))
                    if message.get("id") == payload.get("id"):
                        return message
                    # Notifications and progress from the server are ignored here;
                    # callers receive only the correlated response.
            except asyncio.TimeoutError:
                raise TransportError("MCP stdio request timed out") from None

    async def cancel_request(self, request_id: Any) -> None:
        if self._closed or not self._process or not self._process.stdin:
            return
        payload = {"jsonrpc": "2.0", "method": "notifications/cancelled",
                   "params": {"requestId": request_id, "reason": "caller cancelled"}}
        try:
            async with self._write_lock:
                self._process.stdin.write(_encode(payload) + b"\n")
                await asyncio.wait_for(self._process.stdin.drain(), min(self.timeout, 2.0))
        except (BrokenPipeError, ConnectionError, asyncio.TimeoutError, OSError, TransportError):
            return

    async def close(self) -> None:
        self._closed = True
        process, self._process = self._process, None
        if process is None:
            self._env.clear()
            return
        if process.stdin:
            process.stdin.close()
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), 0.5)
            except asyncio.TimeoutError:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                await process.wait()
        if self._stderr_task:
            self._stderr_task.cancel()
            try:
                await self._stderr_task
            except asyncio.CancelledError:
                pass
            self._stderr_task = None
        self._env.clear()
