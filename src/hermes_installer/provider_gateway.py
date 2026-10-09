"""Loopback OpenAI-compatible gateway and Hermes provider profile materializer.

No public listener or provider activation is created by importing this module.
"""
from __future__ import annotations

import hmac
import http.server
import json
import os
import stat
import threading
import uuid
from pathlib import Path
from typing import Any

from .policy import DispatchContext, Dispatcher, PolicyDenied, Sensitivity
from .state import OwnedRoot, OwnershipError
from .provider_transport import ALLOWED_MODELS, MAX_REQUEST_BYTES

LOCAL_PROVIDER_NAME = "hermes-installer-dispatch"
LOCAL_KEY_ENV = "HERMES_INSTALLER_DISPATCH_KEY"


class GatewayError(RuntimeError):
    """Safe local gateway startup/configuration failure."""


def _write_owned(root: OwnedRoot, relative: str, data: bytes, mode: int = 0o600) -> Path:
    path = root.path(relative)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(info.st_mode):
            raise OwnershipError("Provider plugin file conflicts with a non-regular path")
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
            raise OwnershipError("Existing provider plugin file is not privately owned")
        if path.read_bytes() != data:
            raise OwnershipError("Existing provider plugin file differs; refusing to overwrite it")
        return path
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass
    return path


def _ensure_private_directory(root: OwnedRoot, relative: str) -> bool:
    """Create private owned path components and return whether final leaf was new."""
    parts = relative.split("/")
    created_leaf = False
    for index in range(1, len(parts) + 1):
        path = root.path("/".join(parts[:index]))
        try:
            path.mkdir(mode=0o700)
            if index == len(parts):
                created_leaf = True
        except FileExistsError:
            info = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(info.st_mode):
                raise OwnershipError("Provider plugin path contains a non-directory or symlink") from None
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OwnershipError("Provider plugin path component is not privately owned")
    return created_leaf


def materialize_hermes_provider_plugin(root: OwnedRoot, *, profile_relative: str,
                                       port: int, model: str) -> dict[str, str]:
    """Write the supported Hermes provider plugin under the selected HERMES_HOME."""
    if not isinstance(root, OwnedRoot):
        raise TypeError("provider plugin requires an OwnedRoot")
    root.ensure()
    profile = root.path(profile_relative)
    if not 1 <= port <= 65535 or model not in ALLOWED_MODELS:
        raise GatewayError("Invalid managed local provider endpoint or model")
    plugin = f"{profile_relative.rstrip('/')}/plugins/model-providers/{LOCAL_PROVIDER_NAME}"
    init = f'''"""Installer-managed provider profile. Dispatch is local and policy-gated."""
from providers import register_provider
from providers.base import ProviderProfile

register_provider(ProviderProfile(
    name={LOCAL_PROVIDER_NAME!r},
    aliases=("hermes-installer",),
    display_name="Hermes Installer Policy Gateway",
    description="Local request gate for the pinned public text route",
    env_vars=({LOCAL_KEY_ENV!r},),
    base_url="http://127.0.0.1:{port}/v1",
    auth_type="api_key",
    supports_health_check=False,
    supports_model_listing=False,
    hidden=True,
    default_aux_model={model!r},
    fallback_models=({model!r},),
))
'''.encode("utf-8")
    manifest = (
        "name: hermes-installer-dispatch\n"
        "kind: model-provider\n"
        "version: 1.0.0\n"
        "description: Installer-managed local privacy and budget gateway\n"
    ).encode("utf-8")
    plugin_path = root.path(plugin)
    marker_relative = plugin + "/.hermes-installer-owned"
    marker = ("hermes-installer-provider-plugin-v1\n" + plugin + "\n").encode("utf-8")
    created = _ensure_private_directory(root, plugin)
    if not created:
        marker_path = root.path(marker_relative)
        try:
            marker_info = marker_path.lstat()
            if marker_path.is_symlink() or not stat.S_ISREG(marker_info.st_mode) or marker_info.st_uid != os.getuid() or stat.S_IMODE(marker_info.st_mode) & 0o077 or marker_path.read_bytes() != marker:
                raise OwnershipError("Existing provider plugin directory lacks matching installer ownership")
        except FileNotFoundError:
            raise OwnershipError("Existing provider plugin directory lacks installer ownership") from None
        allowed_entries = {".hermes-installer-owned", "__init__.py", "plugin.yaml"}
        if any(entry.name not in allowed_entries for entry in plugin_path.iterdir()):
            raise OwnershipError("Existing provider plugin directory contains unrelated files")
    else:
        _write_owned(root, marker_relative, marker, 0o600)
    init_path = _write_owned(root, plugin + "/__init__.py", init, 0o600)
    manifest_path = _write_owned(root, plugin + "/plugin.yaml", manifest, 0o600)
    return {"plugin": str(plugin_path), "entrypoint": str(init_path), "manifest": str(manifest_path)}


class _BoundedThreadingHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, *, max_connections: int):
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()

    def handle_error(self, _request, _client_address):
        # Bounded read timeouts and disconnects carry no safe useful log data.
        return


def _error_body(code: str, message: str) -> bytes:
    return json.dumps({"error": {"type": "policy_error", "code": code, "message": message}},
                      separators=(",", ":")).encode("utf-8")


class LocalProviderGateway:
    """HTTP gateway bound to loopback and one installer-trusted profile identity."""

    def __init__(self, dispatcher: Dispatcher, *, token: str, profile_id: str,
                 sensitivity: Sensitivity, model: str, max_output_tokens: int = 4096,
                 host: str = "127.0.0.1", read_timeout_seconds: float = 10.0,
                 max_connections: int = 16):
        if host != "127.0.0.1":
            raise GatewayError("Provider gateway must bind IPv4 loopback only")
        if not isinstance(token, str) or not 32 <= len(token) <= 256 or any(ord(c) < 33 for c in token):
            raise GatewayError("Local dispatch token must be a generated high-entropy secret")
        if not profile_id or len(profile_id) > 128 or model not in ALLOWED_MODELS:
            raise GatewayError("Trusted provider profile identity or model is invalid")
        if not isinstance(sensitivity, Sensitivity):
            raise GatewayError("Provider classification must come from trusted profile configuration")
        if not 1 <= max_output_tokens <= 65_536:
            raise GatewayError("Configured output token limit is outside the supported range")
        if not 0.1 <= read_timeout_seconds <= 60 or not 1 <= max_connections <= 64:
            raise GatewayError("Gateway connection bounds are outside the supported range")
        self.dispatcher = dispatcher
        self._token = token
        self.profile_id = profile_id
        self.sensitivity = sensitivity
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.host = host
        self.read_timeout_seconds = read_timeout_seconds
        self.max_connections = max_connections
        self._closing = threading.Event()
        self._active_lock = threading.Lock()
        self._active_requests: set[threading.Event] = set()
        self._server: _BoundedThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def __repr__(self) -> str:
        return f"LocalProviderGateway(profile={self.profile_id!r}, token=<redacted>, host={self.host!r})"

    @property
    def port(self) -> int:
        if self._server is None:
            raise GatewayError("Provider gateway is not running")
        return int(self._server.server_address[1])

    def _build_handler(self):
        gateway = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self) -> None:
                self.request.settimeout(gateway.read_timeout_seconds)
                super().setup()

            def log_message(self, _format: str, *_args: Any) -> None:
                # Requests/bodies/headers can contain private prompts or credentials.
                return

            def _reply(self, status: int, body: bytes, content_type: str = "application/json") -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def _valid_host_origin(self) -> bool:
                if gateway._server is None:
                    return False
                expected = f"{gateway.host}:{gateway._server.server_address[1]}"
                hosts = self.headers.get_all("Host", [])
                origins = self.headers.get_all("Origin", [])
                return hosts == [expected] and len(origins) <= 1 and (not origins or origins[0] == "http://" + expected)

            def _begin_request(self) -> threading.Event | None:
                cancellation = threading.Event()
                with gateway._active_lock:
                    if gateway._closing.is_set():
                        return None
                    gateway._active_requests.add(cancellation)
                return cancellation

            def _end_request(self, cancellation: threading.Event) -> None:
                with gateway._active_lock:
                    gateway._active_requests.discard(cancellation)

            def _authorized(self) -> bool:
                values = self.headers.get_all("Authorization", [])
                if len(values) != 1:
                    return False
                prefix = "Bearer "
                candidate = values[0][len(prefix):] if values[0].startswith(prefix) else ""
                return hmac.compare_digest(candidate.encode("utf-8"), gateway._token.encode("utf-8"))

            def do_GET(self) -> None:
                if not self._valid_host_origin():
                    self._reply(403, _error_body("gateway.origin", "Gateway Host or Origin is not allowed"))
                    return
                if self.path != "/v1/models":
                    self._reply(404, _error_body("route.not_found", "Gateway path is not available"))
                    return
                if not self._authorized():
                    self._reply(401, _error_body("gateway.unauthorized", "Local provider authorization failed"))
                    return
                body = json.dumps({"object": "list", "data": [
                    {"id": gateway.model, "object": "model", "owned_by": "installer-policy"}
                ]}, separators=(",", ":")).encode("utf-8")
                self._reply(200, body)

            def do_POST(self) -> None:
                if not self._valid_host_origin():
                    self._reply(403, _error_body("gateway.origin", "Gateway Host or Origin is not allowed"))
                    return
                if self.path != "/v1/chat/completions":
                    self._reply(404, _error_body("route.not_found", "Gateway path is not available"))
                    return
                if not self._authorized():
                    self._reply(401, _error_body("gateway.unauthorized", "Local provider authorization failed"))
                    return
                if self.headers.get_all("Transfer-Encoding", []):
                    self._reply(400, _error_body("request.framing", "Transfer-encoded requests are not accepted"))
                    return
                content_lengths = self.headers.get_all("Content-Length", [])
                if len(content_lengths) != 1:
                    self._reply(400, _error_body("request.framing", "Exactly one Content-Length is required"))
                    return
                content_types = self.headers.get_all("Content-Type", [])
                if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() != "application/json":
                    self._reply(415, _error_body("request.content_type", "Only application/json is accepted"))
                    return
                try:
                    raw_length = content_lengths[0]
                    if not raw_length.isascii() or not raw_length.isdecimal():
                        raise ValueError
                    size = int(raw_length)
                except ValueError:
                    self._reply(400, _error_body("request.framing", "A valid Content-Length is required"))
                    return
                if size <= 0 or size > MAX_REQUEST_BYTES:
                    self._reply(413, _error_body("request.bounds", "Request body must be between 1 byte and 1 MiB"))
                    return
                try:
                    raw = self.rfile.read(size)
                except (TimeoutError, OSError):
                    self._reply(408, _error_body("request.timeout", "Request body read deadline elapsed"))
                    return
                if len(raw) != size:
                    self._reply(400, _error_body("request.framing", "Request body was incomplete"))
                    return
                try:
                    value = json.loads(raw)
                    if not isinstance(value, dict) or value.get("model") != gateway.model:
                        raise PolicyDenied("route.model", "Only the configured model is available")
                    requested_caps = []
                    for key in ("max_tokens", "max_completion_tokens", "max_output_tokens"):
                        if key in value:
                            cap = value[key]
                            if not isinstance(cap, int) or isinstance(cap, bool) or cap < 1:
                                raise PolicyDenied("request.bounds", "Output token cap is invalid")
                            requested_caps.append(cap)
                    output_cap = min([gateway.max_output_tokens, *requested_caps])
                    input_tokens = len(raw)  # byte upper bound; tokenizers cannot exceed encoded bytes here.
                    tool_request = bool(value.get("tools")) or value.get("tool_choice") not in (None, "none")
                    cancellation = self._begin_request()
                    if cancellation is None:
                        self._reply(503, _error_body("gateway.closing", "Gateway is shutting down"))
                        return
                    try:
                        context = DispatchContext(
                            profile_id=gateway.profile_id,
                            purpose="native-hermes-chat",
                            sensitivity=gateway.sensitivity,
                            cancelled=lambda: cancellation.is_set() or gateway._closing.is_set(),
                        )
                        result = gateway.dispatcher.dispatch(
                            context, gateway.model, raw, input_tokens=input_tokens,
                            output_token_limit=output_cap, tool_request=tool_request,
                        )
                    finally:
                        self._end_request(cancellation)
                    if cancellation.is_set() or gateway._closing.is_set():
                        self._reply(503, _error_body("gateway.cancelled", "Gateway request was cancelled"))
                        return
                except PolicyDenied as exc:
                    if gateway._closing.is_set():
                        self._reply(503, _error_body("gateway.cancelled", "Gateway request was cancelled"))
                    else:
                        self._reply(403 if exc.code.startswith(("route.", "context.")) else 400,
                                    _error_body(exc.code, str(exc)))
                    return
                except Exception:
                    self._reply(502, _error_body("provider.failed", "Policy gateway request failed"))
                    return
                content_type = result.headers.get("Content-Type", "application/json")
                if content_type not in {"application/json", "text/event-stream"}:
                    content_type = "application/json"
                self._reply(result.status, result.body, content_type)

            def do_PUT(self) -> None:
                self._reply(405, _error_body("route.method", "Method is not available"))

            def do_DELETE(self) -> None:
                self._reply(405, _error_body("route.method", "Method is not available"))

        return Handler

    def start(self) -> int:
        if self._server is not None:
            return self.port
        self._closing.clear()
        server = _BoundedThreadingHTTPServer((self.host, 0), self._build_handler(), max_connections=self.max_connections)
        self._server = server
        thread = threading.Thread(target=server.serve_forever, name="hermes-provider-gateway", daemon=True)
        thread.start()
        self._thread = thread
        return self.port

    def close(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is None:
            return
        self._closing.set()
        with self._active_lock:
            for cancellation in self._active_requests:
                cancellation.set()
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)
