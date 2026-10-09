"""Loopback OpenAI-compatible gateway and Hermes provider profile materializer.

No public listener or provider activation is created by importing this module.
"""
from __future__ import annotations

import hmac
import http.server
import json
import os
import socket
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
HOME_MARKER = ".hermes-installer-home-owned"
HOME_MARKER_CONTENT = b"hermes-installer-managed-home-v1\n"


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


def _write_owned_once(root: OwnedRoot, relative: str, data: bytes, mode: int = 0o600) -> bool:
    """Atomically create an owned file without replacing a concurrent writer."""
    path = root.path(relative)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(tmp, flags, mode)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(tmp, path, follow_symlinks=False)
        except FileExistsError:
            return False
        dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
        return True
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def _read_gateway_port(root: OwnedRoot, relative: str) -> int:
    path = root.path(relative)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
        raise OwnershipError("Recorded gateway port is not a private owned file")
    raw = path.read_bytes()
    if len(raw) > 8 or not raw.endswith(b"\n") or not raw[:-1].isdigit():
        raise OwnershipError("Recorded gateway port is malformed")
    port = int(raw[:-1])
    if not 1024 <= port <= 65535:
        raise OwnershipError("Recorded gateway port is outside the managed range")
    return port


def _persist_gateway_port(root: OwnedRoot, plugin: str, requested: int | None) -> int:
    relative = plugin + "/.gateway-port"
    path = root.path(relative)
    try:
        saved = _read_gateway_port(root, relative)
    except FileNotFoundError:
        saved = None
    if saved is not None:
        if requested not in (None, saved):
            raise GatewayError("The owned provider plugin already records a different gateway port")
        return saved
    if requested is not None and not 1024 <= requested <= 65535:
        raise GatewayError("Managed gateway port must be between 1024 and 65535")
    if requested is None:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", 0))
            selected = int(probe.getsockname()[1])
        finally:
            probe.close()
    else:
        selected = requested
    if not _write_owned_once(root, relative, f"{selected}\n".encode("ascii")):
        saved = _read_gateway_port(root, relative)
        if requested not in (None, saved):
            raise GatewayError("Another setup recorded a different gateway port")
        return saved
    return selected


def _verify_home_ownership(root: OwnedRoot, home_relative: str, *, create: bool) -> Path:
    if not isinstance(home_relative, str) or not home_relative.strip() or home_relative.startswith("/"):
        raise GatewayError("HERMES_HOME must be a non-empty installer-owned relative path")
    home_relative = home_relative.strip("/")
    home = root.path(home_relative)
    created = _ensure_private_directory(root, home_relative)
    marker_path = root.path(home_relative + "/" + HOME_MARKER)
    if created and create:
        if not _write_owned_once(root, home_relative + "/" + HOME_MARKER, HOME_MARKER_CONTENT):
            created = False
    if created and create:
        return home
    try:
        info = marker_path.lstat()
        if (marker_path.is_symlink() or not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
                or marker_path.read_bytes() != HOME_MARKER_CONTENT):
            raise OwnershipError("HERMES_HOME ownership marker is invalid")
    except FileNotFoundError:
        raise OwnershipError("Existing HERMES_HOME is not installer-owned; explicit adoption is required") from None
    return home


def materialize_hermes_provider_plugin(root: OwnedRoot, *, profile_relative: str,
                                       port: int | None, model: str) -> dict[str, str]:
    """Write or safely reconcile the supported Hermes provider plugin."""
    if not isinstance(root, OwnedRoot):
        raise TypeError("provider plugin requires an OwnedRoot")
    root.ensure()
    if model not in ALLOWED_MODELS:
        raise GatewayError("Invalid managed local provider model")
    home = _verify_home_ownership(root, profile_relative, create=True)
    plugin = f"{profile_relative.rstrip('/')}/plugins/model-providers/{LOCAL_PROVIDER_NAME}"
    plugin_path = root.path(plugin)
    created = _ensure_private_directory(root, plugin)
    marker_relative = plugin + "/.hermes-installer-owned"
    marker = ("hermes-installer-provider-plugin-v1\n" + plugin + "\n").encode("utf-8")
    if not created:
        marker_path = root.path(marker_relative)
        try:
            marker_info = marker_path.lstat()
            if (marker_path.is_symlink() or not stat.S_ISREG(marker_info.st_mode)
                    or marker_info.st_uid != os.getuid()
                    or stat.S_IMODE(marker_info.st_mode) & 0o077
                    or marker_path.read_bytes() != marker):
                raise OwnershipError("Existing provider plugin directory lacks matching installer ownership")
        except FileNotFoundError:
            raise OwnershipError("Existing provider plugin directory lacks installer ownership") from None
        allowed_entries = {".hermes-installer-owned", ".gateway-port", "__init__.py", "plugin.yaml"}
        if any(entry.name not in allowed_entries for entry in plugin_path.iterdir()):
            raise OwnershipError("Existing provider plugin directory contains unrelated files")
    else:
        if not _write_owned_once(root, marker_relative, marker, 0o600):
            raise OwnershipError("Provider plugin ownership marker raced with another writer")
    port = _persist_gateway_port(root, plugin, port)
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
    init_path = _write_owned(root, plugin + "/__init__.py", init, 0o600)
    manifest_path = _write_owned(root, plugin + "/plugin.yaml", manifest, 0o600)
    return {"home": str(home), "plugin": str(plugin_path), "entrypoint": str(init_path),
            "manifest": str(manifest_path), "port": str(port)}


def materialize_hermes_profile_config(root: OwnedRoot, *, home_relative: str,
                                       port: int, model: str) -> Path:
    """Write a minimal native Hermes primary/auxiliary profile in an owned HERMES_HOME."""
    if model not in ALLOWED_MODELS or not 1024 <= port <= 65535:
        raise GatewayError("Invalid managed Hermes provider configuration")
    home = _verify_home_ownership(root, home_relative, create=False)
    text = (
        "model:\n"
        f"  provider: {LOCAL_PROVIDER_NAME}\n"
        f"  default: {model}\n"
        "providers:\n"
        f"  {LOCAL_PROVIDER_NAME}:\n"
        f"    name: {LOCAL_PROVIDER_NAME}\n"
        f"    base_url: http://127.0.0.1:{port}/v1\n"
        f"    default_model: {model}\n"
        f"    api_key_env: {LOCAL_KEY_ENV}\n"
        "    transport: chat_completions\n"
    ).encode("utf-8")
    config = root.path(home_relative.strip("/") + "/config.yaml")
    _write_owned(root, home_relative.strip("/") + "/config.yaml", text, 0o600)
    return config


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
                 host: str = "127.0.0.1", port: int = 0, read_timeout_seconds: float = 10.0,
                 max_connections: int = 16,
                 context_factory: Callable[..., object] | None = None):
        if host != "127.0.0.1":
            raise GatewayError("Provider gateway must bind IPv4 loopback only")
        if not isinstance(port, int) or isinstance(port, bool) or (port != 0 and not 1024 <= port <= 65535):
            raise GatewayError("Gateway port must be zero for an ephemeral fixture or a managed user port")
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
        if not callable(context_factory):
            raise GatewayError("A host-issued context factory is required for provider dispatch")
        self.dispatcher = dispatcher
        self._token = token
        self.profile_id = profile_id
        self.sensitivity = sensitivity
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.host = host
        self.requested_port = port
        self.read_timeout_seconds = read_timeout_seconds
        self.max_connections = max_connections
        # The host must provide broker-issued principal, namespace and provenance
        # claims. A missing factory yields an incomplete context and is denied.
        self.context_factory = context_factory
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
                        trace_id = str(uuid.uuid4())
                        context = gateway.context_factory(
                            purpose="native-hermes-chat",
                            intent=trace_id,
                            source_contexts=(),
                            trace_id=trace_id,
                            lease_seconds=30,
                        )
                        result = gateway.dispatcher.dispatch(
                            context, gateway.model, raw, input_tokens=input_tokens,
                            output_token_limit=output_cap, tool_request=tool_request,
                            cancelled=lambda: cancellation.is_set() or gateway._closing.is_set(),
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
        server = _BoundedThreadingHTTPServer((self.host, self.requested_port), self._build_handler(), max_connections=self.max_connections)
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
