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
    if path.exists() and path.is_symlink():
        raise OwnershipError("Provider plugin file cannot be a symlink")
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
    init_path = _write_owned(root, plugin + "/__init__.py", init, 0o600)
    manifest_path = _write_owned(root, plugin + "/plugin.yaml", manifest, 0o600)
    return {"plugin": str(root.path(plugin)), "entrypoint": str(init_path), "manifest": str(manifest_path)}


def _error_body(code: str, message: str) -> bytes:
    return json.dumps({"error": {"type": "policy_error", "code": code, "message": message}},
                      separators=(",", ":")).encode("utf-8")


class LocalProviderGateway:
    """HTTP gateway bound to loopback and one installer-trusted profile identity."""

    def __init__(self, dispatcher: Dispatcher, *, token: str, profile_id: str,
                 sensitivity: Sensitivity, model: str, max_output_tokens: int = 4096,
                 host: str = "127.0.0.1"):
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
        self.dispatcher = dispatcher
        self._token = token
        self.profile_id = profile_id
        self.sensitivity = sensitivity
        self.model = model
        self.max_output_tokens = max_output_tokens
        self.host = host
        self._server: http.server.ThreadingHTTPServer | None = None
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

            def _authorized(self) -> bool:
                values = self.headers.get_all("Authorization", [])
                if len(values) != 1:
                    return False
                prefix = "Bearer "
                candidate = values[0][len(prefix):] if values[0].startswith(prefix) else ""
                return hmac.compare_digest(candidate.encode("utf-8"), gateway._token.encode("utf-8"))

            def do_GET(self) -> None:
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
                if self.path != "/v1/chat/completions":
                    self._reply(404, _error_body("route.not_found", "Gateway path is not available"))
                    return
                if not self._authorized():
                    self._reply(401, _error_body("gateway.unauthorized", "Local provider authorization failed"))
                    return
                if self.headers.get("Transfer-Encoding") is not None:
                    self._reply(400, _error_body("request.framing", "Transfer-encoded requests are not accepted"))
                    return
                try:
                    raw_length = self.headers.get("Content-Length", "")
                    if not raw_length.isascii() or not raw_length.isdecimal():
                        raise ValueError
                    size = int(raw_length)
                except ValueError:
                    self._reply(400, _error_body("request.framing", "A valid Content-Length is required"))
                    return
                if size <= 0 or size > MAX_REQUEST_BYTES:
                    self._reply(413, _error_body("request.bounds", "Request body must be between 1 byte and 1 MiB"))
                    return
                raw = self.rfile.read(size)
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
                    context = DispatchContext(
                        profile_id=gateway.profile_id,
                        purpose="native-hermes-chat",
                        sensitivity=gateway.sensitivity,
                    )
                    result = gateway.dispatcher.dispatch(
                        context, gateway.model, raw, input_tokens=input_tokens,
                        output_token_limit=output_cap, tool_request=tool_request,
                    )
                except PolicyDenied as exc:
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
        server = http.server.ThreadingHTTPServer((self.host, 0), self._build_handler())
        server.daemon_threads = True
        server.block_on_close = False
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
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=2)
