"""Owner-bound, finite Hermes profile reasoning default settings."""
from __future__ import annotations

import asyncio
import secrets
import threading
import time
from typing import Any

from .jarvis_chat import JarvisChatDenied, JarvisChatService, _read_body, _secure_headers

FEATURE_ROUTES = (
    ("GET", "/chat/api/settings/reasoning-effort"),
    ("POST", "/chat/api/settings/reasoning-effort"),
)

SOURCE_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
_SOURCE_FILES = {
    "tui_gateway/methods_config.py": "cc70b29141543df29dd720e1f3b27952dc1e0f8b14167d3c324bda7b073bd71e",
    "tui_gateway/methods_config_set.py": "82d5776f2b376112a257bafef642cd6fefdbe4c46d874a52afed27d7c3f2bcf3",
    "hermes_constants.py": "5d43e6102c69748a2e64fc91623a49e1b0d76623416ce4ec37f23f216c3ce91f",
}
_ALLOWED_EFFORTS = frozenset({"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"})
_GRANT_TTL_SECONDS = 120.0
_GRANT_LIMIT = 128


def decode_native_reasoning(value: Any) -> dict[str, str]:
    """Accept only Hermes' sanitized config.get(reasoning) DTO."""
    if (not isinstance(value, dict) or set(value) != {"value", "display"}
            or not isinstance(value.get("value"), str)
            or value["value"] not in _ALLOWED_EFFORTS
            or not isinstance(value.get("display"), str)
            or value["display"] not in {"show", "hide"}):
        raise JarvisChatDenied("native reasoning setting is unavailable")
    return {"effort": value["value"], "display": value["display"]}


class _RevisionLedger:
    """Short-lived one-use owner/core/config-bound write grants."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._grants: dict[str, tuple[str, str, str, str, float]] = {}

    def issue(self, *, subject: str, generation: str, config_sha256: str, effort: str) -> str:
        now = time.monotonic()
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._grants = {key: value for key, value in self._grants.items() if value[4] > now}
            if len(self._grants) >= _GRANT_LIMIT:
                self._grants.pop(next(iter(self._grants)))
            self._grants[token] = (subject, generation, config_sha256, effort,
                                   now + _GRANT_TTL_SECONDS)
        return token

    def consume(self, token: str, *, subject: str, generation: str,
                config_sha256: str, current_effort: str) -> bool:
        now = time.monotonic()
        with self._lock:
            grant = self._grants.get(token)
            if not grant or grant[4] <= now or grant[:4] != (
                    subject, generation, config_sha256, current_effort):
                return False
            self._grants.pop(token, None)
            return True


async def _native_read(backend: Any) -> dict[str, str]:
    result = await asyncio.wait_for(backend._rpc("config.get", {"key": "reasoning"}), timeout=3.0)
    return decode_native_reasoning(result)


async def apply_global_reasoning(backend: Any, effort: str) -> dict[str, str]:
    """Use Hermes' fixed reasoning setter; never accept a config path from the caller."""
    if not isinstance(effort, str) or effort not in _ALLOWED_EFFORTS:
        raise JarvisChatDenied("requested reasoning effort is unsupported")
    result = await asyncio.wait_for(backend._rpc("config.set", {
        "key": "reasoning", "value": effort, "scope": "global",
    }), timeout=3.0)
    if (not isinstance(result, dict) or set(result) != {"key", "value"}
            or result.get("key") != "reasoning" or result.get("value") != effort):
        raise JarvisChatDenied("native reasoning change was not acknowledged")
    observed = await _native_read(backend)
    if observed["effort"] != effort:
        raise JarvisChatDenied("native reasoning readback differs")
    return observed


def install_jarvis_settings_admin_routes(app: Any, service: JarvisChatService) -> None:
    """Install only the fixed read and write for the pinned native reasoning default."""
    from aiohttp import web
    from .jarvis_models import _verified_snapshot
    from .core_gateway_inspector import verify_current_core_overview

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    ledger = _RevisionLedger()

    async def get_reasoning(request: Any) -> Any:
        try:
            principal, _accepted, _launch, observation, verify_current = await _verified_snapshot(
                request, service)
            native = await _native_read(service.backend)
            verify_current()
            revision = ledger.issue(subject=principal.subject,
                                    generation=principal.core_generation,
                                    config_sha256=observation.config_sha256,
                                    effort=native["effort"])
            return web.json_response({
                "status": "observed",
                "setting": {"id": "agent.reasoning_effort", "value": native["effort"],
                            "source": "native-profile-default"},
                "display": native["display"],
                "allowedValues": ["none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"],
                "applyScope": "future-conversations",
                "revision": revision,
                "source": {"revision": SOURCE_REVISION, "files": _SOURCE_FILES},
            }, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="native settings unavailable", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="native settings unavailable", headers=_secure_headers()) from None

    async def set_reasoning(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            body = await _read_body(request, {"effort", "revision"})
            if (not isinstance(body["effort"], str) or body["effort"] not in _ALLOWED_EFFORTS
                    or not isinstance(body["revision"], str) or not 32 <= len(body["revision"]) <= 128):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            principal, accepted, launch, observation, verify_current = await _verified_snapshot(
                request, service)
            before = await _native_read(service.backend)
            verify_current()
            if not ledger.consume(body["revision"], subject=principal.subject,
                                  generation=principal.core_generation,
                                  config_sha256=observation.config_sha256,
                                  current_effort=before["effort"]):
                raise web.HTTPConflict(text="settings changed; refresh before saving",
                                       headers=_secure_headers())

            # The native setter is idempotent, but a lost acknowledgement is not retried here.
            # Readback is the only success proof; failures remain ambiguous until the owner refreshes.
            saved = await apply_global_reasoning(service.backend, body["effort"])
            after = await asyncio.wait_for(asyncio.to_thread(
                verify_current_core_overview, launch.config,
                peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
                accepted_ingress=accepted), timeout=5.0)
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation
                    or after.core_generation != principal.core_generation
                    or after.verify_current(launch.config, peer_pid=accepted.peer_pid,
                                           peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
                                           accepted_ingress=accepted) is not True):
                raise JarvisChatDenied("owner or current core changed after native write")
            return web.json_response({
                "state": "saved-for-profile", "effort": saved["effort"],
                "applyScope": "future-conversations",
                "note": "The native profile default was read back. Existing other conversations were not changed.",
            }, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPServiceUnavailable(
                text="native settings result is unknown; refresh before retrying",
                headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(
                text="native settings result is unknown; refresh before retrying",
                headers=_secure_headers()) from None

    app.router.add_get(FEATURE_ROUTES[0][1], get_reasoning, allow_head=False)
    app.router.add_post(FEATURE_ROUTES[1][1], set_reasoning, allow_head=False)
