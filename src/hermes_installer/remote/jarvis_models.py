"""Owner-bound, session-scoped Codex model selection for Jarvis conversations."""
from __future__ import annotations

import asyncio
import json
import re
from typing import Any

from .jarvis_chat import JarvisChatDenied, JarvisChatService, _read_body, _secure_headers
from .jarvis_model_catalog import (
    CODEX_ACCOUNT_GATED_MODEL,
    CODEX_MODEL_SOURCE_REVISION,
    CODEX_MODEL_SOURCE_SHA256,
    CODEX_PROVIDER_ID,
    CODEX_SELECTABLE_MODELS,
)

FEATURE_ROUTES = (
    ("GET", "/chat/api/models/conversations"),
    ("GET", "/chat/api/conversations/{conversation_id}/model-settings"),
    ("POST", "/chat/api/conversations/{conversation_id}/model-selection"),
)
_CONVERSATION_ID = re.compile(r"^[A-Za-z0-9_-]{24,64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{22,128}$")


async def _verified_snapshot(request: Any, service: JarvisChatService):
    """Obtain a short-lived root observation tied to this accepted ingress."""
    from .core_gateway import CoreAcceptedIngressObservation
    from .core_gateway_inspector import verify_current_core_overview

    principal = service._current(request)
    accepted = request.get("core_ingress")
    launch = request.app.get("core_gateway_launch")
    if type(accepted) is not CoreAcceptedIngressObservation or launch is None:
        raise JarvisChatDenied("current core projection is unavailable")
    observation = await asyncio.wait_for(asyncio.to_thread(
        verify_current_core_overview, launch.config, peer_pid=accepted.peer_pid,
        peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
        accepted_ingress=accepted), timeout=5.0)
    if (observation.core_generation != principal.core_generation
            or accepted.core_generation != principal.core_generation):
        raise JarvisChatDenied("current core generation changed")

    def verify_current() -> None:
        current = service._current(request)
        if (current.subject != principal.subject
                or current.core_generation != principal.core_generation
                or observation.verify_current(launch.config,
                    peer_pid=accepted.peer_pid, peer_uid=accepted.peer_uid,
                    peer_gid=accepted.peer_gid, accepted_ingress=accepted) is not True):
            raise JarvisChatDenied("current core projection expired")

    return principal, accepted, launch, observation, verify_current


async def _native_status(service: JarvisChatService) -> dict[str, Any]:
    try:
        return await asyncio.wait_for(service.backend.get_model_provider_status(), timeout=2.0)
    except Exception:
        raise JarvisChatDenied("native Codex provider status is unavailable") from None


def _selection_ready(projection: dict[str, Any], native: dict[str, Any]) -> bool:
    return (projection.get("provider") == CODEX_PROVIDER_ID
            and native.get("provider_hint") in {"unknown", CODEX_PROVIDER_ID}
            and native.get("model") == projection.get("model")
            and native.get("codex_credential_configured") is True)


def _catalog() -> list[dict[str, Any]]:
    return ([{"id": model, "selectable": True, "status": "pinned-codex-catalog"}
             for model in CODEX_SELECTABLE_MODELS]
            + [{"id": CODEX_ACCOUNT_GATED_MODEL, "selectable": False,
                "status": "account-entitlement-unverified"}])


def install_jarvis_models_routes(app: Any, service: JarvisChatService) -> None:
    """Install the fixed authenticated routes; the registry owns their declarations."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def list_conversations(request: Any) -> Any:
        try:
            principal, _accepted, _launch, _observation, verify_current = await _verified_snapshot(
                request, service)
            conversations = service.store.list_conversations(principal.subject)
            verify_current()
            return web.json_response({"conversations": conversations}, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="conversations unavailable", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="conversations unavailable", headers=_secure_headers()) from None

    async def get_settings(request: Any) -> Any:
        try:
            if request.raw_path != request.path:
                raise JarvisChatDenied("model settings path is invalid")
            principal, _accepted, _launch, observation, verify_current = await _verified_snapshot(
                request, service)
            conversation_id = request.match_info.get("conversation_id", "")
            if not _CONVERSATION_ID.fullmatch(conversation_id):
                raise JarvisChatDenied("conversation is unavailable")
            conversation = service.store.get_conversation(principal.subject, conversation_id)
            if conversation["core_generation"] != principal.core_generation:
                raise JarvisChatDenied("conversation belongs to a stale core generation")
            native = await _native_status(service)
            verify_current()
            projection = observation.projection
            ready = _selection_ready(projection, native)
            activity = service.store.model_selection_activity(
                principal.subject, conversation_id, principal.core_generation)
            revision = None
            if ready and activity == "available":
                try:
                    revision = service.store.issue_model_selection_revision(
                        principal.subject, conversation_id, principal.core_generation,
                        observation.config_sha256)
                except JarvisChatDenied:
                    activity = service.store.model_selection_activity(
                        principal.subject, conversation_id, principal.core_generation)
            last = service.store.latest_model_selection(
                principal.subject, conversation_id, principal.core_generation,
                conversation["backend_id"])
            payload = {
                "status": "observed",
                "provider": {"id": projection.get("provider"),
                             "status": "configured-unverified" if projection.get("provider") else "unknown"},
                "profileModel": {"id": projection.get("model"),
                                 "status": "configured-unverified" if projection.get("model") else "unknown"},
                "codexCredential": (
                    "configured" if native["codex_credential_configured"] is True else
                    "not-configured" if native["codex_credential_configured"] is False else "unknown"),
                "conversationSelection": last,
                "selectionAvailability": (
                    "provider-or-credential-unverified" if not ready else
                    "turn-active" if activity == "busy" else
                    "available" if revision else "revision-unavailable"),
                "models": _catalog(),
                "source": {"revision": CODEX_MODEL_SOURCE_REVISION,
                           "sha256": CODEX_MODEL_SOURCE_SHA256},
                "revision": revision,
            }
            verify_current()
            return web.json_response(payload, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPForbidden(text="model settings unavailable", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="model settings unavailable", headers=_secure_headers()) from None

    async def set_selection(request: Any) -> Any:
        operation_id = None
        runtime_session_id = None
        principal = None
        try:
            if request.raw_path != request.path:
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            body = await _read_body(request, {"model_id", "revision", "approval_nonce", "idempotency_key"})
            if (not isinstance(body["model_id"], str)
                    or body["model_id"] not in CODEX_SELECTABLE_MODELS
                    or not isinstance(body["idempotency_key"], str)
                    or not _IDEMPOTENCY.fullmatch(body["idempotency_key"])):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            principal, _accepted, _launch, observation, verify_current = await _verified_snapshot(
                request, service)
            conversation_id = request.match_info.get("conversation_id", "")
            if not _CONVERSATION_ID.fullmatch(conversation_id):
                raise JarvisChatDenied("conversation is unavailable")
            native = await _native_status(service)
            verify_current()
            if not _selection_ready(observation.projection, native):
                raise JarvisChatDenied("Codex route readiness is unverified")
            reservation = service.store.reserve_model_selection(
                principal.subject, conversation_id,
                core_generation=principal.core_generation,
                config_sha256=observation.config_sha256,
                model_id=body["model_id"], revision=body["revision"],
                approval_nonce=body["approval_nonce"],
                idempotency_key=body["idempotency_key"])
            operation_id = reservation["operation_id"]
            runtime_session_id = reservation["runtime_session_id"]
            if reservation["replayed"]:
                operation_id = None
                verify_current()
                return web.json_response({"model": reservation["model"],
                                          "state": reservation["state"]}, headers=_secure_headers())

            state = "unknown-pending"
            async with service._resume_lock:
                current = service._current(request)
                conversation = service.store.get_conversation(current.subject, conversation_id)
                if (current.subject != principal.subject
                        or current.core_generation != principal.core_generation
                        or conversation["core_generation"] != principal.core_generation
                        or conversation["backend_id"] != runtime_session_id):
                    raise JarvisChatDenied("conversation session mapping changed")

                async def bind_resumed_session(actual_session_id: str) -> bool:
                    nonlocal runtime_session_id
                    latest = service._current(request)
                    verify_current()
                    if (latest.subject != principal.subject
                            or latest.core_generation != principal.core_generation
                            or not service.store.bind_model_selection_session(
                                principal.subject, operation_id,
                                core_generation=principal.core_generation,
                                runtime_session_id=actual_session_id)):
                        raise JarvisChatDenied("resumed model session ownership changed")
                    runtime_session_id = actual_session_id
                    return True

                response = await asyncio.wait_for(service.backend.set_session_model(
                    conversation["session_key"], body["model_id"],
                    before_set=bind_resumed_session), timeout=10.0)
                verify_current()
                after = await _native_status(service)
                verify_current()
                if (after.get("codex_credential_configured") is not True
                        or after.get("model") != native.get("model")
                        or after.get("provider_hint") != native.get("provider_hint")):
                    state = "unknown-pending"
                elif response.get("state") in {"selected-for-session", "deferred-next-turn",
                                                "confirmation-required"}:
                    state = response["state"]
                else:
                    state = "unknown-pending"
            service.store.finish_model_selection(
                principal.subject, operation_id, state=state,
                runtime_session_id=runtime_session_id)
            operation_id = None
            verify_current()
            return web.json_response({"model": body["model_id"], "state": state},
                                     headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPConflict(text="model selection was not confirmed", headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="model selection status is unknown",
                                             headers=_secure_headers()) from None
        finally:
            if operation_id and principal and runtime_session_id:
                try:
                    service.store.finish_model_selection(
                        principal.subject, operation_id, state="unknown-pending",
                        runtime_session_id=runtime_session_id)
                except Exception:
                    pass

    app.router.add_get(FEATURE_ROUTES[0][1], list_conversations, allow_head=False)
    app.router.add_get(FEATURE_ROUTES[1][1], get_settings, allow_head=False)
    app.router.add_post(FEATURE_ROUTES[2][1], set_selection, allow_head=False)
