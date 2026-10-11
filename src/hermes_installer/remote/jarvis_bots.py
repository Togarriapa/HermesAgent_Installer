"""Owner-only status projection and one-use pause action for Jarvis schedules.

It consumes only typed, fixed CoreRpcClient methods reviewed for the pinned Hermes core; it
is not a browser-facing RPC/CLI proxy. No schedule creation, resume, run or delivery is exposed.
"""
from __future__ import annotations

import secrets
import asyncio
import time
from typing import Any

from .jarvis_channels import project_channel_status
from .jarvis_schedules import project_schedules
from .jarvis_schedule_actions import (
    ScheduleActionDenied,
    ScheduleActionLedger,
    schedule_revision,
)

FEATURE_ROUTES = (
    ("GET", "/chat/api/bots"),
    ("GET", "/chat/api/channels"),
    ("GET", "/chat/api/schedules"),
    ("POST", "/chat/api/schedules/{opaque_id}/pause"),
)
def _now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _clean_label(value: Any, *, limit: int = 120) -> str:
    if not isinstance(value, str):
        return ""
    value = " ".join("".join(char for char in value if ord(char) >= 0x20 and ord(char) != 0x7f).split())
    return value[:limit]


def _profile_projection(row: dict[str, Any] | None) -> list[dict[str, Any]]:
    if row is None or row.get("is_default") is not True:
        return []
    label = _clean_label(row.get("display_name")) or _clean_label(row.get("name"))
    if not label:
        label = "Current default profile"
    return [{
        "opaque_id": secrets.token_urlsafe(18),
        "display_name": label,
        "kind": "profile",
        "state": "selected-default; Bot Mode roster unavailable",
        "bot_mode_available": False,
    }]


def build_status_snapshot(*, core_generation: str, profile: dict[str, Any] | None,
                          schedules: list[dict[str, Any]], observed_at: str | None = None,
                          schedule_approvals: list[Any] | None = None) -> dict[str, Any]:
    """Project closed public fields. Inputs here are already returned by typed core adapters."""
    profiles = _profile_projection(profile)
    schedule_rows, timezone_missing = project_schedules(schedules)
    if schedule_approvals is not None:
        if len(schedule_approvals) != len(schedule_rows):
            raise ValueError("schedule approval projection did not match native rows")
        for row, approval in zip(schedule_rows, schedule_approvals, strict=True):
            if approval is not None:
                row["opaque_id"] = approval.opaque_id
                row["revision"] = approval.revision
                row["pause_approval_nonce"] = approval.approval_nonce
    channels, channel_reason = project_channel_status()
    pending: list[str] = [
        "Bot Mode DM, groups, roster and relay are not represented by native profile inventory.",
        channel_reason,
    ]
    if not profiles:
        pending.append("The fixed native profile status did not identify a current default profile.")
    if timezone_missing:
        pending.append("The fixed native cron list does not report each schedule timezone.")
    return {
        "schema": 1,
        "observed_at": observed_at or _now(),
        "core_generation": core_generation,
        "profiles": profiles,
        "channels": channels,
        "schedules": schedule_rows,
        "pending_reasons": pending,
    }


def install_jarvis_bots_routes(app: Any, service: Any) -> None:
    """Install protected fixed status reads and one finite schedule-pause route."""
    from aiohttp import web
    from .core_client import CoreRpcClient
    from .jarvis_chat import (
        JarvisChatDenied, JarvisChatService, _read_body, _secure_headers,
    )

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    if not isinstance(service.backend, CoreRpcClient):
        raise TypeError("fixed official core status adapter required")

    ledger = getattr(service, "_jarvis_schedule_action_ledger", None)
    if not isinstance(ledger, ScheduleActionLedger):
        ledger = ScheduleActionLedger(service.store.path.with_name("schedule-actions.sqlite3"))
        service._jarvis_schedule_action_ledger = ledger

    async def route(request: Any) -> Any:
        if request.path not in {path for _method, path in FEATURE_ROUTES} or request.raw_path != request.path:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers())
        try:
            principal = service._current(request)
            profiles = await service.backend.list_profiles()
            profile = _sole_default(profiles)
            observed = service._current(request)
            if (observed.subject != principal.subject
                    or observed.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner or core generation changed during status read")
            schedules = await service.backend.list_schedules()
            profiles_after = await service.backend.list_profiles()
            profile_after = _sole_default(profiles_after)
            if ((profile is None) != (profile_after is None)
                    or (profile is not None and profile_after != profile)):
                raise JarvisChatDenied("default profile changed during status read")
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner or core generation changed during status read")
            approvals = None
            if request.path == "/chat/api/schedules":
                if profile is None:
                    raise JarvisChatDenied("current default profile is unavailable")
                approvals = ledger.issue_snapshot(principal.subject, principal.core_generation,
                                                  profile["name"],
                                                  principal.expires_monotonic, schedules)
            payload = build_status_snapshot(core_generation=principal.core_generation,
                                            profile=profile, schedules=schedules,
                                            schedule_approvals=approvals)
            return web.json_response(payload, headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPServiceUnavailable(text="native status is unavailable",
                                             headers=_secure_headers()) from None
        except Exception:
            # No source rows or upstream messages belong in browser responses or logs.
            raise web.HTTPServiceUnavailable(text="native status is unavailable",
                                             headers=_secure_headers()) from None

    async def pause_schedule(request: Any) -> Any:
        accepted_at = time.monotonic()
        try:
            opaque_id = request.match_info.get("opaque_id", "")
            if request.raw_path != request.path:
                raise web.HTTPNotFound(text="not found", headers=_secure_headers())
            principal = service._current(request)
            body = await _read_body(request, {"revision", "approval_nonce", "idempotency_key"})
            revision, approval_nonce, idempotency_key = (
                body["revision"], body["approval_nonce"], body["idempotency_key"])
            if not all(isinstance(value, str) for value in
                       (revision, approval_nonce, idempotency_key)):
                raise web.HTTPBadRequest(text="invalid request", headers=_secure_headers())
            default_before = _sole_default(await service.backend.list_profiles())
            if default_before is None:
                raise ScheduleActionDenied("current default profile is unavailable")
            profile_identity = default_before.get("name")
            if not isinstance(profile_identity, str) or not 1 <= len(profile_identity) <= 128:
                raise ScheduleActionDenied("current default profile identity is invalid")
            prior = ledger.lookup_action(
                subject=principal.subject, core_generation=principal.core_generation,
                profile_identity=profile_identity,
                opaque_id=opaque_id, revision=revision,
                approval_nonce=approval_nonce, idempotency_key=idempotency_key)
            if prior is not None:
                return web.json_response(prior.result or {"status": "pending"},
                                         status=200 if prior.result else 202,
                                         headers=_secure_headers())
            native_job_id = ledger.resolve_approval(
                subject=principal.subject, core_generation=principal.core_generation,
                profile_identity=profile_identity,
                jwt_expiry=principal.expires_monotonic, opaque_id=opaque_id,
                revision=revision, approval_nonce=approval_nonce)
            current_rows = await service.backend.list_schedules()
            if schedule_revision(current_rows) != revision:
                raise ScheduleActionDenied("schedule snapshot changed")
            target = next((row for row in current_rows if row.get("job_id") == native_job_id), None)
            if target is None or target.get("enabled") is not True:
                raise ScheduleActionDenied("schedule is no longer eligible for pause")
            default_after = _sole_default(await service.backend.list_profiles())
            current = service._current(request)
            if (default_after != default_before or current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise ScheduleActionDenied("owner, profile or core generation changed")
            deadline = min(principal.expires_monotonic, principal.witness_expires_monotonic)
            if time.monotonic() - accepted_at > 5.0 or deadline - time.monotonic() <= 0:
                raise ScheduleActionDenied("schedule action ingress authorization expired")
            binding = ledger.spend(
                subject=principal.subject, core_generation=principal.core_generation,
                profile_identity=profile_identity,
                jwt_expiry=principal.expires_monotonic, opaque_id=opaque_id,
                revision=revision, approval_nonce=approval_nonce,
                idempotency_key=idempotency_key)
            if binding.action_state != "pending" or not binding.job_id:
                return web.json_response(binding.result or {"status": "pending"},
                                         status=200 if binding.result else 202,
                                         headers=_secure_headers())
            remaining = min(5.0, deadline - time.monotonic(),
                            5.0 - (time.monotonic() - accepted_at))
            if remaining <= 0 or time.monotonic() - accepted_at > 5.0:
                return web.json_response({"status": "pending"}, status=202,
                                         headers=_secure_headers())
            try:
                await asyncio.wait_for(service.backend.pause_schedule(binding.job_id),
                                       timeout=remaining)
            except Exception:
                # The write may have reached Hermes. The spent nonce remains pending and can
                # never trigger an automatic second pause.
                return web.json_response({"status": "pending"}, status=202,
                                         headers=_secure_headers())
            after_rows = await asyncio.wait_for(service.backend.list_schedules(), timeout=5.0)
            paused = next((row for row in after_rows if row.get("job_id") == binding.job_id), None)
            final_default = _sole_default(await service.backend.list_profiles())
            final_principal = service._current(request)
            if (final_default != default_before or final_principal.subject != principal.subject
                    or final_principal.core_generation != principal.core_generation):
                return web.json_response({"status": "pending"}, status=202,
                                         headers=_secure_headers())
            if (paused is None or paused.get("enabled") is not False
                    or paused.get("state") != "paused"):
                return web.json_response({"status": "pending"}, status=202,
                                         headers=_secure_headers())
            result = {"status": "paused"}
            ledger.complete(binding, result)
            return web.json_response(result, headers=_secure_headers())
        except web.HTTPException:
            raise
        except (JarvisChatDenied, ScheduleActionDenied, ValueError):
            raise web.HTTPConflict(text="schedule action is stale or unavailable",
                                   headers=_secure_headers()) from None
        except Exception:
            return web.json_response({"status": "pending"}, status=202,
                                     headers=_secure_headers())

    for _method, path in FEATURE_ROUTES[:3]:
        app.router.add_get(path, route, allow_head=False)
    app.router.add_post("/chat/api/schedules/{opaque_id}/pause", pause_schedule)


def _sole_default(rows: Any) -> dict[str, Any] | None:
    """Accept only the typed adapter's zero-or-one current-default projection."""
    if not isinstance(rows, list) or len(rows) > 1:
        raise ValueError("native profile status exceeded its bound")
    if not rows:
        return None
    row = rows[0]
    if not isinstance(row, dict) or row.get("is_default") is not True:
        raise ValueError("native profile status was not the current default")
    return row
