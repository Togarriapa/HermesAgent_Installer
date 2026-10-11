"""Owner-scoped Bot-profile readiness, with canonical DM operations kept pending.

Hermes Bot Mode identifies a canonical DM as the exact hidden ``Bot Chat`` session on
that Bot's own enrolled profile. The ordinary Jarvis default profile and the private
Resources profile inventory are not Bot enrollments. This module only projects a
root-supplied enrollment binding; it deliberately does not guess a profile or issue
session RPCs until the trusted root enrollment/session adapter exists.

Pinned native contract reviewed for the next adapter: exact lookup is
``session.list({profile, title:'Bot Chat', limit:200, include_hidden:true})``;
an error is not an empty registry. Only a confirmed miss can create, with
``session.create({profile, title:'Bot Chat', hidden:true,
follow_profile_config:true, idempotency_key})`` followed by eager
``session.title({profile, session_id:runtime_id, title:'Bot Chat'})``. A title
uniqueness race must re-list/adopt the winner. Existing sessions resume by exact
stored ID on the same enrolled profile and use returned transcript rows; there is
no initial kickoff prompt. Browser profile selection, runtime/stored IDs, broad
session browsing and cross-owner transcript access are not part of this contract.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

FEATURE_ROUTES = (("GET", "/chat/api/bot-rooms"),)
_OWNER_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ENROLLMENT_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


@dataclass(frozen=True, slots=True)
class BotProfileEnrollmentBinding:
    """Server-private root enrollment projection, never accepted from a request.

    The trusted root composition may attach a tuple of these to the Jarvis service
    only after validating its durable owner/profile enrollment. ``profile_name`` is
    consumed only for equality/uniqueness checks here and is never returned to a
    browser. It is not itself proof of enrollment.
    """

    enrollment_id: str
    owner_subject_sha256: str
    core_generation: str
    profile_name: str
    display_name: str


def _clean_label(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    value = " ".join("".join(ch for ch in value if ord(ch) >= 0x20 and ord(ch) != 0x7f).split())
    return value[:120]


def project_bot_roster(*, subject: str, core_generation: str,
                       enrollments: tuple[BotProfileEnrollmentBinding, ...] | None) -> dict[str, Any]:
    """Project only current-owner root enrollments and report DM readiness honestly."""
    if (not isinstance(subject, str) or not 1 <= len(subject) <= 512
            or not isinstance(core_generation, str) or not 1 <= len(core_generation) <= 256):
        raise ValueError("current Bot roster principal was invalid")
    owner_hash = hashlib.sha256(subject.encode("utf-8")).hexdigest()
    if enrollments is None:
        enrollments = ()
        enrollment_wired = False
    else:
        enrollment_wired = True
    if not isinstance(enrollments, tuple) or len(enrollments) > 32:
        raise ValueError("Bot profile enrollment snapshot exceeded its bound")

    profiles: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_profiles: set[str] = set()
    for item in enrollments:
        if type(item) is not BotProfileEnrollmentBinding:
            raise ValueError("Bot profile enrollment snapshot was not root-typed")
        if (not isinstance(item.enrollment_id, str)
                or not _ENROLLMENT_ID_RE.fullmatch(item.enrollment_id)
                or not isinstance(item.owner_subject_sha256, str)
                or not _OWNER_HASH_RE.fullmatch(item.owner_subject_sha256)
                or not isinstance(item.core_generation, str) or not 1 <= len(item.core_generation) <= 256
                or not isinstance(item.profile_name, str) or not 1 <= len(item.profile_name) <= 128
                or any(ord(ch) < 0x20 for ch in item.profile_name)
                or not isinstance(item.display_name, str) or not 1 <= len(item.display_name) <= 160
                or any(ord(ch) < 0x20 for ch in item.display_name)):
            raise ValueError("Bot profile enrollment row was invalid")
        if item.owner_subject_sha256 != owner_hash or item.core_generation != core_generation:
            continue
        if item.enrollment_id in seen_ids or item.profile_name in seen_profiles:
            raise ValueError("Bot profile enrollment identity was ambiguous")
        seen_ids.add(item.enrollment_id)
        seen_profiles.add(item.profile_name)
        label = _clean_label(item.display_name) or "Enrolled Bot"
        profiles.append({
            "label": label,
            "enrollment_state": "root-enrolled",
            "canonical_dm_state": "pending",
            "reason": ("Canonical Bot DM is pending its fixed profile-scoped session adapter; "
                       "no session has been opened or read by this feature."),
        })

    reasons: list[str] = []
    if not enrollment_wired:
        reasons.append(
            "No root-verified owner Bot-profile enrollment map is connected; default Jarvis and private Resources profiles are not Bot identities."
        )
    elif not profiles:
        reasons.append("No Bot profile is enrolled for this owner and current core generation.")
    if profiles:
        reasons.append(
            "Canonical Bot DM needs a fixed profile-scoped session.list/create/title/resume adapter and durable owner-to-session binding."
        )
    return {
        "schema": 1,
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "core_generation": core_generation,
        "status": "pending",
        "profiles": profiles,
        "pending_reasons": reasons,
    }


def install_jarvis_bot_rooms_routes(app: Any, service: Any) -> None:
    """Install one protected readiness read; no canonical-DM action is exposed yet."""
    from aiohttp import web
    from .jarvis_chat import JarvisChatDenied, JarvisChatService, _secure_headers

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")

    async def roster(request: Any) -> Any:
        if request.path != "/chat/api/bot-rooms" or request.raw_path != request.path:
            raise web.HTTPNotFound(text="not found", headers=_secure_headers())
        try:
            principal = service._current(request)
            enrollments = getattr(service, "_bot_profile_enrollments", None)
            if enrollments is not None and not isinstance(enrollments, tuple):
                raise ValueError("root Bot enrollment snapshot was malformed")
            payload = project_bot_roster(subject=principal.subject,
                                         core_generation=principal.core_generation,
                                         enrollments=enrollments)
            current = service._current(request)
            if (current.subject != principal.subject
                    or current.core_generation != principal.core_generation):
                raise JarvisChatDenied("owner or core generation changed during Bot roster read")
            return web.json_response(payload, headers=_secure_headers())
        except JarvisChatDenied:
            raise web.HTTPServiceUnavailable(text="Bot roster is unavailable",
                                             headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="Bot roster is unavailable",
                                             headers=_secure_headers()) from None

    app.router.add_get("/chat/api/bot-rooms", roster, allow_head=False)
