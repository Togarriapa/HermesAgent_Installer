#!/usr/bin/env python3
"""Pi-only full-shell fixture probe for the reviewed Jarvis user flows.

This is fixture layout evidence only. It serves the exact finite asset set exposed
by hermes_installer.remote.jarvis_chat_assets.reviewed_chat_asset and a small,
cookie-gated set of deterministic local API responses. It does not start Hermes,
read configuration or credentials, create a live conversation, submit a turn, or use a
provider/model/microphone. Its mobile harness replaces fetch with in-memory responses,
including the UI's create-conversation request, before any network transmission. Chromium is restricted to this loopback fixture by CSP
and host resolution rules. Screenshots and a JSON report are the only retained
outputs; the fixture server and browser profile are temporary.

This compatibility copy extends v24 only to match the current ecosystem assets,
canonical nested navigation, valid Profiles/search fixtures, and native browser
intersection measurements. It changes no product code or acceptance scope.
It exercises only exact reviewed local GET routes and inert UI
navigation/focus actions for Projects/trash, Models, Profiles, Extensions, and
Obsidian. Synthetic status responses deliberately leave source/account readiness
unqualified. It never confirms Restore, Save, Delete, extension mutations, model
selection, voice, or a message submission. Unexpected paths/methods fail closed.

The v24 mobile lane verifies Chats opens the thread/composer first, the history
drawer opens from its toggle, selecting a fixture chat returns to the composer,
and wide layouts retain their persistent conversation rail. It never submits a
message or writes a live record. The motion lane uses the ephemeral fixture's visible Settings control,
emulates device reduced motion, scrolls the Overview reactor out of and back into
view where the real page geometry permits, and otherwise records partial
visibility plus continued motion as not-applicable for the offscreen pause claim.
It also checks the persistent shared Chat header while the document is hidden.
It does not modify a production UI or preference.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from contextlib import nullcontext
import hashlib
import json
import os
import platform
import shutil
import signal
import secrets
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from aiohttp import ClientSession, WSMsgType, web


ASSET_PATHS = (
    "/chat",
    "/chat/assets/app.css",
    "/chat/assets/app.js",
    "/chat/assets/features.js",
    "/chat/assets/features-core.js",
    "/chat/assets/features-workspace.js",
    "/chat/assets/features-knowledge.js",
    "/chat/assets/features-core.css",
    "/chat/assets/features-workspace.css",
    "/chat/assets/features-knowledge.css",
    "/chat/assets/features-ecosystem.js",
    "/chat/assets/features-ecosystem.css",
    "/chat/manifest.webmanifest",
    "/chat/assets/jarvis-app-icon.svg",
)
COOKIE_NAME = "jarvis_visual_fixture"
FIXTURE_MODEL_CONVERSATION_ID = "visualfixture000000000001"
FIXTURE_CONVERSATION_ID = FIXTURE_MODEL_CONVERSATION_ID
FIXTURE_PROJECT_ID = "fixture-project-0001"
FIXTURE_NOTE_ID = "fixture-note-a"
FIXTURE_NOTE_LINK_ID = "fixture-note-b"
FIXTURE_TITLE = "Visual fixture — layout only"
FIXTURE_CONTENT_SHA256 = "0123456789abcdef" * 4
MOBILE_BROWSER_HARNESS_RELATIVE = Path("fixtures/jarvis_chat_mobile_browser_harness_compat226.js")
MOBILE_BROWSER_HARNESS_SOURCE_SHA256 = "14d4a1219976b22d2b0be3e5e4daba3325821d1a65092484d767955cf513b470"
MOBILE_BROWSER_HARNESS_SHA256 = "0b3c38a8d2e42e919443137f4062a84e63a70cd19a10aa0269be4be75770125e"
REVIEWED_ASSET_SHA256: dict[str, str] = {}
COMPATIBILITY_PROVENANCE = {
    "requirements": ["109", "R0201", "R0203", "#35"],
    "baseline_probe_sha256": "e12683344cb5293684aca12ed7c9ca0af69fc0f741594b27953086ee478f8847",
    "reviewed_navigation_function_sha256": "7d9d2d616c76b639ec42459708c3b702ae9ae1644917a7f9128a31f0898f6924",
    "pinned_source_harness_sha256": "14d4a1219976b22d2b0be3e5e4daba3325821d1a65092484d767955cf513b470",
    "added_reviewed_assets": ["/chat/assets/features-ecosystem.js", "/chat/assets/features-ecosystem.css"],
}

NATIVE_INTERSECTION_HELPER = r'''async function observeNativeIntersections(targets, operationDeadline, reserveMs = 0) {
  let observer = null, timer = null, sampleStart = null;
  try {
    if (typeof IntersectionObserver !== "function") return {ok:false, reason:"unsupported"};
    if (!Array.isArray(targets) || !targets.length || new Set(targets).size !== targets.length
        || targets.some(target => !(target instanceof Element) || !target.isConnected
          || target.ownerDocument !== document))
      return {ok:false, reason:"invalid-target-set"};
    const remaining = operationDeadline - performance.now() - reserveMs;
    if (!Number.isFinite(remaining) || remaining <= 0) return {ok:false, reason:"deadline"};
    const outcome = await new Promise(resolve => {
      let settled = false;
      const seen = new Map();
      const finish = value => { if (settled) return; settled = true; resolve(value); };
      observer = new IntersectionObserver(entries => {
        for (const entry of entries) if (targets.includes(entry.target)) seen.set(entry.target, entry);
        if (!targets.every(target => seen.has(target))) return;
        const records = [];
        for (const target of targets) {
          const entry = seen.get(target);
          const rect = value => value && ({x:value.x,y:value.y,left:value.left,top:value.top,
            right:value.right,bottom:value.bottom,width:value.width,height:value.height});
          records.push({target,entry:{time:entry.time,boundingClientRect:rect(entry.boundingClientRect),
            intersectionRect:rect(entry.intersectionRect),rootBounds:rect(entry.rootBounds),
            intersectionRatio:entry.intersectionRatio,isIntersecting:entry.isIntersecting}});
        }
        finish({records});
      }, {root:null,rootMargin:"0px",threshold:0});
      timer = setTimeout(() => finish({error:"timeout"}), remaining);
      sampleStart = performance.now();
      for (const target of targets) observer.observe(target);
    });
    if (outcome.error) return {ok:false,reason:outcome.error};
    const validatedAt = performance.now();
    if (!Number.isFinite(sampleStart) || validatedAt >= operationDeadline - reserveMs)
      return {ok:false,reason:"deadline-after-observation"};
    const records = [];
    let sharedEntryTime = null;
    for (let index = 0; index < targets.length; index++) {
      const target = targets[index], record = outcome.records?.[index];
      if (!target.isConnected || target.ownerDocument !== document || !record || record.target !== target)
        return {ok:false,reason:"target-changed"};
      const {entry} = record;
      const finiteRect = rect => rect && ["x","y","left","top","right","bottom","width","height"]
        .every(key => Number.isFinite(rect[key])) && rect.width >= 0 && rect.height >= 0;
      if (!Number.isFinite(entry.time) || !Number.isFinite(entry.intersectionRatio)
          || typeof entry.isIntersecting !== "boolean" || !finiteRect(entry.boundingClientRect)
          || !finiteRect(entry.intersectionRect) || !finiteRect(entry.rootBounds))
        return {ok:false,reason:"non-finite-entry"};
      if (entry.time < sampleStart || entry.time > validatedAt)
        return {ok:false,reason:"entry-time-outside-fresh-sample"};
      if (entry.boundingClientRect.width <= 0 || entry.boundingClientRect.height <= 0)
        return {ok:false,reason:"empty-target-bounding-box"};
      if (sharedEntryTime === null) sharedEntryTime = entry.time;
      else if (entry.time !== sharedEntryTime) return {ok:false,reason:"different-entry-sample-times"};
      const currentRect = target.getBoundingClientRect();
      for (const key of ["x","y","left","top","right","bottom","width","height"])
        if (currentRect[key] !== entry.boundingClientRect[key])
          return {ok:false,reason:"bounding-geometry-changed-after-native-entry"};
      records.push(entry);
    }
    return {ok:true,records};
  } catch (error) {
    return {ok:false,reason:"observer-error",errorName:error?.name||"Error"};
  } finally {
    if (timer !== null) clearTimeout(timer);
    if (observer) observer.disconnect();
  }
}'''


def _load_mobile_browser_harness() -> str:
    path = Path(__file__).resolve().parent / MOBILE_BROWSER_HARNESS_RELATIVE
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise ProbeFailure(f"mobile chat/Projects browser harness is unavailable: {type(error).__name__}") from None
    digest = hashlib.sha256(payload).hexdigest()
    if len(payload) > 20_000 or digest != MOBILE_BROWSER_HARNESS_SHA256:
        raise ProbeFailure("mobile chat/Projects harness size or pinned digest did not match")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise ProbeFailure("mobile chat/Projects harness is not UTF-8") from None
VIEWPORTS = (
    {"name": "phone", "width": 390, "height": 844, "mobile": True},
    {"name": "tablet", "width": 768, "height": 1024, "mobile": False},
    {"name": "desktop", "width": 1440, "height": 900, "mobile": False},
)
ALLOWED_API = {
    ("GET", "/chat/api/overview"),
    ("GET", "/chat/api/ecosystem"),
    ("GET", "/chat/api/settings"),
    ("GET", "/chat/api/conversations"),
    ("GET", "/chat/api/conversations/trash"),
    ("GET", f"/chat/api/conversations/{FIXTURE_CONVERSATION_ID}/messages"),
    ("GET", "/chat/api/conversations/ui-harness-chat/messages"),
    ("GET", f"/chat/api/conversations/{FIXTURE_CONVERSATION_ID}/model-settings"),
    ("GET", f"/chat/api/conversations/{FIXTURE_MODEL_CONVERSATION_ID}/model-settings"),
    ("GET", "/chat/api/conversations/ui-harness-chat/model-settings"),
    ("GET", f"/chat/api/second-brain/notes/{FIXTURE_NOTE_ID}"),
    ("GET", f"/chat/api/second-brain/notes/{FIXTURE_NOTE_ID}/links"),
    ("GET", "/chat/api/models/conversations"),
    ("GET", "/chat/api/projects"),
    ("GET", "/chat/api/projects/trash"),
    ("GET", "/chat/api/extensions"),
    ("GET", "/chat/api/profiles"),
    ("GET", "/chat/api/second-brain/overview"),
    ("GET", "/chat/api/second-brain/notes"),
    ("GET", "/chat/api/second-brain/search"),
    ("GET", "/chat/api/second-brain/graph"),
    ("GET", "/chat/api/capabilities"),
    ("GET", "/chat/api/native-capabilities"),
    ("GET", "/chat/api/resources/learning"),
}
FIXTURE_OVERVIEW = {
    "core": {
        "status": "process-observed", "readiness": "current-core-witness",
        "observedAt": "2026-10-11T12:00:00Z", "version": None,
        "resourcesState": "pending", "resourceCounts": None,
        "resourcesRevision": None, "discoveryObservedAt": None,
        "activePromptMatchesBundledPrimary": None,
    },
    "chat": {
        "conversationCount": 1,
        "turnCounts": {"total": 0, "completed": 0, "failed": 0, "cancelled": 0, "active": 0},
        "lastTurnAt": None,
        "turnCountsByDay": [
            {"date": f"2026-10-{day:02d}", "total": 0, "completed": 0, "failed": 0, "cancelled": 0}
            for day in range(5, 12)
        ],
        "statistics": {
            "window": {
                "startAt": "2026-10-05T00:00:00Z", "endAt": "2026-10-11T12:00:00Z",
                "timezone": "UTC",
                "basis": "turn accepted during the seven UTC calendar days ending at observation time",
            },
            "observedAt": "2026-10-11T12:00:00Z",
            "turnCounts": {"total": 0, "active": 0, "completed": 0, "failed": 0, "cancelled": 0, "unknown": 0},
            "duration": {
                "basis": "turn accepted to terminal status; elapsed time includes queue time",
                "sampleLimit": 100, "partial": False, "omittedCount": 0, "samples": [],
            },
        },
    },
    "missions": {"state": "unavailable", "approvedPendingCount": None,
                 "reason": "No mission records are included in this visual fixture."},
    "schedules": {"state": "unavailable", "pausedCount": None,
                  "reason": "No schedule records are included in this visual fixture."},
    "resources": {
        "discovery": {"state": "pending", "observedAt": None, "counts": None},
        "dispatch": {"state": "unavailable", "count": None,
                      "reason": "No dispatched identities are included in this visual fixture."},
    },
    "capabilities": {"readiness": "pending", "bundledSkills": 396,
                      "bundledProfiles": 208, "bundledInternalProfiles": 207,
                      "discoveryState": "pending", "discoveredResourceCounts": None},
}


def _refresh_fixture_observation_time() -> None:
    """Use one synthetic current observation per run so the native idle state is verified."""
    observed = datetime.now(timezone.utc).replace(microsecond=0)
    observed_text = observed.isoformat(timespec="seconds").replace("+00:00", "Z")
    start = (observed.replace(hour=0, minute=0, second=0) - timedelta(days=6))
    chat = FIXTURE_OVERVIEW["chat"]
    chat["turnCountsByDay"] = [
        {"date": (start + timedelta(days=offset)).date().isoformat(),
         "total": 0, "completed": 0, "failed": 0, "cancelled": 0}
        for offset in range(7)
    ]
    statistics = chat["statistics"]
    statistics["window"]["startAt"] = start.isoformat(timespec="seconds").replace("+00:00", "Z")
    statistics["window"]["endAt"] = observed_text
    statistics["observedAt"] = observed_text
    FIXTURE_OVERVIEW["core"]["observedAt"] = observed_text
    FIXTURE_ECOSYSTEM["observation"]["observed_at"] = observed_text
    FIXTURE_ECOSYSTEM["observation"]["window"]["to"] = observed_text
FIXTURE_CONVERSATIONS = {"conversations": [{"id": FIXTURE_CONVERSATION_ID, "title": FIXTURE_TITLE}]}
FIXTURE_MESSAGES = {"messages": []}
FIXTURE_ECOSYSTEM = {
    "schema": 2,
    "observation": {"state": "quiet", "observed_at": "2026-10-12T00:00:00Z",
                    "window": {"from": "2026-10-05T00:00:00Z", "to": "2026-10-12T00:00:00Z",
                               "seconds": 604800}, "coverage": "observed-callbacks", "partial": False},
    "summary": {"observed_instances": 0, "active_instances": 0, "observed_active_instances": 0,
                "completed_executions": 0, "observed_completed_executions": 0,
                "observed_tool_calls": 0, "response_duration_ms": None,
                "response_duration_coverage": 0, "event_summaries": 0, "unknown_fields": []},
    "instances": [], "teams": [], "relations": [],
    "pending": {"team_membership": "no_verified_instance_join",
                "communication_edges": "no_verified_sender_recipient_records"},
}
FIXTURE_PROJECTS = {
    "projects": [{"id": FIXTURE_PROJECT_ID, "title": "Fixture project",
                  "instructions": "Synthetic review fixture.", "sharedMemory": "",
                  "obsidianNoteIds": [], "version": 1, "chats": []}]
}
FIXTURE_MODEL_CONVERSATIONS = {"conversations": [{
    "id": FIXTURE_MODEL_CONVERSATION_ID, "title": "Synthetic model-settings fixture"
}]}
FIXTURE_PROFILES_VALID = {"profiles": [{
    "id": "a" * 64, "name": "Synthetic Jarvis profile", "kind": "jarvis",
    "sourceGeneration": "fixture-generation-only",
    "files": [{"kind": "soul", "name": "SOUL.md", "editable": True}],
}]}
FIXTURE_PROFILES_INVALID_EMPTY = {"profiles": []}
PROFILE_ROUTE_CALLS = 0
FIXTURE_API_BODIES = {
    "/chat/api/second-brain/overview": {
        "noteCount": 2, "linkCount": 1, "unresolvedLinkCount": 0, "draftCount": 0,
        "coverage": {"scanned": 2, "limit": 2, "partial": False},
        "state": "fixture", "observedAt": None,
    },
    "/chat/api/second-brain/notes": {"notes": [
        {"noteId": FIXTURE_NOTE_ID, "title": "Fixture note alpha", "tags": ["review"],
         "updatedAt": "2026-10-11T12:00:00Z", "excerpt": "Synthetic only."},
        {"noteId": FIXTURE_NOTE_LINK_ID, "title": "Fixture note beta", "tags": ["planning"],
         "updatedAt": "2026-10-11T12:00:00Z", "excerpt": "No vault is read."},
    ], "nextCursor": None},
    "/chat/api/second-brain/search": {"notes": [
        {"noteId": FIXTURE_NOTE_ID, "title": "Fixture note alpha", "tags": ["review"],
         "updatedAt": "2026-10-11T12:00:00Z", "excerpt": "Synthetic only."},
    ], "nextCursor": None},
    "/chat/api/second-brain/graph": {
        "nodes": [
            {"noteId": FIXTURE_NOTE_ID, "title": "Fixture note alpha", "tags": ["review"]},
            {"noteId": FIXTURE_NOTE_LINK_ID, "title": "Fixture note beta", "tags": ["planning"]},
        ],
        "edges": [{"fromNoteId": FIXTURE_NOTE_ID, "toNoteId": FIXTURE_NOTE_LINK_ID,
                   "kind": "wikilink", "label": "Fixture link"}],
        "unresolved": [], "partial": False,
    },
    "/chat/api/capabilities": {},
    "/chat/api/native-capabilities": {},
    "/chat/api/resources/learning": {},
}


class ProbeFailure(RuntimeError):
    pass


def _headers() -> dict[str, str]:
    return {
        "Cache-Control": "no-store",
        "Content-Security-Policy": (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; "
            "media-src 'none'; object-src 'none'; frame-src 'none'; base-uri 'self'; "
            "form-action 'self'"
        ),
        "Permissions-Policy": (
            "microphone=(), camera=(), geolocation=(), display-capture=(), "
            "usb=(), bluetooth=()"
        ),
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Hermes-Evidence-Class": "local-visual-fixture-only",
    }


def _authenticated(request: web.Request) -> bool:
    expected = request.app["fixture_cookie"]
    return request.cookies.get(COOKIE_NAME) == expected


async def _fixture_route(request: web.Request) -> web.StreamResponse:
    if request.remote != "127.0.0.1":
        raise web.HTTPForbidden(text="loopback fixture only", headers=_headers())

    path = request.path
    if request.method == "GET" and path in ASSET_PATHS:
        if path == "/chat":
            try:
                content_type, body = request.app["asset_getter"](path)
            except (KeyError, TypeError, ValueError):
                raise web.HTTPNotFound(text="reviewed asset unavailable", headers=_headers()) from None
            response = web.Response(body=body, content_type=content_type.split(";", 1)[0], headers=_headers())
            response.headers["Content-Type"] = content_type
            response.set_cookie(
                COOKIE_NAME, request.app["fixture_cookie"], httponly=True,
                secure=False, samesite="Strict", path="/", max_age=900,
            )
            return response
        if not _authenticated(request):
            raise web.HTTPUnauthorized(text="fixture session required", headers=_headers())
        try:
            content_type, body = request.app["asset_getter"](path)
        except (KeyError, TypeError, ValueError):
            raise web.HTTPNotFound(text="reviewed asset unavailable", headers=_headers()) from None
        response = web.Response(body=body, content_type=content_type.split(";", 1)[0], headers=_headers())
        response.headers["Content-Type"] = content_type
        return response

    if path == "/favicon.ico" and request.method == "GET":
        return web.Response(status=204, headers=_headers())

    if path.startswith("/chat/api/"):
        if not _authenticated(request):
            raise web.HTTPUnauthorized(text="fixture session required", headers=_headers())
        if (request.method, path) not in ALLOWED_API:
            request.app["unexpected_api"].append({"method": request.method, "path": path})
            return web.json_response({"error": "outside finite visual fixture"}, status=404, headers=_headers())
        request.app["fixture_requests"].append({"method": request.method, "path": path})
        if path == "/chat/api/overview":
            return web.json_response(FIXTURE_OVERVIEW, headers=_headers())
        if path == "/chat/api/ecosystem":
            return web.json_response(FIXTURE_ECOSYSTEM, headers=_headers())
        if path == "/chat/api/settings":
            # Settings labels remain explicitly unverified in this local fixture.
            return web.json_response({"provider": None, "model": None, "coreVersion": None}, headers=_headers())
        if path == "/chat/api/conversations":
            return web.json_response(FIXTURE_CONVERSATIONS, headers=_headers())
        if path == "/chat/api/models/conversations":
            return web.json_response(FIXTURE_MODEL_CONVERSATIONS, headers=_headers())
        if path == "/chat/api/projects":
            return web.json_response(FIXTURE_PROJECTS, headers=_headers())
        if path == "/chat/api/projects/trash":
            return web.json_response({"projects": [{"id": "fixture-trashed-project",
                "title": "Retained fixture project", "version": 2}]}, headers=_headers())
        if path == "/chat/api/extensions":
            return web.json_response({"schema": 1, "revision": "fixture-revision",
                "readiness": "pending", "items": []}, headers=_headers())
        if path == "/chat/api/profiles":
            global PROFILE_ROUTE_CALLS
            PROFILE_ROUTE_CALLS += 1
            body = (FIXTURE_PROFILES_INVALID_EMPTY if PROFILE_ROUTE_CALLS == 1
                    else FIXTURE_PROFILES_VALID)
            return web.json_response(body, headers=_headers())
        if path == f"/chat/api/second-brain/notes/{FIXTURE_NOTE_ID}":
            return web.json_response({"noteId": FIXTURE_NOTE_ID,
                "title": "Fixture note alpha", "markdown": "Synthetic fixture text only.",
                "updatedAt": "2026-10-11T12:00:00Z", "contentSha256": FIXTURE_CONTENT_SHA256}, headers=_headers())
        if path == f"/chat/api/second-brain/notes/{FIXTURE_NOTE_ID}/links":
            return web.json_response({"links": [{"toNoteId": FIXTURE_NOTE_LINK_ID,
                "kind": "wikilink", "label": "Fixture note beta"}], "backlinks": [],
                "unresolved": []}, headers=_headers())
        if path == "/chat/api/conversations/trash":
            return web.json_response({"conversations": []}, headers=_headers())
        if path in {
            f"/chat/api/conversations/{FIXTURE_CONVERSATION_ID}/model-settings",
            f"/chat/api/conversations/{FIXTURE_MODEL_CONVERSATION_ID}/model-settings",
            "/chat/api/conversations/ui-harness-chat/model-settings",
        }:
            return web.json_response(
                {"error": "fixture-only probe has no account or model-settings observation"},
                status=503, headers=_headers(),
            )
        if path.endswith("/messages"):
            return web.json_response(FIXTURE_MESSAGES, headers=_headers())
        if path in FIXTURE_API_BODIES:
            return web.json_response(FIXTURE_API_BODIES[path], headers=_headers())

    request.app["unexpected_paths"].append({"method": request.method, "path": path})
    return web.Response(status=404, text="outside visual probe allowlist", headers=_headers())


class DevTools:
    def __init__(self, websocket: Any):
        self.websocket = websocket
        self.command_id = 0

    async def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.command_id += 1
        current = self.command_id
        await self.websocket.send_json({"id": current, "method": method, "params": params or {}})
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                message = await self.websocket.receive(timeout=max(0.1, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                break
            if message.type == WSMsgType.TEXT:
                payload = json.loads(message.data)
                if payload.get("id") != current:
                    continue
                if "error" in payload:
                    raise ProbeFailure(f"Chromium DevTools {method} failed: {payload['error']}")
                return payload.get("result", {})
            if message.type in {WSMsgType.CLOSED, WSMsgType.CLOSE, WSMsgType.ERROR}:
                raise ProbeFailure("Chromium DevTools connection closed")
        raise ProbeFailure(f"timed out waiting for Chromium DevTools method {method}")

    async def evaluate(self, expression: str, *, label: str) -> Any:
        result = await self.call("Runtime.evaluate", {
            "expression": expression,
            "awaitPromise": True,
            "returnByValue": True,
            "userGesture": True,
        })
        if "exceptionDetails" in result:
            exception = result["exceptionDetails"]
            parts = [f"CDP Runtime.evaluate failed during {label}"]
            text = exception.get("text")
            if text:
                parts.append(str(text))
            value = exception.get("exception") or {}
            description = value.get("description")
            if description:
                parts.append(str(description)[:2400])
            elif "value" in value:
                parts.append(f"value={value['value']!r}"[:600])
            line = exception.get("lineNumber")
            column = exception.get("columnNumber")
            if isinstance(line, int) or isinstance(column, int):
                parts.append(f"expression location: line {line + 1 if isinstance(line, int) else '?'} "
                             f"column {column + 1 if isinstance(column, int) else '?'}")
            frames = (exception.get("stackTrace") or {}).get("callFrames") or []
            for frame in frames[:6]:
                function = frame.get("functionName") or "<anonymous>"
                url = frame.get("url") or "<inline expression>"
                frame_line = frame.get("lineNumber")
                frame_column = frame.get("columnNumber")
                parts.append(
                    f"  at {function} ({url}:{frame_line + 1 if isinstance(frame_line, int) else '?'}:"
                    f"{frame_column + 1 if isinstance(frame_column, int) else '?'})"
                )
            raise ProbeFailure("\n".join(parts))
        return result.get("result", {}).get("value")


async def _wait_for_chromium(chromium: Path, profile: Path) -> tuple[asyncio.subprocess.Process, int]:
    args = [
        str(chromium), "--headless=new", "--remote-debugging-address=127.0.0.1",
        "--remote-debugging-port=0", f"--user-data-dir={profile}",
        "--no-first-run", "--no-default-browser-check", "--disable-background-networking",
        "--disable-component-update", "--disable-sync", "--disable-extensions",
        "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1",
        "about:blank",
    ]
    process = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
        env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(profile),
             "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
        start_new_session=True,
    )
    active_port = profile / "DevToolsActivePort"
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if process.returncode is not None:
            await _abort_chromium(process, f"Chromium exited before DevTools was ready (status {process.returncode})")
        try:
            lines = active_port.read_text(encoding="ascii").splitlines()
            port = int(lines[0])
            if not 1 <= port <= 65535:
                raise ValueError
            return process, port
        except (FileNotFoundError, OSError, ValueError, IndexError):
            await asyncio.sleep(0.1)
    await _abort_chromium(process, "Chromium DevTools did not become ready within 15 seconds")


async def _abort_chromium(process: asyncio.subprocess.Process, reason: str) -> None:
    try:
        await _stop_chromium(process)
    except Exception as error:
        failure = ProbeFailure(f"{reason}; Chromium shutdown is incomplete and its profile is retained: {error}")
        failure.retain_profile = True
        raise failure from None
    raise ProbeFailure(reason)


async def _stop_chromium(process: asyncio.subprocess.Process) -> None:
    """Stop only the dedicated Chromium process group and wait for it to disappear."""
    process_group = process.pid
    try:
        os.killpg(process_group, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        try:
            os.killpg(process_group, signal.SIGKILL)
        except ProcessLookupError:
            pass
        await asyncio.wait_for(process.wait(), timeout=5)
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        try:
            os.killpg(process_group, 0)
        except ProcessLookupError:
            return
        await asyncio.sleep(0.1)
    try:
        os.killpg(process_group, signal.SIGKILL)
    except ProcessLookupError:
        return
    raise ProbeFailure("Chromium process group remained after bounded shutdown; profile retained")


def _remove_owned_profile(path: Path) -> None:
    """Retry cleanup only for the unique temporary directory created by this run."""
    last_error: OSError | None = None
    for attempt in range(20):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            last_error = error
            if attempt < 19:
                time.sleep(0.1)
    raise ProbeFailure(f"could not remove this run's temporary Chromium profile: {last_error}")


async def _devtools_target(session: ClientSession, port: int) -> tuple[Any, str]:
    endpoint = f"http://127.0.0.1:{port}"
    async with session.put(f"{endpoint}/json/new?about:blank") as response:
        if response.status != 200:
            raise ProbeFailure(f"Chromium refused a local DevTools target (HTTP {response.status})")
        target = await response.json()
    websocket = await session.ws_connect(target["webSocketDebuggerUrl"], heartbeat=10)
    return websocket, target["id"]


async def _wait_ready(devtools: DevTools) -> dict[str, Any]:
    expression = """(async()=>{
      const end=Date.now()+15000;
      while(Date.now()<end){
        const state=document.querySelector('#connection-state')?.dataset.state;
        const title=document.querySelector('#conversation-title')?.textContent?.trim();
        if(state==='ready'&&title===%s)return {ready:true,state,title};
        await new Promise(r=>setTimeout(r,100));
      }
      return {ready:false,state:document.querySelector('#connection-state')?.dataset.state||null,
        title:document.querySelector('#conversation-title')?.textContent?.trim()||null};
    })()""" % json.dumps(FIXTURE_TITLE)
    value = await devtools.evaluate(expression, label="initial authenticated fixture hydration")
    if not isinstance(value, dict) or not value.get("ready"):
        raise ProbeFailure(f"Jarvis did not hydrate the authenticated fixture: {value!r}")
    return value


async def _wait_overview_fixture(devtools: DevTools) -> None:
    expression = """(async()=>{
      const end=Date.now()+5000;
      while(Date.now()<end){
        const root=document.querySelector('[data-feature-root="overview"]');
        const nativeStatus=root?.querySelector('[data-core-status]')?.textContent?.trim();
        const legacyStatus=document.querySelector('#core-status')?.textContent?.trim();
        const observation=root?.querySelector('[data-observation]')?.textContent?.trim();
        const ready=root
          ? Boolean(nativeStatus&&observation&&observation.startsWith('Owner activity updated'))
          : Boolean(legacyStatus&&legacyStatus!=='Loading…');
        if(ready)return {ready:true,contract:root?'overview-feature-assets':'legacy-overview',status:nativeStatus||legacyStatus,observation};
        await new Promise(r=>setTimeout(r,50));
      }
      return {ready:false,status:document.querySelector('[data-feature-root="overview"] [data-core-status],#core-status')?.textContent?.trim()||null};
    })()"""
    value = await devtools.evaluate(expression, label="overview fixture rendering")
    if not isinstance(value, dict) or not value.get("ready"):
        raise ProbeFailure(f"overview fixture did not render before timeout: {value!r}")


async def _probe_central_motion(devtools: DevTools, session: ClientSession,
                                devtools_port: int) -> dict[str, Any]:
    """Exercise device/local motion precedence and stage visibility using the visible UI."""
    expression = NATIVE_INTERSECTION_HELPER + """(async()=>{
      const includeStageIntersection=%s;
      const operationDeadline=performance.now()+8000;
      const stageIdentity=document.querySelector('[data-feature-root="overview"] .overview-stage');
      const captureStageContext=()=>{
        const nodes=[];for(let node=stageIdentity;node;node=node.parentElement)nodes.push(node);
        const scrolling=document.scrollingElement;if(scrolling&&!nodes.includes(scrolling))nodes.push(scrolling);
        return {target:document.querySelector('[data-feature-root="overview"] .overview-stage'),
          targetCount:document.querySelectorAll('[data-feature-root="overview"] .overview-stage').length,
          view:document.querySelector('.workspace')?.dataset.currentView||null,
          documentVisibility:document.visibilityState,viewport:{width:innerWidth,height:innerHeight},nodes,
          scrolls:nodes.map(node=>({top:node.scrollTop,left:node.scrollLeft}))};
      };
      const sameStageContext=(a,b)=>Boolean(a&&b&&a.targetCount===1&&b.targetCount===1
        &&a.target===stageIdentity&&b.target===stageIdentity
        &&a.target===b.target&&a.view===b.view&&a.documentVisibility===b.documentVisibility
        &&a.viewport.width===b.viewport.width&&a.viewport.height===b.viewport.height
        &&a.nodes.length===b.nodes.length&&a.nodes.every((node,index)=>node===b.nodes[index]
          &&a.scrolls[index].top===b.scrolls[index].top&&a.scrolls[index].left===b.scrolls[index].left));
      const serializableStageContext=context=>({view:context.view,documentVisibility:context.documentVisibility,
        viewport:context.viewport,scrolls:context.nodes.map((node,index)=>({tag:node.tagName.toLowerCase(),
          id:node.id||null,className:typeof node.className==='string'?node.className:null,
          top:context.scrolls[index].top,left:context.scrolls[index].left}))});
      const stagePaintVisible=stage=>{
        if(!(stage instanceof Element))return false;
        for(let node=stage;node;node=node.parentElement){
          const style=getComputedStyle(node),opacity=Number.parseFloat(style.opacity);
          if(!node.isConnected||node.hidden||style.display==='none'||style.visibility==='hidden'
            ||style.visibility==='collapse'||!Number.isFinite(opacity)||opacity<=0
            ||style.contentVisibility==='hidden')return false;
        }
        return true;
      };
      const read=async(reserveMs=0)=>{
        const contextBefore=captureStageContext();
        const legacy=document.querySelector('#jarvis-presence');
        const stage=document.querySelector('[data-feature-root="overview"] .overview-stage');
        const stageCount=document.querySelectorAll('[data-feature-root="overview"] .overview-stage').length;
        const nativeStageRead=includeStageIntersection
          ? (stage===stageIdentity&&stageCount===1?await observeNativeIntersections([stage],operationDeadline,reserveMs)
            : {ok:false,reason:'target-changed'}) : null;
        const central=[...document.querySelectorAll(
          '#jarvis-presence .presence-orbit-inner,#jarvis-presence .presence-orbit-dial,'+
          '#jarvis-presence .presence-core,[data-feature-root="overview"] .reactor-orbit-inner,'+
          '[data-feature-root="overview"] .reactor-dial,[data-feature-root="overview"] .reactor-core')];
        const targets=central.map(el=>{
          const style=getComputedStyle(el),rect=el.getBoundingClientRect();
          const animations=el.getAnimations().map(item=>({name:item.animationName||null,state:item.playState,
            duration:item.effect?.getComputedTiming?.().duration??null}));
          return {selector:el.id?'#'+el.id:el.classList?.length?'.'+[...el.classList].join('.'):el.tagName.toLowerCase(),
            animationName:style.animationName,animationPlayState:style.animationPlayState,
            animationDuration:style.animationDuration,transform:style.transform,opacity:style.opacity,
            visible:style.display!=='none'&&style.visibility!=='hidden'&&rect.width>0&&rect.height>0&&rect.right>0&&rect.bottom>0&&rect.left<innerWidth&&rect.top<innerHeight,
            animations};
        });
        const hud=document.querySelector('.assistant-hud .orb-halo');
        const hudStyle=hud?getComputedStyle(hud):null;
        const state=legacy?legacy.dataset.state:stage?.dataset.activity||null;
        const connected=legacy?legacy.dataset.connection==='ready':stage?.dataset.coreState==='verified';
        const quiet=legacy?legacy.dataset.state==='idle':stage?.dataset.activity==='quiet';
        const stageRect=stage?.getBoundingClientRect();
        const stageRunning=stage?document.getAnimations().filter(item=>item.playState==='running'
          &&item.effect?.target instanceof Element&&stage.contains(item.effect.target)).map(item=>({name:item.animationName||null,
            duration:item.effect?.getComputedTiming?.().duration??null})):[];
        const contextAfter=captureStageContext();
        const stageEntry=nativeStageRead?.ok?nativeStageRead.records[0]:null;
        const stagePaintVisibleValue=stagePaintVisible(stage);
        return {documentVisibility:document.visibilityState,pageVisibleAttribute:document.documentElement.dataset.pageVisible||null,
          prefersReduced:matchMedia('(prefers-reduced-motion: reduce)').matches,
          motionPreference:document.documentElement.dataset.jarvisMotion||null,
          sectionPageVisibleAttribute:legacy?.dataset.pageVisible||null,intersection:legacy?.dataset.inViewport||null,
          overviewStageInViewport:stage?.dataset.inViewport||null,
          overviewStageGeometry:stageRect?{top:stageRect.top,bottom:stageRect.bottom,left:stageRect.left,right:stageRect.right,
            intersectsViewport:stageRect.width>0&&stageRect.height>0&&stageRect.bottom>0&&stageRect.top<innerHeight&&stageRect.right>0&&stageRect.left<innerWidth}:null,
          overviewStagePaintVisible:stagePaintVisibleValue,
          overviewStageNativeIntersection:stageEntry,
          overviewStageNativeRead:{ok:Boolean(nativeStageRead?.ok),reason:nativeStageRead?.reason||null},
          overviewStageContextStableDuringRead:sameStageContext(contextBefore,contextAfter),
          overviewStageContext:{before:serializableStageContext(contextBefore),
            after:serializableStageContext(contextAfter)},
          stageInternal:{before:contextBefore,after:contextAfter,target:stage},
          overviewStageRunningAnimations:stageRunning,
          navigatorOnline:navigator.onLine,centralState:state,connectionReady:connected,quiet,
          centralVisible:targets.some(item=>item.visible),targets,
          hud:{animationName:hudStyle?.animationName||'none',animationPlayState:hudStyle?.animationPlayState||'idle',
            transform:hudStyle?.transform||'none',opacity:hudStyle?.opacity||null},
          allRunningAnimations:document.getAnimations().filter(item=>item.playState==='running').map(item=>({
            name:item.animationName||null,duration:item.effect?.getComputedTiming?.().duration??null}))};
      };
      const first=await read(includeStageIntersection?350:0);
      await new Promise(resolve=>setTimeout(resolve,240));
      const second=await read(includeStageIntersection?75:0);
      const changedTargets=first.targets.filter((item,index)=>{
        const next=second.targets[index];
        return next&&item.visible&&next.visible&&item.transform!==next.transform;
      }).map(item=>item.selector);
      const changedAnyTargets=first.targets.filter((item,index)=>{
        const next=second.targets[index];return next&&item.transform!==next.transform;
      }).map(item=>item.selector);
      // CSS animations may attach between the first layout read and the second
      // animation-frame interval. Accept a real running animation from either
      // sample, while retaining the independent transform-change requirement.
      const centralRunning=[...new Set([first,second].flatMap(sample=>sample.targets
        .filter(item=>item.visible&&item.animations.some(animation=>animation.state==='running'
          &&(animation.duration===null||animation.duration>0.001))).map(item=>item.selector)))];
      const allRunning=first.allRunningAnimations.filter(item=>item.duration===null||item.duration>0.001);
      const stageContextSameAcrossSamples=includeStageIntersection
        &&sameStageContext(first.stageInternal.after,second.stageInternal.before)
        &&sameStageContext(first.stageInternal.after,second.stageInternal.after);
      const stageIOEntryUsable=entry=>Boolean(entry&&entry.intersectionRect&&entry.rootBounds&&entry.boundingClientRect);
      const stageOffscreenAtSample=sample=>Boolean(sample.overviewStageNativeRead?.ok
        &&stageIOEntryUsable(sample.overviewStageNativeIntersection)
        &&(sample.overviewStageNativeIntersection.intersectionRect.width===0
          ||sample.overviewStageNativeIntersection.intersectionRect.height===0)
        &&sample.overviewStageNativeIntersection.isIntersecting===false
        &&sample.overviewStageInViewport==='false'&&sample.overviewStagePaintVisible
        &&sample.documentVisibility==='visible');
      const stageGeometryQualified=Boolean(includeStageIntersection&&first.overviewStageContextStableDuringRead
        &&second.overviewStageContextStableDuringRead&&stageContextSameAcrossSamples
        &&first.stageInternal.after.targetCount===1&&second.stageInternal.after.targetCount===1
        &&first.stageInternal.after.view==='overview'&&second.stageInternal.after.view==='overview'
        &&first.overviewStageInViewport!==null&&second.overviewStageInViewport!==null);
      const overviewStageOffscreenQualified=Boolean(stageGeometryQualified
        &&stageOffscreenAtSample(first)&&stageOffscreenAtSample(second));
      const overviewStageOffscreenStopped=Boolean(overviewStageOffscreenQualified
        &&!first.overviewStageRunningAnimations.length&&!second.overviewStageRunningAnimations.length
        &&!changedAnyTargets.length);
      const {stageInternal:firstInternal,...firstReport}=first;
      const {stageInternal:secondInternal,...secondReport}=second;
      return {first:firstReport,second:secondReport,centralRunning,changedTargets,changedAnyTargets,allRunningAnimations:allRunning,
        centralMotionAdvanced:changedTargets.length>0,stageContextSameAcrossSamples,
        overviewStageOffscreenQualified,overviewStageOffscreenStopped,
        offscreenQualificationReason:!includeStageIntersection?'not-requested':
          (!stageGeometryQualified?'geometry-context-changed-or-unavailable':
          (!overviewStageOffscreenQualified?'native-intersection-or-product-marker-disagreement':
          (overviewStageOffscreenStopped?'qualified-and-stopped':'stage-motion-did-not-stop')))};
    })()"""

    async def sample(label: str, *, offscreen_pair: bool = False) -> dict[str, Any]:
        value = await devtools.evaluate(expression % json.dumps(offscreen_pair), label=label)
        if not isinstance(value, dict):
            raise ProbeFailure(f"could not measure central animation during {label}")
        return value

    async def set_local_motion(value: str, label: str) -> dict[str, Any]:
        await _select_view(devtools, "system", '[data-view="settings"]', "settings")
        selected = await devtools.evaluate("""(()=>{
          const control=document.querySelector('#settings-view #ui-motion');
          if(!(control instanceof HTMLSelectElement)||!control.getClientRects().length)return null;
          control.value=%s;control.dispatchEvent(new Event('change',{bubbles:true}));
          return {control:control.value,applied:document.documentElement.dataset.jarvisMotion||null};
        })()""" % json.dumps(value), label=f"select Motion={value} in Settings ({label})")
        if not isinstance(selected, dict) or selected.get("control") != value or selected.get("applied") != value:
            raise ProbeFailure(f"Settings did not apply the requested fixture motion preference: {selected!r}")
        await _select_view(devtools, "command-centre", '[data-view="overview"]', "overview")
        await _wait_overview_fixture(devtools)
        visible = await devtools.evaluate("""(async()=>{
          const end=Date.now()+1500;const stage=document.querySelector('[data-feature-root="overview"] .overview-stage');
          while(Date.now()<end&&stage?.dataset.inViewport!=='true')await new Promise(resolve=>setTimeout(resolve,25));
          const r=stage?.getBoundingClientRect();return {inViewport:stage?.dataset.inViewport||null,
            intersects:Boolean(r&&r.bottom>0&&r.top<innerHeight&&r.right>0&&r.left<innerWidth)};
        })()""", label=f"wait for Overview visible after Motion={value} ({label})")
        if not isinstance(visible, dict) or visible.get("inViewport") != "true" or not visible.get("intersects"):
            raise ProbeFailure(f"Overview did not return to the viewport after Settings: {visible!r}")
        return {**selected, **visible}

    async def scroll_stage_out() -> dict[str, Any]:
        value = await devtools.evaluate(NATIVE_INTERSECTION_HELPER + """(async()=>{
          const operationDeadline=performance.now()+8000;
          const stage=document.querySelector('[data-feature-root="overview"] .overview-stage');
          if(!stage||document.querySelectorAll('[data-feature-root="overview"] .overview-stage').length!==1)
            return {ok:false,reason:'overview stage missing or non-unique'};
          stage.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
          const candidates=[];let node=stage.parentElement;
          while(node){const style=getComputedStyle(node);
            if(['auto','scroll','hidden'].includes(style.overflowY)&&node.scrollHeight>node.clientHeight+8)candidates.push(node);
            node=node.parentElement;}
          const root=document.scrollingElement;if(root&&root.scrollHeight>root.clientHeight+8&&!candidates.includes(root))candidates.push(root);
      const describe=(target)=>({tag:target.tagName,id:target.id||null,
            className:typeof target.className==='string'?target.className:null,
            scrollTop:target.scrollTop,scrollHeight:target.scrollHeight,clientHeight:target.clientHeight,
            maxScrollTop:Math.max(0,target.scrollHeight-target.clientHeight)});
          const paintVisible=target=>{
            if(!(target instanceof Element))return false;
            for(let node=target;node;node=node.parentElement){
              const style=getComputedStyle(node),opacity=Number.parseFloat(style.opacity);
              if(!node.isConnected||node.hidden||style.display==='none'||style.visibility==='hidden'
                ||style.visibility==='collapse'||!Number.isFinite(opacity)||opacity<=0
                ||style.contentVisibility==='hidden')return false;
            }
            return true;
          };
          const readIntersection=async()=>{
            const read=await observeNativeIntersections([stage],operationDeadline,350);
            if(!read.ok)return {ok:false,reason:read.reason||'native-io-unqualified'};
            const entry=read.records[0];
            return {ok:true,entry,zeroArea:entry.intersectionRect.width===0||entry.intersectionRect.height===0,
              fullyOutside:entry.intersectionRect.width===0||entry.intersectionRect.height===0
                ?entry.isIntersecting===false:false,
              paintVisible:paintVisible(stage),marker:stage.dataset.inViewport||null,
              documentVisibility:document.visibilityState};
          };
          let lastIntersection=null;
          for(const target of candidates){target.scrollTop=target.scrollHeight;
            await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
            const rect=stage.getBoundingClientRect();
            lastIntersection=await readIntersection();
            if(document.querySelectorAll('[data-feature-root="overview"] .overview-stage').length!==1
              ||document.querySelector('[data-feature-root="overview"] .overview-stage')!==stage
              ||document.querySelector('.workspace')?.dataset.currentView!=='overview')
              return {ok:true,fullyOffscreen:false,scope:'unqualified',reason:'stage-or-view-changed-during-native-read',
                container:describe(target),stageInViewport:stage.dataset.inViewport||null,stageTop:rect.top,
                stageBottom:rect.bottom,viewportHeight:innerHeight,nativeIntersection:lastIntersection.entry||null};
            if(!lastIntersection.ok)return {ok:true,fullyOffscreen:false,scope:'unqualified',reason:lastIntersection.reason,
              container:describe(target),stageInViewport:stage.dataset.inViewport||null,stageTop:rect.top,
              stageBottom:rect.bottom,viewportHeight:innerHeight,nativeIntersection:null};
            if(lastIntersection.fullyOutside&&lastIntersection.marker==='false'&&lastIntersection.paintVisible
              &&lastIntersection.documentVisibility==='visible')
              return {ok:true,fullyOffscreen:true,scope:'applicable',container:describe(target),stageInViewport:stage.dataset.inViewport||null,
                stageTop:rect.top,stageBottom:rect.bottom,viewportHeight:innerHeight,
                nativeIntersection:lastIntersection.entry};}
          const rect=stage.getBoundingClientRect();
          if(!lastIntersection)lastIntersection=await readIntersection();
          if(document.querySelectorAll('[data-feature-root="overview"] .overview-stage').length!==1
            ||document.querySelector('[data-feature-root="overview"] .overview-stage')!==stage
            ||document.querySelector('.workspace')?.dataset.currentView!=='overview')
            return {ok:true,fullyOffscreen:false,scope:'unqualified',reason:'stage-or-view-changed-during-native-read',
              scrollableCandidates:candidates.map(describe),stageInViewport:stage.dataset.inViewport||null,
              stageTop:rect.top,stageBottom:rect.bottom,viewportHeight:innerHeight,
              nativeIntersection:lastIntersection.entry||null};
          if(!lastIntersection.ok)return {ok:true,fullyOffscreen:false,scope:'unqualified',
            reason:lastIntersection.reason||'native intersection unavailable',
            scrollableCandidates:candidates.map(describe),stageInViewport:stage.dataset.inViewport||null,
            stageTop:rect.top,stageBottom:rect.bottom,viewportHeight:innerHeight,nativeIntersection:null};
          const partial=lastIntersection.entry.isIntersecting===true
            &&lastIntersection.entry.intersectionRect.width>0&&lastIntersection.entry.intersectionRect.height>0
            &&lastIntersection.marker==='true'&&lastIntersection.paintVisible
            &&lastIntersection.documentVisibility==='visible';
          return {ok:true,fullyOffscreen:false,scope:partial?'not-applicable':'unqualified',
            reason:partial?(candidates.length?'maximum real scroll leaves Overview partially visible':'no scrollable container can move Overview fully outside the viewport')
              :'native intersection, product marker, or visible-document state disagrees',
            scrollableCandidates:candidates.map(describe),stageInViewport:stage.dataset.inViewport||null,
            stageTop:rect.top,stageBottom:rect.bottom,viewportHeight:innerHeight,
            stageStillIntersectsViewport:partial,nativeIntersection:lastIntersection.entry};
        })()""", label="scroll Overview stage outside the real viewport")
        if not isinstance(value, dict) or not value.get("ok"):
            raise ProbeFailure(f"could not scroll Overview offscreen for the visibility check: {value!r}")
        return value

    async def restore_stage_visible() -> dict[str, Any]:
        value = await devtools.evaluate("""(async()=>{
          const stage=document.querySelector('[data-feature-root="overview"] .overview-stage');
          if(!stage)return {inViewport:null,intersects:false};
          stage.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
          const end=Date.now()+1500;let r=stage.getBoundingClientRect();
          while(Date.now()<end&&(stage.dataset.inViewport!=='true'||r.bottom<=0||r.top>=innerHeight)){
            await new Promise(resolve=>setTimeout(resolve,25));r=stage.getBoundingClientRect();}
          return {inViewport:stage.dataset.inViewport||null,top:r.top,bottom:r.bottom,
            intersects:r.bottom>0&&r.top<innerHeight&&r.right>0&&r.left<innerWidth};
        })()""", label="restore the Overview stage to the visible viewport")
        if not isinstance(value, dict) or value.get("inViewport") != "true" or not value.get("intersects"):
            raise ProbeFailure(f"Overview stage did not restore to visible state: {value!r}")
        return value

    await devtools.call("Network.enable")
    await devtools.call("Network.emulateNetworkConditions", {
        "offline": False, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1,
    })
    await devtools.call("Emulation.setEmulatedMedia", {
        "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
    })
    try:
        full_preference = await set_local_motion("full", "OS reduced-motion precedence")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "reduce"}],
        })
        os_reduced_local_full = await sample("OS reduce with local Full selected")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
        })
        foreground = await sample("local Full with device motion allowed")
        offscreen_scroll = await scroll_stage_out()
        offscreen_label = ("local Full motion after Overview leaves viewport"
                           if offscreen_scroll.get("fullyOffscreen")
                           else "local Full motion after maximum Overview scroll (partial visibility)")
        offscreen = await sample(offscreen_label, offscreen_pair=True)
        restored_scroll = await restore_stage_visible()
        resumed = await sample("local Full motion after Overview returns to viewport")
        system_preference = await set_local_motion("system", "restore ephemeral fixture preference")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "reduce"}],
        })
        reduced = await sample("OS reduced-motion with local System selected")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
        })
        endpoint = f"http://127.0.0.1:{devtools_port}"
        async with session.put(f"{endpoint}/json/new?about:blank") as response:
            if response.status != 200:
                raise ProbeFailure(f"Chromium refused hidden-tab fixture (HTTP {response.status})")
            hidden_target = await response.json()
        hidden_target_id = str(hidden_target["id"])
        async with session.ws_connect(hidden_target["webSocketDebuggerUrl"], heartbeat=10) as hidden_ws:
            await DevTools(hidden_ws).call("Page.bringToFront")
        await asyncio.sleep(0.15)
        hidden = await sample("background-tab hidden-page motion stop")
        async with session.get(f"{endpoint}/json/close/{hidden_target_id}") as response:
            if response.status not in {200, 204}:
                raise ProbeFailure(f"Chromium refused hidden-tab fixture cleanup (HTTP {response.status})")
        hidden_target_id = None
        await asyncio.sleep(0.15)
        await devtools.call("Network.emulateNetworkConditions", {
            "offline": True, "latency": 0, "downloadThroughput": 0, "uploadThroughput": 0,
        })
        offline = await sample("offline motion stop")
    finally:
        active_error = sys.exception()
        restore_errors: list[str] = []
        if "hidden_target_id" in locals() and hidden_target_id is not None:
            endpoint = f"http://127.0.0.1:{devtools_port}"
            try:
                async with session.get(f"{endpoint}/json/close/{hidden_target_id}") as response:
                    if response.status not in {200, 204}:
                        restore_errors.append(f"hidden tab cleanup returned HTTP {response.status}")
            except Exception as error:
                restore_errors.append(f"hidden tab cleanup: {type(error).__name__}: {error}")
        try:
            await devtools.call("Network.emulateNetworkConditions", {
                "offline": False, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1,
            })
        except Exception as error:
            restore_errors.append(f"online-state restore: {type(error).__name__}: {error}")
        try:
            await devtools.call("Emulation.setEmulatedMedia", {
                "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
            })
        except Exception as error:
            restore_errors.append(f"motion-preference restore: {type(error).__name__}: {error}")
        if restore_errors:
            detail = "; ".join(restore_errors)
            if active_error is not None:
                active_error.add_note(f"Motion-state cleanup also reported: {detail}")
            else:
                raise ProbeFailure(f"motion-state cleanup failed: {detail}")

    foreground_ready = (
        foreground["first"]["documentVisibility"] == "visible"
        and foreground["first"]["pageVisibleAttribute"] == "true"
        and foreground["first"]["motionPreference"] == "full"
        and foreground["first"]["overviewStageInViewport"] == "true"
        and foreground["first"]["centralVisible"]
        and foreground["first"]["connectionReady"]
        and foreground["first"]["quiet"]
    )
    reduced_stopped = (
        reduced["first"]["documentVisibility"] == "visible"
        and reduced["first"]["prefersReduced"] is True
        and reduced["first"]["pageVisibleAttribute"] == "true"
        and reduced["first"]["motionPreference"] == "system"
        and not reduced["allRunningAnimations"]
        and not reduced["centralMotionAdvanced"]
    )
    os_reduce_full_stopped = (
        os_reduced_local_full["first"]["prefersReduced"] is True
        and os_reduced_local_full["first"]["motionPreference"] == "full"
        and os_reduced_local_full["first"]["overviewStageInViewport"] == "true"
        and not os_reduced_local_full["first"]["overviewStageRunningAnimations"]
        and not os_reduced_local_full["allRunningAnimations"]
        and not os_reduced_local_full["centralMotionAdvanced"]
    )
    overview_offscreen_stopped = (
        offscreen["first"]["documentVisibility"] == "visible"
        and offscreen["first"]["motionPreference"] == "full"
        and offscreen_scroll.get("fullyOffscreen") is True
        and offscreen_scroll.get("scope") == "applicable"
        and offscreen.get("overviewStageOffscreenQualified") is True
        and offscreen.get("overviewStageOffscreenStopped") is True
    )
    partial_stage_central_visible = (
        offscreen_scroll.get("fullyOffscreen") is False
        and offscreen_scroll.get("scope") == "not-applicable"
        and offscreen_scroll.get("stageStillIntersectsViewport") is True
        and offscreen["first"].get("centralVisible") is True
    )
    partial_overview_remains_active = (
        offscreen["first"]["documentVisibility"] == "visible"
        and offscreen["first"]["motionPreference"] == "full"
        and offscreen_scroll.get("fullyOffscreen") is False
        and offscreen_scroll.get("scope") == "not-applicable"
        and offscreen_scroll.get("stageStillIntersectsViewport") is True
        and offscreen["first"]["overviewStageInViewport"] == "true"
        and offscreen["first"].get("centralVisible") is True
        and bool(offscreen["centralRunning"])
        and offscreen["centralMotionAdvanced"]
    )
    overview_motion_resumed = (
        resumed["first"]["overviewStageInViewport"] == "true"
        and resumed["first"]["overviewStageGeometry"]["intersectsViewport"]
        and bool(resumed["centralRunning"])
        and resumed["centralMotionAdvanced"]
    )
    hidden_stopped = (
        hidden["first"]["documentVisibility"] == "hidden"
        and not hidden["centralMotionAdvanced"]
    )
    offline_stopped = (
        offline["first"]["navigatorOnline"] is False
        and not offline["centralMotionAdvanced"]
    )
    checks = {
        "foreground_idle_process_and_center_visible": foreground_ready,
        "settings_control_applied_local_full": full_preference.get("control") == "full" and full_preference.get("applied") == "full",
        "settings_control_restored_local_system": system_preference.get("control") == "system" and system_preference.get("applied") == "system",
        "central_idle_animation_running": bool(foreground["centralRunning"]),
        "central_transform_changes_between_samples": foreground["centralMotionAdvanced"],
        "reduced_motion_stops_all_animations": reduced_stopped,
        "OS_reduced_motion_overrides_local_Full": os_reduce_full_stopped,
        "overview_offscreen_motion_stops": overview_offscreen_stopped,
        "overview_partial_visible_motion_remains_active_when_full_offscreen_is_unavailable": (
            partial_overview_remains_active if partial_stage_central_visible else None
        ),
        "overview_motion_resumes_when_visible": overview_motion_resumed,
        "hidden_page_stops_central_motion": hidden_stopped,
        "offline_stops_central_motion": offline_stopped,
    }
    return {
        "sampling_interval_ms": 240,
        "fixture_state": "idle-or-quiet, connected, current synthetic observation; no active work or listening fabricated",
        "foreground": foreground,
        "reduced_motion": reduced,
        "local_full_os_reduced": os_reduced_local_full,
        "offscreen": offscreen,
        "offscreen_scroll": offscreen_scroll,
        "restored_scroll": restored_scroll,
        "resumed": resumed,
        "local_motion_setting_full": full_preference,
        "local_motion_setting_system_restored": system_preference,
        "hidden": hidden,
        "offline": offline,
        "checks": checks,
        "failures": [name for name, passed in checks.items() if passed is False],
    }


async def _probe_shared_header_motion(devtools: DevTools, session: ClientSession,
                                      devtools_port: int) -> dict[str, Any]:
    """Check the shared Chat header orb; Overview separately tests its reactor."""
    await _select_view(devtools, "system", '[data-view="settings"]', "settings")
    setting = await devtools.evaluate("""(()=>{
      const control=document.querySelector('#settings-view #ui-motion');
      if(!(control instanceof HTMLSelectElement)||!control.getClientRects().length)return null;
      control.value='full';control.dispatchEvent(new Event('change',{bubbles:true}));
      return {control:control.value,applied:document.documentElement.dataset.jarvisMotion||null};
    })()""", label="select local Full motion for shared header test")
    if not isinstance(setting, dict) or setting.get("control") != "full" or setting.get("applied") != "full":
        raise ProbeFailure(f"Settings did not apply local Full for shared header test: {setting!r}")
    await _select_view(devtools, "conversations", '[data-view="chat"]', "chat")

    async def sample(label: str) -> dict[str, Any]:
        value = await devtools.evaluate("""(async()=>{
          const hud=document.querySelector('#assistant-hud');
          if(!hud)return {present:false,legacyPresence:Boolean(document.querySelector('.jarvis-presence,#jarvis-presence'))};
          const rect=hud.getBoundingClientRect();
          const intersects=rect.width>0&&rect.height>0&&rect.bottom>0&&rect.top<innerHeight&&rect.right>0&&rect.left<innerWidth;
          const targets=[...hud.querySelectorAll('.orb-halo,.orb-ring,.orb-core')];
          const state=()=>({documentVisibility:document.visibilityState,
            workspaceView:document.querySelector('.workspace')?.dataset.currentView||null,
            pageVisible:document.documentElement.dataset.pageVisible||null,
            localMotion:document.documentElement.dataset.jarvisMotion||null,
            prefersReduced:matchMedia('(prefers-reduced-motion: reduce)').matches,
            assistantState:hud.dataset.state||null,intersects,
            animations:document.getAnimations().filter(item=>item.playState==='running'
              &&item.effect?.target instanceof Element&&hud.contains(item.effect.target))
              .map(item=>({name:item.animationName||null,duration:item.effect?.getComputedTiming?.().duration??null})),
            transforms:targets.map(el=>getComputedStyle(el).transform)});
          const first=state();await new Promise(resolve=>setTimeout(resolve,240));const second=state();
          return {present:true,legacyPresence:Boolean(document.querySelector('.jarvis-presence,#jarvis-presence')),
            first,second,transformAdvanced:first.transforms.some((value,index)=>value!==second.transforms[index])};
        })()""", label=label)
        if not isinstance(value, dict):
            raise ProbeFailure(f"could not measure shared Chat header during {label}")
        return value

    result: dict[str, Any] = {"settings": setting}
    hidden_target_id: str | None = None
    endpoint = f"http://127.0.0.1:{devtools_port}"
    try:
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "reduce"}],
        })
        reduced = await sample("shared Chat header with OS reduced motion and local Full")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
        })
        foreground = await sample("shared Chat header with local Full and device motion allowed")
        async with session.put(f"{endpoint}/json/new?about:blank") as response:
            if response.status != 200:
                raise ProbeFailure(f"Chromium refused hidden shared-header fixture (HTTP {response.status})")
            hidden_target = await response.json()
        hidden_target_id = str(hidden_target["id"])
        async with session.ws_connect(hidden_target["webSocketDebuggerUrl"], heartbeat=10) as hidden_ws:
            await DevTools(hidden_ws).call("Page.bringToFront")
        await asyncio.sleep(0.15)
        hidden = await sample("shared Chat header after the document becomes hidden")
        async with session.get(f"{endpoint}/json/close/{hidden_target_id}") as response:
            if response.status not in {200, 204}:
                raise ProbeFailure(f"Chromium refused hidden shared-header cleanup (HTTP {response.status})")
        hidden_target_id = None
        result.update({"reduced": reduced, "foreground": foreground, "hidden": hidden})
    finally:
        if hidden_target_id is not None:
            async with session.get(f"{endpoint}/json/close/{hidden_target_id}") as response:
                if response.status not in {200, 204}:
                    raise ProbeFailure(f"Chromium refused hidden shared-header cleanup (HTTP {response.status})")
        await devtools.call("Emulation.setEmulatedMedia", {
            "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
        })
        await _select_view(devtools, "system", '[data-view="settings"]', "settings")
        restore = await devtools.evaluate("""(()=>{
          const control=document.querySelector('#settings-view #ui-motion');
          if(!(control instanceof HTMLSelectElement))return {control:null,applied:null};
          control.value='system';control.dispatchEvent(new Event('change',{bubbles:true}));
          return {control:control.value,applied:document.documentElement.dataset.jarvisMotion||null};
        })()""", label="restore local System motion preference after shared header test")
        result["restored_setting"] = restore
    await _select_view(devtools, "command-centre", '[data-view="overview"]', "overview")
    await _wait_overview_fixture(devtools)
    reduced_data = result.get("reduced", {}).get("first", {})
    foreground_data = result.get("foreground", {}).get("first", {})
    hidden_data = result.get("hidden", {})
    result["state_scope"] = {
        "observed_state": foreground_data.get("assistantState"),
        "not_simulated": ["listening", "thinking", "speaking"],
        "reason": "The local fixture does not request microphone access or fabricate an active turn.",
    }
    result["markup_scope"] = {
        "measured_element": "#assistant-hud",
        "legacy_chat_presence_element_found": reduced.get("legacyPresence"),
        "overview_reactor_viewport_checks": "recorded separately in central_motion",
    }
    checks = {
        "shared_chat_header_exists_and_is_visible": (
            reduced.get("present") is True and reduced_data.get("workspaceView") == "chat"
            and reduced_data.get("intersects") is True
        ),
        "OS_reduced_motion_overrides_local_Full": (
            reduced_data.get("prefersReduced") is True and reduced_data.get("localMotion") == "full"
            and not reduced_data.get("animations") and reduced.get("transformAdvanced") is False
        ),
        "visible_header_motion_runs_when_device_allows": (
            foreground_data.get("pageVisible") == "true" and foreground_data.get("assistantState") == "idle"
            and bool(foreground_data.get("animations")) and result.get("foreground", {}).get("transformAdvanced") is True
        ),
        "hidden_document_stops_shared_header_motion": (
            hidden_data.get("first", {}).get("documentVisibility") == "hidden"
            and not hidden_data.get("first", {}).get("animations")
            and hidden_data.get("transformAdvanced") is False
        ),
        "ephemeral_motion_preference_restored": (
            result.get("restored_setting", {}).get("control") == "system"
            and result.get("restored_setting", {}).get("applied") == "system"
        ),
    }
    result["checks"] = checks
    result["failures"] = [name for name, passed in checks.items() if not passed]
    return result


async def _select_view(devtools: DevTools, group: str, selector: str, view: str) -> dict[str, Any]:
    expression = """(async()=>{
      const group=document.querySelector('.nav-group[data-nav-group='+JSON.stringify(%s)+']');
      let button=group?.querySelector(%s), opened=true;
      if(group){
        const summary=group.querySelector('summary');
        if(!group.open)summary.click();
        opened=group.open;
      }else{
        button=document.querySelector('.primary-nav .nav-item[data-view='+JSON.stringify(%s)+']');
        const ancestor=button?.closest('.nav-group');
        if(ancestor&&!ancestor.open)ancestor.querySelector('summary')?.click();
        opened=!ancestor||ancestor.open;
      }
      if(!button)return {ok:false,reason:'destination missing',opened};
      button.click();
      const end=Date.now()+5000;
      while(Date.now()<end){
        const workspace=document.querySelector('.workspace');
        if(workspace?.dataset.currentView===%s){
          const selected=button.getAttribute('aria-current');
          const navGroup=group||button.closest('.nav-group');
          const groupCurrent=navGroup?.querySelector('summary')?.getAttribute('aria-current')||null;
          if(navGroup?.open)navGroup.querySelector('summary')?.click();
          return {ok:true,opened,view:workspace.dataset.currentView,selected,groupCurrent};
        }
        await new Promise(r=>setTimeout(r,50));
      }
      return {ok:false,reason:'view did not change',opened,
        view:document.querySelector('.workspace')?.dataset.currentView||null};
    })()""" % (json.dumps(group), json.dumps(selector), json.dumps(view), json.dumps(view))
    result = await devtools.evaluate(expression, label=f"navigation {group}/{view}")
    if not isinstance(result, dict) or not result.get("ok") or not result.get("opened"):
        raise ProbeFailure(f"navigation failed for {group}/{view}: {result!r}")
    if result.get("selected") != "page":
        raise ProbeFailure(f"navigation destination lacks aria-current=page: {result!r}")
    return result


async def _probe_canonical_navigation(devtools: DevTools) -> dict[str, Any]:
    expression = """(async()=>{
      const expected={work:'projects',resources:'capabilities',system:'settings'};
      const expectedMembers={
        work:['missions','bots','activity','projects'],
        resources:['capabilities','native-controls','resources-learning','native-inventory','files',
          'context','second-brain','extensions','profiles-admin','ecosystem'],
        system:['settings','models-settings','integrations','calendar','settings-admin'],
      };
      const allExpected=['overview','chat',...Object.values(expectedMembers).flat()];
      const nav=document.querySelector('.primary-nav');
      const manageGroups=[...document.querySelectorAll('.primary-nav .nav-group[data-nav-group="manage"]')];
      const manage=manageGroups.length===1?manageGroups[0]:null;
      const summary=manage?.querySelector(':scope > summary')||null;
      const directNav=['overview','chat'].every(view=>{
        const matches=[...nav?.querySelectorAll('.nav-item[data-view]')||[]]
          .filter(item=>item.dataset.view===view);
        return matches.length===1&&!matches[0].closest('.nav-group');
      });
      const navItems=[...nav?.querySelectorAll('.nav-item[data-view]')||[]];
      const allIds=navItems.map(item=>item.dataset.view);
      const uniqueMembership=allIds.length===new Set(allIds).size
        && allExpected.length===new Set(allExpected).size
        && allExpected.length===allIds.length
        && allExpected.every(id=>allIds.includes(id));
      const checks=[];
      for(const [name,destination] of Object.entries(expected)){
        const section=manage?.querySelector('[aria-labelledby="manage-'+name+'-heading"]')||null;
        const heading=section?.querySelector('#manage-'+name+'-heading')||null;
        const label=heading?.textContent?.trim()||null;
        let opened=false;
        if(manage&&summary){
          if(!manage.open)summary.click();
          const openEnd=Date.now()+1000;
          while(Date.now()<openEnd&&(!manage.open||summary.getAttribute('aria-expanded')!=='true'))
            await new Promise(resolve=>setTimeout(resolve,10));
          opened=manage.open&&summary.getAttribute('aria-expanded')==='true';
        }
        const headingStyle=heading?getComputedStyle(heading):null;
        const sectionVisible=Boolean(section&&heading&&!section.hidden&&headingStyle.display!=='none'
          &&headingStyle.visibility!=='hidden'&&heading.getBoundingClientRect().width>0
          &&heading.getBoundingClientRect().height>0);
        const destinations=[...section?.querySelectorAll('.nav-item[data-view]')||[]].map(item=>item.dataset.view);
        const expectedForGroup=expectedMembers[name];
        const exactMembership=Boolean(expectedForGroup&&destinations.length===expectedForGroup.length
          &&new Set(destinations).size===destinations.length
          &&expectedForGroup.every(id=>destinations.includes(id)));
        const button=section?.querySelector('.nav-item[data-view="'+destination+'"]')||null;
        const destinationPresent=Boolean(button&&button.closest('.nav-menu-section')===section);
        if(button)button.click();
        const end=Date.now()+5000;
        let finalState=null;
        while(Date.now()<end){
          const view=document.querySelector('.workspace')?.dataset.currentView||null;
          const selected=button?.getAttribute('aria-current')||null;
          const groupCurrent=summary?.getAttribute('aria-current')||null;
          const panel=[...document.querySelectorAll('[data-view-panel]')]
            .find(item=>item.dataset.viewPanel===destination&&!item.hidden)||null;
          const focusedHeading=panel?.querySelector('h1,h2')||null;
          const headingStyle=focusedHeading?getComputedStyle(focusedHeading):null;
          const panelHeadingVisible=Boolean(focusedHeading&&headingStyle.display!=='none'
            &&headingStyle.visibility!=='hidden'&&focusedHeading.getBoundingClientRect().width>0
            &&focusedHeading.getBoundingClientRect().height>0);
          const focusInsidePanel=Boolean(panelHeadingVisible&&document.activeElement===focusedHeading);
          const closed=Boolean(manage&&!manage.open&&summary?.getAttribute('aria-expanded')==='false');
          finalState={view,selected,groupCurrent,panelHeadingVisible,focusInsidePanel,closed};
          if(view===destination&&selected==='page'&&groupCurrent==='location'
            &&panelHeadingVisible&&focusInsidePanel&&closed)break;
          await new Promise(resolve=>setTimeout(resolve,25));
        }
        checks.push({name,destination,label,sectionVisible,present:Boolean(section),opened,
          destinationPresent,exactMembership,destinations,...(finalState||{})});
      }
      return {directNav,expectedGroups:Object.keys(expected),groups:checks.map(check=>check.name),
        actualManageWrapper:manage?.dataset.navGroup||null,uniqueMembership,allDestinations:allIds,checks};
    })()"""
    value = await devtools.evaluate(expression, label="canonical nested Work, Resources, and System navigation")
    if not isinstance(value, dict):
        raise ProbeFailure("could not inspect canonical navigation groups")
    if (not value.get("directNav")
            or value.get("actualManageWrapper") != "manage"
            or not value.get("uniqueMembership")
            or not set(value.get("expectedGroups", [])).issubset(value.get("groups", []))):
        raise ProbeFailure(f"direct routes or canonical navigation sections are missing: {value!r}")
    if any(not check.get("present") or check.get("label") != check.get("name", "").title()
           or not check.get("sectionVisible") or not check.get("opened")
           or not check.get("destinationPresent") or not check.get("exactMembership")
           or check.get("selected") != "page" or check.get("view") != check.get("destination")
           or check.get("groupCurrent") != "location" or not check.get("panelHeadingVisible")
           or not check.get("focusInsidePanel")
           or not check.get("closed") for check in value.get("checks", [])):
        raise ProbeFailure(f"canonical navigation section did not open, select, focus, and close correctly: {value!r}")
    return value

async def _is_nav_item_visible(devtools: DevTools, view: str) -> bool:
    expression = """(()=>{
      const item=document.querySelector('.primary-nav .nav-item[data-view='+JSON.stringify(%s)+']');
      if(!item||item.hidden)return false;
      const group=item.closest('.nav-group'),wasOpen=group?.open||false;
      if(group&&!wasOpen)group.querySelector('summary')?.click();
      const rect=item.getBoundingClientRect(),style=getComputedStyle(item);
      const visible=style.display!=='none'&&style.visibility!=='hidden'&&rect.width>0&&rect.height>0;
      if(group&&group.open!==wasOpen)group.querySelector('summary')?.click();
      return visible;
    })()""" % json.dumps(view)
    value = await devtools.evaluate(expression, label=f"visibility of {view} navigation item")
    return value is True


async def _measure_state(devtools: DevTools, *, mode: str, group: str) -> dict[str, Any]:
    selectors = {
        "overview": {"main": '[data-view-panel="overview"]',
                     "stage": '[data-feature-root="overview"] .overview-stage, #jarvis-presence',
                     "composer": '[data-feature-root="overview"] .command-panel, #composer',
                     "input": '[data-feature-root="overview"] #command-input, #message-input'},
        "chat": {"main": "#main-content", "stage": "#message-scroll",
                 "composer": "#composer", "input": "#message-input"},
        "knowledge": {"main": '[data-view-panel="second-brain"]',
                       "stage": '[data-feature-root="second-brain"] .brain-browser',
                       "composer": "#___no_composer___",
                       "input": '[data-feature-root="second-brain"] [data-query]'},
    }[mode]
    expression = NATIVE_INTERSECTION_HELPER + """(async()=>{
      const mode=%s;
      const rect=(el)=>{if(!el)return {x:0,y:0,width:0,height:0,right:0,bottom:0};const r=el.getBoundingClientRect();return {x:r.x,y:r.y,width:r.width,height:r.height,right:r.right,bottom:r.bottom}};
      const visible=(el)=>{if(!el||!el.getClientRects().length)return false;const s=getComputedStyle(el),r=el.getBoundingClientRect();return s.visibility!=='hidden'&&s.display!=='none'&&r.width>0&&r.height>0&&r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight};
      const main=document.querySelector(%s), stage=document.querySelector(%s), composer=document.querySelector(%s);
      const input=document.querySelector(%s), nav=document.querySelector('.primary-nav');
      const conversationPanel=document.querySelector('#conversation-panel');
      const historyToggle=document.querySelector('#history-toggle');
      const turnModelControls=document.querySelector('#turn-model-controls');
      const turnModel=document.querySelector('#turn-model');
      const turnEffort=document.querySelector('#turn-effort');
      const chatNav=document.querySelector('.primary-nav .nav-item[data-view="chat"]');
      const chatNavGroup=chatNav?.closest('.nav-group'),chatGroupWasOpen=chatNavGroup?.open||false;
      if(chatNavGroup&&!chatGroupWasOpen)chatNavGroup.querySelector('summary')?.click();
      if(chatNav)chatNav.scrollIntoView({block:'nearest',inline:'center',behavior:'auto'});
      const associatedLabel=(el)=>{
        if(!(el instanceof HTMLInputElement)||!['checkbox','radio'].includes(el.type))return null;
        const labels=[];
        for(const label of Array.from(el.labels||[])){
          if(label.control!==el||!visible(label))continue;
          const r=label.getBoundingClientRect();
          labels.push({element:label,width:Math.round(r.width*100)/100,height:Math.round(r.height*100)/100,
            source:label.htmlFor?`for=${label.htmlFor}`:label.contains(el)?'wrapping-label':'associated-label'});
        }
        if(!labels.length)return null;
        const qualified=labels.find(label=>label.width>=44&&label.height>=44);
        const target=qualified||labels.reduce((best,label)=>Math.min(label.width,label.height)>Math.min(best.width,best.height)?label:best);
        return {...target,qualified:Boolean(qualified),visibleAssociatedLabels:labels.map(({width,height,source})=>({width,height,source}))};
      };
      const touchSelector='a[href],button,summary,input,select,textarea,[role="button"],[role="tab"]';
      const targets=[...document.querySelectorAll(touchSelector)].filter(visible).map(el=>{
        const r=el.getBoundingClientRect(),style=getComputedStyle(el);
        const inlineDocLink=el.matches('a[href]')&&style.display==='inline'&&!el.matches('[role="button"],[role="tab"]')&&!el.closest('.primary-nav');
        const inputLabel=associatedLabel(el);
        const width=Math.round(r.width*100)/100,height=Math.round(r.height*100)/100;
        const effectiveWidth=inputLabel?inputLabel.width:width,effectiveHeight=inputLabel?inputLabel.height:height;
        return {selector:el.id?'#'+el.id:el.className&&typeof el.className==='string'?el.tagName.toLowerCase()+'.'+el.className.trim().split(/\\s+/).join('.'):el.tagName.toLowerCase(),
          label:el.getAttribute('aria-label')||el.innerText?.trim().slice(0,50)||el.getAttribute('placeholder')||el.tagName.toLowerCase(),
          width,height,effectiveWidth,effectiveHeight,
          inputType:el instanceof HTMLInputElement?el.type:null,
          associatedLabel:inputLabel?{source:inputLabel.source,width:inputLabel.width,height:inputLabel.height,
            qualified:inputLabel.qualified,visibleAssociatedLabels:inputLabel.visibleAssociatedLabels}:null,
          inlineDocLink};
      });
      const rootOverflow=document.documentElement.scrollWidth>innerWidth||document.body.scrollWidth>innerWidth;
      const overviewMotionElement=document.querySelector('[data-feature-root="overview"] .reactor-figure')||document.querySelector('.presence-figure');
      const pseudo=getComputedStyle(overviewMotionElement,'::before');
      const seconds=(value)=>value.split(',').map(token=>{const text=token.trim(),number=parseFloat(text);return text.endsWith('ms')?number/1000:number});
      const beforeTransitions=seconds(pseudo.transitionDuration||'0s'),beforeAnimations=seconds(pseudo.animationDuration||'0s');
      const navItems=[...document.querySelectorAll('.primary-nav .nav-item[data-view]')].map(item=>({view:item.dataset.view,
        label:item.innerText.trim(),visible:visible(item),hidden:item.hidden}));
      const quickCommand=%s;
      const quickRect=quickCommand?.getBoundingClientRect();
      const quickStyle=quickCommand?getComputedStyle(quickCommand):null;
      const quickAvailable=Boolean(quickCommand&&!quickCommand.hidden&&quickStyle.display!=='none'&&quickRect.width>0&&quickRect.height>0);
      const newChatButton=document.querySelector('[data-feature-root="overview"] [data-new-conversation],#overview-new-conversation');
      const newChatRect=newChatButton?.getBoundingClientRect();
      const newChatStyle=newChatButton?getComputedStyle(newChatButton):null;
      const newChatAvailable=Boolean(newChatButton&&!newChatButton.hidden&&newChatStyle.display!=='none'&&newChatRect.width>0&&newChatRect.height>0);
      const reduced={matches:matchMedia('(prefers-reduced-motion: reduce)').matches,
        presenceTransition:pseudo?.transitionDuration||null,
        presenceBeforeTransitionSeconds:beforeTransitions,presenceBeforeAnimationSeconds:beforeAnimations,
        presenceBeforeInstant:beforeTransitions.every(value=>Number.isFinite(value)&&value<=0.001)&&beforeAnimations.every(value=>Number.isFinite(value)&&value<=0.001),
        stylesheetHasRule:[...document.styleSheets].some(sheet=>{try{return [...sheet.cssRules].some(rule=>rule.conditionText?.includes('prefers-reduced-motion: reduce')||rule.conditionText?.includes('prefers-reduced-motion:reduce'))}catch(_){return false}})};
      const composerRect=rect(composer),navRect=rect(nav);
      const paintState=(el)=>{
        if(!(el instanceof Element))return {visible:false,chain:[]};
        const chain=[];let isVisible=true;
        for(let node=el;node;node=node.parentElement){
          const style=getComputedStyle(node),opacity=Number.parseFloat(style.opacity);
          chain.push({tag:node.tagName.toLowerCase(),id:node.id||null,display:style.display,
            visibility:style.visibility,opacity:style.opacity,contentVisibility:style.contentVisibility,
            hidden:node.hidden,connected:node.isConnected});
          if(!node.isConnected||node.hidden||style.display==='none'||style.visibility==='hidden'
            ||style.visibility==='collapse'||!Number.isFinite(opacity)||opacity<=0
            ||style.contentVisibility==='hidden')isVisible=false;
        }
        const r=el.getBoundingClientRect();
        return {visible:Boolean(isVisible&&el.getClientRects().length&&r.width>0&&r.height>0),chain};
      };
      const chatTargetLists={composer:[...document.querySelectorAll('#composer')],nav:[...document.querySelectorAll('.primary-nav')]};
      const chatTargetRefs=[chatTargetLists.composer[0]||null,chatTargetLists.nav[0]||null];
      const captureChatContext=()=>{
        const nodes=[];
        for(const target of chatTargetRefs)for(let node=target;node;node=node.parentElement)
          if(!nodes.includes(node))nodes.push(node);
        const scrolling=document.scrollingElement;if(scrolling&&!nodes.includes(scrolling))nodes.push(scrolling);
        return {targets:[...chatTargetRefs],view:document.querySelector('.workspace')?.dataset.currentView||null,
          documentVisibility:document.visibilityState,viewport:{width:innerWidth,height:innerHeight},nodes,
          scrolls:nodes.map(node=>({top:node.scrollTop,left:node.scrollLeft}))};
      };
      const sameChatContext=(a,b)=>Boolean(a&&b&&a.targets.length===2&&b.targets.length===2
        &&a.targets[0]&&a.targets[1]&&a.targets[0]===b.targets[0]&&a.targets[1]===b.targets[1]
        &&a.view===b.view&&a.documentVisibility==='visible'&&b.documentVisibility==='visible'
        &&a.viewport.width===b.viewport.width&&a.viewport.height===b.viewport.height
        &&a.nodes.length===b.nodes.length&&a.nodes.every((node,index)=>node===b.nodes[index]
          &&a.scrolls[index].top===b.scrolls[index].top&&a.scrolls[index].left===b.scrolls[index].left));
      const serializeChatContext=context=>({view:context.view,documentVisibility:context.documentVisibility,
        viewport:context.viewport,targets:context.targets.map(node=>({id:node?.id||null,
          className:typeof node?.className==='string'?node.className:null,connected:Boolean(node?.isConnected)})),
        scrolls:context.nodes.map((node,index)=>({tag:node.tagName.toLowerCase(),id:node.id||null,
          className:typeof node.className==='string'?node.className:null,
          top:context.scrolls[index].top,left:context.scrolls[index].left}))});
      const chatContextBefore=captureChatContext();
      const operationDeadline=performance.now()+5000;
      const nativeIntersection=mode==='chat'
        ? (chatTargetLists.composer.length===1&&chatTargetLists.nav.length===1
          ? await observeNativeIntersections(chatTargetRefs,operationDeadline,350)
          : {ok:false,reason:'selector-count'}) : null;
      const finalComposerMatches=[...document.querySelectorAll('#composer')];
      const finalNavMatches=[...document.querySelectorAll('.primary-nav')];
      const sameChatTargets=mode==='chat'&&chatTargetRefs[0]?.isConnected&&chatTargetRefs[1]?.isConnected
        &&finalComposerMatches.length===1&&finalNavMatches.length===1
        &&finalComposerMatches[0]===chatTargetRefs[0]&&finalNavMatches[0]===chatTargetRefs[1];
      const chatContextAfter=captureChatContext();
      const chatContextStable=sameChatContext(chatContextBefore,chatContextAfter);
      const chatViewCurrent=document.querySelector('.workspace')?.dataset.currentView==='chat';
      const composerPaint=paintState(composer),navPaint=paintState(nav);
      const composerIntersection=nativeIntersection?.ok?nativeIntersection.records[0]?.intersectionRect:null;
      const navIntersection=nativeIntersection?.ok?nativeIntersection.records[1]?.intersectionRect:null;
      const nativeOverlap=mode==='chat'&&nativeIntersection?.ok&&composerIntersection&&navIntersection
        ? {left:Math.max(composerIntersection.left,navIntersection.left),
          top:Math.max(composerIntersection.top,navIntersection.top),
          right:Math.min(composerIntersection.right,navIntersection.right),
          bottom:Math.min(composerIntersection.bottom,navIntersection.bottom),
          width:Math.max(0,Math.min(composerIntersection.right,navIntersection.right)-Math.max(composerIntersection.left,navIntersection.left)),
          height:Math.max(0,Math.min(composerIntersection.bottom,navIntersection.bottom)-Math.max(composerIntersection.top,navIntersection.top))}:null;
      const clearanceQualified=Boolean(mode==='chat'&&chatViewCurrent&&sameChatTargets&&chatContextStable
        &&nativeIntersection?.ok&&composerPaint.visible&&navPaint.visible
        &&composerIntersection?.width>0&&composerIntersection?.height>0
        &&navIntersection?.width>0&&navIntersection?.height>0&&nativeOverlap);
      const bottomNavClearOfChatComposer=Boolean(clearanceQualified
        &&(nativeOverlap.width===0||nativeOverlap.height===0));
      const report={mode,viewport:{width:innerWidth,height:innerHeight},
        primaryNavItems:navItems,
        chatNavigation:{visible:visible(chatNav),grouped:Boolean(chatNavGroup),
          scrollLeft:nav?Math.round(nav.scrollLeft):null,navWidth:nav?Math.round(nav.clientWidth):null,
          itemWidth:chatNav?Math.round(chatNav.getBoundingClientRect().width):null},
        overviewQuickCommand:{present:Boolean(quickCommand),available:quickAvailable,inViewport:visible(quickCommand),
          width:quickRect?Math.round(quickRect.width*100)/100:0,height:quickRect?Math.round(quickRect.height*100)/100:0,
          label:quickCommand?.innerText?.trim().slice(0,60)||null},
        overviewNewChatButton:{present:Boolean(newChatButton),available:newChatAvailable,
          width:newChatRect?Math.round(newChatRect.width*100)/100:0,height:newChatRect?Math.round(newChatRect.height*100)/100:0},
        overviewFeatureContract:{present:Boolean(document.querySelector('[data-feature-root="overview"]')),
          reactorStage:Boolean(document.querySelector('[data-feature-root="overview"] .overview-stage')),
          reactorSvg:Boolean(document.querySelector('[data-feature-root="overview"] .reactor-figure svg')),
          coreStatus:Boolean(document.querySelector('[data-feature-root="overview"] [data-core-status]')),
          telemetry:Boolean(document.querySelector('[data-feature-root="overview"] [data-metric="total"]')),
          commandInput:Boolean(document.querySelector('[data-feature-root="overview"] #command-input')),
          legacy:Boolean(Boolean(document.querySelector('#jarvis-presence'))&&Boolean(document.querySelector('#core-status')))},
        chatFeatureContract:{messageScroll:Boolean(document.querySelector('#message-scroll')),
          composer:Boolean(document.querySelector('#composer')),nativeTextarea:input instanceof HTMLTextAreaElement},
        conversationNavigation:{
          railVisible:visible(conversationPanel),
          railRect:rect(conversationPanel),
          drawerOpen:conversationPanel?.dataset.open==='true',
          historyToggleVisible:visible(historyToggle),
          historyToggleExpanded:historyToggle?.getAttribute('aria-expanded')||null,
          historyToggleLabel:historyToggle?.getAttribute('aria-label')||null},
        perMessageControls:{
          containerVisible:visible(turnModelControls),
          modelVisible:visible(turnModel),
          reasoningVisible:visible(turnEffort),
          modelDisabled:Boolean(turnModel?.disabled),
          reasoningDisabled:Boolean(turnEffort?.disabled)},
        knowledgeFeatureContract:{root:Boolean(document.querySelector('[data-feature-root="second-brain"]')),
          searchForm:Boolean(document.querySelector('[data-feature-root="second-brain"] form[data-search-form]')),
          searchInput:input instanceof HTMLInputElement&&input.type==='search',
          noteList:Boolean(document.querySelector('[data-feature-root="second-brain"] [data-note-list]')),
          graph:Boolean(document.querySelector('[data-feature-root="second-brain"] [data-graph]'))},
        textarea:{visible:visible(input),tag:input?.tagName||null,native:input instanceof HTMLTextAreaElement,inputMode:input?.getAttribute('inputmode')||null},
        mainstage:{visible:visible(main),rect:rect(main)},viewStage:{visible:visible(stage),rect:rect(stage)},
        composer:{visible:visible(composer),rect:composerRect,paint:composerPaint,
          nativeIntersection:composerIntersection},
        bottomNav:{visible:visible(nav),rect:navRect,paint:navPaint,
          nativeIntersection:navIntersection,overlapsComposer:mode==='chat'?!bottomNavClearOfChatComposer:false,
          clearanceQualified,clearOfChatComposer:mode==='chat'?bottomNavClearOfChatComposer:null,
          nativeIntersectionRead:nativeIntersection?{ok:nativeIntersection.ok,reason:nativeIntersection.reason||null,
            entries:nativeIntersection.records?.map(item=>({time:item.time,
              boundingClientRect:item.boundingClientRect,intersectionRect:item.intersectionRect,
              rootBounds:item.rootBounds,intersectionRatio:item.intersectionRatio,
              isIntersecting:item.isIntersecting}))||[]}:null,
          contextStable:mode==='chat'?chatContextStable:null,
          context:mode==='chat'?{before:serializeChatContext(chatContextBefore),
            after:serializeChatContext(chatContextAfter)}:null,
          nativeOverlap},
        horizontalOverflow:{document:rootOverflow,documentWidth:document.documentElement.scrollWidth,bodyWidth:document.body.scrollWidth,viewportWidth:innerWidth},
        reducedMotion:reduced,touchTargets:targets,
        touchViolations:targets.filter(item=>!item.inlineDocLink&&(item.effectiveHeight<44||item.effectiveWidth<44)),
        inlineDocumentationLinks:targets.filter(item=>item.inlineDocLink).length};
      if(chatNavGroup&&chatNavGroup.open!==chatGroupWasOpen)chatNavGroup.querySelector('summary')?.click();
      return report;
    })()""" % (json.dumps(mode), json.dumps(selectors["main"]), json.dumps(selectors["stage"]),
             json.dumps(selectors["composer"]), json.dumps(selectors["input"]),
             'document.querySelector(\'[data-feature-root="overview"] button[data-command-prompt],.quick-actions button[data-command-prompt]\')' if mode == "overview" else "null")
    report = await devtools.evaluate(expression, label=f"{mode} layout measurement ({group})")
    if not isinstance(report, dict):
        raise ProbeFailure(f"could not measure {mode} layout")
    report["checks"] = {
        "mainstage_visible": report["mainstage"]["visible"],
        "view_stage_visible": report["viewStage"]["visible"],
        "chat_navigation_reachable": report["chatNavigation"]["visible"],
        "no_document_horizontal_overflow": not report["horizontalOverflow"]["document"],
        "reduced_motion_stylesheet_rule_present": report["reducedMotion"]["stylesheetHasRule"],
        "all_visible_touch_targets_at_least_44px": not report["touchViolations"],
    }
    if mode == "chat":
        report["checks"].update({
            "native_chat_textarea_visible": report["textarea"]["visible"] and report["textarea"]["native"],
            "chat_inputmode_text_for_mobile_keyboard": report["textarea"]["inputMode"] == "text",
            "chat_feature_contract_present": all(report["chatFeatureContract"].values()),
            "per_message_model_and_reasoning_controls_visible": (
                report["perMessageControls"]["containerVisible"]
                and report["perMessageControls"]["modelVisible"]
                and report["perMessageControls"]["reasoningVisible"]
            ),
            "chat_composer_visible": report["composer"]["visible"],
            "bottom_nav_clear_of_chat_composer": report["bottomNav"]["clearOfChatComposer"] is True,
        })
    elif mode == "overview":
        native_contract=report["overviewFeatureContract"]["present"]
        contract_ok=(report["overviewFeatureContract"]["reactorStage"]
                     and report["overviewFeatureContract"]["reactorSvg"]
                     and report["overviewFeatureContract"]["coreStatus"]
                     and report["overviewFeatureContract"]["telemetry"]
                     and report["overviewFeatureContract"]["commandInput"])
        legacy_contract=report["overviewFeatureContract"]["legacy"]
        report["checks"]["overview_purpose_contract_present"] = contract_ok if native_contract else legacy_contract
        report["checks"]["overview_quick_command_available_44px"] = (
            report["overviewQuickCommand"]["available"]
            and report["overviewQuickCommand"]["width"] >= 44
            and report["overviewQuickCommand"]["height"] >= 44
        )
        report["checks"]["overview_new_chat_button_available_44px"] = (
            report["overviewNewChatButton"]["available"]
            and report["overviewNewChatButton"]["width"] >= 44
            and report["overviewNewChatButton"]["height"] >= 44
        )
    elif mode == "knowledge":
        report["checks"]["knowledge_search_visible"] = report["textarea"]["visible"]
        report["checks"]["knowledge_feature_contract_present"] = all(report["knowledgeFeatureContract"].values())
    report["failures"] = [name for name, passed in report["checks"].items() if not passed]
    report["touchViolations"] = report["touchViolations"][:30]
    report["touchTargets"] = report["touchTargets"][:100]
    return report


async def _screenshot(devtools: DevTools, output_dir: Path, item: dict[str, Any], mode: str,
                      *, state: dict[str, Any] | None = None) -> dict[str, Any]:
    await asyncio.sleep(0.2)
    route = await devtools.evaluate("""(()=>({path:location.pathname,
      workspaceView:document.querySelector('.workspace')?.dataset.currentView||null}))()""",
      label=f"capture route for {mode} screenshot")
    stem = f"{item['name']}-{item['width']}x{item['height']}-{mode}-fixture"
    png_path = output_dir / f"{stem}.png"
    jpeg_path = output_dir / f"{stem}.jpg"
    png = await devtools.call("Page.captureScreenshot", {
        "format": "png", "fromSurface": True, "captureBeyondViewport": False,
    })
    png_bytes = base64.b64decode(png["data"], validate=True)
    png_path.write_bytes(png_bytes)
    jpeg = await devtools.call("Page.captureScreenshot", {
        "format": "jpeg", "quality": 55, "fromSurface": True,
        "captureBeyondViewport": False,
    })
    jpeg_bytes = base64.b64decode(jpeg["data"], validate=True)
    jpeg_path.write_bytes(jpeg_bytes)
    loaded_paths = await devtools.evaluate("""(()=>[...new Set(performance.getEntriesByType('resource')
      .map(entry=>{try{return new URL(entry.name).pathname}catch(_){return null}})
      .filter(path=>path&&path.startsWith('/chat/assets/')))].sort())()""",
      label=f"record served assets for {mode} screenshot")
    return {
        "route": route,
        "view_state": state or {},
        "viewport": {"name": item["name"], "width": item["width"], "height": item["height"]},
        "loaded_asset_paths": loaded_paths,
        "reviewed_asset_sha256": {path: REVIEWED_ASSET_SHA256[path] for path in loaded_paths
                                   if path in REVIEWED_ASSET_SHA256},
        "png": {"path": str(png_path), "bytes": len(png_bytes),
                "sha256": hashlib.sha256(png_bytes).hexdigest()},
        "jpeg": {"path": str(jpeg_path), "bytes": len(jpeg_bytes),
                 "sha256": hashlib.sha256(jpeg_bytes).hexdigest(), "quality": 55},
        "capture_method": "direct Chromium DevTools viewport capture; no image processing",
    }


async def _phone_chat_journey_screenshots(devtools: DevTools, item: dict[str, Any],
                                          output_dir: Path) -> list[dict[str, Any]]:
    """Capture the fixture-only history drawer and the return to its composer."""
    opened = await devtools.evaluate("""(async()=>{
      const toggle=document.querySelector('#history-toggle');
      const panel=document.querySelector('#conversation-panel');
      if(!toggle||!panel)return {ok:false,reason:'history control or panel missing'};
      if(panel.dataset.open!=='true')toggle.click();
      const end=Date.now()+1500;
      while(Date.now()<end){
        const r=panel.getBoundingClientRect();
        if(panel.dataset.open==='true'&&toggle.getAttribute('aria-expanded')==='true'
            &&toggle.getAttribute('aria-label')==='Return to conversation'
            &&r.width>0&&r.height>0&&r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight){
          return {ok:true,workspaceView:document.querySelector('.workspace')?.dataset.currentView||null,
            drawerOpen:true,historyExpanded:toggle.getAttribute('aria-expanded'),
            historyLabel:toggle.getAttribute('aria-label'),drawerRect:{x:r.x,y:r.y,width:r.width,height:r.height}};
        }
        await new Promise(resolve=>setTimeout(resolve,25));
      }
      return {ok:false,reason:'history drawer did not enter the viewport',
        drawerOpen:panel.dataset.open==='true',historyExpanded:toggle.getAttribute('aria-expanded')};
    })()""", label="open the phone conversation history drawer")
    if not isinstance(opened, dict) or not opened.get("ok"):
        raise ProbeFailure(f"phone history drawer did not open visibly: {opened!r}")
    drawer_capture = await _screenshot(devtools, output_dir, item, "chat-drawer", state=opened)

    selected = await devtools.evaluate("""(async()=>{
      const panel=document.querySelector('#conversation-panel');
      const toggle=document.querySelector('#history-toggle');
      const conversation=document.querySelector('.conversation-item');
      if(!panel||!toggle||!conversation)return {ok:false,reason:'history drawer has no selectable fixture chat'};
      conversation.click();
      const end=Date.now()+2500;
      while(Date.now()<end){
        const main=document.querySelector('#main-content');
        const controls=document.querySelector('#turn-model-controls');
        const input=document.querySelector('#message-input');
        const send=document.querySelector('#send-button');
        const selectedConversation=document.querySelector('.conversation-item[aria-current="page"]');
        const inViewport=el=>{
          if(!el||el.hidden||!el.getClientRects().length)return false;
          const s=getComputedStyle(el),r=el.getBoundingClientRect();
          return s.display!=='none'&&s.visibility!=='hidden'&&r.width>0&&r.height>0
            &&r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight;
        };
        if(panel.dataset.open!=='true'&&toggle.getAttribute('aria-expanded')==='false'
            &&toggle.getAttribute('aria-label')==='Show conversations'&&inViewport(main)
            &&inViewport(controls)&&inViewport(input)&&inViewport(send)&&selectedConversation){
          input.focus({preventScroll:true});
          return {ok:true,workspaceView:document.querySelector('.workspace')?.dataset.currentView||null,
            drawerOpen:false,historyExpanded:toggle.getAttribute('aria-expanded'),
            historyLabel:toggle.getAttribute('aria-label'),selectedChat:selectedConversation.getAttribute('aria-current'),
            mainVisible:true,modelControlsVisible:true,messageInputVisible:true,sendVisible:true,
            messageInputFocused:document.activeElement===input};
        }
        await new Promise(resolve=>setTimeout(resolve,25));
      }
      return {ok:false,reason:'selecting a fixture chat did not return to the composer',
        drawerOpen:panel.dataset.open==='true',historyExpanded:toggle.getAttribute('aria-expanded')};
    })()""", label="select a phone fixture conversation and return to its composer")
    if not isinstance(selected, dict) or not selected.get("ok"):
        raise ProbeFailure(f"phone chat selection did not return to a visible composer: {selected!r}")
    selected_capture = await _screenshot(devtools, output_dir, item, "chat-selected", state=selected)
    return [drawer_capture, selected_capture]


async def _review_affected_view(devtools: DevTools, *, view: str, group: str,
                                selector: str, item: dict[str, Any], output_dir: Path) -> dict[str, Any]:
    """Exercise safe, exact local-fixture interactions and capture one named view."""
    navigation = await _select_view(devtools, group, selector, view)
    model_entry = None
    project_fixture_interaction = None
    profile_fixture_interaction = None
    await devtools.evaluate("""(async()=>{
      const requestedView=%s;
      const end=Date.now()+2500;
      while(Date.now()<end){
        const panel=document.querySelector('[data-view-panel='+JSON.stringify(requestedView)+']');
        const statuses=[...(panel?.querySelectorAll('[role=status],[aria-live]')||[])].map(node=>node.textContent.trim());
        const loading=statuses.some(value=>/^(Loading|Reading|Refreshing|Loading the current)/i.test(value));
        const profileStatus=panel?.querySelector('[data-profile-status]')?.textContent.trim()||null;
        const ready=requestedView==='profiles-admin'
          ? profileStatus==='Current native profiles are unavailable.'
            ||profileStatus==='Select Jarvis or an internal Expert profile to inspect its existing files.'
          : !loading;
        if(ready)return {ready:true,statuses};
        await new Promise(resolve=>setTimeout(resolve,50));
      }
      return {ready:false,timedOut:true};
    })()""" % json.dumps(view), label=f"initial {view} fixture hydration")
    if view == "profiles-admin":
        invalid_denial = await devtools.evaluate("""(()=>{
          const root=document.querySelector('[data-feature-root="profiles-admin"]');
          const status=root?.querySelector('[data-profile-status]');
          const empty=root?.querySelector('[data-profile-empty]');
          return {explicitUnavailable:status?.textContent.trim()==='Current native profiles are unavailable.',
            invalidEmptyNotReportedAsSearchEmpty:empty?.hidden===true,
            status:status?.textContent.trim()||null};
        })()""", label="reject an invalid empty native Profiles fixture explicitly")
        invalid_denial_tested = PROFILE_ROUTE_CALLS == 1
        if invalid_denial_tested:
            await _select_view(devtools, "", '[data-view="overview"]', "overview")
            await _select_view(devtools, "resources", '[data-view="profiles-admin"]', "profiles-admin")
        valid_profile_search = await devtools.evaluate("""(async()=>{
          const root=document.querySelector('[data-feature-root="profiles-admin"]');
          const status=root?.querySelector('[data-profile-status]');
          const select=root?.querySelector('[data-profile-select]');
          const search=root?.querySelector('[data-profile-search]');
          const empty=root?.querySelector('[data-profile-empty]');
          const end=Date.now()+2500;
          while(Date.now()<end){
            const hasSynthetic=[...(select?.options||[])].some(option=>option.value===%s);
            if(status?.textContent.trim()==='Select Jarvis or an internal Expert profile to inspect its existing files.'&&hasSynthetic)break;
            await new Promise(resolve=>setTimeout(resolve,25));
          }
          const positiveCatalogLoaded=Boolean(select&&[...select.options].some(option=>option.value===%s));
          const statusAfterLoad=status?.textContent.trim()||null;
          if(search){search.value='fixture-no-profile-matches-226';search.dispatchEvent(new Event('input',{bubbles:true}));}
          const searchEnd=Date.now()+1500;
          while(Date.now()<searchEnd&&empty?.hidden!==false)await new Promise(resolve=>setTimeout(resolve,25));
          return {positiveCatalogLoaded,statusAfterLoad,
            syntheticProfileId:%s,
            searchEmptyVisible:Boolean(empty&&!empty.hidden&&empty.textContent.trim()==='No profiles match this search.'),
            matchingProfileCount:root?.querySelector('[data-profile-count]')?.textContent.trim()||null,
            remainingOptions:select?.options.length??null};
        })()""" % (json.dumps("a" * 64), json.dumps("a" * 64), json.dumps("a" * 64)),
        label="load one synthetic native profile and verify the legitimate no-match search state")
        profile_fixture_interaction = {"invalidDenialTested":invalid_denial_tested,
            "invalidDenial":invalid_denial,"validProfileSearch":valid_profile_search}
    elif view == "models-settings":
        await _select_view(devtools, "conversations", '[data-view="chat"]', "chat")
        model_entry = await devtools.evaluate("""(async()=>{
          const link=document.querySelector('.chat-model-link[data-view="models-settings"]');
          if(!link)return {reachable:false,reason:'per-message model link missing'};
          link.click();const end=Date.now()+2000;
          while(Date.now()<end){if(document.querySelector('.workspace')?.dataset.currentView==='models-settings')
            return {reachable:true,source:'Chat per-message model link'};
            await new Promise(resolve=>setTimeout(resolve,25));}
          return {reachable:false,reason:'model link did not open Models'};
        })()""", label="open Models from the Chat per-message entry")
        await devtools.evaluate("""(async()=>{const end=Date.now()+2000;while(Date.now()<end){
          const select=document.querySelector('[data-feature-root="models-settings"] [data-models-conversation]');
          if(select&&!select.disabled)return true;await new Promise(resolve=>setTimeout(resolve,25));}return false;})()""",
          label="wait for synthetic conversation list")
        # Select only a synthetic local conversation; the exact settings route
        # responds 503 and no model choice is submitted.
        await devtools.evaluate("""(()=>{
          const select=document.querySelector('[data-feature-root="models-settings"] [data-models-conversation]');
          if(!select)return false;select.value=%s;select.dispatchEvent(new Event('change',{bubbles:true}));return true;
        })()""" % json.dumps(FIXTURE_MODEL_CONVERSATION_ID), label="synthetic model conversation selection")
    elif view == "projects":
        project_fixture_interaction = await devtools.evaluate("""(async()=>{
          const end=Date.now()+3000;
          let row=null,restore=null;
          while(Date.now()<end){
            const root=document.querySelector('[data-feature-root="projects"]');
            row=root?.querySelector('[data-project-list] button')||null;
            restore=root?.querySelector('[data-trash] button')||null;
            if(row&&restore)break;
            await new Promise(resolve=>setTimeout(resolve,40));
          }
          if(!row||!restore)return {fixtureRowsReady:false,rowPresent:Boolean(row),restorePresent:Boolean(restore)};
          row.click();
          const selectedEnd=Date.now()+1500;
          let selected=false,deleteVisible=false,restoreVisible=false,confirmationCancelled=false;
          let deleteGeometry=null,restoreGeometry=null;
          const measure=(el)=>{
            const r=el.getBoundingClientRect(),ancestors=[];
            for(let node=el.parentElement;node;node=node.parentElement){
              const style=getComputedStyle(node);
              if(['auto','scroll','hidden','clip'].some(value=>style.overflowX===value||style.overflowY===value)){
                const b=node.getBoundingClientRect(),left=b.left+node.clientLeft,top=b.top+node.clientTop;
                const right=left+node.clientWidth,bottom=top+node.clientHeight;
                ancestors.push({tag:node.tagName,id:node.id||null,overflowX:style.overflowX,overflowY:style.overflowY,
                  clientWidth:node.clientWidth,clientHeight:node.clientHeight,scrollTop:node.scrollTop,
                  left,top,right,bottom,clips:r.left<left-1||r.right>right+1||r.top<top-1||r.bottom>bottom+1});
              }
            }
            return {rect:{left:r.left,top:r.top,right:r.right,bottom:r.bottom,width:r.width,height:r.height},
              viewport:{width:innerWidth,height:innerHeight},ancestors};
          };
          while(Date.now()<selectedEnd){
            const root=document.querySelector('[data-feature-root="projects"]');
            const current=root?.querySelector('[data-project-list] button[aria-current="true"]');
            const remove=root?.querySelector('[data-archive]');
            selected=Boolean(current&&current.dataset.id===%s);
            if(selected&&remove&&!remove.hidden){
              remove.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
              await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
              const rect=remove.getBoundingClientRect(),style=getComputedStyle(remove);
              deleteGeometry=measure(remove);
              deleteVisible=rect.width>0&&rect.height>0&&rect.bottom>0&&rect.top<innerHeight
                &&rect.right>0&&rect.left<innerWidth&&style.display!=='none'&&style.visibility!=='hidden'
                &&!deleteGeometry.ancestors.some(item=>item.clips);
              if(deleteVisible)break;
            }
            await new Promise(resolve=>setTimeout(resolve,30));
          }
          if(selected&&deleteVisible){
            const remove=document.querySelector('[data-feature-root="projects"] [data-archive]');
            const original=window.confirm;
            window.confirm=(message)=>{window.__fixtureConfirmMessage=String(message);return false;};
            try{remove.click();}finally{window.confirm=original;}
            confirmationCancelled=typeof window.__fixtureConfirmMessage==='string'
              &&window.__fixtureConfirmMessage.startsWith('Move this project to Trash?')
              &&window.__fixtureConfirmMessage.includes('Its chats and note links stay saved')
              &&window.__fixtureConfirmMessage.includes('Obsidian notes remain in your vault')
              &&window.__fixtureConfirmMessage.includes('project context pauses until you restore it');
            restore.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
            await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
            const restoreRect=restore.getBoundingClientRect(),restoreStyle=getComputedStyle(restore);
            restoreGeometry=measure(restore);
            restoreVisible=!restore.hidden&&restoreRect.width>0&&restoreRect.height>0
              &&restoreRect.bottom>0&&restoreRect.top<innerHeight
              &&restoreRect.right>0&&restoreRect.left<innerWidth
              &&restoreStyle.display!=='none'&&restoreStyle.visibility!=='hidden'
              &&!restoreGeometry.ancestors.some(item=>item.clips);
            remove.scrollIntoView({block:'center',inline:'nearest',behavior:'auto'});
            await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
            deleteGeometry=measure(remove);
          }
          return {fixtureRowsReady:true,rowTitle:row.textContent.trim(),
            selectedFixtureProject:selected,deleteControlVisible:deleteVisible,
            confirmationCancelled,trashRestoreVisible:restoreVisible,deleteGeometry,restoreGeometry};
        })()""" % json.dumps(FIXTURE_PROJECT_ID),
          label="wait for and select the synthetic project; cancel its delete confirmation")
    elif view == "second-brain":
        await devtools.evaluate("""(()=>{
          const note=document.querySelector('[data-feature-root="second-brain"] [data-note-list] button');
          if(note)note.click();return Boolean(note);
        })()""", label="open synthetic Obsidian note")
        await devtools.evaluate("""(()=>{
          const category=[...document.querySelectorAll('[data-feature-root="second-brain"] [data-graph-legend] button')]
            .find(button=>button.textContent.includes('review'));
          if(category)category.click();return Boolean(category);
        })()""", label="filter synthetic graph tag")
        await devtools.evaluate("""(async()=>{const end=Date.now()+1500;while(Date.now()<end){
          if(document.querySelector('[data-reader-title]')?.textContent.trim()==='Fixture note alpha')return true;
          await new Promise(resolve=>setTimeout(resolve,50));}return false;})()""",
          label="wait for synthetic note detail")

    await devtools.evaluate("""(async()=>{
      const end=Date.now()+2500;
      while(Date.now()<end){
        const panel=document.querySelector('[data-view-panel='+JSON.stringify(%s)+']');
        const ready={
          projects:Boolean(panel?.querySelector('[data-project-list] li')&&panel?.querySelector('[data-trash] button')),
          secondBrain:Boolean(panel?.querySelector('[data-graph-status]')?.textContent.trim()&&panel?.querySelector('[data-note-list] button')),
          models:Boolean(panel?.querySelector('[data-models-status]')?.textContent.trim()&&!panel.querySelector('[data-models-status]').textContent.includes('Loading')),
          profiles:Boolean(panel?.querySelector('[data-profile-status]')?.textContent.trim()&&!panel.querySelector('[data-profile-status]').textContent.includes('Loading')),
          extensions:Boolean(panel?.querySelector('[data-extension-status]')?.textContent.trim()&&!panel.querySelector('[data-extension-status]').textContent.includes('Loading'))
        };
        if(ready[%s]||!Object.prototype.hasOwnProperty.call(ready,%s))return ready;
        await new Promise(resolve=>setTimeout(resolve,50));
      }
      return {timedOut:true};
    })()""" % (json.dumps(view), json.dumps({"projects":"projects","second-brain":"secondBrain","models-settings":"models","profiles-admin":"profiles","extensions":"extensions"}.get(view, "")), json.dumps({"projects":"projects","second-brain":"secondBrain","models-settings":"models","profiles-admin":"profiles","extensions":"extensions"}.get(view, ""))), label=f"wait for {view} fixture status")

    # Start at the view's actual primary-navigation item, then send real Tab
    # key events. No Enter/Space activation or text submission is sent.
    await devtools.evaluate("""(()=>{
      const button=document.querySelector('.primary-nav .nav-item[data-view='+JSON.stringify(%s)+']');
      if(button){const group=button.closest('.nav-group');if(group&&!group.open)group.querySelector('summary')?.click();button.focus();}
      return Boolean(button);
    })()""" % json.dumps(view), label=f"focus {view} navigation destination")
    steps = []
    for _ in range(5):
        await devtools.call("Input.dispatchKeyEvent", {"type": "rawKeyDown", "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9})
        await devtools.call("Input.dispatchKeyEvent", {"type": "keyUp", "key": "Tab", "code": "Tab", "windowsVirtualKeyCode": 9})
        state = await devtools.evaluate("""(()=>{
          const el=document.activeElement;if(!el)return null;const r=el.getBoundingClientRect();
          const label=el.getAttribute('aria-label')||el.labels?.[0]?.textContent?.trim()||el.innerText?.trim()||el.getAttribute('placeholder')||el.tagName;
          return {tag:el.tagName,role:el.getAttribute('role'),label:String(label).slice(0,80),
            visible:r.width>0&&r.height>0&&getComputedStyle(el).visibility!=='hidden',
            focusVisible:el.matches(':focus-visible'),disabled:Boolean(el.disabled)};
        })()""", label=f"keyboard focus after Tab in {view}")
        steps.append(state)

    await devtools.evaluate("""(async()=>{
      for(const group of document.querySelectorAll('.primary-nav .nav-group')){
        if(group.open)group.open=false;
      }
      await new Promise(resolve=>requestAnimationFrame(()=>requestAnimationFrame(resolve)));
      return [...document.querySelectorAll('.primary-nav .nav-group')].map(group=>({
        open:group.open,ariaExpanded:group.querySelector('summary')?.getAttribute('aria-expanded')??null
      }));
    })()""", label=f"close navigation groups and settle state before capturing {view}")
    state = await devtools.evaluate("""(()=>{
      const currentView=%s;
      const panel=document.querySelector('[data-view-panel='+JSON.stringify(currentView)+']');
      const root=panel?.querySelector('[data-feature-root]')||panel;
      const visible=(el)=>{if(!el||el.hidden)return false;const r=el.getBoundingClientRect(),s=getComputedStyle(el);return r.width>0&&r.height>0&&r.right>0&&r.bottom>0&&r.left<innerWidth&&r.top<innerHeight&&s.display!=='none'&&s.visibility!=='hidden'};
      const navItem=document.querySelector('.primary-nav .nav-item[data-view='+JSON.stringify(currentView)+']');
      const navGroup=navItem?.closest('.nav-group')||null;
      const summary=navGroup?.querySelector('summary')||null;
      const menu=navGroup?.querySelector('.nav-menu,[role="menu"]')||null;
      const menuRect=menu?.getBoundingClientRect()||null;
      const menuRendered=Boolean(menu&&!menu.hidden&&menuRect?.width>0&&menuRect?.height>0&&getComputedStyle(menu).visibility!=='hidden');
      const canonicalGroups=[...document.querySelectorAll('.primary-nav .nav-group[data-nav-group]')];
      const openGroups=canonicalGroups.filter(group=>group.open).map(group=>group.dataset.navGroup);
      const heading=root?.querySelector('h1,h2')||null;
      const primaryControlSelector={
        'models-settings':'[data-models-conversation]',
        'profiles-admin':'[data-profile-select]',
        'extensions':'[data-add-skill] input[name="identifier"]',
        'projects':'[data-project-list] button',
        'second-brain':'[data-note-list] button'
      }[currentView]||null;
      const primaryControl=primaryControlSelector?root?.querySelector(primaryControlSelector):null;
      if(heading&&!visible(heading))heading.scrollIntoView({block:'nearest',inline:'nearest',behavior:'auto'});
      const status=[...root.querySelectorAll('[role=status],[aria-live]')].map(el=>el.textContent.trim()).filter(Boolean).slice(0,5);
      const controls=[...root.querySelectorAll('button,a[href],input,select,textarea,[role=button],[role=tab]')]
        .filter(visible).slice(0,32).map(el=>({tag:el.tagName,type:el.type||null,
          label:(el.getAttribute('aria-label')||el.labels?.[0]?.textContent?.trim()||el.innerText?.trim()||el.placeholder||el.tagName).slice(0,80),
          disabled:Boolean(el.disabled),expanded:el.getAttribute('aria-expanded')}));
      return {panelVisible:visible(panel),heading:heading?.textContent?.trim()||null,headingVisible:visible(heading),
        primaryControlSelector,primaryControlVisible:visible(primaryControl),
        selectedNavigation:{ariaCurrent:navItem?.getAttribute('aria-current')||null,
          groupOpen:navGroup?navGroup.open:null,
          summaryAriaExpanded:summary?.getAttribute('aria-expanded')??null,
          menuRendered},
        navigationGroups:canonicalGroups.map(group=>({name:group.dataset.navGroup,
          open:group.open,summaryAriaExpanded:group.querySelector('summary')?.getAttribute('aria-expanded')??null,
          menuRendered:(()=>{const menu=group.querySelector('.nav-menu,[role="menu"]');
            const rect=menu?.getBoundingClientRect();return Boolean(menu&&!menu.hidden&&rect?.width>0&&rect?.height>0&&getComputedStyle(menu).visibility!=='hidden');})()})),
        openNavigationGroups:openGroups,
        status,controls,projectSelected:currentView==='projects'&&Boolean(root.querySelector('[data-project-list] button[aria-current="true"]')),
        trashRestoreVisible:currentView==='projects'&&[...root.querySelectorAll('[data-trash] button')].some(visible),
        projectDeleteVisible:currentView==='projects'&&visible(root.querySelector('[data-archive]')),
        profileAdminError:root.querySelector('[data-profile-status]')?.textContent?.trim()||null,
        profileAdminEmptyVisible:Boolean(root.querySelector('[data-profile-empty]')&&!root.querySelector('[data-profile-empty]').hidden),
        extensionStatus:root.querySelector('[data-extension-status]')?.textContent?.trim()||null,
        modelStatus:root.querySelector('[data-models-status]')?.textContent?.trim()||null,
        modelApplyDisabled:Boolean(root.querySelector('[data-models-apply]')?.disabled),
        noteTitle:root.querySelector('[data-reader-title]')?.textContent?.trim()||null,
        readerMetadata:(()=>{
          const el=root.querySelector('[data-reader-meta]');if(!el)return null;
          const range=document.createRange();range.selectNodeContents(el);
          const fragments=[...range.getClientRects()].map(r=>({left:r.left,right:r.right,top:r.top,bottom:r.bottom}));
          const bounds=(node)=>{if(!node)return null;const r=node.getBoundingClientRect();return {left:r.left,right:r.right,top:r.top,bottom:r.bottom,width:r.width,height:r.height,clientWidth:node.clientWidth,scrollWidth:node.scrollWidth};};
          const container=el.closest('.brain-reader-heading');
          const containerBounds=bounds(container), elementBounds=bounds(el);
          const renderedRight=fragments.length?Math.max(...fragments.map(r=>r.right)):null;
          const renderedLeft=fragments.length?Math.min(...fragments.map(r=>r.left)):null;
          const clippedByContainer=Boolean(containerBounds&&fragments.some(r=>r.right>containerBounds.right+1||r.left<containerBounds.left-1));
          const clippingAncestors=[];
          for(let node=el.parentElement;node;node=node.parentElement){
            const style=getComputedStyle(node),overflow=style.overflowX;
            if(['hidden','clip','auto','scroll'].includes(overflow)){
              const r=node.getBoundingClientRect(),left=r.left+node.clientLeft,right=left+node.clientWidth;
              if(fragments.some(fragment=>fragment.right>right+1||fragment.left<left-1))
                clippingAncestors.push({tag:node.tagName,id:node.id||null,className:typeof node.className==='string'?node.className:null,overflow,left,right});
            }
          }
          const clippedByViewport=fragments.some(r=>r.right>innerWidth+1||r.left< -1);
          return {text:el.textContent.trim(),textLength:el.textContent.trim().length,
            expectedDigestPresent:el.textContent.includes(%s),element:elementBounds,container:containerBounds,
            renderedLeft,renderedRight,fragmentCount:fragments.length,
            horizontalScrollOverflow:Boolean(elementBounds&&elementBounds.scrollWidth>elementBounds.clientWidth+1),
            clippedByContainer,clippedByAncestor:clippingAncestors.length>0,clippingAncestors,clippedByViewport};
        })(),
        graphStatus:root.querySelector('[data-graph-status]')?.textContent?.trim()||null,
        projectDeleteConfirmation:window.__fixtureConfirmMessage||null,
        focus:document.activeElement?.tagName||null};
    })()""" % (json.dumps(view), json.dumps(FIXTURE_CONTENT_SHA256)), label=f"review state in {view}")
    screenshot = await _screenshot(devtools, output_dir, item, view, state=state)
    checks = {
        "view_panel_visible": bool(state and state.get("panelVisible")),
        "view_heading_visible": bool(state and state.get("heading") and state.get("headingVisible")),
        "primary_feature_control_visible": bool(state and state.get("primaryControlVisible")),
        "selected_feature_remains_selected": bool(state and state.get("selectedNavigation", {}).get("ariaCurrent") == "page"),
        "selected_navigation_group_closed_before_capture": bool(state and (
            state.get("selectedNavigation", {}).get("groupOpen") is None
            or state.get("selectedNavigation", {}).get("groupOpen") is False)
            and state.get("selectedNavigation", {}).get("menuRendered") is False
            and state.get("selectedNavigation", {}).get("summaryAriaExpanded") in (None, "false")),
        "all_navigation_menus_closed_before_capture": bool(state and not state.get("openNavigationGroups")
            and all(group.get("open") is False and group.get("summaryAriaExpanded") == "false"
                    and group.get("menuRendered") is False for group in state.get("navigationGroups", []))),
        "keyboard_reaches_visible_focus": any(step and step.get("visible") for step in steps),
    }
    if view == "projects":
        checks.update({"project_fixture_ready_before_selection": bool(project_fixture_interaction and project_fixture_interaction.get("fixtureRowsReady")),
                       "fixture_project_selected": bool(project_fixture_interaction and project_fixture_interaction.get("selectedFixtureProject")
                                                         and state and state.get("projectSelected")),
                       "project_delete_control_visible_after_selection": bool(project_fixture_interaction and project_fixture_interaction.get("deleteControlVisible")
                                                                                and not any(item.get("clips") for item in (project_fixture_interaction.get("deleteGeometry", {})
                                                                                                                           .get("ancestors", [])))),
                       "retained_trash_restore_control_visible": bool(project_fixture_interaction and project_fixture_interaction.get("trashRestoreVisible")),
                       "project_trash_confirmation_cancelled": bool(project_fixture_interaction and project_fixture_interaction.get("confirmationCancelled")
                                                                     and state and "Move this project to Trash?" in (state.get("projectDeleteConfirmation") or ""))})
    elif view == "second-brain":
        checks.update({"fixture_note_opened": bool(state and state.get("noteTitle") == "Fixture note alpha"),
                       "graph_fixture_rendered": bool(state and "actual note links" in (state.get("graphStatus") or "")),
                       "long_note_digest_metadata_visible_without_horizontal_clipping": bool(
                           state and state.get("readerMetadata")
                           and state["readerMetadata"].get("expectedDigestPresent")
                           and state["readerMetadata"].get("textLength", 0) >= 64
                           and not state["readerMetadata"].get("horizontalScrollOverflow")
                           and not state["readerMetadata"].get("clippedByContainer")
                           and not state["readerMetadata"].get("clippedByAncestor")
                           and not state["readerMetadata"].get("clippedByViewport")
                       )})
    elif view == "models-settings":
        checks.update({"model_settings_failure_is_visible": bool(state and state.get("modelStatus") == "Current model settings are unavailable."),
                       "model_apply_remains_disabled": bool(state and state.get("modelApplyDisabled"))})
    elif view == "profiles-admin":
        valid_search = (profile_fixture_interaction or {}).get("validProfileSearch") or {}
        checks["synthetic_native_profile_is_loaded_and_valid_empty_search_is_visible"] = bool(
            valid_search.get("positiveCatalogLoaded")
            and valid_search.get("searchEmptyVisible")
            and valid_search.get("remainingOptions") == 1
            and "0 matching profiles" in (valid_search.get("matchingProfileCount") or "")
            and state and state.get("profileAdminEmptyVisible")
        )
        if (profile_fixture_interaction or {}).get("invalidDenialTested"):
            invalid = (profile_fixture_interaction or {}).get("invalidDenial") or {}
            checks["invalid_empty_profiles_are_explicitly_unavailable"] = bool(
                invalid.get("explicitUnavailable")
                and invalid.get("invalidEmptyNotReportedAsSearchEmpty")
            )
    elif view == "extensions":
        checks["extension_inventory_is_explicitly_pending"] = bool(state and "pending" in (state.get("extensionStatus") or "").lower())
    if view == "models-settings":
        checks["chat_per_message_model_entry_reachable"] = bool(model_entry and model_entry.get("reachable"))
    return {"view": view, "navigation": navigation, "secondary_entry": model_entry,
            "project_fixture_interaction": project_fixture_interaction,
            "profile_fixture_interaction": profile_fixture_interaction,
            "state": state,
            "keyboard_tab_sequence": steps, "screenshot": screenshot,
            "checks": checks, "failures": [key for key, passed in checks.items() if not passed],
            "mutation_confirmed": False}


async def _viewport_probe(devtools: DevTools, item: dict[str, Any], output_dir: Path,
                          session: ClientSession, devtools_port: int,
                          mobile_browser_harness: str | None = None) -> dict[str, Any]:
    await devtools.call("Page.reload")
    await _wait_ready(devtools)
    await devtools.call("Emulation.setDeviceMetricsOverride", {
        "width": item["width"], "height": item["height"], "deviceScaleFactor": 1,
        "mobile": item["mobile"],
    })
    touch_params = {"enabled": item["mobile"]}
    if item["mobile"]:
        touch_params["maxTouchPoints"] = 1
    await devtools.call("Emulation.setTouchEmulationEnabled", touch_params)
    await devtools.call("Network.enable")
    await devtools.call("Network.emulateNetworkConditions", {
        "offline": False, "latency": 0, "downloadThroughput": -1, "uploadThroughput": -1,
    })
    await devtools.call("Emulation.setEmulatedMedia", {
        "features": [{"name": "prefers-reduced-motion", "value": "no-preference"}],
    })
    mobile_harness_result = None
    if item["mobile"]:
        if mobile_browser_harness is None:
            raise ProbeFailure("mobile chat/Projects browser harness was not loaded")
        try:
            mobile_harness_result = await devtools.evaluate(
                mobile_browser_harness, label="mobile chat drawer/composer and Projects lifecycle harness")
        except ProbeFailure as error:
            mobile_harness_result = {
                "result": "fail", "failure": "mobile harness evaluation raised " + type(error).__name__,
                "checks": {}, "failures": ["harness_execution"],
            }
        if not isinstance(mobile_harness_result, dict):
            mobile_harness_result = {"result": "fail", "failure": "harness returned no structured report", "checks": {}}
        required_harness_checks = (
            "chatNavigationShowsThreadComposer", "selectedChatNavigationRetained",
            "historyDrawerOpensFromControl", "selectionReturnsToUsableComposer",
            "selectionClosesDrawer", "selectedChatComposerAcceptsFocus",
            "modelsCanBeSelectedFromSystem", "systemClosesAfterModelsSelection",
            "modelsHeadingVisibleAfterMenuCloses", "focusMovesToVisibleModelsHeading",
            "projectCreateFormReached", "projectsScopeAbortedBeforeLateResponse",
            "inactiveProjectStatusAndListUnaffectedByLateRead", "oneCreateForOneSubmit",
            "returningToChatShowsComposer", "repeatedChatsOpensDrawer",
            "newChatClosesDrawerAndFocusesComposer",
        )
        required_failures = [
            name for name in required_harness_checks if mobile_harness_result.get("checks", {}).get(name) is not True
        ]
        mobile_harness_result["failures"] = list(dict.fromkeys(
            list(mobile_harness_result.get("failures", [])) + required_failures
        ))
        if mobile_harness_result.get("result") == "pass" and mobile_harness_result["failures"]:
            mobile_harness_result["result"] = "fail"
    canonical_navigation = await _probe_canonical_navigation(devtools)
    overview_nav = await _select_view(devtools, "command-centre", '[data-view="overview"]', "overview")
    await _wait_overview_fixture(devtools)
    overview = await _measure_state(devtools, mode="overview", group="command-centre")
    overview_screenshot = await _screenshot(devtools, output_dir, item, "overview", state=overview)
    chat_nav = await _select_view(devtools, "conversations", '[data-view="chat"]', "chat")
    chat = await _measure_state(devtools, mode="chat", group="conversations")
    if item["mobile"]:
        phone_history = chat["conversationNavigation"]
        chat["checks"].update({
            "phone_chat_landing_keeps_history_drawer_closed": (
                not phone_history["drawerOpen"] and not phone_history["railVisible"]
                and phone_history["historyToggleVisible"]
                and phone_history["historyToggleExpanded"] == "false"
                and phone_history["historyToggleLabel"] == "Show conversations"
            ),
        })
    else:
        chat["checks"]["wide_chat_keeps_persistent_history_rail"] = (
            chat["conversationNavigation"]["railVisible"]
            and not chat["conversationNavigation"]["drawerOpen"]
        )
    chat["failures"] = [name for name, passed in chat["checks"].items() if not passed]
    chat_screenshot = await _screenshot(devtools, output_dir, item, "chat", state=chat)
    chat_journey_screenshots = (
        await _phone_chat_journey_screenshots(devtools, item, output_dir) if item["mobile"] else []
    )
    knowledge_nav = None
    knowledge = None
    if await _is_nav_item_visible(devtools, "second-brain"):
        knowledge_nav = await _select_view(devtools, "knowledge", '[data-view="second-brain"]', "second-brain")
        knowledge = await _measure_state(devtools, mode="knowledge", group="knowledge")
    await _select_view(devtools, "command-centre", '[data-view="overview"]', "overview")
    await _wait_overview_fixture(devtools)
    central_motion = await _probe_central_motion(devtools, session, devtools_port)
    shared_header_motion = await _probe_shared_header_motion(devtools, session, devtools_port)
    failures = [f"overview/{name}" for name in overview["failures"]]
    failures.extend(f"chat/{name}" for name in chat["failures"])
    if mobile_harness_result is not None:
        harness_failures = mobile_harness_result.get("failures", [])
        failures.extend(f"mobile-browser-harness/{name}" for name in harness_failures)
        if mobile_harness_result.get("result") != "pass" and not harness_failures:
            failures.append("mobile-browser-harness/result-not-pass")
    if knowledge:
        failures.extend(f"knowledge/{name}" for name in knowledge["failures"])
    failures.extend(f"overview/motion/{name}" for name in central_motion["failures"])
    failures.extend(f"chat/shared-header-motion/{name}" for name in shared_header_motion["failures"])
    affected = []
    affected_views = (
        ("projects", "", '[data-view="projects"]'),
        ("second-brain", "", '[data-view="second-brain"]'),
        ("models-settings", "system", '[data-view="models-settings"]'),
        ("profiles-admin", "resources", '[data-view="profiles-admin"]'),
        ("extensions", "resources", '[data-view="extensions"]'),
    )
    for affected_view, nav_group, nav_selector in affected_views:
        view_report = await _review_affected_view(
            devtools, view=affected_view, group=nav_group, selector=nav_selector,
            item=item, output_dir=output_dir)
        affected.append(view_report)
        failures.extend(f"{affected_view}/{name}" for name in view_report["failures"])
    return {
        "name": item["name"], "viewport": {"width": item["width"], "height": item["height"]},
        "overview": {**overview, "screenshot": overview_screenshot, "navigation": overview_nav},
        "central_motion": central_motion,
        "shared_header_motion": shared_header_motion,
        "chat": {**chat, "screenshot": chat_screenshot, "navigation": chat_nav,
                 "mobile_journey_screenshots": chat_journey_screenshots},
        "canonical_navigation": canonical_navigation, "knowledge_navigation": knowledge_nav, "knowledge": knowledge,
        "mobile_chat_projects_browser_harness": mobile_harness_result,
        "affected_flow_review": affected,
        "failures": failures,
    }


async def _run(args: argparse.Namespace) -> int:
    global REVIEWED_ASSET_SHA256
    if platform.machine() != "aarch64":
        raise ProbeFailure(f"Pi-only guard: expected aarch64, found {platform.machine()!r}")
    if os.geteuid() == 0:
        raise ProbeFailure("run as the normal Pi account so Chromium keeps its sandbox enabled")
    if not args.chromium.is_file() or not os.access(args.chromium, os.X_OK):
        raise ProbeFailure(f"Chromium is not executable at {args.chromium}")

    source_root = args.source_root.resolve(strict=True)
    package_parents = (source_root / "src", source_root)
    package_parent = next((candidate for candidate in package_parents
                           if (candidate / "hermes_installer/remote/jarvis_chat_assets.py").is_file()), None)
    if package_parent is None:
        raise ProbeFailure(
            "source root must contain src/hermes_installer/... or hermes_installer/...: "
            f"{source_root}"
        )
    source_top: str | None = None
    source_commit: str | None = None
    try:
        source_top = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "--show-toplevel"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
        source_commit = subprocess.run(
            ["git", "-C", str(source_root), "rev-parse", "HEAD"],
            check=True, capture_output=True, text=True, timeout=5,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        # Pi may receive the reviewed `ui-<commit>-source` tree without .git.
        # Exact served-asset digests remain in the report in that case.
        source_top = None
        source_commit = None

    sys.path.insert(0, str(package_parent))
    try:
        from hermes_installer.remote.jarvis_chat_assets import reviewed_chat_asset
    except Exception as error:
        raise ProbeFailure(f"could not import the reviewed Jarvis asset registry: {type(error).__name__}: {error}") from None
    assets: dict[str, tuple[str, bytes]] = {}
    for path in ASSET_PATHS:
        try:
            content_type, content = reviewed_chat_asset(path)
        except Exception as error:
            raise ProbeFailure(f"reviewed asset lookup failed for {path}: {type(error).__name__}: {error}") from None
        if not isinstance(content, bytes) or len(content) > 3_000_000:
            raise ProbeFailure(f"reviewed asset has invalid type or exceeds 3 MiB: {path}")
        assets[path] = (content_type, content)
    REVIEWED_ASSET_SHA256 = {
        path: hashlib.sha256(body).hexdigest() for path, (_mime, body) in assets.items()
    }

    _refresh_fixture_observation_time()
    if args.output_dir.is_symlink():
        raise ProbeFailure("output directory must not be a symlink")
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    if any(output_dir.iterdir()):
        raise ProbeFailure("output directory must be empty; choose a new v24 evidence directory")
    fixture_cookie = secrets.token_urlsafe(32)
    app = web.Application(client_max_size=1024)
    app["fixture_cookie"] = fixture_cookie
    app["asset_getter"] = assets.__getitem__
    app["fixture_requests"] = []
    app["unexpected_api"] = []
    app["unexpected_paths"] = []
    app.router.add_route("*", "/{tail:.*}", _fixture_route)
    runner = web.AppRunner(app, access_log=None)
    chromium_process: asyncio.subprocess.Process | None = None
    devtools_ws = None
    temp_root: Path | None = None
    try:
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0, backlog=8)
        await site.start()
        sockets = site._server.sockets if site._server else []
        if not sockets:
            raise ProbeFailure("loopback fixture server did not bind")
        port = sockets[0].getsockname()[1]
        temp_root = Path(tempfile.mkdtemp(prefix="hermes-visual-probe-"))
        with nullcontext(str(temp_root)) as temp_name:
            temp_root = Path(temp_name)
            profile = temp_root / "chromium-profile"
            profile.mkdir(mode=0o700)
            chromium_process, devtools_port = await _wait_for_chromium(args.chromium, profile)
            async with ClientSession() as session:
                devtools_ws, target_id = await _devtools_target(session, devtools_port)
                devtools = DevTools(devtools_ws)
                await devtools.call("Page.enable")
                await devtools.call("Runtime.enable")
                await devtools.call("Emulation.setEmulatedMedia", {
                    "features": [{"name": "prefers-reduced-motion", "value": "reduce"}],
                })
                await devtools.call("Page.navigate", {"url": f"http://127.0.0.1:{port}/chat"})
                await _wait_ready(devtools)
                mobile_browser_harness = _load_mobile_browser_harness()

                reports = []
                for viewport in VIEWPORTS:
                    reports.append(await _viewport_probe(devtools, viewport, output_dir,
                                                         session, devtools_port,
                                                         mobile_browser_harness if viewport["mobile"] else None))

            # _viewport_probe places purpose checks and motion checks together
            # in this canonical list. Derive the exit grade from it so a failed
            # motion gate cannot disappear from the summary.
            failed = [f"{item['name']}/{check}" for item in reports for check in item["failures"]]
            fixture_requests = list(app["fixture_requests"])
            unexpected_api = list(app["unexpected_api"])
            unexpected_paths = list(app["unexpected_paths"])
            if unexpected_api:
                failed.append("only_allowlisted_fixture_API_requests")
            if unexpected_paths:
                failed.append("only_allowlisted_loopback_paths")
            if not fixture_requests:
                failed.append("authenticated_fixture_API_was_used")
            phone_harness = next((item.get("mobile_chat_projects_browser_harness") for item in reports
                                  if item.get("mobile_chat_projects_browser_harness") is not None), None)
            if not isinstance(phone_harness, dict) or phone_harness.get("result") != "pass":
                failed.append("phone_mobile_chat_projects_browser_harness")
            report = {
                "schema_version": 2,
                "evidence_class": "local-authenticated-fixture-layout-only",
                "created_by": "probe_jarvis_affected_flows_compat226.py",
                "compatibility_provenance": COMPATIBILITY_PROVENANCE,
                "python": sys.version.split()[0],
                "chromium": str(args.chromium),
                "source": {"root": str(source_root), "package_parent": str(package_parent),
                           "git_top_level": source_top, "git_commit": source_commit},
                "mobile_chat_projects_harness": {
                    "path": str(Path(__file__).resolve().parent / MOBILE_BROWSER_HARNESS_RELATIVE),
                    "sha256": MOBILE_BROWSER_HARNESS_SHA256,
                    "source_harness_sha256": MOBILE_BROWSER_HARNESS_SOURCE_SHA256,
                    "report": phone_harness,
                    "scope": "phone-only Chromium UI harness; all /chat/api calls are in-memory fetch stubs",
                },
                "assets": {
                    path: {"content_type": mime, "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                    for path, (mime, body) in assets.items()
                },
                "fixture": {
                    "authentication": "per-run random HttpOnly loopback cookie; no real account or secret",
                    "synthetic_observed_at": FIXTURE_OVERVIEW["core"]["observedAt"],
                    "conversation_id": FIXTURE_CONVERSATION_ID,
                    "conversation_title": FIXTURE_TITLE,
                    "api_requests": fixture_requests,
                    "unexpected_api_requests": unexpected_api,
                    "unexpected_paths": unexpected_paths,
                    "live_fixture_server_mutations": "none; non-allowlisted methods and routes return 404",
                    "in_memory_fetch_mutations": "phone harness intercepts fake conversation/project POSTs in window.fetch; no request reaches the fixture server or a target",
                    "provider_or_model_traffic": "none",
                    "microphone_permission": "denied by Permissions-Policy; no capture requested",
                    "external_requests": "blocked by same-origin CSP and Chromium host resolver rule",
                    "synthetic_reads": "Projects, Models, Profiles, Extensions, and two Obsidian notes are deterministic local fixtures",
                    "interactions": "exact navigation, keyboard Tab traversal, project/note selection, local graph-tag filter, bounded mobile chat drawer/composer journey, and in-memory Projects lifecycle harness",
                    "prohibited_actions": "no live message submit, restore, delete, project save, profile save, extension mutation, model apply, audio, or microphone",
                },
                "viewports": reports,
                "failed_checks": failed,
                "result": "pass" if not failed else "fail",
                "exit_code": 0 if not failed else 1,
                "limits": [
                    "Layout and navigation evidence uses synthetic local fixtures only.",
                    "It does not prove Cloudflare Access, owner authentication, live Hermes APIs, model use, or Pi production readiness.",
                    "The probe never sends a conversation turn or activates voice input/output.",
                    "Fixture clicks/focus and synthetic route responses do not establish live account, vault, native-resource, save, restore, or mobile-device acceptance.",
                ],
            }
            report_path = output_dir / "responsive-fixture-report-compat226.json"
            report_path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            duration_samples = [
                {
                    "viewport": item["name"],
                    "before_transition_seconds": item["overview"]["reducedMotion"]["presenceBeforeTransitionSeconds"],
                    "before_animation_seconds": item["overview"]["reducedMotion"]["presenceBeforeAnimationSeconds"],
                }
                for item in reports
            ]
            touch_violation_samples = [
                {
                    "viewport": item["name"], "mode": mode,
                    "selector": target["selector"], "label": target["label"],
                    "input_type": target["inputType"],
                    "raw_width": target["width"], "raw_height": target["height"],
                    "effective_width": target["effectiveWidth"],
                    "effective_height": target["effectiveHeight"],
                    "associated_label": target["associatedLabel"],
                }
                for item in reports for mode in ("overview", "chat", "knowledge") if item.get(mode)
                for target in item[mode]["touchViolations"]
            ][:24]
            print(json.dumps({
                "result": report["result"], "exit_code": report["exit_code"], "report": str(report_path),
                "screenshots": [
                    {"route": capture["route"], "viewport": capture["viewport"],
                     "jpeg": capture["jpeg"]}
                    for item in reports
                    for capture in ([item["overview"]["screenshot"], item["chat"]["screenshot"]]
                                    + item["chat"].get("mobile_journey_screenshots", [])
                                    + [flow["screenshot"] for flow in item["affected_flow_review"]])
                ],
                "failed_checks": failed,
                "mobile_chat_projects_harness": phone_harness,
                "diagnostics": {
                    "presence_css_durations_at_layout_sample": duration_samples,
                    "central_motion_by_viewport": [
                        {"viewport": item["name"], "checks": item["central_motion"]["checks"],
                         "foreground_central_running": item["central_motion"]["foreground"]["centralRunning"],
                         "foreground_changed_targets": item["central_motion"]["foreground"]["changedTargets"],
                         "reduced_active_animation_count": len(item["central_motion"]["reduced_motion"]["allRunningAnimations"]),
                         "hidden_visibility": item["central_motion"]["hidden"]["first"]["documentVisibility"],
                         "offline_navigator_state": item["central_motion"]["offline"]["first"]["navigatorOnline"]}
                        for item in reports
                    ],
                    "visible_control_size_violations_first_24": touch_violation_samples,
                    "direct_nav_inventory_phone": reports[0]["overview"]["primaryNavItems"],
                    "overview_purpose_checks": [
                        {"viewport": item["name"], "presence_stage_visible": item["overview"]["viewStage"]["visible"],
                         "feature_contract": item["overview"]["overviewFeatureContract"],
                         "quick_command": item["overview"]["overviewQuickCommand"],
                         "new_chat_button": item["overview"]["overviewNewChatButton"],
                         "chat_nav_reachable": item["overview"]["chatNavigation"]["visible"]}
                        for item in reports
                    ],
                    "chat_purpose_checks": [
                        {"viewport": item["name"], "native_textarea_visible": item["chat"]["textarea"]["visible"] and item["chat"]["textarea"]["native"],
                         "composer_visible": item["chat"]["composer"]["visible"],
                         "per_message_model_and_reasoning_controls_visible": item["chat"]["perMessageControls"]["containerVisible"]
                             and item["chat"]["perMessageControls"]["modelVisible"]
                             and item["chat"]["perMessageControls"]["reasoningVisible"],
                         "conversation_rail_visible": item["chat"]["conversationNavigation"]["railVisible"],
                         "history_drawer_open": item["chat"]["conversationNavigation"]["drawerOpen"],
                         "nav_overlaps_composer": item["chat"]["bottomNav"]["overlapsComposer"],
                         "chat_nav_reachable": item["chat"]["chatNavigation"]["visible"]}
                        for item in reports
                    ],
                    "canonical_navigation_by_viewport": [item["canonical_navigation"] for item in reports],
                    "knowledge_navigation_by_viewport": [item["knowledge_navigation"] for item in reports],
                    "knowledge_purpose_checks": [item["knowledge"]["checks"] if item["knowledge"] else None for item in reports],
                },
            }, indent=2, ensure_ascii=False))
            return 0 if not failed else 1
    finally:
        active_error = sys.exception()
        cleanup_errors: list[str] = []
        if devtools_ws is not None and not devtools_ws.closed:
            try:
                await devtools_ws.close()
            except Exception as error:
                cleanup_errors.append(f"DevTools websocket cleanup: {type(error).__name__}: {error}")
        chromium_stopped = chromium_process is None and not getattr(active_error, "retain_profile", False)
        if chromium_process is not None:
            try:
                await _stop_chromium(chromium_process)
                chromium_stopped = True
            except Exception as error:
                chromium_stopped = False
                cleanup_errors.append(f"Chromium shutdown: {type(error).__name__}: {error}")
        if temp_root is not None and chromium_stopped:
            try:
                _remove_owned_profile(temp_root)
            except Exception as error:
                cleanup_errors.append(f"temporary profile cleanup: {type(error).__name__}: {error}")
        try:
            await runner.cleanup()
        except Exception as error:
            cleanup_errors.append(f"fixture server cleanup: {type(error).__name__}: {error}")
        if cleanup_errors:
            detail = "; ".join(cleanup_errors)
            if active_error is not None:
                active_error.add_note(f"Cleanup also reported: {detail}")
            else:
                raise ProbeFailure(f"cleanup failed: {detail}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True,
                        help="top-level selected HermesInstaller checkout on the Pi")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="directory for fixture screenshots and JSON evidence")
    parser.add_argument("--chromium", type=Path, default=Path("/usr/bin/chromium"),
                        help="Pi Chromium executable (default: /usr/bin/chromium)")
    args = parser.parse_args()
    try:
        return asyncio.run(_run(args))
    except (ProbeFailure, OSError, web.HTTPException) as error:
        print(f"responsive fixture probe failed safely: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
