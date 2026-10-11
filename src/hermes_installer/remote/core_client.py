"""Finite, server-side client for the pinned Hermes ``hermes serve`` TUI gateway.

This module deliberately implements the tiny JSON-RPC subset the Jarvis chat adapter needs.
It never relays arbitrary methods or exposes the service token/runtime session ids to a browser.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import inspect
import json
import math
import re
import secrets
from dataclasses import dataclass
from typing import Any, AsyncIterator, Callable, Literal, Mapping
from urllib.parse import quote

from .jarvis_chat import JarvisChatDenied, _read_private_secret
from .jarvis_activity import NativeActivityEvent, _STATUSES, _USAGE_FIELDS
from .jarvis_model_catalog import CODEX_KNOWN_MODEL_ID_SET, CODEX_MODEL_ID_SET, CODEX_PROVIDER_ID

CORE_PORT = 8766
CORE_PATH = "/api/ws"
MAX_RPC_FRAME_BYTES = 256 * 1024
MAX_CORE_TEXT_CHARS = 64_000
MAX_FILE_ATTACHMENT_BYTES = 128 * 1024
_ATTACHMENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$")


@dataclass(frozen=True, slots=True)
class NativeFileAttachment:
    """Private native @file reference returned by the pinned attach RPC."""

    name: str
    ref_text: str


def _valid_session_id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 512
            and not any(ord(char) < 0x20 for char in value))


@dataclass(frozen=True, slots=True)
class CoreTurnEvent:
    kind: Literal["delta", "complete", "failed", "cancelled", "activity"]
    text: str = ""
    activity: NativeActivityEvent | None = None


class CoreRpcClient:
    """Calls a fixed loopback Hermes WebSocket with a protected systemd credential.

    ``token_file`` is the protected credential source used by the fixed headless ``hermes serve``
    LoadCredential. It is read afresh for every connection. Endpoint, port and RPC methods cannot come from the
    HTTP request. The pinned Hermes websocket accepts its loopback dashboard token as ``?token=``.
    """

    def __init__(self, *, token_file=None, token_owner_uid: int = 0,
                 token_group_gid: int = 981, timeout_seconds: float = 15.0):
        from pathlib import Path
        if token_file is None:
            token_file = Path("/etc/hermes-installer/jarvis-core/session-token")
        if not isinstance(token_file, Path) or not token_file.is_absolute():
            raise ValueError("absolute protected Hermes credential path required")
        if (type(token_owner_uid) is not int or token_owner_uid < 0
                or type(token_group_gid) is not int or token_group_gid < 0
                or not 1 <= timeout_seconds <= 60):
            raise ValueError("invalid protected Hermes client settings")
        self._token_file = token_file
        self._token_owner_uid = token_owner_uid
        self._token_group_gid = token_group_gid
        self._timeout_seconds = timeout_seconds

    def _url(self) -> str:
        token = _read_private_secret(self._token_file, owner_uid=self._token_owner_uid,
                                     allowed_group=self._token_group_gid)
        return f"ws://127.0.0.1:{CORE_PORT}{CORE_PATH}?token={quote(token, safe='')}"

    async def _connect(self):
        from aiohttp import ClientSession, ClientTimeout, WSMsgType
        client = ClientSession(timeout=ClientTimeout(total=self._timeout_seconds, connect=2))
        try:
            ws = await client.ws_connect(self._url(), heartbeat=15,
                                         max_msg_size=MAX_RPC_FRAME_BYTES,
                                         receive_timeout=None)
        except Exception:
            await client.close()
            raise JarvisChatDenied("official core gateway is unavailable") from None
        # Each caller closes both resources, including on cancellation.
        return client, ws, WSMsgType

    async def _receive(self, ws, ws_types, *, expected_id: str | None = None,
                       session_id: str | None = None, deadline: float | None = None,
                       early_events: list[dict] | None = None) -> dict:
        while True:
            timeout = self._timeout_seconds
            if deadline is not None:
                timeout = min(timeout, max(0.05, deadline - asyncio.get_running_loop().time()))
            try:
                message = await asyncio.wait_for(ws.receive(), timeout=timeout)
            except asyncio.TimeoutError:
                if deadline is not None and asyncio.get_running_loop().time() < deadline:
                    continue
                raise JarvisChatDenied("official core gateway response was incomplete") from None
            except Exception:
                raise JarvisChatDenied("official core gateway response was incomplete") from None
            if message.type in {ws_types.CLOSED, ws_types.CLOSE, ws_types.ERROR}:
                raise JarvisChatDenied("official core gateway disconnected")
            if message.type != ws_types.TEXT or not isinstance(message.data, str):
                continue
            if len(message.data.encode("utf-8", "replace")) > MAX_RPC_FRAME_BYTES:
                raise JarvisChatDenied("official core gateway frame exceeded its bound")
            try:
                frame = json.loads(message.data)
            except (ValueError, TypeError):
                raise JarvisChatDenied("official core gateway frame was invalid") from None
            if not isinstance(frame, dict):
                continue
            if expected_id is not None and frame.get("id") == expected_id:
                if "error" in frame:
                    raise JarvisChatDenied("official core gateway rejected the request")
                result = frame.get("result")
                if not isinstance(result, dict):
                    raise JarvisChatDenied("official core gateway result was invalid")
                return result
            if session_id is not None and frame.get("method") in {"event", "approval"}:
                params = frame.get("params")
                direct_match = isinstance(params, dict) and params.get("session_id") == session_id
                payload = params.get("payload") if isinstance(params, dict) else None
                global_approval = (isinstance(params, dict) and params.get("type") == "approval.cancelled"
                                   and isinstance(payload, dict) and payload.get("session_id") == session_id)
                if direct_match or global_approval:
                    if early_events is not None:
                        if len(early_events) >= 128:
                            raise JarvisChatDenied("official core sent too many early events")
                        early_events.append(frame)
                    else:
                        return frame

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict:
        # Method names are not parameters to public endpoints; this still defends internal misuse.
        if method not in {"session.create", "session.resume", "session.history", "session.interrupt",
                          "profiles.list", "cron.manage", "plugins.list", "mcp.servers.status",
                          "file.attach", "tools.list", "skills.manage", "config.get", "config.set"}:
            raise JarvisChatDenied("core method is outside the fixed adapter")
        client, ws, ws_types = await self._connect()
        request_id = secrets.token_hex(12)
        try:
            await ws.send_json({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
            return await self._receive(ws, ws_types, expected_id=request_id)
        except JarvisChatDenied:
            raise
        except Exception:
            raise JarvisChatDenied("official core gateway request failed") from None
        finally:
            await ws.close()
            await client.close()

    async def get_model_provider_status(self) -> dict[str, Any]:
        """Read the pinned gateway's sanitized provider/model status.

        ``config.get provider`` includes a provider inventory. Only the Codex
        credential-presence boolean is projected; no provider rows or config
        values leave this method. This does not prove login validity or access.
        """
        result = await self._rpc("config.get", {"key": "provider"})
        model = result.get("model")
        provider = result.get("provider")
        providers = result.get("providers")
        if (not isinstance(model, str) or not 1 <= len(model) <= 160
                or any(ord(char) < 0x20 for char in model)
                or not isinstance(provider, str) or provider not in {"unknown", CODEX_PROVIDER_ID}
                or not isinstance(providers, list) or len(providers) > 128):
            raise JarvisChatDenied("official core model status was invalid")
        codex_rows = []
        for row in providers:
            if not isinstance(row, dict):
                raise JarvisChatDenied("official core provider status was invalid")
            provider_id = row.get("id")
            if (not isinstance(provider_id, str) or not 1 <= len(provider_id) <= 64
                    or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", provider_id)):
                raise JarvisChatDenied("official core provider status was invalid")
            if provider_id == CODEX_PROVIDER_ID:
                authenticated = row.get("authenticated")
                if type(authenticated) is not bool:
                    raise JarvisChatDenied("official core Codex credential status was invalid")
                codex_rows.append(authenticated)
        if len(codex_rows) > 1:
            raise JarvisChatDenied("official core Codex provider status was ambiguous")
        return {
            "model": model,
            "provider_hint": provider,
            "codex_credential_configured": codex_rows[0] if codex_rows else None,
            "known_model": model in CODEX_KNOWN_MODEL_ID_SET,
        }

    async def _rpc_on_socket(self, ws: Any, ws_types: Any, method: str,
                             params: dict[str, Any]) -> dict[str, Any]:
        """Issue one finite RPC without changing the native session's socket binding."""
        if method not in {"session.resume", "config.set"}:
            raise JarvisChatDenied("core method is outside the fixed model adapter")
        request_id = secrets.token_hex(12)
        try:
            await ws.send_json({"jsonrpc": "2.0", "id": request_id,
                                "method": method, "params": params})
            return await self._receive(ws, ws_types, expected_id=request_id)
        except JarvisChatDenied:
            raise
        except Exception:
            raise JarvisChatDenied("official core model request failed") from None

    async def set_session_model(self, stored_session_id: str, model_id: str, *,
                                before_set: Callable[[str], Any]) -> dict[str, Any]:
        """Resume an owned durable session, then set its model on that same socket.

        The browser cannot supply a native command, provider, key, or config
        key. ``--session`` is always included so the native parser cannot turn
        this request into a profile-default write. The callback atomically binds
        the actual resumed runtime ID to the already-reserved owner conversation
        before config.set runs. Keeping resume and set on one WebSocket avoids
        Hermes detaching the session between RPCs.
        """
        if (not _valid_session_id(stored_session_id) or not isinstance(model_id, str)
                or model_id not in CODEX_MODEL_ID_SET or not callable(before_set)):
            raise JarvisChatDenied("model selection is outside the fixed session adapter")
        value = f"{model_id} --provider {CODEX_PROVIDER_ID} --session"
        client, ws, ws_types = await self._connect()
        try:
            resumed = await self._rpc_on_socket(ws, ws_types, "session.resume", {
                "session_id": stored_session_id, "source": "jarvis",
            })
            runtime_id = resumed.get("session_id")
            if (not _valid_session_id(runtime_id) or resumed.get("resumed") != stored_session_id):
                raise JarvisChatDenied("official core resume did not confirm the owned session")
            binding = before_set(runtime_id)
            if inspect.isawaitable(binding):
                binding = await binding
            if binding is not True:
                raise JarvisChatDenied("owned model session binding was not confirmed")
            result = await self._rpc_on_socket(ws, ws_types, "config.set", {
                "key": "model", "value": value, "session_id": runtime_id,
            })
        finally:
            await ws.close()
            await client.close()
        if (result.get("key") != "model" or result.get("value") != model_id
                or result.get("scope") != "session"
                or type(result.get("confirm_required")) is not bool
                or not isinstance(result.get("warning"), str)
                or not isinstance(result.get("confirm_message"), str)):
            raise JarvisChatDenied("official core model selection response was invalid")
        deferred = result.get("deferred", False)
        if type(deferred) is not bool:
            raise JarvisChatDenied("official core model selection response was invalid")
        if result["confirm_required"] or result["warning"] or result["confirm_message"]:
            state = "confirmation-required"
        elif deferred:
            state = "deferred-next-turn"
        else:
            state = "selected-for-session"
        return {"model": model_id, "state": state}

    @staticmethod
    def _bounded_profile_text(value: Any, *, limit: int = 160) -> str | None:
        if not isinstance(value, str):
            return None
        value = value.strip()
        if not value or len(value) > limit or any(ord(char) < 0x20 for char in value):
            return None
        return value

    async def list_profiles(self) -> list[dict[str, Any]]:
        """Return at most the default row, with no filesystem/session/roster metadata."""
        result = await self._rpc("profiles.list", {"include_sessions": False})
        rows = result.get("profiles")
        if not isinstance(rows, list) or len(rows) > 512:
            raise JarvisChatDenied("official core profile status was invalid")
        defaults = [row for row in rows if isinstance(row, dict) and row.get("is_default") is True]
        if not defaults:
            return []
        if len(defaults) != 1:
            raise JarvisChatDenied("official core default profile was ambiguous")
        row = defaults[0]
        name = self._bounded_profile_text(row.get("name"), limit=96)
        if name is None:
            raise JarvisChatDenied("official core default profile was invalid")
        return [{
            "name": name,
            "display_name": self._bounded_profile_text(row.get("display_name")) or name,
            "is_default": True,
        }]

    async def list_schedules(self) -> list[dict[str, Any]]:
        """Read the current gateway process profile's schedule store; no profile selector."""
        result = await self._rpc("cron.manage", {"action": "list", "include_disabled": True})
        rows = result.get("jobs")
        if result.get("success") is not True:
            raise JarvisChatDenied("official core schedule read was not confirmed")
        if not isinstance(rows, list) or len(rows) > 512:
            raise JarvisChatDenied("official core schedule status was invalid")
        projected = []
        allowed_states = {"scheduled", "paused", "disabled", "running", "pending", "completed",
                          "error", "blocked_config", "ok", "delivery_queued", "delivery_failed", "failed"}
        for row in rows:
            if not isinstance(row, dict):
                raise JarvisChatDenied("official core schedule row was invalid")
            job_id = self._bounded_profile_text(row.get("job_id"), limit=256)
            if job_id is None:
                raise JarvisChatDenied("official core schedule row was invalid")
            def timestamp(key: str) -> str | None:
                value = row.get(key)
                if not isinstance(value, str) or len(value) > 96 or any(ord(c) < 0x20 for c in value):
                    return None
                return value or None
            status = row.get("last_status")
            state = row.get("state")
            projected.append({
                "job_id": job_id,
                # _format_job falls back to prompt[:50] when there is no explicit label. Never
                # forward that ambiguous field to Jarvis; native content stays private.
                "name": "Scheduled job",
                "enabled": row.get("enabled") if type(row.get("enabled")) is bool else None,
                "schedule": self._bounded_profile_text(row.get("schedule"), limit=96),
                "next_run_at": timestamp("next_run_at"),
                "last_run_at": timestamp("last_run_at"),
                "last_status": status if isinstance(status, str) and status in allowed_states else None,
                "state": state if isinstance(state, str) and state in allowed_states else "unknown",
                "paused_at": timestamp("paused_at"),
            })
        return projected

    async def list_plugins(self) -> list[dict[str, Any]]:
        """Return only the pinned gateway's loaded-plugin label/version/enabled snapshot."""
        result = await self._rpc("plugins.list", {})
        rows = result.get("plugins")
        if not isinstance(rows, list) or len(rows) > 512:
            raise JarvisChatDenied("official core plugin status was invalid")
        projected = []
        for row in rows:
            if not isinstance(row, dict):
                raise JarvisChatDenied("official core plugin row was invalid")
            name = self._bounded_profile_text(row.get("name"), limit=96)
            version = self._bounded_profile_text(row.get("version"), limit=64)
            enabled = row.get("enabled")
            if name is None or version is None or type(enabled) is not bool:
                raise JarvisChatDenied("official core plugin row was invalid")
            projected.append({"name": name, "version": version, "enabled": enabled})
        return projected

    async def mcp_status(self) -> dict[str, Any]:
        """Read cached MCP connection states; native status RPC does not probe/connect."""
        result = await self._rpc("mcp.servers.status", {})
        rows = result.get("servers")
        checked_at = result.get("checked_at")
        if (not isinstance(rows, list) or len(rows) > 512
                or type(checked_at) is not int or not 0 <= checked_at <= 2**53 - 1):
            raise JarvisChatDenied("official core MCP status was invalid")
        statuses = {"connected", "disabled", "connecting", "failed", "lazy", "configured"}
        projected = []
        for row in rows:
            if not isinstance(row, dict):
                raise JarvisChatDenied("official core MCP row was invalid")
            name = self._bounded_profile_text(row.get("name"), limit=96)
            transport = self._bounded_profile_text(row.get("transport"), limit=48)
            tools = row.get("tools")
            connected, disabled = row.get("connected"), row.get("disabled")
            status = row.get("status")
            if (name is None or transport is None or type(tools) is not int or not 0 <= tools <= 100_000
                    or type(connected) is not bool or type(disabled) is not bool or status not in statuses):
                raise JarvisChatDenied("official core MCP row was invalid")
            projected.append({"name": name, "transport": transport, "tools": tools,
                              "connected": connected, "disabled": disabled, "status": status})
        return {"servers": projected, "checked_at": checked_at}

    async def toolsets_inventory(self) -> list[dict[str, Any]]:
        """Read the fixed default-profile toolset selection and resolved tool names."""
        result = await self._rpc("tools.list", {})
        rows = result.get("toolsets")
        if not isinstance(rows, list) or len(rows) > 256:
            raise JarvisChatDenied("official core toolset inventory was invalid")
        projected: list[dict[str, Any]] = []
        total_tools = 0
        for row in rows:
            if not isinstance(row, dict):
                raise JarvisChatDenied("official core toolset row was invalid")
            name = self._bounded_profile_text(row.get("name"), limit=96)
            count, enabled, tools = row.get("tool_count"), row.get("enabled"), row.get("tools")
            if (name is None or type(count) is not int or not 0 <= count <= 10_000
                    or type(enabled) is not bool or not isinstance(tools, list) or len(tools) > 512):
                raise JarvisChatDenied("official core toolset row was invalid")
            safe_tools = []
            for tool in tools:
                label = self._bounded_profile_text(tool, limit=128)
                if label is None:
                    raise JarvisChatDenied("official core tool name was invalid")
                safe_tools.append(label)
            total_tools += len(safe_tools)
            if total_tools > 2_000:
                raise JarvisChatDenied("official core toolset inventory exceeded its bound")
            projected.append({"name": name, "tool_count": count, "enabled": enabled,
                              "tools": safe_tools})
        return projected

    async def skills_inventory(self) -> list[dict[str, Any]]:
        """List locally available default-profile skill labels without hub or install calls."""
        result = await self._rpc("skills.manage", {"action": "list"})
        groups = result.get("skills")
        if not isinstance(groups, dict) or len(groups) > 256:
            raise JarvisChatDenied("official core skill inventory was invalid")
        projected: list[dict[str, Any]] = []
        total_skills = 0
        for category, values in sorted(groups.items()):
            safe_category = self._bounded_profile_text(category, limit=96)
            if safe_category is None or not isinstance(values, list) or len(values) > 2_000:
                raise JarvisChatDenied("official core skill category was invalid")
            names = []
            for value in values:
                name = self._bounded_profile_text(value, limit=128)
                if name is None:
                    raise JarvisChatDenied("official core skill name was invalid")
                names.append(name)
            total_skills += len(names)
            if total_skills > 2_000:
                raise JarvisChatDenied("official core skill inventory exceeded its bound")
            projected.append({"category": safe_category, "names": names})
        return projected

    async def pause_schedule(self, job_id: str) -> None:
        """Pause exactly one server-selected job and confirm the native paused state."""
        if (not isinstance(job_id, str) or not 1 <= len(job_id) <= 256
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in job_id)):
            raise JarvisChatDenied("official core schedule selection was invalid")
        result = await self._rpc("cron.manage", {"action": "pause", "name": job_id})
        job = result.get("job")
        if (result.get("success") is not True or not isinstance(job, dict)
                or job.get("state") != "paused"
                or (job.get("job_id") is not None and job.get("job_id") != job_id)):
            raise JarvisChatDenied("official core schedule pause was not confirmed")

    async def attach_file(self, session_id: str, *, name: str, media_type: str,
                          content: bytes) -> NativeFileAttachment:
        """Stage bounded server-provided bytes in one live owned session.

        The adapter always sends an empty native ``path`` and constructs the data URL itself;
        callers cannot select a gateway filesystem path or the RPC method/params.
        """
        if (not _valid_session_id(session_id) or not isinstance(name, str)
                or not _ATTACHMENT_NAME_RE.fullmatch(name) or ".." in name
                or media_type not in {"text/plain", "text/markdown", "text/csv", "application/json"}
                or not isinstance(content, bytes) or not 1 <= len(content) <= MAX_FILE_ATTACHMENT_BYTES):
            raise JarvisChatDenied("file attachment is outside the fixed adapter bounds")
        encoded = base64.b64encode(content).decode("ascii")
        result = await self._rpc("file.attach", {
            "session_id": session_id,
            "path": "",
            "data_url": f"data:{media_type};base64,{encoded}",
            "name": name,
        })
        returned_name, ref_text = result.get("name"), result.get("ref_text")
        if (result.get("attached") is not True or result.get("uploaded") is not True
                or not isinstance(returned_name, str) or not 1 <= len(returned_name) <= 160
                or any(ord(char) < 0x20 for char in returned_name)
                or not isinstance(ref_text, str) or not ref_text.startswith("@file:")
                or len(ref_text) > 4096 or any(ord(char) < 0x20 for char in ref_text)):
            raise JarvisChatDenied("official core file attachment was not confirmed")
        return NativeFileAttachment(name=returned_name, ref_text=ref_text)

    @staticmethod
    def _activity_from_frame(frame: Mapping[str, Any], session_id: str) -> NativeActivityEvent | None:
        """Validate/project one pinned Hermes event or approval request without raw payload retention."""
        method = frame.get("method")
        params = frame.get("params")
        if not isinstance(params, dict):
            return None
        event_type = ""
        payload: Mapping[str, Any] = params
        native_id: Any = None
        if method == "approval":
            if params.get("session_id") != session_id:
                return None
            event_type, native_id = "approval", frame.get("id")
            status = "pending"
        elif method == "event":
            event_type = params.get("type") if isinstance(params.get("type"), str) else ""
            candidate = params.get("payload")
            if not isinstance(candidate, dict):
                return None
            payload = candidate
            if params.get("session_id") != session_id:
                if not (event_type == "approval.cancelled" and payload.get("session_id") == session_id):
                    return None
        else:
            return None
        if event_type not in {
                "tool.start", "tool.complete", "tool.generating", "status.update",
                "subagent.spawn_requested", "subagent.start", "subagent.progress",
                "subagent.thinking", "subagent.tool", "subagent.complete",
                "approval", "approval.cancelled", "request.cancel", "todo.updated", "session.usage",
                "message.complete"}:
            return None
        duration = None
        identity: str | None = None
        usage: tuple[tuple[str, int], ...] | None = None
        if event_type in {"tool.start", "tool.complete"}:
            native_id = payload.get("tool_id")
            status = "running" if event_type == "tool.start" else "returned"
            raw_duration = payload.get("duration_s")
            if type(raw_duration) in (int, float) and math.isfinite(raw_duration) and 0 <= raw_duration <= 3600:
                duration = round(raw_duration * 1000)
        elif event_type == "tool.generating":
            status = "generating"
        elif event_type == "status.update":
            raw_status = payload.get("kind")
            status = raw_status if isinstance(raw_status, str) and raw_status in _STATUSES else "unknown"
        elif event_type.startswith("subagent."):
            status_by_event = {
                "subagent.spawn_requested": "queued", "subagent.start": "running",
                "subagent.progress": "running", "subagent.thinking": "running",
                "subagent.tool": "running",
            }
            raw_status = payload.get("status")
            if event_type == "subagent.complete" and isinstance(raw_status, str) and raw_status in _STATUSES:
                status = raw_status
            else:
                status = status_by_event.get(event_type, "unknown")
            native_id = payload.get("subagent_id") or payload.get("delegation_id")
            raw_duration = payload.get("duration_seconds")
            if type(raw_duration) in (int, float) and math.isfinite(raw_duration) and 0 <= raw_duration <= 3600:
                duration = round(raw_duration * 1000)
        elif event_type == "approval.cancelled":
            status = "cancelled"
            ids = payload.get("request_ids")
            if isinstance(ids, list) and ids and len(ids) <= 32 and all(
                    isinstance(value, str) and 1 <= len(value) <= 128 for value in ids):
                native_id = hashlib.sha256("\0".join(ids).encode("utf-8")).hexdigest()
        elif event_type == "request.cancel":
            native_id = payload.get("id")
            reason = payload.get("reason")
            status = "cancelled" if reason in {"timeout", "interrupted", "resolved", "tui_close"} else "unknown"
        elif event_type == "todo.updated":
            status = "updated"
        elif event_type in {"session.usage", "message.complete"}:
            status = "observed" if event_type == "session.usage" else (
                payload.get("status") if payload.get("status") in {"complete", "error", "interrupted"}
                else "unknown")
            raw_usage = payload.get("usage")
            if isinstance(raw_usage, dict):
                counters = tuple((key, value) for key, value in raw_usage.items()
                                 if key in _USAGE_FIELDS and type(value) is int and 0 <= value <= 10**15)
                usage = counters or None
        if isinstance(native_id, str) and 0 < len(native_id) <= 512:
            identity = native_id
        return NativeActivityEvent(event_type=event_type, status=status, session_id=session_id,
                                   source_identity=identity, duration_ms=duration, usage=usage,
                                   source_at=None)

    async def create_session(self) -> tuple[str, str]:
        result = await self._rpc("session.create", {
            "source": "jarvis", "title": "Jarvis",
            "idempotency_key": "jarvis_" + secrets.token_urlsafe(24),
        })
        runtime_id, stored_id = result.get("session_id"), result.get("stored_session_id")
        if not (_valid_session_id(runtime_id) and _valid_session_id(stored_id)):
            raise JarvisChatDenied("official core session creation was not confirmed")
        return runtime_id, stored_id

    async def resume_session(self, stored_session_id: str) -> str:
        """Rebind an owned persisted session after its Hermes process generation changes."""
        if not _valid_session_id(stored_session_id):
            raise JarvisChatDenied("stored core session mapping is invalid")
        result = await self._rpc("session.resume", {
            "session_id": stored_session_id, "source": "jarvis",
        })
        runtime_id = result.get("session_id")
        resumed_id = result.get("resumed")
        if (not _valid_session_id(runtime_id)
                or resumed_id != stored_session_id):
            raise JarvisChatDenied("official core resume did not confirm the stored session")
        return runtime_id

    async def resume_history(self, stored_session_id: str) -> tuple[str, list[dict[str, Any]]]:
        """Reattach a stored session and return its bounded transcript from that response.

        Each RPC uses a short-lived WebSocket. Hermes detaches session transports when a socket
        closes, and session-scoped ``session.history`` rejects a reaped runtime ID. Resuming the
        durable stored ID is the official recovery path and returns both a fresh runtime ID and
        transcript in one bounded response.
        """
        if not _valid_session_id(stored_session_id):
            raise JarvisChatDenied("stored core session mapping is invalid")
        result = await self._rpc("session.resume", {"session_id": stored_session_id, "source": "jarvis"})
        runtime_id, resumed_id, rows = (result.get("session_id"), result.get("resumed"),
                                        result.get("messages"))
        if (not _valid_session_id(runtime_id) or resumed_id != stored_session_id
                or not isinstance(rows, list) or len(rows) > 20_000):
            raise JarvisChatDenied("official core resume history was invalid")
        return runtime_id, self._project_history_rows(rows)

    @staticmethod
    def _project_history_rows(rows: list[Any]) -> list[dict[str, Any]]:
        projected: list[dict[str, Any]] = []
        for row in rows:
            if not isinstance(row, dict) or row.get("role") not in {"user", "assistant"}:
                continue
            # session.resume uses the browser/TUI projection (content); session.history uses the
            # internal text projection. Accept only these two pinned upstream field names.
            text = row.get("text", row.get("content"))
            if not isinstance(text, str):
                continue
            timestamp = row.get("timestamp", row.get("createdAt", 0))
            projected.append({"role": row["role"], "content": text[:MAX_CORE_TEXT_CHARS],
                              "createdAt": timestamp if isinstance(timestamp, (int, float)) else 0})
        return projected[-200:]

    async def history(self, session_id: str) -> list[dict[str, Any]]:
        if not _valid_session_id(session_id):
            raise JarvisChatDenied("official core session mapping is invalid")
        result = await self._rpc("session.history", {"session_id": session_id})
        rows = result.get("messages")
        if not isinstance(rows, list) or len(rows) > 20_000:
            raise JarvisChatDenied("official core history was invalid")
        return self._project_history_rows(rows)

    async def stream_owned_turn(self, stored_session_id: str, text: str, *,
                                before_submit: Callable[[str], Any] | None = None
                                ) -> AsyncIterator[CoreTurnEvent]:
        """Resume the durable session and submit on one WebSocket transport.

        Hermes detaches sessions from a WebSocket when it closes. Therefore a cached runtime
        session id is not sufficient after an idle period: ``session.resume`` must bind this
        connection before ``prompt.submit`` is sent, and both operations must share the socket.
        The optional trusted callback runs with the actual runtime id between those operations.
        """
        if not _valid_session_id(stored_session_id) or not isinstance(text, str):
            raise JarvisChatDenied("official core turn is invalid")
        client, ws, ws_types = await self._connect()
        try:
            resume_id = secrets.token_hex(12)
            await ws.send_json({"jsonrpc": "2.0", "id": resume_id, "method": "session.resume",
                                "params": {"session_id": stored_session_id, "source": "jarvis"}})
            resumed = await self._receive(ws, ws_types, expected_id=resume_id)
            session_id, resumed_key = resumed.get("session_id"), resumed.get("resumed")
            if not _valid_session_id(session_id) or resumed_key != stored_session_id:
                raise JarvisChatDenied("official core resume did not confirm the stored session")
            if before_submit is not None:
                if not callable(before_submit):
                    raise JarvisChatDenied("official core turn mapping callback is invalid")
                result = before_submit(session_id)
                if inspect.isawaitable(result):
                    await result

            request_id = secrets.token_hex(12)
            await ws.send_json({"jsonrpc": "2.0", "id": request_id, "method": "prompt.submit",
                                "params": {"session_id": session_id, "text": text}})
            early_events: list[dict] = []
            accepted = await self._receive(ws, ws_types, expected_id=request_id,
                                           session_id=session_id, early_events=early_events)
            if accepted.get("status") != "streaming":
                # The BFF already enforces one active turn per conversation. A queued/redirected
                # request would detach this HTTP turn from the response it is meant to own.
                raise JarvisChatDenied("official core did not accept a dedicated turn")
            deadline = asyncio.get_running_loop().time() + 600
            pending_frames = iter(early_events)
            streamed_text = ""
            while True:
                try:
                    frame = next(pending_frames)
                except StopIteration:
                    frame = await self._receive(ws, ws_types, session_id=session_id, deadline=deadline)
                params = frame.get("params")
                event_name = params.get("type") if isinstance(params, dict) else ""
                payload = params.get("payload") if isinstance(params, dict) else None
                activity = self._activity_from_frame(frame, session_id)
                if event_name == "message.complete" and isinstance(payload, dict):
                    status = payload.get("status")
                    if status == "complete":
                        final_text = payload.get("text")
                        if final_text not in (None, "") and not isinstance(final_text, str):
                            raise JarvisChatDenied("official core final text was invalid")
                        if not streamed_text:
                            if not isinstance(final_text, str) or not final_text:
                                raise JarvisChatDenied("official core completed without assistant text")
                            if len(final_text) > MAX_CORE_TEXT_CHARS:
                                raise JarvisChatDenied("official core text exceeded its bound")
                            yield CoreTurnEvent("delta", final_text)
                        elif isinstance(final_text, str) and final_text:
                            if final_text == streamed_text:
                                pass
                            elif final_text.startswith(streamed_text):
                                suffix = final_text[len(streamed_text):]
                                if len(final_text) > MAX_CORE_TEXT_CHARS:
                                    raise JarvisChatDenied("official core text exceeded its bound")
                                if suffix:
                                    yield CoreTurnEvent("delta", suffix)
                            else:
                                raise JarvisChatDenied("official core final text did not match its stream")
                        if activity is not None:
                            yield CoreTurnEvent("activity", activity=activity)
                        yield CoreTurnEvent("complete")
                    elif status == "interrupted":
                        if activity is not None:
                            yield CoreTurnEvent("activity", activity=activity)
                        yield CoreTurnEvent("cancelled")
                    else:
                        if activity is not None:
                            yield CoreTurnEvent("activity", activity=activity)
                        yield CoreTurnEvent("failed")
                    return
                if activity is not None:
                    yield CoreTurnEvent("activity", activity=activity)
                if event_name == "message.delta" and isinstance(payload, dict):
                    delta = payload.get("text")
                    if isinstance(delta, str) and delta:
                        if len(streamed_text) + len(delta) > MAX_CORE_TEXT_CHARS:
                            raise JarvisChatDenied("official core text exceeded its bound")
                        streamed_text += delta
                        yield CoreTurnEvent("delta", delta)
        except JarvisChatDenied:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise JarvisChatDenied("official core turn ended without a terminal event") from None
        finally:
            await ws.close()
            await client.close()

    async def stream(self, stored_session_id: str, text: str) -> AsyncIterator[CoreTurnEvent]:
        """Compatibility spelling; the first ID is the durable stored session key."""
        async for event in self.stream_owned_turn(stored_session_id, text):
            yield event

    async def stop(self, session_id: str) -> None:
        if not _valid_session_id(session_id):
            raise JarvisChatDenied("official core session mapping is invalid")
        result = await self._rpc("session.interrupt", {"session_id": session_id})
        if result.get("status") not in {"interrupted", "not_interrupted"}:
            raise JarvisChatDenied("official core interrupt was not confirmed")
