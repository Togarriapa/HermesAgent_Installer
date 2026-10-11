"""Finite, server-side client for the pinned Hermes ``hermes serve`` TUI gateway.

This module deliberately implements the tiny JSON-RPC subset the Jarvis chat adapter needs.
It never relays arbitrary methods or exposes the service token/runtime session ids to a browser.
"""
from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import dataclass
from typing import Any, AsyncIterator, Literal
from urllib.parse import quote

from .jarvis_chat import JarvisChatDenied, _read_private_secret

CORE_PORT = 8766
CORE_PATH = "/api/ws"
MAX_RPC_FRAME_BYTES = 256 * 1024
MAX_CORE_TEXT_CHARS = 64_000


def _valid_session_id(value: Any) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= 512
            and not any(ord(char) < 0x20 for char in value))


@dataclass(frozen=True, slots=True)
class CoreTurnEvent:
    kind: Literal["delta", "complete", "failed", "cancelled"]
    text: str = ""


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
            if session_id is not None and frame.get("method") == "event":
                params = frame.get("params")
                if isinstance(params, dict) and params.get("session_id") == session_id:
                    if early_events is not None:
                        if len(early_events) >= 128:
                            raise JarvisChatDenied("official core sent too many early events")
                        early_events.append(frame)
                    else:
                        return frame

    async def _rpc(self, method: str, params: dict[str, Any]) -> dict:
        # Method names are not parameters to public endpoints; this still defends internal misuse.
        if method not in {"session.create", "session.resume", "session.history", "session.interrupt"}:
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

    async def stream(self, session_id: str, text: str) -> AsyncIterator[CoreTurnEvent]:
        if not _valid_session_id(session_id) or not isinstance(text, str):
            raise JarvisChatDenied("official core turn is invalid")
        client, ws, ws_types = await self._connect()
        request_id = secrets.token_hex(12)
        try:
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
                if event_name == "message.delta" and isinstance(payload, dict):
                    delta = payload.get("text")
                    if isinstance(delta, str) and delta:
                        if len(streamed_text) + len(delta) > MAX_CORE_TEXT_CHARS:
                            raise JarvisChatDenied("official core text exceeded its bound")
                        streamed_text += delta
                        yield CoreTurnEvent("delta", delta)
                elif event_name == "message.complete" and isinstance(payload, dict):
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
                                # The public stream is append-only. Do not claim success when
                                # Hermes' authoritative final answer cannot be reconciled safely.
                                raise JarvisChatDenied("official core final text did not match its stream")
                        elif not streamed_text:
                            raise JarvisChatDenied("official core completed without assistant text")
                        yield CoreTurnEvent("complete")
                    elif status == "interrupted":
                        yield CoreTurnEvent("cancelled")
                    else:
                        yield CoreTurnEvent("failed")
                    return
        except JarvisChatDenied:
            raise
        except asyncio.CancelledError:
            raise
        except Exception:
            raise JarvisChatDenied("official core turn ended without a terminal event") from None
        finally:
            await ws.close()
            await client.close()

    async def stop(self, session_id: str) -> None:
        if not _valid_session_id(session_id):
            raise JarvisChatDenied("official core session mapping is invalid")
        result = await self._rpc("session.interrupt", {"session_id": session_id})
        if result.get("status") not in {"interrupted", "not_interrupted"}:
            raise JarvisChatDenied("official core interrupt was not confirmed")
