"""Protected current-core native Codex process observations.

This adapter reports observations made by the root-enrolled, source-pinned Hermes
process.  It is explicitly *not* an independent TLS observer.  The root service
must authenticate the peer against the active core custody before accepting any
record and must join records to a registered owner turn and selected subscription.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import socket
import stat
import struct
import threading
import weakref
import base64
import time
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping


CORE_NATIVE_OBSERVER_SOCKET = Path("/run/hermes-installer/core-native-observer.sock")
MAX_FRAME = 256 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z", re.ASCII)
_CODEX_ENDPOINT = "https://chatgpt.com/backend-api/codex"
_CODEX_PROVIDER = "openai-codex"
_CODEX_MODE = "codex_responses"


class CoreNativeObservationUnavailable(PermissionError):
    """Current protected core observation could not be registered or consumed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or _HASH.fullmatch(value) is None:
        raise CoreNativeObservationUnavailable(f"{label} is malformed")
    return value


def _require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise CoreNativeObservationUnavailable(f"{label} is malformed")
    return value


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(_value: str) -> Any:
    raise ValueError("invalid JSON number")


def _read_exact(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        block = conn.recv(size - len(chunks))
        if not block:
            raise OSError("observer socket closed during a frame")
        chunks.extend(block)
    return bytes(chunks)


def _read_frame(conn: socket.socket) -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(conn, 4))[0]
    if not 2 <= size <= MAX_FRAME:
        raise ValueError("observer frame exceeded its bound")
    value = json.loads(_read_exact(conn, size).decode("utf-8", errors="strict"),
                       object_pairs_hook=_unique_pairs,
                       parse_constant=_reject_constant)
    if not isinstance(value, dict):
        raise ValueError("observer frame must be an object")
    return value


@dataclass(frozen=True, slots=True)
class OwnerTurnHandle:
    """Opaque root handle for an accepted owner turn; contains no JWT or prompt."""

    handle: str
    core_generation: str
    session_id: str
    conversation_id: str
    gateway_turn_id: str
    prompt_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _ID.fullmatch(self.session_id or "")
                or not _ID.fullmatch(self.conversation_id or "")
                or not _ID.fullmatch(self.gateway_turn_id or "")
                or not _HASH.fullmatch(self.prompt_sha256 or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 600.0):
            raise CoreNativeObservationUnavailable("root owner-turn handle is malformed")


@dataclass(frozen=True, slots=True)
class ObservedProviderAttempt:
    """A short-lived attempt handle returned by the protected root registry."""

    handle: str
    owner_turn_handle: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root provider-attempt handle is malformed")


@dataclass(frozen=True, slots=True)
class ObservedNativeToolCall:
    """Root-retained provider tool call, correlated with its live native attempt."""

    handle: str
    attempt_handle: str
    owner_turn_handle: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.handle or "")
                or not _OPAQUE.fullmatch(self.attempt_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.tool_call_id or "")
                or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or isinstance(self.expires_monotonic, bool)
                or not isinstance(self.expires_monotonic, (int, float))
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root observed-tool handle is malformed")


@dataclass(frozen=True, slots=True)
class NativeSourceMember:
    """One exact source member in a root-selected Resources profile."""

    path: str
    sha256: str
    size: int

    def __post_init__(self) -> None:
        if not isinstance(self.path, str):
            raise CoreNativeObservationUnavailable("root source-member manifest is malformed")
        parts = PurePosixPath(self.path)
        if (not self.path or len(self.path) > 512
                or parts.is_absolute() or any(part in {"", ".", ".."} for part in parts.parts)
                or str(parts) != self.path or not _HASH.fullmatch(self.sha256 or "")
                or type(self.size) is not int or not 0 <= self.size <= 4 * 1024 * 1024):
            raise CoreNativeObservationUnavailable("root source-member manifest is malformed")


@dataclass(frozen=True, slots=True)
class RootSelectedInternalProfileDispatchClaim:
    """Closed, short-lived dispatch claim returned only over authenticated root IPC.

    Prompt bytes and member identities are revealed only after one-use consume to
    the same protected core process. This DTO is still not a serialized Hermes
    Agent or authority to widen its tool/privacy closure.
    """

    claim_handle: str
    owner_turn_handle: str
    observed_call_handle: str
    core_generation: str
    session_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    account_fingerprint: str
    profile_id: str
    source_revision: str
    source_manifest: tuple[NativeSourceMember, ...]
    source_manifest_sha256: str
    prompt_bytes: bytes
    prompt_sha256: str
    prompt_revision: str
    evidence_class: str
    provider: str
    api_mode: str
    base_url: str
    additional_metered_budget: int
    parent_tool_names: tuple[str, ...]
    parent_privacy_grants: tuple[str, ...]
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (any(not _OPAQUE.fullmatch(value or "") for value in (
                    self.claim_handle, self.owner_turn_handle, self.observed_call_handle))
                or not _HASH.fullmatch(self.core_generation or "")
                or not _ID.fullmatch(self.session_id or "") or not _ID.fullmatch(self.turn_id or "")
                or not _ID.fullmatch(self.tool_call_id or "") or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or not _HASH.fullmatch(self.account_fingerprint or "")
                or not _ID.fullmatch(self.profile_id or "")
                or re.fullmatch(r"[0-9a-f]{40,64}", self.source_revision or "") is None
                or not isinstance(self.source_manifest, tuple) or not self.source_manifest
                or len(self.source_manifest) > 512
                or any(type(row) is not NativeSourceMember for row in self.source_manifest)
                or len({row.path for row in self.source_manifest}) != len(self.source_manifest)
                or _hash([{"path": row.path, "sha256": row.sha256, "size": row.size}
                          for row in self.source_manifest]) != self.source_manifest_sha256
                or not isinstance(self.prompt_bytes, bytes) or not self.prompt_bytes
                or len(self.prompt_bytes) > 128 * 1024
                or hashlib.sha256(self.prompt_bytes).hexdigest() != self.prompt_sha256
                or not _ID.fullmatch(self.prompt_revision or "")
                or self.evidence_class != "protected-core-process-observation"
                or self.provider != _CODEX_PROVIDER or self.api_mode != _CODEX_MODE
                or self.base_url != _CODEX_ENDPOINT
                or type(self.additional_metered_budget) is not int
                or self.additional_metered_budget != 0
                or not isinstance(self.parent_tool_names, tuple)
                or not self.parent_tool_names or len(self.parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.parent_tool_names)
                or not isinstance(self.parent_privacy_grants, tuple)
                or len(self.parent_privacy_grants) > 128
                or any(not _ID.fullmatch(item or "") for item in self.parent_privacy_grants)
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.expires_monotonic)
                or self.expires_monotonic <= time.monotonic()
                or self.expires_monotonic > time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")


class CoreNativeObservationClient:
    """Fixed bounded client for the root-owned current-core observation socket."""

    def __init__(self, *, socket_path: Path = CORE_NATIVE_OBSERVER_SOCKET,
                 timeout: float = 2.0):
        if (not isinstance(socket_path, Path) or not socket_path.is_absolute()
                or isinstance(timeout, bool) or not isinstance(timeout, (int, float))
                or not 0.1 <= timeout <= 5.0):
            raise ValueError("fixed absolute observer socket and bounded timeout are required")
        self._socket_path = socket_path
        self._timeout = float(timeout)

    def _rpc(self, operation: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        if operation not in {
            "register-owner-turn", "register-attempt", "register-response",
            "register-tool-call", "prepare-dispatch", "consume-dispatch",
        }:
            raise CoreNativeObservationUnavailable("observer operation is not supported")
        nonce = secrets.token_urlsafe(32)
        request = {"schema": 1, "op": operation, "nonce": nonce, **dict(payload)}
        if "nonce" in payload or "op" in payload or "schema" in payload:
            raise CoreNativeObservationUnavailable("observer payload contains reserved fields")
        raw = _canonical(request)
        if len(raw) > MAX_FRAME:
            raise CoreNativeObservationUnavailable("observer request exceeded its bound")
        try:
            info = self._socket_path.lstat()
            if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) not in {0o600, 0o660}:
                raise ValueError("root observer socket custody differs")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
                conn.settimeout(self._timeout)
                conn.connect(str(self._socket_path))
                if not hasattr(socket, "SO_PEERCRED"):
                    raise ValueError("observer peer credentials are unavailable")
                peer_pid, peer_uid, _peer_gid = struct.unpack(
                    "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                if peer_pid <= 1 or peer_uid != 0:
                    raise ValueError("observer peer is not root")
                conn.sendall(struct.pack("!I", len(raw)) + raw)
                response = _read_frame(conn)
            if (not {"schema", "nonce", "ok"} <= set(response)
                    or type(response.get("schema")) is not int or response["schema"] != 1
                    or response.get("nonce") != nonce or type(response.get("ok")) is not bool):
                raise ValueError("observer response does not match request")
            if response["ok"] is not True:
                raise CoreNativeObservationUnavailable("root rejected current-core observation")
            return response
        except CoreNativeObservationUnavailable:
            raise
        except Exception:
            raise CoreNativeObservationUnavailable("protected core observer is unavailable") from None

    def register_owner_turn(self, *, access_jwt: str, ingress_nonce: str,
                            ingress_proof_sha256: str, core_generation: str,
                            conversation_id: str, gateway_turn_id: str, session_id: str,
                            prompt_sha256: str) -> OwnerTurnHandle:
        """Register an accepted owner turn before prompt.submit; JWT is transient only.

        ``gateway_turn_id`` is server-owned ingress identity, not a predicted Hermes
        turn ID. The root binds it to the actual native turn when the protected core
        observation reports that turn; no native ID is invented by this producer.
        """
        if not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384:
            raise CoreNativeObservationUnavailable("current Access assertion is unavailable")
        payload = {
            "access_jwt": access_jwt,
            "ingress_nonce": _require_id(ingress_nonce, "ingress nonce"),
            "ingress_proof_sha256": _require_hash(ingress_proof_sha256, "ingress proof"),
            "core_generation": _require_hash(core_generation, "core generation"),
            "conversation_id": _require_id(conversation_id, "conversation ID"),
            "gateway_turn_id": _require_id(gateway_turn_id, "gateway turn ID"),
            "session_id": _require_id(session_id, "native session ID"),
            "prompt_sha256": _require_hash(prompt_sha256, "prompt digest"),
        }
        row = self._rpc("register-owner-turn", payload)
        try:
            return OwnerTurnHandle(row["owner_turn_handle"], row["core_generation"],
                                   row["session_id"], row["conversation_id"],
                                   row["gateway_turn_id"], row["prompt_sha256"],
                                   row["expires_monotonic"])
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root owner-turn receipt is malformed") from None

    def register_attempt(self, *, session_id: str, turn_id: str, api_request_id: str,
                         provider: str, model: str, base_url: str, api_mode: str,
                         account_fingerprint: str, request_sha256: str,
                         retry_count: int) -> ObservedProviderAttempt:
        """Register one exact native logical attempt; route uncertainty is denied."""
        if (provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url.rstrip("/") != _CODEX_ENDPOINT or type(retry_count) is not int
                or retry_count != 0):
            raise CoreNativeObservationUnavailable("attempt is outside the selected Codex subscription route")
        payload = {
            "session_id": _require_id(session_id, "session ID"),
            "turn_id": _require_id(turn_id, "turn ID"),
            "api_request_id": _require_id(api_request_id, "API request ID"),
            "provider": provider, "model": _require_id(model, "model"),
            "base_url": _CODEX_ENDPOINT, "api_mode": _CODEX_MODE,
            "account_fingerprint": _require_hash(account_fingerprint, "account fingerprint"),
            "request_sha256": _require_hash(request_sha256, "request digest"),
            "retry_count": retry_count,
        }
        row = self._rpc("register-attempt", payload)
        try:
            return ObservedProviderAttempt(row["attempt_handle"], row["owner_turn_handle"],
                                          row["expires_monotonic"])
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root provider-attempt receipt is malformed") from None

    def register_response(self, *, attempt: ObservedProviderAttempt,
                          response_sha256: str, tool_calls: list[dict[str, str]],
                          completed: bool) -> None:
        if type(attempt) is not ObservedProviderAttempt or type(completed) is not bool:
            raise CoreNativeObservationUnavailable("provider response is not correlated")
        calls = []
        if not isinstance(tool_calls, list) or len(tool_calls) > 128:
            raise CoreNativeObservationUnavailable("provider tool-call inventory is malformed")
        for call in tool_calls:
            if not isinstance(call, dict) or set(call) != {"id", "name", "arguments_sha256"}:
                raise CoreNativeObservationUnavailable("provider tool-call row is malformed")
            calls.append({"id": _require_id(call["id"], "provider tool-call ID"),
                          "name": _require_id(call["name"], "provider tool name"),
                          "arguments_sha256": _require_hash(call["arguments_sha256"], "tool arguments digest")})
        self._rpc("register-response", {
            "attempt_handle": attempt.handle,
            "response_sha256": _require_hash(response_sha256, "response digest"),
            "tool_calls": calls, "completed": completed,
        })

    def register_tool_call(self, *, attempt: ObservedProviderAttempt,
                           tool_call_id: str, canonical_arguments: bytes) -> ObservedNativeToolCall:
        if (type(attempt) is not ObservedProviderAttempt or not isinstance(canonical_arguments, bytes)
                or not 2 <= len(canonical_arguments) <= 64 * 1024):
            raise CoreNativeObservationUnavailable("native tool-call arguments are invalid")
        try:
            parsed = json.loads(canonical_arguments.decode("utf-8", errors="strict"),
                                object_pairs_hook=_unique_pairs)
            if not isinstance(parsed, dict) or _canonical(parsed) != canonical_arguments:
                raise ValueError
        except Exception:
            raise CoreNativeObservationUnavailable("native tool-call arguments are not canonical") from None
        row = self._rpc("register-tool-call", {
            "attempt_handle": attempt.handle,
            "tool_call_id": _require_id(tool_call_id, "tool-call ID"),
            "canonical_arguments_b64": __import__("base64").b64encode(canonical_arguments).decode("ascii"),
        })
        try:
            return ObservedNativeToolCall(row["observed_call_handle"], row["attempt_handle"],
                                          row["owner_turn_handle"], row["tool_call_id"],
                                          row["tool_name"], row["arguments_sha256"],
                                          row["expires_monotonic"])
        except (KeyError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root native tool-call receipt is malformed") from None

    def prepare_dispatch(self, *, observed_call: ObservedNativeToolCall) -> str:
        if type(observed_call) is not ObservedNativeToolCall:
            raise CoreNativeObservationUnavailable("root observed call is required")
        row = self._rpc("prepare-dispatch", {"observed_call_handle": observed_call.handle})
        claim = row.get("claim_handle")
        if not isinstance(claim, str) or not _OPAQUE.fullmatch(claim):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")
        return claim

    def consume_dispatch(self, *, claim_handle: str) -> RootSelectedInternalProfileDispatchClaim:
        if not isinstance(claim_handle, str) or not _OPAQUE.fullmatch(claim_handle):
            raise CoreNativeObservationUnavailable("root dispatch claim is malformed")
        row = self._rpc("consume-dispatch", {"claim_handle": claim_handle})
        claim = row.get("dispatch_claim")
        required = {
            "schema", "claim_handle", "owner_turn_handle", "observed_call_handle",
            "core_generation", "session_id", "turn_id", "tool_call_id", "tool_name",
            "arguments_sha256", "account_fingerprint", "profile_id", "source_revision",
            "source_manifest", "source_manifest_sha256", "prompt_b64", "prompt_sha256",
            "prompt_revision", "parent_tool_names", "parent_privacy_grants", "expires_monotonic",
            "evidence_class", "provider", "api_mode", "base_url", "additional_metered_budget",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed")
        try:
            if type(claim["schema"]) is not int or claim["schema"] != 1:
                raise ValueError
            encoded_prompt = claim["prompt_b64"]
            if not isinstance(encoded_prompt, str) or len(encoded_prompt) > 4 * 128 * 1024:
                raise ValueError
            prompt_bytes = base64.b64decode(encoded_prompt, validate=True)
            prompt_bytes.decode("utf-8", errors="strict")
            raw_manifest = claim["source_manifest"]
            if not isinstance(raw_manifest, list) or not 1 <= len(raw_manifest) <= 512:
                raise ValueError
            manifest = []
            for item in raw_manifest:
                if not isinstance(item, dict) or set(item) != {"path", "sha256", "size"}:
                    raise ValueError
                manifest.append(NativeSourceMember(item["path"], item["sha256"], item["size"]))
            names, grants = claim["parent_tool_names"], claim["parent_privacy_grants"]
            if (not isinstance(names, list) or not isinstance(grants, list)
                    or any(not isinstance(value, str) for value in (*names, *grants))):
                raise ValueError
            if claim["claim_handle"] != claim_handle:
                raise ValueError
            return RootSelectedInternalProfileDispatchClaim(
                claim_handle=claim["claim_handle"], owner_turn_handle=claim["owner_turn_handle"],
                observed_call_handle=claim["observed_call_handle"],
                core_generation=claim["core_generation"], session_id=claim["session_id"],
                turn_id=claim["turn_id"], tool_call_id=claim["tool_call_id"],
                tool_name=claim["tool_name"], arguments_sha256=claim["arguments_sha256"],
                account_fingerprint=claim["account_fingerprint"], profile_id=claim["profile_id"],
                source_revision=claim["source_revision"], source_manifest=tuple(manifest),
                source_manifest_sha256=claim["source_manifest_sha256"],
                prompt_bytes=prompt_bytes, prompt_sha256=claim["prompt_sha256"],
                prompt_revision=claim["prompt_revision"], parent_tool_names=tuple(names),
                parent_privacy_grants=tuple(grants), expires_monotonic=claim["expires_monotonic"],
                evidence_class=claim["evidence_class"], provider=claim["provider"],
                api_mode=claim["api_mode"], base_url=claim["base_url"],
                additional_metered_budget=claim["additional_metered_budget"],
            )
        except Exception:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed") from None


def _codex_account_fingerprint(credential_resolver: Callable[[], Mapping[str, Any]]) -> str:
    """Resolve the retained OAuth identity, then discard its bearer without exporting it."""
    if not callable(credential_resolver):
        raise CoreNativeObservationUnavailable("retained Codex auth resolver is unavailable")
    try:
        credentials = credential_resolver()
        token = credentials.get("api_key") if isinstance(credentials, Mapping) else None
        base_url = credentials.get("base_url") if isinstance(credentials, Mapping) else None
        provider = credentials.get("provider") if isinstance(credentials, Mapping) else None
        source = credentials.get("source") if isinstance(credentials, Mapping) else None
        auth_mode = credentials.get("auth_mode") if isinstance(credentials, Mapping) else None
        if (provider != _CODEX_PROVIDER or source != "hermes-auth-store"
                or auth_mode != "chatgpt" or not isinstance(base_url, str)
                or base_url.rstrip("/") != _CODEX_ENDPOINT or not isinstance(token, str) or not token):
            raise ValueError
        from agent.credential_pool import _codex_principal_identity
        identity = _codex_principal_identity(token)
        if (not isinstance(identity, tuple) or len(identity) != 2
                or any(not isinstance(value, str) or not value for value in identity)):
            raise ValueError
        return hashlib.sha256(b"hermes-codex-subscription-account-v1\0" +
                              (identity[0] + "\0" + identity[1]).encode("utf-8")).hexdigest()
    except Exception:
        raise CoreNativeObservationUnavailable("current Codex subscription identity is unavailable") from None


def _response_tool_calls(response: Any) -> list[tuple[str, str, bytes]]:
    """Extract exact function-call arguments from the consumed native Responses result."""
    output = getattr(response, "output", None)
    if not isinstance(output, (tuple, list)):
        return []
    calls: list[tuple[str, str, bytes]] = []
    for item in output:
        if getattr(item, "type", None) != "function_call":
            continue
        call_id, name, arguments = (getattr(item, "call_id", None), getattr(item, "name", None),
                                    getattr(item, "arguments", None))
        if not isinstance(call_id, str) or not isinstance(name, str) or not isinstance(arguments, str):
            raise CoreNativeObservationUnavailable("Codex function-call response is malformed")
        try:
            parsed = json.loads(arguments, object_pairs_hook=_unique_pairs)
            if not isinstance(parsed, dict):
                raise ValueError
            canonical = _canonical(parsed)
        except Exception:
            raise CoreNativeObservationUnavailable("Codex function-call arguments are malformed") from None
        calls.append((call_id, name, canonical))
    return calls


def install_native_codex_process_observer(ctx: Any, *, client: CoreNativeObservationClient,
                                          credential_resolver: Callable[[], Mapping[str, Any]] | None = None) -> Any:
    """Install the supported additive LLM execution middleware in the selected core.

    Hermes' official ``llm_execution`` middleware wraps ``_perform_api_call``.  The
    single-use downstream callback is the real Codex provider execution and does not
    return until the Responses SSE stream has reached its terminal response.  This
    reports protected process observations, not root-captured TLS bytes.
    """
    register = getattr(ctx, "register_middleware", None)
    if not callable(register) or type(client) is not CoreNativeObservationClient:
        raise CoreNativeObservationUnavailable("pinned Hermes middleware seam is unavailable")

    request_attempts: OrderedDict[tuple[str, str], ObservedProviderAttempt | None] = OrderedDict()
    call_lineage = register_tool_call_from_current_parent._lineage
    lineage_lock = register_tool_call_from_current_parent._lock

    def resolve_credentials() -> Mapping[str, Any]:
        if credential_resolver is not None:
            return credential_resolver()
        from hermes_cli.auth_codex import resolve_codex_runtime_credentials
        return resolve_codex_runtime_credentials(read_only=True)

    def observe(**event: Any) -> Any:
        next_call = event.get("next_call")
        request = event.get("request")
        route = (event.get("provider"), event.get("api_mode"), event.get("base_url"))
        if route != (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT):
            # Leave ordinary model routes alone. Resources delegation remains unavailable
            # because it cannot obtain a root observed call handle on those routes.
            return next_call(request) if callable(next_call) else None
        if not callable(next_call) or not isinstance(request, dict):
            raise CoreNativeObservationUnavailable("native Codex call boundary is malformed")
        session_id, turn_id, api_request_id = (event.get("session_id"), event.get("turn_id"),
                                                event.get("api_request_id"))
        try:
            request_key = (_require_id(session_id, "session ID"),
                           _require_id(api_request_id, "API request ID"))
            _require_id(turn_id, "turn ID")
        except CoreNativeObservationUnavailable:
            return next_call(request)
        with lineage_lock:
            # Hermes re-enters this supported middleware for an outer retry with the
            # same api_request_id. The first observation is logical-attempt-only; a
            # second call is allowed to proceed for ordinary chat but cannot mint proof.
            if request_key in request_attempts:
                return next_call(request)
            request_attempts[request_key] = None  # reserved before any provider effect
            request_attempts.move_to_end(request_key)
            while len(request_attempts) > 1024:
                request_attempts.popitem(last=False)
        if event.get("middleware_trace"):
            return next_call(request)
        try:
            account = _codex_account_fingerprint(resolve_credentials)
            attempt = client.register_attempt(
                session_id=session_id, turn_id=turn_id, api_request_id=api_request_id,
                provider=event.get("provider"), model=event.get("model"),
                base_url=event.get("base_url"), api_mode=event.get("api_mode"),
                account_fingerprint=account, request_sha256=_hash(request), retry_count=0,
            )
        except CoreNativeObservationUnavailable:
            return next_call(request)
        with lineage_lock:
            request_attempts[request_key] = attempt
        try:
            response = next_call(request)
        except BaseException:
            # Retire the root attempt as an unsuccessful logical observation. This
            # receipt can never authorize a tool call or delegation.
            try:
                failure_bytes = _canonical({"completed": False})
                client.register_response(attempt=attempt,
                    response_sha256=hashlib.sha256(failure_bytes).hexdigest(),
                    tool_calls=[], completed=False)
            except Exception:
                pass
            raise
        try:
            # Verify the retained current resolver still selects the same identity after
            # response completion, while never sending the credential itself to root.
            try:
                same_account = _codex_account_fingerprint(resolve_credentials) == account
            except CoreNativeObservationUnavailable:
                same_account = False
            if not same_account:
                return response
            calls = _response_tool_calls(response)
            response_bytes = _canonical(response.model_dump(mode="json"))
            if not 1 <= len(response_bytes) <= MAX_FRAME:
                return response
            try:
                client.register_response(
                    attempt=attempt, response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                    tool_calls=[{"id": call_id, "name": name,
                                 "arguments_sha256": hashlib.sha256(arguments).hexdigest()}
                                for call_id, name, arguments in calls],
                    completed=True,
                )
            except CoreNativeObservationUnavailable:
                return response
            with lineage_lock:
                for call_id, name, arguments in calls:
                    call_lineage[call_id] = (attempt, session_id, turn_id, name, arguments, None)
                    call_lineage.move_to_end(call_id)
                while len(call_lineage) > 1024:
                    call_lineage.popitem(last=False)
            return response
        except Exception:
            # Observation failure must not discard a successfully consumed answer.
            # Without its root response receipt, Resources delegation has no call handle.
            return response

    registrations = []
    try:
        registrations.append(register("llm_execution", observe))
        return tuple(registrations)
    except Exception:
        raise CoreNativeObservationUnavailable("native Codex observer registration failed") from None


def register_tool_call_from_current_parent(*, client: CoreNativeObservationClient,
                                           parent_agent: Any, tool_call_id: str,
                                           tool_name: str, arguments: Mapping[str, Any]
                                           ) -> ObservedNativeToolCall:
    """Join a returned provider call to Hermes' live injected parent Agent.

    Resource handlers call this before preparing a claim. The response-side
    observer retained the exact provider call ID, tool name, canonical argument
    bytes, core session, and turn. The first use binds that record to the live
    Agent instance; later uses require object identity, not a serialized Agent.
    """
    if type(client) is not CoreNativeObservationClient or not isinstance(arguments, Mapping):
        raise CoreNativeObservationUnavailable("selected live parent and native observer are required")
    try:
        canonical = _canonical(dict(arguments))
        session_id = _require_id(getattr(parent_agent, "session_id", None), "parent session ID")
        turn_id = _require_id(getattr(parent_agent, "_current_turn_id", None), "parent turn ID")
        tool_call_id = _require_id(tool_call_id, "provider tool-call ID")
        tool_name = _require_id(tool_name, "native tool name")
        parent_ref = weakref.ref(parent_agent)
    except Exception:
        raise CoreNativeObservationUnavailable("live Hermes parent lineage is unavailable") from None
    # The registry is populated only by the source-enrolled middleware after its
    # actual downstream Codex response completed. It is process-local and bounded.
    table = getattr(register_tool_call_from_current_parent, "_lineage", None)
    lock = getattr(register_tool_call_from_current_parent, "_lock", None)
    if not isinstance(table, OrderedDict) or not isinstance(lock, type(threading.RLock())):
        raise CoreNativeObservationUnavailable("native response lineage registry is unavailable")
    with lock:
        row = table.get(tool_call_id)
        if row is None:
            raise CoreNativeObservationUnavailable("tool call has no completed provider response")
        attempt, observed_session, observed_turn, observed_name, observed_args, bound_parent = row
        if (session_id != observed_session or turn_id != observed_turn or tool_name != observed_name
                or canonical != observed_args):
            raise CoreNativeObservationUnavailable("live native call differs from its provider response")
        old_parent = bound_parent() if callable(bound_parent) else None
        if old_parent is not None and old_parent is not parent_agent:
            raise CoreNativeObservationUnavailable("native tool call belongs to another parent Agent")
        if old_parent is None:
            # The supported PluginContext dispatch injects the actual current Agent;
            # store only a weak reference so this lineage cannot keep a turn alive.
            table[tool_call_id] = (attempt, observed_session, observed_turn, observed_name,
                                   observed_args, parent_ref)
        table.move_to_end(tool_call_id)
        # Consume local lineage before crossing IPC. If the reply is lost, root
        # replay protection keeps a second request from minting another handle.
        del table[tool_call_id]
    return client.register_tool_call(attempt=attempt, tool_call_id=tool_call_id,
                                     canonical_arguments=canonical)


# Function attributes keep the local parent/call join private to this imported
# source module and avoid a process-global registry object exposed to plugins.
register_tool_call_from_current_parent._lineage = OrderedDict()
register_tool_call_from_current_parent._lock = threading.RLock()


__all__ = [
    "CORE_NATIVE_OBSERVER_SOCKET", "CoreNativeObservationClient",
    "CoreNativeObservationUnavailable", "ObservedNativeToolCall",
    "NativeSourceMember", "ObservedProviderAttempt", "OwnerTurnHandle",
    "RootSelectedInternalProfileDispatchClaim",
    "install_native_codex_process_observer", "register_tool_call_from_current_parent",
]
