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
import os
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping


CORE_NATIVE_OBSERVER_SOCKET = Path("/run/hermes-jarvis-native-observer/native-observer.sock")
_CORE_NATIVE_OBSERVER_GROUP = 1000
MAX_FRAME = 256 * 1024
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z", re.ASCII)
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,191}\Z", re.ASCII)
_CODEX_ENDPOINT = "https://chatgpt.com/backend-api/codex"
_CODEX_PROVIDER = "openai-codex"
_CODEX_MODE = "codex_responses"
_OBSERVER_RUNTIME_DIR = Path("/run/hermes-jarvis-native-observer")
_NATIVE_INHERITANCE_POLICY_SEAL = object()


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
class RootSelectedOrchestratorDelegationPolicy:
    """Root-enrolled owner policy for Hermes' native inherited-tool delegation.

    This policy is distinct from the Resources profile manifest: the profile has
    no tool grants, and its empty ``profile_tool_names`` remains empty.  The
    policy authorizes only the exact current parent tool closure selected by the
    root-verified native configuration.  Hermes still applies its own blocked,
    disabled, pause, depth, and lifecycle rules when it builds the child.
    """

    schema: int
    policy_handle: str
    policy_sha256: str
    core_generation: str
    core_source_generation: str
    owner_subject_sha256: str
    profile_id: str
    mode: str
    parent_tool_configuration_sha256: str
    allowed_parent_tool_names: tuple[str, ...]
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    additional_metered_budget: int
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (type(self.schema) is not int or self.schema != 1
                or not _OPAQUE.fullmatch(self.policy_handle or "")
                or not _HASH.fullmatch(self.policy_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.core_source_generation or "")
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or self.profile_id != "orchestrator"
                or self.mode != "native-parent-inheritance"
                or not _HASH.fullmatch(self.parent_tool_configuration_sha256 or "")
                or not isinstance(self.allowed_parent_tool_names, tuple)
                or not self.allowed_parent_tool_names or len(self.allowed_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.allowed_parent_tool_names)
                or len(set(self.allowed_parent_tool_names)) != len(self.allowed_parent_tool_names)
                or tuple(sorted(self.allowed_parent_tool_names)) != self.allowed_parent_tool_names
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or "delegate_task" not in self.allowed_parent_tool_names
                or type(self.additional_metered_budget) is not int
                or self.additional_metered_budget != 0
                or type(self.issued_monotonic) not in (float, int)
                or type(self.expires_monotonic) not in (float, int)
                or not math.isfinite(self.issued_monotonic)
                or not math.isfinite(self.expires_monotonic)
                or self.issued_monotonic > time.monotonic()
                or self.expires_monotonic <= self.issued_monotonic
                or self.expires_monotonic > self.issued_monotonic + 600.0
                or self._seal is not _NATIVE_INHERITANCE_POLICY_SEAL):
            raise CoreNativeObservationUnavailable("root native inheritance policy is malformed")


def _native_policy_digest_fields(policy: RootSelectedOrchestratorDelegationPolicy) -> dict[str, Any]:
    return {
        "schema": policy.schema,
        "policy_handle": policy.policy_handle,
        "core_generation": policy.core_generation,
        "core_source_generation": policy.core_source_generation,
        "owner_subject_sha256": policy.owner_subject_sha256,
        "profile_id": policy.profile_id,
        "mode": policy.mode,
        "parent_tool_configuration_sha256": policy.parent_tool_configuration_sha256,
        "allowed_parent_tool_names": list(policy.allowed_parent_tool_names),
        "allow_inherited_mcp": policy.allow_inherited_mcp,
        "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
        "additional_metered_budget": policy.additional_metered_budget,
        "issued_monotonic": policy.issued_monotonic,
        "expires_monotonic": policy.expires_monotonic,
    }


@dataclass(frozen=True, slots=True)
class RootSelectedInternalProfileDispatchClaim:
    """Closed, short-lived dispatch claim returned only over authenticated root IPC.

    Prompt bytes and member identities are revealed only after one-use consume to
    the same protected core process. This DTO is still not a serialized Hermes
    Agent or authority to widen its tool/privacy closure.
    """

    claim_handle: str
    owner_turn_handle: str
    gateway_turn_id: str
    owner_subject_sha256: str
    observed_call_handle: str
    core_generation: str
    generation_sha256: str
    session_id: str
    turn_id: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    account_fingerprint: str
    profile_id: str
    source_revision: str
    profile_manifest_sha256: str
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
    delegation_policy_handle: str
    delegation_policy_sha256: str
    parent_tool_configuration_sha256: str
    allowed_parent_tool_names: tuple[str, ...]
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    profile_tool_names: tuple[str, ...]
    parent_privacy_grants: tuple[str, ...]
    profile_privacy_requirements: tuple[str, ...]
    expires_monotonic: float

    def __post_init__(self) -> None:
        if (any(not _OPAQUE.fullmatch(value or "") for value in (
                    self.claim_handle, self.owner_turn_handle, self.observed_call_handle))
                or not _ID.fullmatch(self.gateway_turn_id or "")
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.generation_sha256 or "")
                or not _ID.fullmatch(self.session_id or "") or not _ID.fullmatch(self.turn_id or "")
                or not _ID.fullmatch(self.tool_call_id or "") or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or not _HASH.fullmatch(self.account_fingerprint or "")
                or not _ID.fullmatch(self.profile_id or "")
                or not _HASH.fullmatch(self.profile_manifest_sha256 or "")
                or not isinstance(self.source_revision, str) or not 1 <= len(self.source_revision) <= 128
                or any(ord(char) < 0x21 or ord(char) > 0x7e for char in self.source_revision)
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
                or not _OPAQUE.fullmatch(self.delegation_policy_handle or "")
                or not _HASH.fullmatch(self.delegation_policy_sha256 or "")
                or not _HASH.fullmatch(self.parent_tool_configuration_sha256 or "")
                or not isinstance(self.allowed_parent_tool_names, tuple)
                or not self.allowed_parent_tool_names or len(self.allowed_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.allowed_parent_tool_names)
                or tuple(sorted(set(self.parent_tool_names))) != self.parent_tool_names
                or tuple(sorted(set(self.allowed_parent_tool_names))) != self.allowed_parent_tool_names
                or self.parent_tool_names != self.allowed_parent_tool_names
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or not isinstance(self.profile_tool_names, tuple)
                or len(self.profile_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.profile_tool_names)
                or not isinstance(self.parent_privacy_grants, tuple)
                or len(self.parent_privacy_grants) > 128
                or any(not _ID.fullmatch(item or "") for item in self.parent_privacy_grants)
                or not isinstance(self.profile_privacy_requirements, tuple)
                or self.profile_privacy_requirements
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
            "register-attempt", "register-response",
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
            parent_info = self._socket_path.parent.lstat()
            info = self._socket_path.lstat()
            if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
                    or parent_info.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(parent_info.st_mode) != 0o750
                    or not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                    or info.st_gid != _CORE_NATIVE_OBSERVER_GROUP
                    or stat.S_IMODE(info.st_mode) != 0o660
                    or info.st_gid not in {*os.getgroups(), os.getegid()}):
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

    def register_attempt(self, *, session_id: str, turn_id: str, api_request_id: str,
                         provider: str, model: str, base_url: str, api_mode: str,
                         account_fingerprint: str, request_sha256: str,
                         parent_tool_names: tuple[str, ...],
                         prompt_sha256: str,
                         retry_count: int) -> ObservedProviderAttempt:
        """Register one exact native logical attempt; route uncertainty is denied."""
        if (provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url.rstrip("/") != _CODEX_ENDPOINT or type(retry_count) is not int
                or retry_count != 0 or not isinstance(parent_tool_names, tuple)
                or not parent_tool_names or len(parent_tool_names) > 512
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in parent_tool_names)
                or len(set(parent_tool_names)) != len(parent_tool_names)
                or "delegate_task" not in parent_tool_names):
            raise CoreNativeObservationUnavailable("attempt is outside the selected Codex subscription route")
        payload = {
            "session_id": _require_id(session_id, "session ID"),
            "turn_id": _require_id(turn_id, "turn ID"),
            "api_request_id": _require_id(api_request_id, "API request ID"),
            "provider": provider, "model": _require_id(model, "model"),
            "base_url": _CODEX_ENDPOINT, "api_mode": _CODEX_MODE,
            "account_fingerprint": _require_hash(account_fingerprint, "account fingerprint"),
            "request_sha256": _require_hash(request_sha256, "request digest"),
            "prompt_sha256": _require_hash(prompt_sha256, "prompt digest"),
            "parent_tool_names": list(parent_tool_names),
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
            "schema", "claim_handle", "owner_turn_handle", "gateway_turn_id",
            "owner_subject_sha256", "observed_call_handle",
            "core_generation", "session_id", "turn_id", "tool_call_id", "tool_name",
            "generation_sha256",
            "arguments_sha256", "account_fingerprint", "profile_id", "source_revision",
            "profile_manifest_sha256", "profile_tool_names", "profile_privacy_requirements",
            "source_manifest", "source_manifest_sha256", "prompt_b64", "prompt_sha256",
            "prompt_revision", "parent_tool_names", "parent_privacy_grants", "expires_monotonic",
            "evidence_class", "provider", "api_mode", "base_url", "additional_metered_budget",
            "delegation_policy_handle", "delegation_policy_sha256",
            "parent_tool_configuration_sha256", "allowed_parent_tool_names",
            "allow_inherited_mcp", "allow_native_orchestrator_delegation",
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
            profile_tools, privacy_requirements = claim["profile_tool_names"], claim["profile_privacy_requirements"]
            allowed_names = claim["allowed_parent_tool_names"]
            if (not isinstance(names, list) or not isinstance(grants, list)
                    or not isinstance(allowed_names, list)
                    or not isinstance(profile_tools, list) or not isinstance(privacy_requirements, list)
                    or any(not isinstance(value, str) for value in (*names, *grants, *allowed_names, *profile_tools, *privacy_requirements))
                    or type(claim["allow_inherited_mcp"]) is not bool
                    or type(claim["allow_native_orchestrator_delegation"]) is not bool):
                raise ValueError
            if claim["claim_handle"] != claim_handle:
                raise ValueError
            return RootSelectedInternalProfileDispatchClaim(
                claim_handle=claim["claim_handle"], owner_turn_handle=claim["owner_turn_handle"],
                gateway_turn_id=claim["gateway_turn_id"],
                owner_subject_sha256=claim["owner_subject_sha256"],
                observed_call_handle=claim["observed_call_handle"],
                core_generation=claim["core_generation"], session_id=claim["session_id"],
                generation_sha256=claim["generation_sha256"],
                turn_id=claim["turn_id"], tool_call_id=claim["tool_call_id"],
                tool_name=claim["tool_name"], arguments_sha256=claim["arguments_sha256"],
                account_fingerprint=claim["account_fingerprint"], profile_id=claim["profile_id"],
                source_revision=claim["source_revision"],
                profile_manifest_sha256=claim["profile_manifest_sha256"],
                source_manifest=tuple(manifest),
                source_manifest_sha256=claim["source_manifest_sha256"],
                prompt_bytes=prompt_bytes, prompt_sha256=claim["prompt_sha256"],
                prompt_revision=claim["prompt_revision"], parent_tool_names=tuple(names),
                delegation_policy_handle=claim["delegation_policy_handle"],
                delegation_policy_sha256=claim["delegation_policy_sha256"],
                parent_tool_configuration_sha256=claim["parent_tool_configuration_sha256"],
                allowed_parent_tool_names=tuple(allowed_names),
                allow_inherited_mcp=claim["allow_inherited_mcp"],
                allow_native_orchestrator_delegation=claim["allow_native_orchestrator_delegation"],
                profile_tool_names=tuple(profile_tools), parent_privacy_grants=tuple(grants),
                profile_privacy_requirements=tuple(privacy_requirements),
                expires_monotonic=claim["expires_monotonic"],
                evidence_class=claim["evidence_class"], provider=claim["provider"],
                api_mode=claim["api_mode"], base_url=claim["base_url"],
                additional_metered_budget=claim["additional_metered_budget"],
            )
        except Exception:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed") from None


class RootCoreNativeObservationRegistry:
    """Root-memory issuer joining real owner turns to protected native observations.

    This registry is composed inside the existing inspector process. It accepts
    owner turns only from that process's independently validated gateway op;
    core worker frames are accepted only after a fresh current-process custody
    check on their Unix peer credentials.
    """

    def __init__(self, custody: Any, selected_profile_source: Any, *, config: Any):
        from hermes_installer.remote.core_gateway_inspector import CoreNativeObserverCustody
        from hermes_installer.components.resources_active_profile_source import RootSelectedActiveProfileSource
        if type(custody) is not CoreNativeObserverCustody:
            raise CoreNativeObservationUnavailable("sealed current-core observer custody is required")
        if type(selected_profile_source) is not RootSelectedActiveProfileSource:
            raise CoreNativeObservationUnavailable("sealed active Resources source is required")
        if not callable(getattr(selected_profile_source, "is_current_sealed", None)):
            raise CoreNativeObservationUnavailable("current active Resources source verifier is unavailable")
        self._custody = custody
        self._source = selected_profile_source
        self._config = config
        self._lock = threading.RLock()
        self._owners: dict[str, Any] = {}
        self._owner_turn_bindings: dict[str, str] = {}
        self._policies: dict[str, dict[str, Any]] = {}
        self._owner_policy_handles: dict[str, str] = {}
        self._attempts: dict[str, dict[str, Any]] = {}
        self._calls: dict[str, dict[str, Any]] = {}
        self._claims: dict[str, dict[str, Any]] = {}
        self._closed = False

    @classmethod
    def from_current_core_custody(cls, custody: Any, *, selected_profile_source: Any,
                                  config: Any = None) -> "RootCoreNativeObservationRegistry":
        if config is None:
            raise CoreNativeObservationUnavailable("fixed inspector configuration is required")
        return cls(custody, selected_profile_source, config=config)

    def register_owner_turn(self, observation: Any) -> str:
        """Accept only the inspector's exact sealed, independently JWT-checked record."""
        from hermes_installer.remote.core_gateway_inspector import CoreVerifiedOwnerTurnObservation
        if type(observation) is not CoreVerifiedOwnerTurnObservation:
            raise CoreNativeObservationUnavailable("sealed root owner-turn observation is required")
        now = time.monotonic()
        if observation.is_current_sealed(self._config, custody=self._custody, now=now) is not True:
            self._close_fd(getattr(observation, "_core_pidfd", None))
            raise CoreNativeObservationUnavailable("owner-turn observation is stale or not current")
        handle = observation.owner_turn_handle
        with self._lock:
            self._ensure_open()
            if handle in self._owners:
                self._close_fd(getattr(observation, "_core_pidfd", None))
                raise CoreNativeObservationUnavailable("owner-turn observation was already registered")
            self._owners[handle] = observation
            while len(self._owners) > 256:
                expired_handle, expired = self._owners.popitem()
                self._owner_turn_bindings.pop(expired_handle, None)
                self._close_fd(getattr(expired, "_core_pidfd", None))
        return handle

    def enroll_current_orchestrator_policy(self, owner_turn_observation: Any,
                                           current_tool_configuration: Any
                                           ) -> RootSelectedOrchestratorDelegationPolicy:
        """Root-enroll the owner turn's current native parent inheritance policy.

        The configuration is a fixed sealed readback from the inspector, not a
        caller mapping.  This policy grants no additional tools: its allowlist is
        the already-selected native parent closure, and Hermes' own child builder
        continues to apply its blocked/disabled, pause, depth and lifecycle gates.
        """
        from hermes_installer.remote.core_gateway_inspector import (
            CoreVerifiedNativeToolConfiguration,
            CoreVerifiedOwnerTurnObservation,
        )
        if (type(owner_turn_observation) is not CoreVerifiedOwnerTurnObservation
                or type(current_tool_configuration) is not CoreVerifiedNativeToolConfiguration):
            raise CoreNativeObservationUnavailable("sealed owner and native tool configuration are required")
        now = time.monotonic()
        handle = owner_turn_observation.owner_turn_handle
        if (current_tool_configuration.is_current_sealed(
                    custody=self._custody, owner_turn=owner_turn_observation, now=now) is not True
                or owner_turn_observation.is_current_sealed(
                    self._config, custody=self._custody, now=now) is not True
                or current_tool_configuration.core_generation != owner_turn_observation.core_generation
                or current_tool_configuration.core_source_generation != owner_turn_observation.core_source_generation
                or current_tool_configuration.owner_subject_sha256 != owner_turn_observation.owner_subject_sha256):
            raise CoreNativeObservationUnavailable("current native tool configuration is not owner-bound")
        names = current_tool_configuration.allowed_parent_tool_names
        if (not isinstance(names, tuple) or not names or len(names) > 256
                or tuple(sorted(set(names))) != names
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in names)
                or "delegate_task" not in names
                or type(current_tool_configuration.allow_inherited_mcp) is not bool
                or type(current_tool_configuration.allow_native_orchestrator_delegation) is not bool
                or current_tool_configuration.allow_native_orchestrator_delegation is not True):
            raise CoreNativeObservationUnavailable("selected native delegation policy is unavailable")
        issued = time.monotonic()
        expiry = min(float(owner_turn_observation.expires_monotonic), issued + 600.0)
        if expiry <= issued:
            raise CoreNativeObservationUnavailable("owner turn expires before policy enrollment")
        policy_handle = secrets.token_urlsafe(32)
        fields = {
            "schema": 1, "policy_handle": policy_handle,
            "core_generation": owner_turn_observation.core_generation,
            "core_source_generation": owner_turn_observation.core_source_generation,
            "owner_subject_sha256": owner_turn_observation.owner_subject_sha256,
            "profile_id": "orchestrator", "mode": "native-parent-inheritance",
            "parent_tool_configuration_sha256": current_tool_configuration.tool_configuration_sha256,
            "allowed_parent_tool_names": list(names),
            "allow_inherited_mcp": current_tool_configuration.allow_inherited_mcp,
            "allow_native_orchestrator_delegation": current_tool_configuration.allow_native_orchestrator_delegation,
            "additional_metered_budget": 0,
            "issued_monotonic": issued, "expires_monotonic": expiry,
        }
        policy = RootSelectedOrchestratorDelegationPolicy(
            schema=1, policy_handle=policy_handle,
            policy_sha256=_hash(fields),
            core_generation=owner_turn_observation.core_generation,
            core_source_generation=owner_turn_observation.core_source_generation,
            owner_subject_sha256=owner_turn_observation.owner_subject_sha256,
            profile_id="orchestrator", mode="native-parent-inheritance",
            parent_tool_configuration_sha256=current_tool_configuration.tool_configuration_sha256,
            allowed_parent_tool_names=names,
            allow_inherited_mcp=current_tool_configuration.allow_inherited_mcp,
            allow_native_orchestrator_delegation=True,
            additional_metered_budget=0, issued_monotonic=issued,
            expires_monotonic=expiry, _seal=_NATIVE_INHERITANCE_POLICY_SEAL,
        )
        with self._lock:
            self._ensure_open()
            if self._owners.get(handle) is not owner_turn_observation:
                raise CoreNativeObservationUnavailable("owner turn was not registered by this root")
            old_handle = self._owner_policy_handles.pop(handle, None)
            if old_handle is not None:
                self._policies.pop(old_handle, None)
            self._policies[policy_handle] = {
                "policy": policy, "owner": owner_turn_observation,
                "configuration": current_tool_configuration,
            }
            self._owner_policy_handles[handle] = policy_handle
            while len(self._policies) > 256:
                stale_handle = next(iter(self._policies))
                stale = self._policies.pop(stale_handle)
                self._owner_policy_handles.pop(stale["owner"].owner_turn_handle, None)
        return policy

    @staticmethod
    def _close_fd(fd: Any) -> None:
        if type(fd) is int and fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass

    def _ensure_open(self) -> None:
        if self._closed:
            raise CoreNativeObservationUnavailable("root observer registry is closed")

    def _prune(self, now: float) -> None:
        for handle, row in list(self._policies.items()):
            policy = row.get("policy")
            if not isinstance(policy, RootSelectedOrchestratorDelegationPolicy) or policy.expires_monotonic <= now:
                self._policies.pop(handle, None)
                owner = row.get("owner")
                if owner is not None:
                    self._owner_policy_handles.pop(owner.owner_turn_handle, None)
        for handle, row in list(self._attempts.items()):
            if row["expiry"] <= now:
                self._attempts.pop(handle, None)
        for handle, row in list(self._calls.items()):
            if row["expiry"] <= now:
                self._calls.pop(handle, None)
        for handle, row in list(self._claims.items()):
            if row["expiry"] <= now:
                self._claims.pop(handle, None)

    def _owner_for(self, session_id: str, turn_id: str) -> Any:
        now = time.monotonic()
        for handle, owner in list(self._owners.items()):
            if owner.expires_monotonic <= now:
                self._owners.pop(handle, None)
                self._owner_turn_bindings.pop(handle, None)
                policy_handle = self._owner_policy_handles.pop(handle, None)
                if policy_handle is not None:
                    self._policies.pop(policy_handle, None)
                self._close_fd(getattr(owner, "_core_pidfd", None))
                continue
            if (owner.session_id == session_id
                    and owner.core_generation == self._custody.core_generation
                    and owner.is_current_sealed(self._config, custody=self._custody, now=now) is True):
                # The first middleware attempt binds the actual native turn ID;
                # subsequent attempts must retain that same ID.
                bound = self._owner_turn_bindings.get(handle)
                if bound is None:
                    self._owner_turn_bindings[handle] = turn_id
                    return owner
                if bound == turn_id:
                    return owner
        return None

    def _policy_for_owner(self, owner: Any, now: float) -> RootSelectedOrchestratorDelegationPolicy | None:
        from hermes_installer.remote.core_gateway_inspector import CoreVerifiedNativeToolConfiguration
        handle = self._owner_policy_handles.get(owner.owner_turn_handle)
        row = self._policies.get(handle) if isinstance(handle, str) else None
        if row is None or row.get("owner") is not owner:
            return None
        policy = row.get("policy")
        configuration = row.get("configuration")
        if (type(policy) is not RootSelectedOrchestratorDelegationPolicy
                or type(configuration) is not CoreVerifiedNativeToolConfiguration
                or policy._seal is not _NATIVE_INHERITANCE_POLICY_SEAL
                or policy.expires_monotonic <= now
                or policy.core_generation != self._custody.core_generation
                or policy.core_generation != owner.core_generation
                or policy.core_source_generation != self._custody.core_source_generation
                or policy.owner_subject_sha256 != owner.owner_subject_sha256
                or _hash(_native_policy_digest_fields(policy)) != policy.policy_sha256
                or configuration.is_current_sealed(
                    custody=self._custody, owner_turn=owner, now=now) is not True):
            self._policies.pop(handle, None)
            self._owner_policy_handles.pop(owner.owner_turn_handle, None)
            return None
        return policy

    def is_current_orchestrator_policy(self, policy: Any, owner_turn_observation: Any) -> bool:
        """Verify the exact root-retained policy before the gateway op returns."""
        if type(policy) is not RootSelectedOrchestratorDelegationPolicy:
            return False
        with self._lock:
            now = time.monotonic()
            if (self._closed
                    or self._owners.get(getattr(owner_turn_observation, "owner_turn_handle", None))
                        is not owner_turn_observation
                    or self._policy_for_owner(owner_turn_observation, now) is not policy):
                return False
            return True

    def _handle(self, peer: tuple[int, int, int], request: dict[str, Any]) -> dict[str, Any]:
        op = request.get("op")
        nonce = request.get("nonce")
        if type(request.get("schema")) is not int or request["schema"] != 1 or not isinstance(nonce, str):
            raise ValueError("invalid observer request")
        with self._lock:
            self._ensure_open()
            self._prune(time.monotonic())
            if op == "register-attempt":
                required = {"schema", "op", "nonce", "session_id", "turn_id", "api_request_id",
                            "provider", "model", "base_url", "api_mode", "account_fingerprint",
                            "request_sha256", "prompt_sha256", "parent_tool_names", "retry_count"}
                if set(request) != required:
                    raise ValueError("attempt schema mismatch")
                owner = self._owner_for(request["session_id"], request["turn_id"])
                policy = self._policy_for_owner(owner, time.monotonic()) if owner is not None else None
                if (owner is None or request["provider"] != _CODEX_PROVIDER
                        or request["api_mode"] != _CODEX_MODE or request["base_url"] != _CODEX_ENDPOINT
                        or type(request["retry_count"]) is not int or request["retry_count"] != 0
                        or not _HASH.fullmatch(request["account_fingerprint"])
                        or not _HASH.fullmatch(request["request_sha256"])
                        or not _HASH.fullmatch(request["prompt_sha256"])
                        or request["prompt_sha256"] != owner.prompt_sha256
                        or not isinstance(request["parent_tool_names"], list)
                        or not 1 <= len(request["parent_tool_names"]) <= 512
                        or any(not isinstance(name, str) or not _ID.fullmatch(name)
                               for name in request["parent_tool_names"])
                        or len(set(request["parent_tool_names"])) != len(request["parent_tool_names"])
                        or policy is None
                        or tuple(sorted(request["parent_tool_names"])) != policy.allowed_parent_tool_names):
                    raise ValueError("attempt is not an enrolled current subscription turn")
                handle = secrets.token_urlsafe(32)
                if len(self._attempts) >= 2048:
                    raise ValueError("native attempt registry is full")
                expiry = min(float(owner.expires_monotonic), time.monotonic() + 30.0)
                self._attempts[handle] = {"owner": owner, "session_id": request["session_id"],
                    "turn_id": request["turn_id"], "api_request_id": request["api_request_id"],
                    "account": request["account_fingerprint"], "expiry": expiry, "response": None,
                    "parent_tool_names": tuple(request["parent_tool_names"]),
                    "policy_handle": policy.policy_handle}
                return {"schema": 1, "nonce": nonce, "ok": True, "attempt_handle": handle,
                        "owner_turn_handle": owner.owner_turn_handle, "expires_monotonic": expiry}
            if op == "register-response":
                if set(request) != {"schema", "op", "nonce", "attempt_handle", "response_sha256", "tool_calls", "completed"}:
                    raise ValueError("response schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if (row is None or row["expiry"] <= time.monotonic() or row["response"] is not None
                        or type(request["completed"]) is not bool or not _HASH.fullmatch(request["response_sha256"])
                        or not isinstance(request["tool_calls"], list) or len(request["tool_calls"]) > 128):
                    raise ValueError("response is not a live unique attempt result")
                calls = {}
                for item in request["tool_calls"]:
                    if (not isinstance(item, dict) or set(item) != {"id", "name", "arguments_sha256"}
                            or not _ID.fullmatch(item["id"]) or not _ID.fullmatch(item["name"])
                            or not _HASH.fullmatch(item["arguments_sha256"]) or item["id"] in calls):
                        raise ValueError("provider call inventory is malformed")
                    calls[item["id"]] = item
                row["response"] = (request["response_sha256"], calls) if request["completed"] else (None, {})
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "register-tool-call":
                if set(request) != {"schema", "op", "nonce", "attempt_handle", "tool_call_id", "canonical_arguments_b64"}:
                    raise ValueError("tool-call schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if row is None or row["expiry"] <= time.monotonic() or row["response"] is None:
                    raise ValueError("tool call has no completed live response")
                returned = row["response"][1].get(request["tool_call_id"])
                args = base64.b64decode(request["canonical_arguments_b64"], validate=True)
                if (returned is None or hashlib.sha256(args).hexdigest() != returned["arguments_sha256"]
                        or not _ID.fullmatch(returned["name"])):
                    raise ValueError("tool call differs from consumed provider output")
                call_handle = secrets.token_urlsafe(32)
                if len(self._calls) >= 2048:
                    raise ValueError("native call registry is full")
                self._calls[call_handle] = {"owner": row["owner"], "attempt": request["attempt_handle"],
                    "handle": call_handle, "attempt_session_id": row["session_id"],
                    "attempt_turn_id": row["turn_id"],
                    "parent_tool_names": row["parent_tool_names"],
                    "policy_handle": row["policy_handle"],
                    "tool_call_id": request["tool_call_id"], "tool_name": returned["name"],
                    "arguments": args, "arguments_sha256": returned["arguments_sha256"],
                    "expiry": row["expiry"], "peer": peer, "claim": None}
                return {"schema": 1, "nonce": nonce, "ok": True, "observed_call_handle": call_handle,
                        "attempt_handle": request["attempt_handle"],
                        "owner_turn_handle": row["owner"].owner_turn_handle,
                        "tool_call_id": request["tool_call_id"], "tool_name": returned["name"],
                        "arguments_sha256": returned["arguments_sha256"], "expires_monotonic": row["expiry"]}
            if op == "prepare-dispatch":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle"}:
                    raise ValueError("prepare schema mismatch")
                call = self._calls.get(request["observed_call_handle"])
                source = self._source.resolve_current(self._custody)
                policy_row = self._policies.get(call["policy_handle"]) if call is not None else None
                policy = policy_row.get("policy") if policy_row is not None else None
                try:
                    call_args = json.loads(call["arguments"].decode("utf-8", errors="strict")) if call else None
                    parent_tools = frozenset(call["parent_tool_names"]) if call else frozenset()
                except Exception:
                    call_args, parent_tools = None, frozenset()
                if (call is None or call["expiry"] <= time.monotonic() or call["claim"] is not None
                        or call["tool_name"] != "resources_delegate"
                        or call["peer"] != peer
                        or policy is None
                        or type(policy) is not RootSelectedOrchestratorDelegationPolicy
                        or self._policy_for_owner(call["owner"], time.monotonic()) is not policy
                        or tuple(sorted(parent_tools)) != policy.allowed_parent_tool_names
                        or policy.additional_metered_budget != 0
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or source.profile_id != "orchestrator"
                        or source.profile_privacy_requirements
                        or not isinstance(call_args, dict) or set(call_args) != {"goal"}
                        or not isinstance(call_args.get("goal"), str)
                        or not call_args["goal"].strip() or len(call_args["goal"]) > 1200
                        or any(ord(char) < 0x20 and char not in "\n\t" for char in call_args["goal"])):
                    raise ValueError("selected profile or native call is unavailable")
                claim_handle = secrets.token_urlsafe(32)
                if len(self._claims) >= 2048:
                    raise ValueError("dispatch claim registry is full")
                call["claim"] = claim_handle
                self._claims[claim_handle] = {"call": call,
                    "owner": call["owner"], "policy": policy,
                    "expiry": min(call["expiry"], float(source.expires_monotonic),
                                  policy.expires_monotonic)}
                return {"schema": 1, "nonce": nonce, "ok": True, "claim_handle": claim_handle}
            if op == "consume-dispatch":
                if set(request) != {"schema", "op", "nonce", "claim_handle"}:
                    raise ValueError("consume schema mismatch")
                claim = self._claims.pop(request["claim_handle"], None)
                if claim is None or claim["expiry"] <= time.monotonic():
                    raise ValueError("dispatch claim expired or was already consumed")
                call, owner = claim["call"], claim["owner"]
                policy = claim["policy"]
                source = self._source.resolve_current(self._custody)
                if (call["peer"] != peer or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=time.monotonic()) is not True
                        or self._policy_for_owner(owner, time.monotonic()) is not policy
                        or tuple(sorted(call["parent_tool_names"])) != policy.allowed_parent_tool_names):
                    raise ValueError("dispatch lineage is no longer current")
                # Source/tool/privacy intersection is completed by the consumer against
                # the exact locally injected parent Agent; no Agent crosses this socket.
                manifest = [{"path": item.path, "sha256": item.sha256, "size": item.size}
                            for item in source.source_member_manifest]
                body = {"schema": 1, "claim_handle": request["claim_handle"],
                    "owner_turn_handle": owner.owner_turn_handle, "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "observed_call_handle": call["handle"],
                    "core_generation": owner.core_generation, "session_id": call["attempt_session_id"],
                    "generation_sha256": source.generation_sha256,
                    "turn_id": call["attempt_turn_id"], "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "account_fingerprint": self._attempts[call["attempt"]]["account"],
                    "profile_id": source.profile_id, "source_revision": source.source_revision,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "profile_tool_names": sorted(source.profile_tool_names),
                    "profile_privacy_requirements": sorted(source.profile_privacy_requirements),
                    "source_manifest": manifest, "source_manifest_sha256": _hash(manifest),
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256, "prompt_revision": source.source_revision,
                    "parent_tool_names": list(call["parent_tool_names"]), "parent_privacy_grants": [],
                    "delegation_policy_handle": policy.policy_handle,
                    "delegation_policy_sha256": policy.policy_sha256,
                    "parent_tool_configuration_sha256": policy.parent_tool_configuration_sha256,
                    "allowed_parent_tool_names": list(policy.allowed_parent_tool_names),
                    "allow_inherited_mcp": policy.allow_inherited_mcp,
                    "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
                    "expires_monotonic": claim["expiry"], "evidence_class": "protected-core-process-observation",
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE, "base_url": _CODEX_ENDPOINT,
                    "additional_metered_budget": 0}
                return {"schema": 1, "nonce": nonce, "ok": True, "dispatch_claim": body}
        raise ValueError("unsupported observer operation")

    def serve_connection(self, connection: socket.socket) -> None:
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        request = _read_frame(connection)
        nonce = request.get("nonce") if isinstance(request, dict) else None
        try:
            if self._custody.verify_peer(self._config, self._owner_for_peer(request), connection) is not True:
                raise PermissionError("core peer custody did not verify")
            result = self._handle((peer_pid, peer_uid, peer_gid), request)
        except Exception:
            result = {"schema": 1, "nonce": nonce, "ok": False}
        raw = _canonical(result)
        connection.sendall(struct.pack("!I", len(raw)) + raw)

    def _owner_for_peer(self, request: dict[str, Any]) -> Any:
        with self._lock:
            for owner in self._owners.values():
                if owner.core_pid == self._custody.core_pid and owner.core_start_ticks == self._custody.core_start_ticks:
                    return owner
        raise CoreNativeObservationUnavailable("current authenticated core owner turn is unavailable")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            for owner in self._owners.values():
                self._close_fd(getattr(owner, "_core_pidfd", None))
            self._owners.clear()
            self._owner_turn_bindings.clear()
            self._policies.clear()
            self._owner_policy_handles.clear()
            self._attempts.clear()
            self._calls.clear()
            self._claims.clear()


def serve_core_native_observer(registry: RootCoreNativeObservationRegistry, *,
                               socket_path: Path = CORE_NATIVE_OBSERVER_SOCKET,
                               admin_gid: int = _CORE_NATIVE_OBSERVER_GROUP,
                               stop_event: threading.Event | None = None) -> None:
    """Serve fixed bounded IPC in the already-running inspector process."""
    if type(registry) is not RootCoreNativeObservationRegistry or socket_path != CORE_NATIVE_OBSERVER_SOCKET:
        raise CoreNativeObservationUnavailable("fixed root observer registry and socket are required")
    runtime = _OBSERVER_RUNTIME_DIR
    info = runtime.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != admin_gid
            or stat.S_IMODE(info.st_mode) != 0o750):
        raise CoreNativeObservationUnavailable("root observer runtime directory custody differs")
    try:
        old = socket_path.lstat()
    except FileNotFoundError:
        old = None
    if old is not None:
        if not stat.S_ISSOCK(old.st_mode) or old.st_uid != 0 or old.st_gid != admin_gid:
            raise CoreNativeObservationUnavailable("existing observer socket is not root-owned")
        socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(socket_path))
        os.chown(socket_path, 0, admin_gid)
        os.chmod(socket_path, 0o660)
        listener.listen(16)
        listener.settimeout(0.5)
        while stop_event is None or not stop_event.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            with connection:
                connection.settimeout(2.0)
                try:
                    registry.serve_connection(connection)
                except Exception:
                    # Malformed peers cannot stop the root inspector's worker listener.
                    continue
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass


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


def _request_tool_names(request: Mapping[str, Any]) -> tuple[str, ...]:
    """Read the exact function-tool inventory sent to the provider."""
    tools = request.get("tools")
    if not isinstance(tools, list) or not 1 <= len(tools) <= 512:
        raise CoreNativeObservationUnavailable("native parent tool inventory is unavailable")
    names: list[str] = []
    for item in tools:
        if not isinstance(item, Mapping):
            raise CoreNativeObservationUnavailable("native parent tool inventory is malformed")
        name = item.get("name")
        if name is None and isinstance(item.get("function"), Mapping):
            name = item["function"].get("name")
        if not isinstance(name, str) or not _ID.fullmatch(name):
            raise CoreNativeObservationUnavailable("native parent tool inventory is malformed")
        names.append(name)
    if len(set(names)) != len(names):
        raise CoreNativeObservationUnavailable("native parent tool inventory is ambiguous")
    return tuple(sorted(names))


def _native_prompt_sha256(request: Mapping[str, Any]) -> str:
    """Hash the exact final user text in the Codex Responses request.

    Multimodal or transformed prompts that cannot be proven byte-identical to
    the accepted ingress prompt do not produce an owner-turn attempt receipt.
    """
    items = request.get("input")
    if not isinstance(items, list):
        raise CoreNativeObservationUnavailable("native user prompt is unavailable")
    users = [item for item in items if isinstance(item, Mapping)
             and item.get("type") == "message" and item.get("role") == "user"]
    if not users:
        raise CoreNativeObservationUnavailable("native user prompt is unavailable")
    content = users[-1].get("content")
    if (not isinstance(content, list) or len(content) != 1
            or not isinstance(content[0], Mapping) or content[0].get("type") != "input_text"
            or not isinstance(content[0].get("text"), str)):
        raise CoreNativeObservationUnavailable("native user prompt cannot be bound byte-for-byte")
    return hashlib.sha256(content[0]["text"].encode("utf-8", errors="strict")).hexdigest()


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
                account_fingerprint=account, request_sha256=_hash(request),
                parent_tool_names=_request_tool_names(request),
                prompt_sha256=_native_prompt_sha256(request), retry_count=0,
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


class RootInternalProfileClaimSource:
    """Resources-side adapter joining exact live handler metadata to root claims."""

    def __init__(self, client: CoreNativeObservationClient):
        if type(client) is not CoreNativeObservationClient:
            raise CoreNativeObservationUnavailable("fixed native observation client is required")
        self._client = client

    def consume_current_claim(self, profile_id: str, parent_agent: object, *,
                              tool_call_id: str, tool_name: str,
                              arguments: Mapping[str, Any], turn_id: str):
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        if profile_id != "orchestrator" or tool_name != "resources_delegate":
            raise CoreNativeObservationUnavailable("only the fixed orchestrator tool may be claimed")
        observed_turn = _require_id(getattr(parent_agent, "_current_turn_id", None), "native turn ID")
        if turn_id != observed_turn:
            raise CoreNativeObservationUnavailable("handler turn differs from the current parent turn")
        observed_call = register_tool_call_from_current_parent(
            client=self._client, parent_agent=parent_agent, tool_call_id=tool_call_id,
            tool_name=tool_name, arguments=arguments)
        claim_handle = self._client.prepare_dispatch(observed_call=observed_call)
        claim = self._client.consume_dispatch(claim_handle=claim_handle)
        try:
            parent_tools = frozenset(getattr(parent_agent, "valid_tool_names"))
            if (type(claim) is not RootSelectedInternalProfileDispatchClaim
                    or claim.profile_id != profile_id or claim.tool_name != tool_name
                    or claim.tool_call_id != tool_call_id or claim.turn_id != observed_turn
                    or claim.session_id != getattr(parent_agent, "session_id")
                    or claim.arguments_sha256 != hashlib.sha256(_canonical(dict(arguments))).hexdigest()
                    or set(claim.parent_tool_names) != set(parent_tools)
                    or claim.profile_privacy_requirements or claim.parent_privacy_grants):
                raise ValueError
            route_receipt = _hash({
                "evidence_class": claim.evidence_class, "provider": claim.provider,
                "api_mode": claim.api_mode, "base_url": claim.base_url,
                "account_fingerprint": claim.account_fingerprint,
                "owner_turn_handle": claim.owner_turn_handle,
                "gateway_turn_id": claim.gateway_turn_id,
                "tool_call_id": claim.tool_call_id,
                "delegation_policy_sha256": claim.delegation_policy_sha256,
                "parent_tool_configuration_sha256": claim.parent_tool_configuration_sha256,
            })
            return ResourcesDispatchClaim(
                claim_id=claim.claim_handle, profile_id=claim.profile_id,
                source_revision=claim.source_revision,
                generation_sha256=claim.generation_sha256,
                profile_manifest_sha256=claim.profile_manifest_sha256,
                effective_prompt=claim.prompt_bytes,
                effective_prompt_sha256=claim.prompt_sha256,
                parent_agent=parent_agent, parent_session_id=claim.session_id,
                owner_subject_sha256=claim.owner_subject_sha256,
                parent_tool_names=parent_tools,
                profile_tool_names=frozenset(claim.profile_tool_names),
                # This is native parent inheritance authorized by the distinct
                # root policy, not a Resources profile tool grant.
                inherited_child_tool_names=frozenset(claim.allowed_parent_tool_names),
                parent_privacy_grants=frozenset(),
                profile_privacy_requirements=frozenset(),
                delegation_policy_handle=claim.delegation_policy_handle,
                delegation_policy_sha256=claim.delegation_policy_sha256,
                parent_tool_configuration_sha256=claim.parent_tool_configuration_sha256,
                allowed_parent_tool_names=frozenset(claim.allowed_parent_tool_names),
                allow_inherited_mcp=claim.allow_inherited_mcp,
                allow_native_orchestrator_delegation=claim.allow_native_orchestrator_delegation,
                route_class="existing-owner-codex-zero-additional-metered",
                route_receipt_sha256=route_receipt,
                max_additional_metered_microusd=0,
                expires_monotonic=claim.expires_monotonic,
            )
        except Exception:
            raise CoreNativeObservationUnavailable("root claim does not match the live native parent") from None


def register_native_resources_observer(ctx: Any, runtime_context: Any, *,
                                       credential_resolver: Callable[[], Mapping[str, Any]] | None = None) -> tuple[Any, ...]:
    """Register the fixed Resources handler and additive Codex middleware together.

    The plugin runtime may inject only the exact fixed socket client; it cannot
    replace route evidence, select a profile, or mint claims.
    """
    client = getattr(runtime_context, "core_native_observation_client", None)
    if client is None:
        client = CoreNativeObservationClient()
    if type(client) is not CoreNativeObservationClient:
        raise CoreNativeObservationUnavailable("fixed root observer client is unavailable")
    from hermes_installer.components.resources_internal_dispatch import register_resources_delegate
    middleware = install_native_codex_process_observer(
        ctx, client=client, credential_resolver=credential_resolver)
    tool = register_resources_delegate(ctx, RootInternalProfileClaimSource(client))
    return (*middleware, tool)


# Function attributes keep the local parent/call join private to this imported
# source module and avoid a process-global registry object exposed to plugins.
register_tool_call_from_current_parent._lineage = OrderedDict()
register_tool_call_from_current_parent._lock = threading.RLock()


__all__ = [
    "CORE_NATIVE_OBSERVER_SOCKET", "CoreNativeObservationClient",
    "CoreNativeObservationUnavailable", "ObservedNativeToolCall",
    "NativeSourceMember", "ObservedProviderAttempt", "OwnerTurnHandle",
    "RootSelectedInternalProfileDispatchClaim", "RootCoreNativeObservationRegistry",
    "RootInternalProfileClaimSource", "serve_core_native_observer",
    "install_native_codex_process_observer", "register_native_resources_observer",
    "register_tool_call_from_current_parent",
]
