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
import sqlite3
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from hermes_installer.remote.jarvis_mission_executor import MissionBinding


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
_RESOURCES_DELEGATE_REGISTRATION_SEAL = object()
_RESOURCES_DELEGATE_SOURCE_SHA256 = "6eee1b932dfda36efc93e3901ccedf86af06af684d1c5c77bf882c1ba18a5d64"
_RESOURCES_DELEGATE_SCHEMA_SHA256 = "9325cea421e122395475b0ba0d0517cb4aa4c16c3d4a14c5145f9fcc3f957f33"
_MISSION_AUTHORIZATION_SEAL = object()
_NATIVE_CHILD_AUTHORIZATION_SEAL = object()
_MASTER_PLANNING_COMPLETION_SEAL = object()
_SELECTED_SOURCE_DELIVERY_SEAL = object()


@dataclass(frozen=True, slots=True)
class CoreNativeResourcesDelegateRegistration:
    """Fixed registration descriptor consumed by the inspector's source verifier.

    This is an expected-value descriptor, not runtime evidence by itself. The
    inspector must independently verify the package-relative bytes and the
    Hermes process must expose the tool in the observed provider request.
    """

    schema: int
    name: str
    toolset: str
    package_relative_path: str
    schema_sha256: str
    source_sha256: str
    _seal: object


def current_resources_delegate_registration() -> CoreNativeResourcesDelegateRegistration:
    """Return the fixed Resources tool identity and expected source digests."""
    return CoreNativeResourcesDelegateRegistration(
        schema=1,
        name="resources_delegate",
        toolset="resources_internal",
        package_relative_path="components/resources_internal_dispatch.py",
        schema_sha256=_RESOURCES_DELEGATE_SCHEMA_SHA256,
        source_sha256=_RESOURCES_DELEGATE_SOURCE_SHA256,
        _seal=_RESOURCES_DELEGATE_REGISTRATION_SEAL,
    )


class CoreNativeObservationUnavailable(PermissionError):
    """Current protected core observation could not be registered or consumed."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _hash(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _mission_binding_from_wire(value: Any) -> MissionBinding | None:
    if value is None:
        return None
    try:
        binding = MissionBinding.from_wire(value)
        if type(binding) is not MissionBinding or binding.to_wire() != value:
            raise ValueError
        return binding
    except Exception:
        raise CoreNativeObservationUnavailable("mission binding payload is malformed") from None


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


_MASTER_READ_CALL_SEAL = object()
_MASTER_READ_TOOL_NAMES = frozenset({"web_search", "web_extract", "skills_list", "skill_view"})


@dataclass(frozen=True, slots=True)
class RootVerifiedMasterReadCall:
    """Root classification of one exact current master/selected-child call."""

    observed_call_handle: str
    owner_turn_handle: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    source_generation_sha256: str
    mode: str
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.observed_call_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _ID.fullmatch(self.tool_call_id or "")
                or not _ID.fullmatch(self.tool_name or "")
                or not _HASH.fullmatch(self.arguments_sha256 or "")
                or not _HASH.fullmatch(self.source_generation_sha256 or "")
                or self.mode not in {"master_read", "master_effect", "expert_read"}
                or type(self.expires_monotonic) not in (int, float)
                or not time.monotonic() < self.expires_monotonic <= time.monotonic() + 30.0
                or self._seal is not _MASTER_READ_CALL_SEAL):
            raise CoreNativeObservationUnavailable("root native caller classification is malformed")

    def matches_call(self, observed_call: Any, *, tool_name: str,
                     arguments_sha256: str, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        return (type(observed_call) is ObservedNativeToolCall
                and self._seal is _MASTER_READ_CALL_SEAL
                and now < self.expires_monotonic
                and self.observed_call_handle == observed_call.handle
                and self.owner_turn_handle == observed_call.owner_turn_handle
                and self.tool_call_id == observed_call.tool_call_id
                and self.tool_name == tool_name == observed_call.tool_name
                and self.arguments_sha256 == arguments_sha256 == observed_call.arguments_sha256)


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
    policy caps tools at the configured native parent maximum. The observed
    provider request carries the effective current subset. Hermes still applies its own blocked,
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
    configured_parent_tool_names: tuple[str, ...]
    resources_delegate_schema_sha256: str
    resources_delegate_source_sha256: str
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
                or self.profile_id != "hermes"
                or self.mode != "native-parent-inheritance"
                or not _HASH.fullmatch(self.parent_tool_configuration_sha256 or "")
                or self.resources_delegate_schema_sha256 != _RESOURCES_DELEGATE_SCHEMA_SHA256
                or self.resources_delegate_source_sha256 != _RESOURCES_DELEGATE_SOURCE_SHA256
                or not isinstance(self.configured_parent_tool_names, tuple)
                or not self.configured_parent_tool_names or len(self.configured_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.configured_parent_tool_names)
                or len(set(self.configured_parent_tool_names)) != len(self.configured_parent_tool_names)
                or tuple(sorted(self.configured_parent_tool_names)) != self.configured_parent_tool_names
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or "delegate_task" not in self.configured_parent_tool_names
                or "resources_delegate" not in self.configured_parent_tool_names
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
        "configured_parent_tool_names": list(policy.configured_parent_tool_names),
        "resources_delegate_schema_sha256": policy.resources_delegate_schema_sha256,
        "resources_delegate_source_sha256": policy.resources_delegate_source_sha256,
        "allow_inherited_mcp": policy.allow_inherited_mcp,
        "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
        "additional_metered_budget": policy.additional_metered_budget,
        "issued_monotonic": policy.issued_monotonic,
        "expires_monotonic": policy.expires_monotonic,
    }


def _configuration_has_fixed_resources_delegate(configuration: Any) -> bool:
    registration = current_resources_delegate_registration()
    return (
        type(registration) is CoreNativeResourcesDelegateRegistration
        and registration._seal is _RESOURCES_DELEGATE_REGISTRATION_SEAL
        and getattr(configuration, "resources_delegate_name", None) == registration.name
        and getattr(configuration, "resources_delegate_toolset", None) == registration.toolset
        and getattr(configuration, "resources_delegate_schema_sha256", None) == registration.schema_sha256
        and getattr(configuration, "resources_delegate_source_sha256", None) == registration.source_sha256
    )


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
    core_source_generation: str
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
    configured_parent_tool_names: tuple[str, ...]
    allow_inherited_mcp: bool
    allow_native_orchestrator_delegation: bool
    mission_binding: MissionBinding | None
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
                or not _HASH.fullmatch(self.core_source_generation or "")
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
                or not isinstance(self.configured_parent_tool_names, tuple)
                or not self.configured_parent_tool_names or len(self.configured_parent_tool_names) > 256
                or any(not _ID.fullmatch(item or "") for item in self.configured_parent_tool_names)
                or tuple(sorted(set(self.parent_tool_names))) != self.parent_tool_names
                or tuple(sorted(set(self.configured_parent_tool_names))) != self.configured_parent_tool_names
                or not set(self.parent_tool_names).issubset(self.configured_parent_tool_names)
                or type(self.allow_inherited_mcp) is not bool
                or type(self.allow_native_orchestrator_delegation) is not bool
                or not self.allow_native_orchestrator_delegation
                or (self.mission_binding is not None
                    and type(self.mission_binding) is not MissionBinding)
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


@dataclass(frozen=True, slots=True)
class RootVerifiedMissionDispatchAuthorization:
    """Typed one-use result of the root's immediate persisted-approval recheck."""

    claim_handle: str
    mission_binding_sha256: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    source_profile_id: str
    canonical_arguments_sha256: str
    expires_monotonic: float
    _seal: object

    def matches_claim(self, claim: RootSelectedInternalProfileDispatchClaim,
                      canonical_arguments_sha256: str, *, now: float) -> bool:
        return bool(
            type(self) is RootVerifiedMissionDispatchAuthorization
            and self._seal is _MISSION_AUTHORIZATION_SEAL
            and type(claim) is RootSelectedInternalProfileDispatchClaim
            and claim.mission_binding is not None
            and self.claim_handle == claim.claim_handle
            and self.mission_binding_sha256 == _hash(claim.mission_binding.to_wire())
            and self.gateway_turn_id == claim.gateway_turn_id
            and self.owner_subject_sha256 == claim.owner_subject_sha256
            and self.core_generation == claim.core_generation
            and self.core_source_generation == claim.core_source_generation
            and self.source_profile_id == claim.mission_binding.source_profile_id == "hermes"
            and self.canonical_arguments_sha256 == canonical_arguments_sha256
            and self.canonical_arguments_sha256 == claim.arguments_sha256
            and _HASH.fullmatch(self.mission_binding_sha256 or "") is not None
            and type(self.expires_monotonic) in (int, float)
            and math.isfinite(float(self.expires_monotonic))
            and now < self.expires_monotonic <= min(claim.expires_monotonic, now + 30.0)
        )


@dataclass(frozen=True, slots=True)
class RootNativeSelectedSourceDelivery:
    """Exact selected source bytes delivered from root for a single child build."""

    source_handle: str
    profile_id: str
    source_revision: str
    generation_sha256: str
    source_manifest_sha256: str
    profile_manifest_sha256: str
    effective_prompt: bytes
    effective_prompt_sha256: str
    _seal: object

    @property
    def source_member_manifest_sha256(self) -> str:
        """Compatibility name used by native child authorization matching."""
        return self.source_manifest_sha256

    def __post_init__(self) -> None:
        if (not _OPAQUE.fullmatch(self.source_handle or "")
                or not _ID.fullmatch(self.profile_id or "")
                or not isinstance(self.source_revision, str) or not self.source_revision
                or not all(_HASH.fullmatch(item or "") for item in (
                    self.generation_sha256, self.source_manifest_sha256,
                    self.profile_manifest_sha256, self.effective_prompt_sha256))
                or not isinstance(self.effective_prompt, bytes) or not self.effective_prompt
                or len(self.effective_prompt) > 128 * 1024
                or hashlib.sha256(self.effective_prompt).hexdigest() != self.effective_prompt_sha256
                or self._seal is not _SELECTED_SOURCE_DELIVERY_SEAL):
            raise CoreNativeObservationUnavailable("root selected source delivery is malformed")


@dataclass(frozen=True, slots=True)
class RootVerifiedNativeChildAuthorization:
    """Short-lived root admission for one exact native child session."""

    owner_turn_handle: str
    gateway_turn_id: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    parent_session_id: str
    parent_turn_id: str
    child_session_id: str
    profile_id: str
    source_generation_sha256: str
    source_manifest_sha256: str
    prompt_sha256: str
    goal_sha256: str
    account_fingerprint: str
    mode: str
    allowed_tool_names: tuple[str, ...]
    tool_closure_sha256: str
    additional_metered_budget: int
    admission_handle: str
    expires_monotonic: float
    _parent_agent: Any
    _child_agent: Any
    _source: Any
    _seal: object

    def matches_child(self, *, parent_agent: Any, child: Any, source: Any,
                      mode: Any, goal: str, now: float) -> bool:
        try:
            actual_names = tuple(sorted(getattr(child, "valid_tool_names")))
            actual_source = (
                getattr(source, "profile_id", getattr(source, "source_id", None)),
                getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None)),
                getattr(source, "source_member_manifest_sha256",
                        getattr(source, "profile_member_manifest_sha256", None)),
                getattr(source, "effective_prompt_sha256",
                        getattr(source, "profile_prompt_sha256", None)),
            )
            parent_route = tuple(getattr(parent_agent, key, None)
                                 for key in ("provider", "api_mode", "base_url", "model"))
            child_route = tuple(getattr(child, key, None)
                                for key in ("provider", "api_mode", "base_url", "model"))
        except (TypeError, AttributeError):
            return False
        fixed_names = frozenset(
            {"web_search", "web_extract", "skills_list", "skill_view"}
            if getattr(mode, "value", None) == "expert-read-research" else set()
        )
        expected_names = tuple(self.allowed_tool_names)
        return bool(
            type(self) is RootVerifiedNativeChildAuthorization
            and self._seal is _NATIVE_CHILD_AUTHORIZATION_SEAL
            and self._parent_agent is parent_agent and self._child_agent is child
            and self._source is source
            and self.owner_turn_handle and self.gateway_turn_id
            and _HASH.fullmatch(self.owner_subject_sha256 or "")
            and _HASH.fullmatch(self.core_generation or "")
            and _HASH.fullmatch(self.core_source_generation or "")
            and self.parent_session_id == getattr(parent_agent, "session_id", None)
            and self.parent_turn_id == getattr(parent_agent, "_current_turn_id", None)
            and self.child_session_id == getattr(child, "session_id", None)
            and hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest() == self.goal_sha256
            and actual_source == (self.profile_id, self.source_generation_sha256,
                                  self.source_manifest_sha256, self.prompt_sha256)
            and tuple(sorted(expected_names)) == expected_names
            and set(expected_names).issubset(fixed_names)
            and actual_names == expected_names
            and type(self.additional_metered_budget) is int
            and self.additional_metered_budget == 0
            and _hash(list(actual_names)) == self.tool_closure_sha256
            and parent_route == child_route
            and parent_route == (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT,
                                 getattr(parent_agent, "model", None))
            and _HASH.fullmatch(self.account_fingerprint or "")
            and _HASH.fullmatch(self.goal_sha256 or "")
            and type(self.expires_monotonic) in (int, float)
            and math.isfinite(float(self.expires_monotonic))
            and now < self.expires_monotonic <= now + 30.0
        )


@dataclass(frozen=True, slots=True)
class CoreVerifiedJarvisMasterPlanningCompletion:
    """Root-confirmed completion receipt for a no-tools Jarvis planner child."""

    owner_subject_sha256: str
    owner_turn_handle: str
    gateway_turn_id: str
    core_generation: str
    core_source_generation: str
    prompt_sha256: str
    response_sha256: str
    completion_handle: str
    expires_monotonic: float
    _client: Any
    _seal: object

    def is_current_sealed(self, config: Any = None, custody: Any = None,
                          now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        if (type(self) is not CoreVerifiedJarvisMasterPlanningCompletion
                or self._seal is not _MASTER_PLANNING_COMPLETION_SEAL
                or not _HASH.fullmatch(self.owner_subject_sha256 or "")
                or not _HASH.fullmatch(self.core_generation or "")
                or not _HASH.fullmatch(self.core_source_generation or "")
                or not _HASH.fullmatch(self.prompt_sha256 or "")
                or not _HASH.fullmatch(self.response_sha256 or "")
                or not isinstance(self.owner_turn_handle, str)
                or not isinstance(self.gateway_turn_id, str)
                or not _OPAQUE.fullmatch(self.completion_handle or "")
                or not current < self.expires_monotonic <= current + 30.0):
            return False
        verifier = getattr(self._client, "verify_planning_completion", None)
        return bool(callable(verifier) and verifier(self, config=config, custody=custody) is True)


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
            "authorize-mission-dispatch", "admit-native-child",
            "admit-master-planner-child",
            "complete-native-child", "verify-planning-completion",
            "request-final-effect", "poll-final-effect", "authorize-master-read-call",
            "read-selected-expert-source", "admit-selected-expert-child",
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
                or len(parent_tool_names) > 512
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in parent_tool_names)
                or len(set(parent_tool_names)) != len(parent_tool_names)):
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
                          response_sha256: str, response_text_sha256: str | None,
                          tool_calls: list[dict[str, str]],
                          completed: bool) -> None:
        if type(attempt) is not ObservedProviderAttempt or type(completed) is not bool:
            raise CoreNativeObservationUnavailable("provider response is not correlated")
        calls = []
        text_digest = (_require_hash(response_text_sha256, "response text digest")
                       if response_text_sha256 is not None else None)
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
            "response_text_sha256": text_digest,
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
            "core_generation", "core_source_generation", "session_id", "turn_id", "tool_call_id", "tool_name",
            "generation_sha256",
            "arguments_sha256", "account_fingerprint", "profile_id", "source_revision",
            "profile_manifest_sha256", "profile_tool_names", "profile_privacy_requirements",
            "source_manifest", "source_manifest_sha256", "prompt_b64", "prompt_sha256",
            "prompt_revision", "parent_tool_names", "parent_privacy_grants", "expires_monotonic",
            "evidence_class", "provider", "api_mode", "base_url", "additional_metered_budget",
            "delegation_policy_handle", "delegation_policy_sha256",
            "parent_tool_configuration_sha256", "configured_parent_tool_names",
            "allow_inherited_mcp", "allow_native_orchestrator_delegation",
            "mission_binding",
        }
        if not isinstance(claim, dict) or set(claim) != required:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed")
        try:
            if type(claim["schema"]) is not int or claim["schema"] != 1:
                raise ValueError
            mission_binding = _mission_binding_from_wire(claim["mission_binding"])
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
            configured_names = claim["configured_parent_tool_names"]
            if (not isinstance(names, list) or not isinstance(grants, list)
                    or not isinstance(configured_names, list)
                    or not isinstance(profile_tools, list) or not isinstance(privacy_requirements, list)
                    or any(not isinstance(value, str) for value in (*names, *grants, *configured_names, *profile_tools, *privacy_requirements))
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
                core_source_generation=claim["core_source_generation"],
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
                configured_parent_tool_names=tuple(configured_names),
                allow_inherited_mcp=claim["allow_inherited_mcp"],
                allow_native_orchestrator_delegation=claim["allow_native_orchestrator_delegation"],
                mission_binding=mission_binding,
                profile_tool_names=tuple(profile_tools), parent_privacy_grants=tuple(grants),
                profile_privacy_requirements=tuple(privacy_requirements),
                expires_monotonic=claim["expires_monotonic"],
                evidence_class=claim["evidence_class"], provider=claim["provider"],
                api_mode=claim["api_mode"], base_url=claim["base_url"],
                additional_metered_budget=claim["additional_metered_budget"],
            )
        except Exception:
            raise CoreNativeObservationUnavailable("root dispatch claim payload is malformed") from None

    def authorize_mission_dispatch(self, *, claim: RootSelectedInternalProfileDispatchClaim):
        if type(claim) is not RootSelectedInternalProfileDispatchClaim or claim.mission_binding is None:
            raise CoreNativeObservationUnavailable("a root-sealed mission claim is required")
        row = self._rpc("authorize-mission-dispatch", {"claim_handle": claim.claim_handle})
        required = {"schema", "nonce", "ok", "claim_handle", "mission_binding_sha256", "gateway_turn_id",
                    "owner_subject_sha256", "core_generation", "core_source_generation",
                    "source_profile_id", "canonical_arguments_sha256", "expires_monotonic"}
        if (not isinstance(row, dict) or set(row) != required
                or type(row.get("ok")) is not bool or row["ok"] is not True):
            raise CoreNativeObservationUnavailable("mission authorization response is malformed")
        binding = claim.mission_binding
        if (type(row["schema"]) is not int or row["schema"] != 1
                or row["claim_handle"] != claim.claim_handle
                or row["mission_binding_sha256"] != _hash(binding.to_wire())
                or row["gateway_turn_id"] != claim.gateway_turn_id
                or row["owner_subject_sha256"] != claim.owner_subject_sha256
                or row["core_generation"] != claim.core_generation
                or row["core_source_generation"] != claim.core_source_generation
                or row["source_profile_id"] != binding.source_profile_id
                or row["canonical_arguments_sha256"] != claim.arguments_sha256):
            raise CoreNativeObservationUnavailable("mission authorization does not match the claim")
        return RootVerifiedMissionDispatchAuthorization(
            claim_handle=claim.claim_handle,
            mission_binding_sha256=row["mission_binding_sha256"],
            gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"],
            core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"],
            source_profile_id=row["source_profile_id"],
            canonical_arguments_sha256=row["canonical_arguments_sha256"],
            expires_monotonic=row["expires_monotonic"],
            _seal=_MISSION_AUTHORIZATION_SEAL,
        )

    def admit_native_child(self, *, parent_claim: RootSelectedInternalProfileDispatchClaim,
                           child: Any, source: Any, mode: Any, goal: str
                           ) -> RootVerifiedNativeChildAuthorization:
        """Root-admit one constructed child before any child provider request."""
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (type(parent_claim) is not RootSelectedInternalProfileDispatchClaim
                or type(mode) is not NativeChildMode or not isinstance(goal, str)
                or not goal or len(goal.encode("utf-8", errors="strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("typed parent claim, child mode, and bounded goal are required")
        parent = parent_claim.parent_agent
        try:
            profile_id = getattr(source, "profile_id", getattr(source, "source_id", None))
            generation = getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None))
            manifest = getattr(source, "source_member_manifest_sha256",
                               getattr(source, "profile_member_manifest_sha256", None))
            prompt = getattr(source, "effective_prompt_sha256", getattr(source, "profile_prompt_sha256", None))
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            current_child_turn = getattr(child, "_current_turn_id", None)
            child_turn = (_require_id(current_child_turn, "child turn ID")
                          if current_child_turn else "")
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("constructed child lineage is incomplete") from None
        if (not isinstance(profile_id, str) or not isinstance(generation, str)
                or not isinstance(manifest, str) or not isinstance(prompt, str)
                or provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url != _CODEX_ENDPOINT or model != getattr(parent, "model", None)
                or tuple(sorted(set(tool_names))) != tool_names):
            raise CoreNativeObservationUnavailable("child differs from the selected source or Codex route")
        row = self._rpc("admit-native-child", {
            "parent_claim_handle": parent_claim.claim_handle,
            "owner_turn_handle": parent_claim.owner_turn_handle,
            "parent_session_id": parent_claim.session_id,
            "parent_turn_id": parent_claim.turn_id,
            "child_session_id": child_session,
            "child_turn_id": child_turn,
            "profile_id": _require_id(profile_id, "selected profile ID"),
            "source_generation_sha256": _require_hash(generation, "selected source generation"),
            "source_manifest_sha256": _require_hash(manifest, "selected source manifest"),
            "prompt_sha256": _require_hash(prompt, "selected source prompt"),
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest(),
            "mode": mode.value,
            "tool_names": list(tool_names), "tool_closure_sha256": _hash(list(tool_names)),
            "account_fingerprint": parent_claim.account_fingerprint,
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "parent_session_id", "parent_turn_id",
                    "child_session_id", "profile_id", "source_generation_sha256",
                    "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["owner_turn_handle"] != parent_claim.owner_turn_handle
                or row["gateway_turn_id"] != parent_claim.gateway_turn_id
                or row["owner_subject_sha256"] != parent_claim.owner_subject_sha256
                or row["core_generation"] != parent_claim.core_generation
                or row["core_source_generation"] != parent_claim.core_source_generation
                or row["parent_session_id"] != parent_claim.session_id
                or row["parent_turn_id"] != parent_claim.turn_id
                or row["child_session_id"] != child_session
                or row["profile_id"] != profile_id
                or row["source_generation_sha256"] != generation
                or row["source_manifest_sha256"] != manifest
                or row["prompt_sha256"] != prompt
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8")).hexdigest()
                or row["account_fingerprint"] != parent_claim.account_fingerprint
                or row["mode"] != mode.value
                or row["tool_names"] != list(tool_names)
                or row["tool_closure_sha256"] != _hash(list(tool_names))
                or type(row["additional_metered_budget"]) is not int
                or row["additional_metered_budget"] != 0
                or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root child admission does not match its request")
        try:
            expiry = float(row["expires_monotonic"])
        except (TypeError, ValueError):
            raise CoreNativeObservationUnavailable("root child admission expiry is malformed") from None
        if not time.monotonic() < expiry <= min(parent_claim.expires_monotonic, time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root child admission is stale")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"],
            parent_session_id=row["parent_session_id"], parent_turn_id=row["parent_turn_id"],
            child_session_id=row["child_session_id"], profile_id=row["profile_id"],
            source_generation_sha256=row["source_generation_sha256"],
            source_manifest_sha256=row["source_manifest_sha256"], prompt_sha256=row["prompt_sha256"],
            goal_sha256=row["goal_sha256"], account_fingerprint=row["account_fingerprint"],
            mode=row["mode"], allowed_tool_names=tool_names,
            tool_closure_sha256=row["tool_closure_sha256"],
            additional_metered_budget=row["additional_metered_budget"],
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            _parent_agent=parent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def admit_master_planner_child(self, *, owner_turn_handle: str, parent_agent: Any,
                                   child: Any, goal: str) -> RootVerifiedNativeChildAuthorization:
        """Admit a no-tools Jarvis planner child from a registered live owner turn.

        This bootstrap path intentionally does not consume a Resources delegation
        claim: planning must be based on the root-verified active master source,
        before any expert selection exists. The owner handle, session/turn and
        Codex account are all rejoined by the root registry.
        """
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        if (not isinstance(owner_turn_handle, str) or not _OPAQUE.fullmatch(owner_turn_handle)
                or type(child) is type(None) or not isinstance(goal, str) or not goal
                or len(goal.encode("utf-8", errors="strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("registered owner turn and bounded planner request are required")
        try:
            parent_session = _require_id(getattr(parent_agent, "session_id"), "parent session ID")
            parent_turn = _require_id(getattr(parent_agent, "_current_turn_id"), "parent turn ID")
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            child_turn = getattr(child, "_current_turn_id", None)
            child_turn = _require_id(child_turn, "child turn ID") if child_turn else ""
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
            source = self._master_source
            source_generation = getattr(source, "generation_sha256", getattr(source, "artifact_sha256", None))
            source_manifest = getattr(source, "source_member_manifest_sha256",
                                      getattr(source, "profile_member_manifest_sha256", None))
            prompt_sha256 = getattr(source, "effective_prompt_sha256", getattr(source, "profile_prompt_sha256", None))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("planner child lineage is incomplete") from None
        if (type(source) is not RootVerifiedJarvisMasterSource
                or getattr(source, "profile_id", None) != "hermes"
                or source.is_current_sealed(self._custody, now=time.monotonic()) is not True
                or provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE
                or base_url != _CODEX_ENDPOINT or not isinstance(model, str)
                or tuple(sorted(set(tool_names))) != tool_names or tool_names):
            raise CoreNativeObservationUnavailable("current no-tools Jarvis planner source/route is unavailable")
        parent_route = tuple(getattr(parent_agent, key, None)
                             for key in ("provider", "api_mode", "base_url", "model"))
        if parent_route != (provider, api_mode, base_url, model):
            raise CoreNativeObservationUnavailable("planner child route differs from its live parent")
        row = self._rpc("admit-master-planner-child", {
            "owner_turn_handle": owner_turn_handle, "parent_session_id": parent_session,
            "parent_turn_id": parent_turn, "child_session_id": child_session,
            "child_turn_id": child_turn, "source_generation_sha256": _require_hash(source_generation, "master source generation"),
            "source_manifest_sha256": _require_hash(source_manifest, "master source manifest"),
            "prompt_sha256": _require_hash(prompt_sha256, "master prompt"),
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest(),
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
            "tool_names": [], "tool_closure_sha256": _hash([]),
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation",
                    "core_source_generation", "parent_session_id", "parent_turn_id",
                    "child_session_id", "profile_id", "source_generation_sha256",
                    "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or row.get("schema") != 1
                or row["owner_turn_handle"] != owner_turn_handle
                or row["parent_session_id"] != parent_session or row["parent_turn_id"] != parent_turn
                or row["child_session_id"] != child_session or row["profile_id"] != "hermes"
                or row["source_generation_sha256"] != source_generation
                or row["source_manifest_sha256"] != source_manifest or row["prompt_sha256"] != prompt_sha256
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8", errors="strict")).hexdigest()
                or row["mode"] != NativeChildMode.PLANNER.value or row["tool_names"] != []
                or row["tool_closure_sha256"] != _hash([]) or row["additional_metered_budget"] != 0
                or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root planner admission does not match this request")
        expiry = float(row["expires_monotonic"])
        now = time.monotonic()
        owner = self._owners.get(owner_turn_handle)
        if owner is None or not now < expiry <= min(owner.expires_monotonic, now + 30.0):
            raise CoreNativeObservationUnavailable("root planner admission is stale")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=owner_turn_handle, gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], parent_session_id=parent_session,
            parent_turn_id=parent_turn, child_session_id=child_session, profile_id="hermes",
            source_generation_sha256=source_generation, source_manifest_sha256=source_manifest,
            prompt_sha256=prompt_sha256, goal_sha256=row["goal_sha256"],
            account_fingerprint=row["account_fingerprint"], mode=NativeChildMode.PLANNER.value,
            allowed_tool_names=(), tool_closure_sha256=_hash([]), additional_metered_budget=0,
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            _parent_agent=parent_agent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def read_selected_expert_source(self, *, native_claim: RootSelectedInternalProfileDispatchClaim,
                                    source_id: str) -> RootNativeSelectedSourceDelivery:
        if (type(native_claim) is not RootSelectedInternalProfileDispatchClaim
                or native_claim.profile_id != "hermes"
                or not _ID.fullmatch(source_id or "")):
            raise CoreNativeObservationUnavailable("root Resources claim and selected source ID are required")
        row = self._rpc("read-selected-expert-source", {
            "claim_handle": native_claim.claim_handle,
            "owner_turn_handle": native_claim.owner_turn_handle,
            "source_id": source_id,
        })
        required = {"schema", "nonce", "ok", "source_handle", "profile_id", "source_revision",
                    "generation_sha256", "source_manifest_sha256", "profile_manifest_sha256",
                    "prompt_b64", "prompt_sha256", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["profile_id"] != source_id or not _OPAQUE.fullmatch(row["source_handle"] or "")):
            raise CoreNativeObservationUnavailable("root selected source response is malformed")
        try:
            prompt = base64.b64decode(row["prompt_b64"], validate=True)
            delivery = RootNativeSelectedSourceDelivery(
                source_handle=row["source_handle"], profile_id=row["profile_id"],
                source_revision=row["source_revision"], generation_sha256=row["generation_sha256"],
                source_manifest_sha256=row["source_manifest_sha256"],
                profile_manifest_sha256=row["profile_manifest_sha256"],
                effective_prompt=prompt, effective_prompt_sha256=row["prompt_sha256"],
                _seal=_SELECTED_SOURCE_DELIVERY_SEAL,
            )
            if not time.monotonic() < float(row["expires_monotonic"]) <= min(
                    native_claim.expires_monotonic, time.monotonic() + 30.0):
                raise ValueError
            return delivery
        except Exception:
            raise CoreNativeObservationUnavailable("root selected source is stale or malformed") from None

    def admit_selected_expert_child(self, *, native_claim: RootSelectedInternalProfileDispatchClaim,
                                    child: Any, source: RootNativeSelectedSourceDelivery,
                                    goal: str) -> RootVerifiedNativeChildAuthorization:
        from hermes_installer.remote.native_child_adapter import NativeChildMode
        if (type(native_claim) is not RootSelectedInternalProfileDispatchClaim
                or type(source) is not RootNativeSelectedSourceDelivery
                or source._seal is not _SELECTED_SOURCE_DELIVERY_SEAL
                or not isinstance(goal, str) or not goal or len(goal.encode("utf-8", "strict")) > 32 * 1024):
            raise CoreNativeObservationUnavailable("typed Resources claim/source and bounded goal are required")
        try:
            child_session = _require_id(getattr(child, "session_id"), "child session ID")
            child_turn = getattr(child, "_current_turn_id", None)
            child_turn = _require_id(child_turn, "child turn ID") if child_turn else ""
            tool_names = tuple(sorted(getattr(child, "valid_tool_names")))
            provider, api_mode, base_url, model = tuple(
                getattr(child, key, None) for key in ("provider", "api_mode", "base_url", "model"))
        except (AttributeError, TypeError, ValueError):
            raise CoreNativeObservationUnavailable("constructed expert child lineage is incomplete") from None
        if (provider != _CODEX_PROVIDER or api_mode != _CODEX_MODE or base_url != _CODEX_ENDPOINT
                or not isinstance(model, str) or not model
                or tuple(sorted(set(tool_names))) != tool_names
                or not set(tool_names).issubset({"web_search", "web_extract", "skills_list", "skill_view"})):
            raise CoreNativeObservationUnavailable("expert child route or finite tool closure differs")
        row = self._rpc("admit-selected-expert-child", {
            "claim_handle": native_claim.claim_handle,
            "owner_turn_handle": native_claim.owner_turn_handle,
            "source_handle": source.source_handle, "source_id": source.profile_id,
            "child_session_id": child_session, "child_turn_id": child_turn,
            "goal_sha256": hashlib.sha256(goal.encode("utf-8", "strict")).hexdigest(),
            "tool_names": list(tool_names), "tool_closure_sha256": _hash(list(tool_names)),
            "provider": provider, "api_mode": api_mode, "base_url": base_url, "model": model,
        })
        required = {"schema", "nonce", "ok", "admission_handle", "owner_turn_handle",
                    "gateway_turn_id", "owner_subject_sha256", "core_generation", "core_source_generation",
                    "parent_session_id", "parent_turn_id", "child_session_id", "profile_id",
                    "source_generation_sha256", "source_manifest_sha256", "prompt_sha256", "goal_sha256",
                    "account_fingerprint", "mode", "tool_names", "tool_closure_sha256",
                    "additional_metered_budget", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["owner_turn_handle"] != native_claim.owner_turn_handle
                or row["gateway_turn_id"] != native_claim.gateway_turn_id
                or row["owner_subject_sha256"] != native_claim.owner_subject_sha256
                or row["core_generation"] != native_claim.core_generation
                or row["core_source_generation"] != native_claim.core_source_generation
                or row["parent_session_id"] != native_claim.session_id
                or row["child_session_id"] != child_session or row["profile_id"] != source.profile_id
                or row["source_generation_sha256"] != source.generation_sha256
                or row["source_manifest_sha256"] != source.source_manifest_sha256
                or row["prompt_sha256"] != source.effective_prompt_sha256
                or row["goal_sha256"] != hashlib.sha256(goal.encode("utf-8", "strict")).hexdigest()
                or row["mode"] != NativeChildMode.EXPERT_READ_RESEARCH.value
                or row["tool_names"] != list(tool_names) or row["tool_closure_sha256"] != _hash(list(tool_names))
                or row["additional_metered_budget"] != 0 or not _OPAQUE.fullmatch(row["admission_handle"] or "")):
            raise CoreNativeObservationUnavailable("root expert admission does not match this child")
        expiry = float(row["expires_monotonic"])
        if not time.monotonic() < expiry <= min(native_claim.expires_monotonic, time.monotonic() + 30.0):
            raise CoreNativeObservationUnavailable("root expert admission expired")
        return RootVerifiedNativeChildAuthorization(
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], parent_session_id=row["parent_session_id"],
            parent_turn_id=row["parent_turn_id"], child_session_id=row["child_session_id"],
            profile_id=row["profile_id"], source_generation_sha256=row["source_generation_sha256"],
            source_manifest_sha256=row["source_manifest_sha256"], prompt_sha256=row["prompt_sha256"],
            goal_sha256=row["goal_sha256"], account_fingerprint=row["account_fingerprint"],
            mode=row["mode"], allowed_tool_names=tuple(row["tool_names"]),
            tool_closure_sha256=row["tool_closure_sha256"],
            additional_metered_budget=row["additional_metered_budget"],
            admission_handle=row["admission_handle"], expires_monotonic=expiry,
            _parent_agent=native_claim.parent_agent, _child_agent=child, _source=source,
            _seal=_NATIVE_CHILD_AUTHORIZATION_SEAL,
        )

    def complete_native_child(self, *, authorization: RootVerifiedNativeChildAuthorization,
                              result: Mapping[str, Any]) -> CoreVerifiedJarvisMasterPlanningCompletion | None:
        if (type(authorization) is not RootVerifiedNativeChildAuthorization
                or authorization._seal is not _NATIVE_CHILD_AUTHORIZATION_SEAL
                or not isinstance(result, Mapping)):
            raise CoreNativeObservationUnavailable("root-admitted child result is required")
        if authorization.mode != "planner":
            return None
        if result.get("status") != "completed" or result.get("failed") is True:
            raise CoreNativeObservationUnavailable("planner child did not complete successfully")
        summary = result.get("summary")
        if not isinstance(summary, str) or not summary:
            raise CoreNativeObservationUnavailable("planner child completion text is unavailable")
        response_sha256 = hashlib.sha256(summary.encode("utf-8", errors="strict")).hexdigest()
        row = self._rpc("complete-native-child", {
            "admission_handle": authorization.admission_handle,
            "status": "completed", "response_sha256": response_sha256,
        })
        required = {"schema", "nonce", "ok", "completion_handle", "owner_subject_sha256",
                    "owner_turn_handle", "gateway_turn_id", "core_generation",
                    "core_source_generation", "prompt_sha256", "response_sha256",
                    "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["completion_handle"] == ""
                or row["owner_subject_sha256"] != authorization.owner_subject_sha256
                or row["owner_turn_handle"] != authorization.owner_turn_handle
                or row["gateway_turn_id"] != authorization.gateway_turn_id
                or row["core_generation"] != authorization.core_generation
                or row["core_source_generation"] != authorization.core_source_generation
                or row["prompt_sha256"] != authorization.goal_sha256
                or row["response_sha256"] != response_sha256
                or not _OPAQUE.fullmatch(row["completion_handle"] or "")):
            raise CoreNativeObservationUnavailable("root planning completion receipt is malformed")
        expiry = float(row["expires_monotonic"])
        if not time.monotonic() < expiry <= authorization.expires_monotonic:
            raise CoreNativeObservationUnavailable("root planning completion expired")
        return CoreVerifiedJarvisMasterPlanningCompletion(
            owner_subject_sha256=row["owner_subject_sha256"],
            owner_turn_handle=row["owner_turn_handle"], gateway_turn_id=row["gateway_turn_id"],
            core_generation=row["core_generation"], core_source_generation=row["core_source_generation"],
            prompt_sha256=row["prompt_sha256"], response_sha256=row["response_sha256"],
            completion_handle=row["completion_handle"], expires_monotonic=expiry,
            _client=self, _seal=_MASTER_PLANNING_COMPLETION_SEAL,
        )

    def verify_planning_completion(self, completion: CoreVerifiedJarvisMasterPlanningCompletion,
                                   *, config: Any = None, custody: Any = None) -> bool:
        if (type(completion) is not CoreVerifiedJarvisMasterPlanningCompletion
                or completion._seal is not _MASTER_PLANNING_COMPLETION_SEAL):
            return False
        try:
            row = self._rpc("verify-planning-completion", {
                "completion_handle": completion.completion_handle,
                "owner_turn_handle": completion.owner_turn_handle,
                "gateway_turn_id": completion.gateway_turn_id,
                "owner_subject_sha256": completion.owner_subject_sha256,
                "core_generation": completion.core_generation,
                "core_source_generation": completion.core_source_generation,
                "prompt_sha256": completion.prompt_sha256,
                "response_sha256": completion.response_sha256,
            })
            return (set(row) == {"schema", "nonce", "ok"}
                    and type(row["schema"]) is int and row["schema"] == 1
                    and row["ok"] is True)
        except Exception:
            return False

    def request_final_effect(self, *, observed_call_handle: str, review_sha256: str):
        """Request owner approval for one exact observed normal-master tool call."""
        from hermes_installer.remote.jarvis_final_effects import FinalEffectPending, review_digest
        if (not isinstance(observed_call_handle, str) or not _OPAQUE.fullmatch(observed_call_handle)
                or not isinstance(review_sha256, str) or not _HASH.fullmatch(review_sha256)):
            raise CoreNativeObservationUnavailable("observed effect identity is malformed")
        row = self._rpc("request-final-effect", {
            "observed_call_handle": observed_call_handle, "review_sha256": review_sha256,
        })
        required = {"schema", "nonce", "ok", "pending_id", "review_sha256", "expires_monotonic"}
        if (set(row) != required or type(row.get("schema")) is not int or row["schema"] != 1
                or row["review_sha256"] != review_sha256
                or not _OPAQUE.fullmatch(row["pending_id"] or "")):
            raise CoreNativeObservationUnavailable("root final-effect pending receipt is malformed")
        try:
            return FinalEffectPending(row["pending_id"], row["review_sha256"], row["expires_monotonic"])
        except Exception:
            raise CoreNativeObservationUnavailable("root final-effect pending receipt is stale") from None

    def poll_final_effect(self, *, pending: Any, observed_call: ObservedNativeToolCall):
        """Return one exact root-consumed approval; None means still pending only."""
        from hermes_installer.remote.jarvis_final_effects import FinalEffectPending, FinalEffectPermit
        if (type(pending) is not FinalEffectPending or type(observed_call) is not ObservedNativeToolCall
                or pending.expires_monotonic > observed_call.expires_monotonic):
            raise CoreNativeObservationUnavailable("typed live final-effect request is required")
        row = self._rpc("poll-final-effect", {
            "observed_call_handle": observed_call.handle,
            "pending_id": pending.pending_id, "review_sha256": pending.review_sha256,
        })
        if set(row) == {"schema", "nonce", "ok", "state"}:
            if type(row.get("schema")) is int and row["schema"] == 1 and row["state"] == "pending":
                return None
            raise CoreNativeObservationUnavailable("owner did not approve this final effect")
        fields = {"schema", "nonce", "ok", "state", "permit"}
        permit_fields = {"pending_id", "owner_turn_handle", "gateway_turn_id", "owner_subject_sha256",
                         "core_generation", "core_source_generation", "source_generation_sha256",
                         "source_profile_id", "tool_call_id", "tool_name", "arguments_sha256",
                         "review_sha256", "expires_monotonic"}
        payload = row.get("permit") if isinstance(row, dict) else None
        if (set(row) != fields or type(row.get("schema")) is not int or row["schema"] != 1
                or row.get("state") != "permit" or not isinstance(payload, dict)
                or set(payload) != permit_fields):
            raise CoreNativeObservationUnavailable("root final-effect permit is malformed")
        try:
            permit = FinalEffectPermit(**payload)
        except Exception:
            raise CoreNativeObservationUnavailable("root final-effect permit is stale") from None
        if not permit.matches_call(observed_call, tool_name=observed_call.tool_name,
                                  arguments_sha256=observed_call.arguments_sha256,
                                  review_sha256=pending.review_sha256):
            raise CoreNativeObservationUnavailable("root final-effect permit does not match this call")
        return permit

    def authorize_current_tool_call(self, *, observed_call: ObservedNativeToolCall
                                    ) -> RootVerifiedMasterReadCall:
        """Classify this exact call as master read/effect or admitted expert read.

        A name alone never grants the bypass: the root joins the handle to the
        live owner turn, consumed provider response, current Jarvis source or
        admitted expert child, and its immutable tool closure.
        """
        if type(observed_call) is not ObservedNativeToolCall:
            raise CoreNativeObservationUnavailable("root observed native call is required")
        row = self._rpc("authorize-master-read-call", {
            "observed_call_handle": observed_call.handle,
        })
        fields = {"schema", "nonce", "ok", "observed_call_handle", "owner_turn_handle",
                  "tool_call_id", "tool_name", "arguments_sha256", "source_generation_sha256",
                  "mode", "expires_monotonic"}
        if (set(row) != fields or type(row.get("schema")) is not int or row["schema"] != 1
                or row["observed_call_handle"] != observed_call.handle
                or row["owner_turn_handle"] != observed_call.owner_turn_handle
                or row["tool_call_id"] != observed_call.tool_call_id
                or row["tool_name"] != observed_call.tool_name
                or row["arguments_sha256"] != observed_call.arguments_sha256):
            raise CoreNativeObservationUnavailable("root caller classification is malformed")
        try:
            receipt = RootVerifiedMasterReadCall(
                observed_call_handle=row["observed_call_handle"],
                owner_turn_handle=row["owner_turn_handle"], tool_call_id=row["tool_call_id"],
                tool_name=row["tool_name"], arguments_sha256=row["arguments_sha256"],
                source_generation_sha256=row["source_generation_sha256"], mode=row["mode"],
                expires_monotonic=row["expires_monotonic"], _seal=_MASTER_READ_CALL_SEAL)
        except Exception:
            raise CoreNativeObservationUnavailable("root caller classification is stale") from None
        if not receipt.matches_call(observed_call, tool_name=observed_call.tool_name,
                                   arguments_sha256=observed_call.arguments_sha256):
            raise CoreNativeObservationUnavailable("root caller classification changed")
        if (observed_call.tool_name in _MASTER_READ_TOOL_NAMES
                and receipt.mode not in {"master_read", "expert_read"}
                or observed_call.tool_name not in _MASTER_READ_TOOL_NAMES
                and receipt.mode != "master_effect"):
            raise CoreNativeObservationUnavailable("root caller classification has the wrong effect mode")
        return receipt

    def authorize_master_read_call(self, *, observed_call: ObservedNativeToolCall
                                   ) -> RootVerifiedMasterReadCall:
        """Compatibility spelling for the root current-caller classifier."""
        return self.authorize_current_tool_call(observed_call=observed_call)


class RootCoreNativeObservationRegistry:
    """Root-memory issuer joining real owner turns to protected native observations.

    This registry is composed inside the existing inspector process. It accepts
    owner turns only from that process's independently validated gateway op;
    core worker frames are accepted only after a fresh current-process custody
    check on their Unix peer credentials.
    """

    def __init__(self, custody: Any, selected_profile_source: Any, *, config: Any):
        from hermes_installer.remote.core_gateway_inspector import CoreNativeObserverCustody
        from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        if type(custody) is not CoreNativeObserverCustody:
            raise CoreNativeObservationUnavailable("sealed current-core observer custody is required")
        if (selected_profile_source is not None
                and (type(selected_profile_source) is not RootVerifiedJarvisMasterSource
                     or selected_profile_source.profile_id != "hermes"
                     or selected_profile_source.native_profile_key != "default"
                     or selected_profile_source.display_name != "Jarvis")):
            raise CoreNativeObservationUnavailable("sealed current Jarvis master source is required")
        if (selected_profile_source is not None
                and not callable(getattr(selected_profile_source, "is_current_sealed", None))):
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
        self._mission_pending: dict[str, dict[str, Any]] = {}
        self._mission_authorized_claims: set[str] = set()
        self._consumed_dispatches: dict[str, dict[str, Any]] = {}
        self._child_sessions: dict[str, dict[str, Any]] = {}
        self._planning_completions: dict[str, dict[str, Any]] = {}
        self._master_selections: dict[str, dict[str, Any]] = {}
        self._selected_source_deliveries: dict[str, dict[str, Any]] = {}
        self._master_source: Any = None
        self._final_effect_store: Any = None
        try:
            from hermes_installer.components.resources_active_profile_source import (
                RootVerifiedJarvisMasterSource,
            )
            self._master_source = RootVerifiedJarvisMasterSource.current_master_source(
                custody, config=config,
            )
        except Exception:
            # Ordinary ingress stays available; planning/child admission stays unavailable.
            self._master_source = None
        self._closed = False

    @classmethod
    def from_current_core_custody(cls, custody: Any, *, selected_profile_source: Any = None,
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

    def enroll_master_decision(self, decision: Any) -> str:
        """Retain a current root-sealed plan and exactly its verified selected sources."""
        from hermes_installer.remote.jarvis_master_planning import CoreVerifiedJarvisMasterPlanDecision
        from hermes_installer.components.resources_active_profile_source import RootSelectedActiveProfileSource
        if (type(decision) is not CoreVerifiedJarvisMasterPlanDecision
                or decision.is_current_sealed(self._config, custody=self._custody,
                                              now=time.monotonic()) is not True):
            raise CoreNativeObservationUnavailable("current Jarvis master plan decision is required")
        with self._lock:
            self._ensure_open()
            owner = self._owners.get(decision.owner_turn_handle)
            if (owner is None or owner.gateway_turn_id != decision.gateway_turn_id
                    or owner.owner_subject_sha256 != decision.owner_subject_sha256
                    or owner.core_generation != decision.core_generation
                    or owner.core_source_generation != decision.core_source_generation):
                raise CoreNativeObservationUnavailable("master plan does not match a retained owner turn")
        resolver = getattr(RootSelectedActiveProfileSource, "resolve_selected", None)
        if not callable(resolver):
            raise CoreNativeObservationUnavailable("decision-bound Resources source resolver is unavailable")
        sources = resolver(decision, self._custody, config=self._config)
        if (not isinstance(sources, tuple) or len(sources) != len(decision.selected_source_ids)
                or tuple(getattr(item, "profile_id", None) for item in sources)
                    != tuple(decision.selected_source_ids)
                or any(type(item) is not RootSelectedActiveProfileSource
                       or item.is_current_sealed(self._custody, now=time.monotonic()) is not True
                       for item in sources)):
            raise CoreNativeObservationUnavailable("selected Resources sources are not current")
        enrollment_handle = secrets.token_urlsafe(32)
        # The source's short monotonic expiry is a readback freshness window,
        # not a child-authority lease. Every use re-reads that source; the
        # retained decision remains the authority deadline.
        expiry = float(decision.expires_monotonic)
        with self._lock:
            self._ensure_open()
            self._master_selections[enrollment_handle] = {
                "decision": decision, "owner": owner,
                "sources": {item.profile_id: item for item in sources},
                "expiry": expiry,
            }
            while len(self._master_selections) > 128:
                self._master_selections.pop(next(iter(self._master_selections)))
        return enrollment_handle

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
        master_source = self._current_master_source()
        if (master_source is None
                or current_tool_configuration.is_current_sealed(
                    custody=self._custody, owner_turn=owner_turn_observation, now=now) is not True
                or not _configuration_has_fixed_resources_delegate(current_tool_configuration)
                or owner_turn_observation.is_current_sealed(
                    self._config, custody=self._custody, now=now) is not True
                or current_tool_configuration.core_generation != owner_turn_observation.core_generation
                or current_tool_configuration.core_source_generation != owner_turn_observation.core_source_generation
                or current_tool_configuration.owner_subject_sha256 != owner_turn_observation.owner_subject_sha256):
            raise CoreNativeObservationUnavailable("current native tool configuration is not owner-bound")
        names = current_tool_configuration.configured_parent_tool_names
        if (not isinstance(names, tuple) or not names or len(names) > 256
                or tuple(sorted(set(names))) != names
                or any(not isinstance(name, str) or not _ID.fullmatch(name) for name in names)
                or "delegate_task" not in names or "resources_delegate" not in names):
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
            "profile_id": "hermes", "mode": "native-parent-inheritance",
            "parent_tool_configuration_sha256": current_tool_configuration.tool_configuration_sha256,
            "configured_parent_tool_names": list(names),
            "resources_delegate_schema_sha256": _RESOURCES_DELEGATE_SCHEMA_SHA256,
            "resources_delegate_source_sha256": _RESOURCES_DELEGATE_SOURCE_SHA256,
            # Fixed root-enrolled owner-only policy bits; neither selected by the
            # Hermes user config nor inferred from provider tools.list metadata.
            "allow_inherited_mcp": True,
            "allow_native_orchestrator_delegation": True,
            "additional_metered_budget": 0,
            "issued_monotonic": issued, "expires_monotonic": expiry,
        }
        policy = RootSelectedOrchestratorDelegationPolicy(
            schema=1, policy_handle=policy_handle,
            policy_sha256=_hash(fields),
            core_generation=owner_turn_observation.core_generation,
            core_source_generation=owner_turn_observation.core_source_generation,
            owner_subject_sha256=owner_turn_observation.owner_subject_sha256,
            profile_id="hermes", mode="native-parent-inheritance",
            parent_tool_configuration_sha256=current_tool_configuration.tool_configuration_sha256,
            configured_parent_tool_names=names,
            resources_delegate_schema_sha256=_RESOURCES_DELEGATE_SCHEMA_SHA256,
            resources_delegate_source_sha256=_RESOURCES_DELEGATE_SOURCE_SHA256,
            allow_inherited_mcp=True,
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

    def _current_master_source(self) -> Any | None:
        """Re-read the sole Jarvis master source from protected current custody."""
        try:
            from hermes_installer.components.resources_active_profile_source import (
                RootVerifiedJarvisMasterSource,
            )
            source = RootVerifiedJarvisMasterSource.current_master_source(
                self._custody, config=self._config)
            if (type(source) is RootVerifiedJarvisMasterSource
                    and source.profile_id == "hermes"
                    and source.native_profile_key == "default"
                    and source.display_name == "Jarvis"
                    and source.is_current_sealed(self._custody, now=time.monotonic()) is True):
                self._master_source = source
                return source
        except Exception:
            pass
        self._master_source = None
        return None

    def _final_effect_ledger(self) -> Any:
        """Open the fixed root-owned chat ledger without following mutable paths."""
        if self._final_effect_store is not None:
            return self._final_effect_store
        from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
        expected = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        if CHAT_STORE_PATH != expected:
            raise CoreNativeObservationUnavailable("fixed root final-effect ledger path differs")
        parent = os.lstat(expected.parent)
        target = os.lstat(expected)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
                or parent.st_mode & 0o022
                or not stat.S_ISREG(target.st_mode) or target.st_uid != 0
                or target.st_nlink != 1 or target.st_mode & 0o022):
            raise CoreNativeObservationUnavailable("fixed root final-effect ledger custody differs")

        def connect():
            db = sqlite3.connect(expected, timeout=2, isolation_level=None)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=2000")
            return db

        from hermes_installer.remote.jarvis_final_effects import RootFinalEffectLedger
        self._final_effect_store = RootFinalEffectLedger(connect)
        return self._final_effect_store

    def _classify_current_call(self, handle: str, peer: tuple[int, int, int], *,
                               now: float) -> tuple[dict[str, Any], Any, Any, str]:
        """Join a root call to either the current Jarvis master or admitted expert."""
        call = self._calls.get(handle)
        if (call is None or call["peer"] != peer or call["expiry"] <= now
                or call.get("claim") is not None):
            raise ValueError("observed call is not a live unclaimed native dispatch")
        owner = call.get("owner")
        attempt = self._attempts.get(call.get("attempt"))
        if (owner is None or attempt is None or attempt.get("response") is None
                or attempt.get("owner") is not owner
                or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                or self._policy_for_owner(owner, now) is None
                or attempt.get("account") is None or not _HASH.fullmatch(attempt["account"])):
            raise ValueError("observed call owner or provider attempt is not current")
        if (not isinstance(attempt.get("provider"), str)
                or (attempt.get("provider"), attempt.get("api_mode"), attempt.get("base_url"))
                    != (_CODEX_PROVIDER, _CODEX_MODE, _CODEX_ENDPOINT)):
            raise ValueError("observed call did not use the enrolled Codex subscription route")
        returned = attempt["response"][1].get(call["tool_call_id"])
        if (returned is None or returned.get("name") != call["tool_name"]
                or returned.get("arguments_sha256") != call["arguments_sha256"]):
            raise ValueError("observed call differs from the completed provider response")
        child = self._child_sessions.get(call.get("attempt_session_id"))
        if child is not None:
            source = child.get("source")
            if (child.get("mode") != "expert-read-research"
                    or child.get("owner") is not owner or child.get("peer") != peer
                    or child.get("expiry", 0) <= now or child.get("complete")
                    or attempt.get("child_admission_handle") != child.get("admission_handle")
                    or not callable(getattr(source, "is_current_sealed", None))
                    or source.is_current_sealed(self._custody, now=now) is not True
                    or source.profile_id in {"hermes"}
                    or call["tool_name"] not in child.get("tool_names", ())
                    or call["tool_name"] not in _MASTER_READ_TOOL_NAMES):
                raise ValueError("expert child call is outside its admitted read closure")
            return call, owner, child, "expert_read"
        source = self._current_master_source()
        if (call.get("attempt_session_id") != owner.session_id or source is None
                or source.is_current_sealed(custody=self._custody, now=now) is not True
                or source.profile_id != "hermes"
                or call["tool_name"] not in attempt.get("parent_tool_names", ())):
            raise ValueError("normal call is not from the current Jarvis master")
        mode = "master_read" if call["tool_name"] in _MASTER_READ_TOOL_NAMES else "master_effect"
        return call, owner, source, mode

    def _owner_for_review(self, owner_turn_handle: str, owner_subject_sha256: str,
                          gateway_peer: tuple[int, int, int], *, now: float) -> Any:
        if (not _OPAQUE.fullmatch(owner_turn_handle or "")
                or not _HASH.fullmatch(owner_subject_sha256 or "")):
            raise CoreNativeObservationUnavailable("current owner turn is unavailable")
        owner = self._owners.get(owner_turn_handle)
        if (owner is None or owner.owner_subject_sha256 != owner_subject_sha256
                or (owner.peer_gateway_pid, owner.peer_gateway_uid, owner.peer_gateway_gid) != gateway_peer
                or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                or self._policy_for_owner(owner, now) is None):
            raise CoreNativeObservationUnavailable("current owner turn is unavailable")
        source = self._current_master_source()
        if (source is None or source.profile_id != "hermes"
                or source.is_current_sealed(self._custody, now=now) is not True):
            raise CoreNativeObservationUnavailable("current Jarvis master source is unavailable")
        return owner

    def list_final_effects_for_owner(self, owner_turn_handle: str, owner_subject_sha256: str,
                                     gateway_peer: tuple[int, int, int]) -> tuple[Any, ...]:
        from hermes_installer.remote.jarvis_final_effects import FinalEffectReview
        now = time.monotonic()
        with self._lock:
            self._ensure_open()
            owner = self._owner_for_review(owner_turn_handle, owner_subject_sha256, gateway_peer, now=now)
            rows = self._final_effect_ledger().pending_for_owner(
                owner_subject_sha256=owner.owner_subject_sha256,
                gateway_turn_id=owner.gateway_turn_id,
                owner_turn_handle=owner.owner_turn_handle,
                core_generation=owner.core_generation)
            reviews = []
            for row in rows:
                if (not isinstance(row, dict)
                        or set(row) != {"pendingId", "turnId", "toolName", "reviewSha256",
                                        "preview", "status", "expiresInMs"}
                        or row["turnId"] != owner.gateway_turn_id):
                    raise CoreNativeObservationUnavailable("root review row shape is unavailable")
                preview = _canonical(row["preview"]).decode("utf-8", errors="strict")
                expiry = time.monotonic() + max(0, min(30_000, int(row["expiresInMs"]))) / 1000.0
                reviews.append(FinalEffectReview(
                    pending_id=row["pendingId"], review_sha256=row["reviewSha256"],
                    tool_name=row["toolName"], preview_json=preview,
                    status=row["status"], expires_monotonic=expiry))
            if self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                      gateway_peer, now=time.monotonic()) is not owner:
                raise CoreNativeObservationUnavailable("owner turn changed during effect listing")
            return tuple(reviews)

    def decide_final_effect_for_owner(self, owner_turn_handle: str, owner_subject_sha256: str,
                                      gateway_peer: tuple[int, int, int], *, pending_id: str,
                                      review_sha256: str, decision: str,
                                      idempotency_key: str) -> str:
        now = time.monotonic()
        with self._lock:
            self._ensure_open()
            owner = self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                           gateway_peer, now=now)
            status = self._final_effect_ledger().decide(
                owner_subject_sha256=owner.owner_subject_sha256,
                gateway_turn_id=owner.gateway_turn_id,
                owner_turn_handle=owner.owner_turn_handle,
                core_generation=owner.core_generation,
                pending_id=pending_id, review_sha256=review_sha256,
                decision=decision, idempotency_key=idempotency_key)
            if self._owner_for_review(owner_turn_handle, owner_subject_sha256,
                                      gateway_peer, now=time.monotonic()) is not owner:
                raise CoreNativeObservationUnavailable("owner turn changed during effect decision")
            return status

    def preflight_native_mission(self, binding: Any, *, owner_subject_sha256: str,
                                 gateway_turn_id: str) -> bool:
        """Check a just-spent launch row before the BFF queues its native prompt."""
        from hermes_installer.remote.core_gateway_inspector import _mission_binding_wire
        if (type(binding) is not MissionBinding or binding.schema != 2
                or binding.source_profile_id != "hermes"
                or binding.execution_mode not in {"oneshot", "kanban"}
                or not isinstance(owner_subject_sha256, str) or not _HASH.fullmatch(owner_subject_sha256)
                or not isinstance(gateway_turn_id, str) or not _ID.fullmatch(gateway_turn_id)):
            raise CoreNativeObservationUnavailable("typed current mission binding is required")
        try:
            wire = _mission_binding_wire(binding)
            if wire != binding.to_wire():
                raise ValueError
            from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
            from hermes_installer.remote.jarvis_mission_executor import (
                MissionLedgerReader, resolve_spent_mission_binding,
            )
            if CHAT_STORE_PATH != Path("/var/lib/hermes-jarvis-chat/chat.sqlite3"):
                raise ValueError
            with self._lock:
                self._ensure_open()
                now = time.monotonic()
                source = self._current_master_source()
                if (source is None or source.profile_id != "hermes"
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or self._custody.core_generation == ""
                        or resolve_spent_mission_binding(
                            MissionLedgerReader(path=CHAT_STORE_PATH), binding,
                            gateway_turn_id=gateway_turn_id,
                            owner_subject_sha256=owner_subject_sha256,
                            core_generation=self._custody.core_generation,
                            core_source_generation=self._custody.core_source_generation) is not True):
                    raise ValueError
                return True
        except Exception:
            raise CoreNativeObservationUnavailable("spent mission preflight is unavailable") from None

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
        for handle, row in list(self._mission_pending.items()):
            if row["expiry"] <= now:
                self._mission_pending.pop(handle, None)
        for handle, row in list(self._consumed_dispatches.items()):
            if row["expiry"] <= now:
                self._consumed_dispatches.pop(handle, None)
        for session_id, row in list(self._child_sessions.items()):
            if row["expiry"] <= now:
                self._child_sessions.pop(session_id, None)
        for handle, row in list(self._planning_completions.items()):
            if row["expiry"] <= now:
                self._planning_completions.pop(handle, None)
        for handle, row in list(self._master_selections.items()):
            if row["expiry"] <= now:
                self._master_selections.pop(handle, None)
        for handle, row in list(self._selected_source_deliveries.items()):
            if row["expiry"] <= now:
                self._selected_source_deliveries.pop(handle, None)

    def _owner_for(self, session_id: str, turn_id: str) -> Any:
        now = time.monotonic()
        child_row = self._child_sessions.get(session_id)
        if child_row is not None and child_row["expiry"] > now:
            owner = child_row["owner"]
            if (owner.core_generation == self._custody.core_generation
                    and owner.is_current_sealed(self._config, custody=self._custody, now=now) is True):
                bound = child_row.get("turn_id")
                if bound is None:
                    child_row["turn_id"] = turn_id
                    return owner
                if bound == turn_id:
                    return owner
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
                    custody=self._custody, owner_turn=owner, now=now) is not True
                or not _configuration_has_fixed_resources_delegate(configuration)):
            self._policies.pop(handle, None)
            self._owner_policy_handles.pop(owner.owner_turn_handle, None)
            return None
        return policy

    def _selection_for_mission(self, owner: Any, source_id: str, now: float) -> tuple[Any, Any] | None:
        """Join a spent schema-2 mission binding to one live sealed master decision."""
        from hermes_installer.components.resources_active_profile_source import RootSelectedActiveProfileSource
        binding = getattr(owner, "mission_binding", None)
        if type(binding) is not MissionBinding or binding.schema != 2:
            return None
        matches = []
        for row in self._master_selections.values():
            decision = row.get("decision")
            source = row.get("sources", {}).get(source_id)
            if (row["expiry"] <= now or source is None
                    or decision.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                    or decision.owner_subject_sha256 != owner.owner_subject_sha256
                    or decision.core_generation != owner.core_generation
                    or decision.core_source_generation != owner.core_source_generation
                    or row.get("owner") is None
                    or row["owner"].owner_subject_sha256 != owner.owner_subject_sha256
                    or decision.mission_id != binding.mission_id
                    or decision.revision != binding.revision
                    or decision.plan_sha256 != binding.plan_sha256
                    or decision.execution_mode != binding.execution_mode
                    or tuple(decision.selected_source_ids) != tuple(binding.selected_source_ids)
                    or source_id not in binding.selected_source_ids
                    or type(source) is not RootSelectedActiveProfileSource
                    or source.is_current_sealed(self._custody, now=now) is not True):
                continue
            matches.append((row, source))
        return matches[0] if len(matches) == 1 else None

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
            if op == "authorize-master-read-call":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle"}:
                    raise ValueError("caller classification schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "observed_call_handle": call["handle"],
                    "owner_turn_handle": owner.owner_turn_handle,
                    "tool_call_id": call["tool_call_id"], "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "source_generation_sha256": source.generation_sha256,
                    "mode": mode, "expires_monotonic": min(
                        call["expiry"], owner.expires_monotonic, time.monotonic() + 30.0)}
            if op == "request-final-effect":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle", "review_sha256"}:
                    raise ValueError("final-effect request schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                from hermes_installer.remote.jarvis_final_effects import review_digest
                if (mode != "master_effect" or source.profile_id != "hermes"
                        or call["tool_name"] in _MASTER_READ_TOOL_NAMES
                        or review_digest(call["tool_name"], call["arguments_sha256"])
                            != request["review_sha256"]):
                    raise ValueError("only a current Jarvis master effect can request approval")
                pending = self._final_effect_ledger().issue_pending(
                    owner_subject_sha256=owner.owner_subject_sha256,
                    gateway_turn_id=owner.gateway_turn_id,
                    owner_turn_handle=owner.owner_turn_handle,
                    core_generation=owner.core_generation,
                    core_source_generation=owner.core_source_generation,
                    source_generation_sha256=source.generation_sha256,
                    tool_call_id=call["tool_call_id"], tool_name=call["tool_name"],
                    arguments_sha256=call["arguments_sha256"],
                    review_sha256=request["review_sha256"],
                    expires_monotonic=min(call["expiry"], owner.expires_monotonic,
                                          time.monotonic() + 30.0),
                    canonical_arguments=call["arguments"])
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "pending_id": pending.pending_id,
                    "review_sha256": pending.review_sha256,
                    "expires_monotonic": pending.expires_monotonic}
            if op == "poll-final-effect":
                if set(request) != {"schema", "op", "nonce", "observed_call_handle",
                                    "pending_id", "review_sha256"}:
                    raise ValueError("final-effect poll schema mismatch")
                call, owner, source, mode = self._classify_current_call(
                    request["observed_call_handle"], peer, now=time.monotonic())
                if mode != "master_effect" or source.profile_id != "hermes":
                    raise ValueError("experts and non-master callers cannot consume final effects")
                ledger = self._final_effect_ledger()
                expected = {
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"],
                    "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                }
                state = ledger.poll(request["pending_id"], request["review_sha256"], expected=expected)
                if state != "approved" or not ledger.consume_approval(
                        request["pending_id"], request["review_sha256"], expected=expected):
                    if state == "pending":
                        return {"schema": 1, "nonce": nonce, "ok": True, "state": "pending"}
                    raise ValueError("final-effect approval is denied, stale, or already spent")
                permit = {
                    "pending_id": request["pending_id"],
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_generation_sha256": source.generation_sha256,
                    "source_profile_id": "hermes", "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "review_sha256": request["review_sha256"],
                    "expires_monotonic": min(call["expiry"], owner.expires_monotonic,
                                              time.monotonic() + 30.0),
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "state": "permit", "permit": permit}
            if op == "read-selected-expert-source":
                required = {"schema", "op", "nonce", "claim_handle", "owner_turn_handle", "source_id"}
                if set(request) != required:
                    raise ValueError("selected source request schema mismatch")
                now = time.monotonic()
                claim = self._consumed_dispatches.get(request["claim_handle"])
                owner = claim.get("owner") if claim is not None else None
                call = claim.get("call") if claim is not None else None
                if (claim is None or owner is None or call is None
                        or claim["expiry"] <= now or call["peer"] != peer
                        or owner.owner_turn_handle != request["owner_turn_handle"]
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or type(owner.mission_binding) is not MissionBinding
                        or owner.mission_binding.execution_mode not in {"oneshot", "kanban"}
                        or request["source_id"] not in owner.mission_binding.selected_source_ids
                        or call["tool_name"] != "resources_delegate"):
                    raise ValueError("selected source is not bound to this live mission claim")
                try:
                    args = json.loads(call["arguments"].decode("utf-8", errors="strict"))
                except Exception:
                    raise ValueError("selected source arguments are malformed") from None
                if (not isinstance(args, dict) or set(args) != {"goal"}
                        or not isinstance(args["goal"], str)
                        or _hash({"goal": args["goal"]}) != owner.mission_binding.task_sha256
                        or call["arguments_sha256"] != owner.mission_binding.task_sha256):
                    raise ValueError("selected source goal differs from the spent mission task")
                selected = self._selection_for_mission(owner, request["source_id"], now)
                if selected is None:
                    raise ValueError("current master decision does not select this source")
                selection, source = selected
                if (selection.get("owner") is None
                        or selection["owner"].owner_subject_sha256 != owner.owner_subject_sha256
                        or selection["owner"].core_generation != owner.core_generation
                        or selection["owner"].core_source_generation != owner.core_source_generation
                        or source.is_current_sealed(self._custody, now=now) is not True):
                    raise ValueError("selected source or owner decision is stale")
                handle = secrets.token_urlsafe(32)
                expiry = min(float(claim["expiry"]), float(owner.expires_monotonic), now + 30.0)
                self._selected_source_deliveries[handle] = {
                    "source": source, "selection": selection, "claim": claim,
                    "owner": owner, "peer": peer, "expiry": expiry, "consumed": False,
                }
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "source_handle": handle, "profile_id": source.profile_id,
                    "source_revision": source.source_revision,
                    "generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256,
                    "expires_monotonic": expiry}
            if op == "admit-selected-expert-child":
                required = {"schema", "op", "nonce", "claim_handle", "owner_turn_handle",
                            "source_handle", "source_id", "child_session_id", "child_turn_id",
                            "goal_sha256", "tool_names", "tool_closure_sha256", "provider",
                            "api_mode", "base_url", "model"}
                if set(request) != required:
                    raise ValueError("selected child admission schema mismatch")
                now = time.monotonic()
                delivered = self._selected_source_deliveries.get(request["source_handle"])
                claim = self._consumed_dispatches.get(request["claim_handle"])
                owner = claim.get("owner") if claim is not None else None
                call = claim.get("call") if claim is not None else None
                source = delivered.get("source") if delivered is not None else None
                if (delivered is None or delivered["consumed"] or delivered["expiry"] <= now
                        or delivered["peer"] != peer or claim is None or owner is None or call is None
                        or delivered["claim"] is not claim or delivered["owner"] is not owner
                        or owner.owner_turn_handle != request["owner_turn_handle"]
                        or call["peer"] != peer or call["tool_name"] != "resources_delegate"
                        or type(owner.mission_binding) is not MissionBinding
                        or request["source_id"] != source.profile_id
                        or source.profile_id not in owner.mission_binding.selected_source_ids
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is not claim["policy"]):
                    raise ValueError("selected child is not bound to current owner/source authority")
                try:
                    args = json.loads(call["arguments"].decode("utf-8", errors="strict"))
                except Exception:
                    raise ValueError("selected child arguments are malformed") from None
                if (not isinstance(args, dict) or set(args) != {"goal"}
                        or not isinstance(args["goal"], str)
                        or _hash({"goal": args["goal"]}) != owner.mission_binding.task_sha256
                        or call["arguments_sha256"] != owner.mission_binding.task_sha256
                        or request["goal_sha256"] != hashlib.sha256(args["goal"].encode("utf-8", "strict")).hexdigest()):
                    raise ValueError("selected child goal does not match the approved task")
                allowed = {"web_search", "web_extract", "skills_list", "skill_view"}
                names = request["tool_names"]
                if (not isinstance(names, list) or len(names) > len(allowed)
                        or any(not isinstance(name, str) or name not in allowed for name in names)
                        or len(set(names)) != len(names) or names != sorted(names)
                        or request["tool_closure_sha256"] != _hash(names)
                        or request["provider"] != _CODEX_PROVIDER
                        or request["api_mode"] != _CODEX_MODE or request["base_url"] != _CODEX_ENDPOINT):
                    raise ValueError("selected child route or fixed safe tool closure is invalid")
                attempt = self._attempts.get(call["attempt"])
                if (attempt is None or attempt["response"] is None
                        or attempt["owner"] is not owner or attempt["session_id"] != owner.session_id
                        or request["model"] != attempt["model"]
                        or not _HASH.fullmatch(attempt["account"] or "")):
                    raise ValueError("selected child has no current observed parent route")
                child_session = _require_id(request["child_session_id"], "child session ID")
                if child_session in self._child_sessions or child_session == owner.session_id:
                    raise ValueError("selected child session is already bound")
                child_turn = request["child_turn_id"]
                if child_turn and not _ID.fullmatch(child_turn):
                    raise ValueError("selected child turn ID is malformed")
                delivered["consumed"] = True
                admission = secrets.token_urlsafe(32)
                expiry = min(float(delivered["expiry"]), float(owner.expires_monotonic),
                             float(claim["policy"].expires_monotonic), now + 30.0)
                child = {"admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "owner": owner, "policy": claim["policy"], "parent_session_id": owner.session_id,
                    "parent_turn_id": call["attempt_turn_id"], "session_id": child_session,
                    "turn_id": child_turn or None, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account": attempt["account"],
                    "mode": "expert-read-research", "tool_names": tuple(names),
                    "tool_closure_sha256": _hash(names), "provider": _CODEX_PROVIDER,
                    "api_mode": _CODEX_MODE, "base_url": _CODEX_ENDPOINT, "model": attempt["model"],
                    "source": source, "attempts": [], "peer": peer, "expiry": expiry,
                    "complete": False, "response_text_sha256": None}
                self._child_sessions[child_session] = child
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "parent_session_id": owner.session_id,
                    "parent_turn_id": child["parent_turn_id"], "child_session_id": child_session,
                    "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account_fingerprint": attempt["account"],
                    "mode": "expert-read-research", "tool_names": names,
                    "tool_closure_sha256": _hash(names), "additional_metered_budget": 0,
                    "expires_monotonic": expiry}
            if op == "admit-master-planner-child":
                from hermes_installer.components.resources_active_profile_source import (
                    RootVerifiedJarvisMasterSource,
                )
                required = {"schema", "op", "nonce", "owner_turn_handle", "parent_session_id",
                            "parent_turn_id", "child_session_id", "child_turn_id",
                            "source_generation_sha256", "source_manifest_sha256", "prompt_sha256",
                            "goal_sha256", "provider", "api_mode", "base_url", "model",
                            "tool_names", "tool_closure_sha256"}
                if set(request) != required:
                    raise ValueError("master planner admission schema mismatch")
                now = time.monotonic()
                owner = self._owners.get(request["owner_turn_handle"])
                source = self._master_source
                if (owner is None or owner.expires_monotonic <= now
                        or owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or owner.session_id != request["parent_session_id"]
                        or self._owner_turn_bindings.get(owner.owner_turn_handle) != request["parent_turn_id"]
                        or type(source) is not RootVerifiedJarvisMasterSource
                        or source.profile_id != "hermes"
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is None
                        or request["provider"] != _CODEX_PROVIDER or request["api_mode"] != _CODEX_MODE
                        or request["base_url"] != _CODEX_ENDPOINT
                        or not _ID.fullmatch(request["model"] or "")
                        or request["tool_names"] != [] or request["tool_closure_sha256"] != _hash([])
                        or not _HASH.fullmatch(request["goal_sha256"] or "")):
                    raise ValueError("current owner turn or master source is unavailable")
                attempt = next((row for row in reversed(tuple(self._attempts.values()))
                                if row["owner"] is owner and row["session_id"] == owner.session_id
                                and row["turn_id"] == request["parent_turn_id"]
                                and row["response"] is not None
                                and row["account"] and row.get("model")), None)
                if (attempt is None or attempt["account"] == ""
                        or request["model"] != attempt["model"]
                        or request["source_generation_sha256"] != source.generation_sha256
                        or request["source_manifest_sha256"] != source.source_member_manifest_sha256
                        or request["prompt_sha256"] != source.effective_prompt_sha256):
                    raise ValueError("planner route/source does not match a completed owner turn")
                child_session = _require_id(request["child_session_id"], "child session ID")
                if child_session in self._child_sessions or child_session == owner.session_id:
                    raise ValueError("planner child session is already bound")
                child_turn = request["child_turn_id"]
                if child_turn and not _ID.fullmatch(child_turn):
                    raise ValueError("planner child turn ID is malformed")
                policy = self._policy_for_owner(owner, now)
                admission = secrets.token_urlsafe(32)
                # Source freshness is checked again before every dispatch and
                # completion; it must not shorten the owner/decision lease.
                expiry = min(float(owner.expires_monotonic),
                             float(policy.expires_monotonic), now + 30.0)
                child = {"admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "owner": owner, "policy": policy, "parent_session_id": owner.session_id,
                    "parent_turn_id": request["parent_turn_id"], "session_id": child_session,
                    "turn_id": child_turn or None, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account": attempt["account"],
                    "mode": "planner", "tool_names": (), "tool_closure_sha256": _hash([]),
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE,
                    "base_url": _CODEX_ENDPOINT, "model": attempt["model"],
                    "source": source, "attempts": [], "peer": peer, "expiry": expiry,
                    "complete": False, "response_text_sha256": None}
                self._child_sessions[child_session] = child
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "admission_handle": admission, "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "parent_session_id": owner.session_id,
                    "parent_turn_id": request["parent_turn_id"],
                    "child_session_id": child_session, "profile_id": source.profile_id,
                    "source_generation_sha256": source.generation_sha256,
                    "source_manifest_sha256": source.source_member_manifest_sha256,
                    "prompt_sha256": source.effective_prompt_sha256,
                    "goal_sha256": request["goal_sha256"], "account_fingerprint": attempt["account"],
                    "mode": "planner", "tool_names": [], "tool_closure_sha256": _hash([]),
                    "additional_metered_budget": 0, "expires_monotonic": expiry}
            if op == "admit-native-child":
                raise ValueError("legacy Resources-parent child admission is disabled")
            if op == "complete-native-child":
                if set(request) != {"schema", "op", "nonce", "admission_handle", "status", "response_sha256"}:
                    raise ValueError("child completion schema mismatch")
                child = next((row for row in self._child_sessions.values()
                              if row["admission_handle"] == request["admission_handle"]), None)
                now = time.monotonic()
                if (child is None or child["peer"] != peer or child["expiry"] <= now
                        or child["complete"] or request["status"] != "completed"
                        or not _HASH.fullmatch(request["response_sha256"] or "")):
                    raise ValueError("child completion is not a live admitted result")
                owner, policy = child["owner"], child["policy"]
                source = child.get("source")
                attempts = [self._attempts.get(handle) for handle in child["attempts"]]
                if (owner.is_current_sealed(self._config, custody=self._custody, now=now) is not True
                        or self._policy_for_owner(owner, now) is not policy
                        or not callable(getattr(source, "is_current_sealed", None))
                        or source.is_current_sealed(self._custody, now=now) is not True
                        or source.profile_id != child["profile_id"]
                        or source.generation_sha256 != child["source_generation_sha256"]
                        or source.effective_prompt_sha256 != child["prompt_sha256"]
                        or child["turn_id"] is None or len(attempts) != 1
                        or any(row is None or row["child_admission_handle"] != child["admission_handle"]
                               or row["response"] is None for row in attempts)
                        or child["mode"] != "planner"
                        or attempts[0]["response"][1]
                        or attempts[0]["response"][2] != request["response_sha256"]
                        or attempts[0]["account"] != child["account"]):
                    raise ValueError("planner completion lacks a current zero-tool provider result")
                child["complete"] = True
                child["response_text_sha256"] = request["response_sha256"]
                completion_handle = secrets.token_urlsafe(32)
                expiry = min(child["expiry"], now + 30.0)
                self._planning_completions[completion_handle] = {
                    "child": child, "response_sha256": request["response_sha256"],
                    "expiry": expiry}
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "completion_handle": completion_handle,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "owner_turn_handle": owner.owner_turn_handle,
                    "gateway_turn_id": owner.gateway_turn_id,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "prompt_sha256": child["goal_sha256"],
                    "response_sha256": request["response_sha256"],
                    "expires_monotonic": expiry}
            if op == "verify-planning-completion":
                fields = {"schema", "op", "nonce", "completion_handle", "owner_turn_handle",
                          "gateway_turn_id", "owner_subject_sha256", "core_generation",
                          "core_source_generation", "prompt_sha256", "response_sha256"}
                if set(request) != fields:
                    raise ValueError("planning completion schema mismatch")
                record = self._planning_completions.get(request["completion_handle"])
                if record is None or record["expiry"] <= time.monotonic():
                    raise ValueError("planning completion expired")
                child, owner = record["child"], record["child"]["owner"]
                source = child.get("source")
                if (child["complete"] is not True or child["peer"] != peer
                        or owner.is_current_sealed(self._config, custody=self._custody,
                                                   now=time.monotonic()) is not True
                        or not callable(getattr(source, "is_current_sealed", None))
                        or source.is_current_sealed(self._custody, now=time.monotonic()) is not True
                        or request["owner_turn_handle"] != owner.owner_turn_handle
                        or request["gateway_turn_id"] != owner.gateway_turn_id
                        or request["owner_subject_sha256"] != owner.owner_subject_sha256
                        or request["core_generation"] != owner.core_generation
                        or request["core_source_generation"] != owner.core_source_generation
                        or request["prompt_sha256"] != child["goal_sha256"]
                        or request["response_sha256"] != record["response_sha256"]):
                    raise ValueError("planning completion is stale or mismatched")
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "register-attempt":
                required = {"schema", "op", "nonce", "session_id", "turn_id", "api_request_id",
                            "provider", "model", "base_url", "api_mode", "account_fingerprint",
                            "request_sha256", "prompt_sha256", "parent_tool_names", "retry_count"}
                if set(request) != required:
                    raise ValueError("attempt schema mismatch")
                owner = self._owner_for(request["session_id"], request["turn_id"])
                policy = self._policy_for_owner(owner, time.monotonic()) if owner is not None else None
                child = self._child_sessions.get(request["session_id"])
                child_tools = tuple(child["tool_names"]) if child is not None else None
                is_child_attempt = child is not None
                if (owner is None or request["provider"] != _CODEX_PROVIDER
                        or request["api_mode"] != _CODEX_MODE or request["base_url"] != _CODEX_ENDPOINT
                        or type(request["retry_count"]) is not int or request["retry_count"] != 0
                        or not _HASH.fullmatch(request["account_fingerprint"])
                        or not _HASH.fullmatch(request["request_sha256"])
                        or not _HASH.fullmatch(request["prompt_sha256"])
                        or request["prompt_sha256"] != (child["goal_sha256"] if is_child_attempt
                                                          else owner.prompt_sha256)
                        or not isinstance(request["parent_tool_names"], list)
                        or len(request["parent_tool_names"]) > 512
                        or any(not isinstance(name, str) or not _ID.fullmatch(name)
                               for name in request["parent_tool_names"])
                        or len(set(request["parent_tool_names"])) != len(request["parent_tool_names"])
                        or policy is None
                        or (is_child_attempt and (
                            child["owner"] is not owner or child["expiry"] <= time.monotonic()
                            or child["peer"] != peer
                            or not callable(getattr(child.get("source"), "is_current_sealed", None))
                            or child["source"].is_current_sealed(
                                self._custody, now=time.monotonic()) is not True
                            or child["turn_id"] not in (None, request["turn_id"])
                            or request["account_fingerprint"] != child["account"]
                            or tuple(request["parent_tool_names"]) != child_tools
                            or (child["mode"] == "planner" and bool(request["parent_tool_names"]))
                        ))
                        or (not is_child_attempt and (
                            not 1 <= len(request["parent_tool_names"])
                            or not set(request["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                            or "resources_delegate" not in request["parent_tool_names"]
                            or (not policy.allow_inherited_mcp
                                and any(name.startswith("mcp__") for name in request["parent_tool_names"]))
                        ))):
                    raise ValueError("attempt is not an enrolled current subscription turn")
                if is_child_attempt and child["turn_id"] is None:
                    child["turn_id"] = request["turn_id"]
                handle = secrets.token_urlsafe(32)
                if len(self._attempts) >= 2048:
                    raise ValueError("native attempt registry is full")
                expiry = min(float(owner.expires_monotonic), time.monotonic() + 30.0)
                self._attempts[handle] = {"owner": owner, "session_id": request["session_id"],
                    "turn_id": request["turn_id"], "api_request_id": request["api_request_id"],
                    "account": request["account_fingerprint"], "expiry": expiry, "response": None,
                    "parent_tool_names": tuple(request["parent_tool_names"]),
                    "provider": request["provider"], "api_mode": request["api_mode"],
                    "base_url": request["base_url"],
                    "policy_handle": policy.policy_handle, "model": request["model"],
                    "child_admission_handle": child["admission_handle"] if is_child_attempt else None,
                    "response_text_sha256": None}
                if is_child_attempt:
                    child["attempts"].append(handle)
                return {"schema": 1, "nonce": nonce, "ok": True, "attempt_handle": handle,
                        "owner_turn_handle": owner.owner_turn_handle, "expires_monotonic": expiry}
            if op == "register-response":
                if set(request) != {"schema", "op", "nonce", "attempt_handle", "response_sha256",
                                    "response_text_sha256", "tool_calls", "completed"}:
                    raise ValueError("response schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if (row is None or row["expiry"] <= time.monotonic() or row["response"] is not None
                        or type(request["completed"]) is not bool or not _HASH.fullmatch(request["response_sha256"])
                        or (request["response_text_sha256"] is not None
                            and not _HASH.fullmatch(request["response_text_sha256"]))
                        or not isinstance(request["tool_calls"], list) or len(request["tool_calls"]) > 128):
                    raise ValueError("response is not a live unique attempt result")
                calls = {}
                for item in request["tool_calls"]:
                    if (not isinstance(item, dict) or set(item) != {"id", "name", "arguments_sha256"}
                            or not _ID.fullmatch(item["id"]) or not _ID.fullmatch(item["name"])
                            or not _HASH.fullmatch(item["arguments_sha256"]) or item["id"] in calls):
                        raise ValueError("provider call inventory is malformed")
                    calls[item["id"]] = item
                child = self._child_sessions.get(row["session_id"])
                if child is not None:
                    if (any(item["name"] not in child["tool_names"] for item in calls.values())
                            or (child["mode"] == "planner" and calls)
                            or (child["mode"] == "planner" and request["completed"]
                                and not _HASH.fullmatch(request["response_text_sha256"] or ""))):
                        raise ValueError("child response exceeds its admitted tool or text closure")
                row["response"] = ((request["response_sha256"], calls,
                                    request["response_text_sha256"])
                                   if request["completed"] else (None, {}, None))
                if request["completed"]:
                    row["response_text_sha256"] = request["response_text_sha256"]
                    if child is not None:
                        child["response_text_sha256"] = request["response_text_sha256"]
                return {"schema": 1, "nonce": nonce, "ok": True}
            if op == "register-tool-call":
                if set(request) != {"schema", "op", "nonce", "attempt_handle", "tool_call_id", "canonical_arguments_b64"}:
                    raise ValueError("tool-call schema mismatch")
                row = self._attempts.get(request["attempt_handle"])
                if row is None or row["expiry"] <= time.monotonic() or row["response"] is None:
                    raise ValueError("tool call has no completed live response")
                returned = row["response"][1].get(request["tool_call_id"])
                child = self._child_sessions.get(row["session_id"])
                if child is not None and (returned is None or returned["name"] not in child["tool_names"]):
                    raise ValueError("child tool call is outside its admitted finite closure")
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
                source = self._current_master_source()
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
                        or not parent_tools.issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in parent_tools))
                        or policy.additional_metered_budget != 0
                        or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or source.profile_id != "hermes"
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
                    # The profile object's short TTL is readback freshness, not
                    # the authority deadline. Its exact currentness is re-read
                    # at consume and immediately before native child admission.
                    "expiry": min(call["expiry"], policy.expires_monotonic,
                                  time.monotonic() + 30.0)}
                return {"schema": 1, "nonce": nonce, "ok": True, "claim_handle": claim_handle}
            if op == "consume-dispatch":
                if set(request) != {"schema", "op", "nonce", "claim_handle"}:
                    raise ValueError("consume schema mismatch")
                claim = self._claims.pop(request["claim_handle"], None)
                if claim is None or claim["expiry"] <= time.monotonic():
                    raise ValueError("dispatch claim expired or was already consumed")
                call, owner = claim["call"], claim["owner"]
                policy = claim["policy"]
                source = self._current_master_source()
                if (call["peer"] != peer or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=time.monotonic()) is not True
                        or self._policy_for_owner(owner, time.monotonic()) is not policy
                        or not set(call["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in call["parent_tool_names"]))):
                    raise ValueError("dispatch lineage is no longer current")
                if owner.mission_binding is not None and owner.mission_binding.execution_mode == "pending":
                    raise ValueError("pending mission mode cannot dispatch")
                self._consumed_dispatches[request["claim_handle"]] = {
                    **claim, "expiry": min(claim["expiry"], time.monotonic() + 30.0),
                }
                # Source/tool/privacy intersection is completed by the consumer against
                # the exact locally injected parent Agent; no Agent crosses this socket.
                manifest = [{"path": item.path, "sha256": item.sha256, "size": item.size}
                            for item in source.source_member_manifest]
                body = {"schema": 1, "claim_handle": request["claim_handle"],
                    "owner_turn_handle": owner.owner_turn_handle, "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "observed_call_handle": call["handle"],
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "session_id": call["attempt_session_id"],
                    "generation_sha256": source.generation_sha256,
                    "turn_id": call["attempt_turn_id"], "tool_call_id": call["tool_call_id"],
                    "tool_name": call["tool_name"], "arguments_sha256": call["arguments_sha256"],
                    "account_fingerprint": self._attempts[call["attempt"]]["account"],
                    "profile_id": source.profile_id, "source_revision": source.source_revision,
                    "profile_manifest_sha256": source.profile_manifest_sha256,
                    "profile_tool_names": [],
                    "profile_privacy_requirements": [],
                    "source_manifest": manifest, "source_manifest_sha256": _hash(manifest),
                    "prompt_b64": base64.b64encode(source.effective_prompt).decode("ascii"),
                    "prompt_sha256": source.effective_prompt_sha256, "prompt_revision": source.source_revision,
                    "parent_tool_names": list(call["parent_tool_names"]), "parent_privacy_grants": [],
                    "delegation_policy_handle": policy.policy_handle,
                    "delegation_policy_sha256": policy.policy_sha256,
                    "parent_tool_configuration_sha256": policy.parent_tool_configuration_sha256,
                    "configured_parent_tool_names": list(policy.configured_parent_tool_names),
                    "allow_inherited_mcp": policy.allow_inherited_mcp,
                    "allow_native_orchestrator_delegation": policy.allow_native_orchestrator_delegation,
                    "mission_binding": (owner.mission_binding.to_wire()
                                        if owner.mission_binding is not None else None),
                    "expires_monotonic": claim["expiry"], "evidence_class": "protected-core-process-observation",
                    "provider": _CODEX_PROVIDER, "api_mode": _CODEX_MODE, "base_url": _CODEX_ENDPOINT,
                    "additional_metered_budget": 0}
                if owner.mission_binding is not None:
                    if len(self._mission_pending) >= 128:
                        raise ValueError("pending mission authorization registry is full")
                    self._mission_pending[request["claim_handle"]] = claim
                return {"schema": 1, "nonce": nonce, "ok": True, "dispatch_claim": body}
            if op == "authorize-mission-dispatch":
                if set(request) != {"schema", "op", "nonce", "claim_handle"}:
                    raise ValueError("mission authorization schema mismatch")
                pending = self._mission_pending.pop(request["claim_handle"], None)
                if pending is None or pending["expiry"] <= time.monotonic():
                    raise ValueError("mission authorization is expired or already consumed")
                call, owner = pending["call"], pending["owner"]
                policy = pending["policy"]
                source = self._current_master_source()
                if (call["peer"] != peer
                        or call.get("claim") != request["claim_handle"]
                        or source is None
                        or source.is_current_sealed(custody=self._custody, now=time.monotonic()) is not True
                        or owner.is_current_sealed(self._config, custody=self._custody, now=time.monotonic()) is not True
                        or self._policy_for_owner(owner, time.monotonic()) is not policy
                        or policy.additional_metered_budget != 0
                        or not set(call["parent_tool_names"]).issubset(policy.configured_parent_tool_names)
                        or (not policy.allow_inherited_mcp
                            and any(name.startswith("mcp__") for name in call["parent_tool_names"]))
                        or type(owner.mission_binding) is not MissionBinding
                        or source.profile_id != "hermes"
                        or call["tool_name"] != "resources_delegate"):
                    raise ValueError("mission dispatch lineage is no longer current")
                from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
                from hermes_installer.remote.jarvis_mission_executor import (
                    MissionLedgerReader, resolve_spent_mission_claim,
                )
                if CHAT_STORE_PATH != Path("/var/lib/hermes-jarvis-chat/chat.sqlite3"):
                    raise ValueError("fixed mission ledger path differs")
                arguments_sha256 = call["arguments_sha256"]
                if resolve_spent_mission_claim(
                        MissionLedgerReader(path=CHAT_STORE_PATH), owner.mission_binding,
                        owner.gateway_turn_id, owner.owner_subject_sha256,
                        owner.core_generation, owner.core_source_generation,
                        source.profile_id, arguments_sha256) is not True:
                    raise ValueError("spent mission approval no longer matches the native call")
                return {"schema": 1, "nonce": nonce, "ok": True,
                    "claim_handle": request["claim_handle"],
                    "mission_binding_sha256": _hash(owner.mission_binding.to_wire()),
                    "gateway_turn_id": owner.gateway_turn_id,
                    "owner_subject_sha256": owner.owner_subject_sha256,
                    "core_generation": owner.core_generation,
                    "core_source_generation": owner.core_source_generation,
                    "source_profile_id": owner.mission_binding.source_profile_id,
                    "canonical_arguments_sha256": arguments_sha256,
                    "expires_monotonic": min(pending["expiry"], owner.expires_monotonic)}
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
            self._mission_pending.clear()
            self._consumed_dispatches.clear()
            self._child_sessions.clear()
            self._planning_completions.clear()
            self._master_selections.clear()
            self._selected_source_deliveries.clear()


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
    if not isinstance(tools, list) or len(tools) > 512:
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


def _native_delegate_execution_gate(*, tool_name: str, args: Any,
                                    next_call: Callable[[Any], Any], **_event: Any) -> Any:
    """Block model-issued direct delegation while preserving the Resources adapter.

    Official PluginContext.dispatch_tool calls tools.registry.dispatch directly and
    therefore does not traverse tool_execution middleware. The fixed Resources
    handler is the only approved internal caller; ordinary model tool execution
    reaches this middleware and is denied without invoking downstream dispatch.
    """
    if tool_name == "delegate_task":
        return json.dumps({"success": False, "state": "native-delegation-requires-resources-policy",
                           "message": "Use the owner-authorized Resources delegation route."})
    return next_call(args)


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
                    response_text_sha256=None, tool_calls=[], completed=False)
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
            output_text = getattr(response, "output_text", None)
            response_text_sha256 = None
            if isinstance(output_text, str):
                output_bytes = output_text.encode("utf-8", errors="strict")
                if output_bytes and len(output_bytes) <= 32 * 1024:
                    response_text_sha256 = hashlib.sha256(output_bytes).hexdigest()
            response_bytes = _canonical(response.model_dump(mode="json"))
            if not 1 <= len(response_bytes) <= MAX_FRAME:
                return response
            try:
                client.register_response(
                    attempt=attempt, response_sha256=hashlib.sha256(response_bytes).hexdigest(),
                    response_text_sha256=response_text_sha256,
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
        # This is a model-call gate, not the trusted Resources wrapper path:
        # PluginContext.dispatch_tool bypasses tool_execution middleware.
        registrations.append(register("tool_execution", _native_delegate_execution_gate))
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
        self._lock = threading.RLock()
        self._mission_claims: OrderedDict[str, tuple[object, RootSelectedInternalProfileDispatchClaim]] = OrderedDict()
        self._authorized_mission_claims: set[str] = set()

    def read_selected_expert_source(
            self, *, resources_claim: object, source_id: str) -> RootNativeSelectedSourceDelivery:
        """Resolve only a source selected by this root-sealed mission claim."""
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims
                or resources_claim.mission_binding is None
                or source_id not in resources_claim.mission_binding.selected_source_ids):
            raise CoreNativeObservationUnavailable("source is not selected by the sealed owner intent")
        return self._client.read_selected_expert_source(
            native_claim=retained[1], source_id=source_id)

    def admit_selected_expert_child(
            self, *, resources_claim: object, child: Any,
            source: RootNativeSelectedSourceDelivery, goal: str
            ) -> RootVerifiedNativeChildAuthorization:
        """Forward the exact consumed claim/source to root admission."""
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        with self._lock:
            retained = self._mission_claims.get(getattr(resources_claim, "claim_id", ""))
        if (type(resources_claim) is not ResourcesDispatchClaim or retained is None
                or retained[0] is not resources_claim
                or resources_claim.claim_id not in self._authorized_mission_claims):
            raise CoreNativeObservationUnavailable("typed consumed Resources claim is required")
        return self._client.admit_selected_expert_child(
            native_claim=retained[1], child=child, source=source, goal=goal)

    def consume_current_claim(self, profile_id: str, parent_agent: object, *,
                              tool_call_id: str, tool_name: str,
                              arguments: Mapping[str, Any], turn_id: str):
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        if profile_id != "hermes" or tool_name != "resources_delegate":
            raise CoreNativeObservationUnavailable("only the fixed Jarvis master tool may be claimed")
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
                    or not set(claim.parent_tool_names).issubset(claim.configured_parent_tool_names)
                    or (not claim.allow_inherited_mcp and any(name.startswith("mcp__") for name in parent_tools))
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
            resources_claim = ResourcesDispatchClaim(
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
                inherited_child_tool_names=parent_tools,
                parent_privacy_grants=frozenset(),
                profile_privacy_requirements=frozenset(),
                delegation_policy_handle=claim.delegation_policy_handle,
                delegation_policy_sha256=claim.delegation_policy_sha256,
                parent_tool_configuration_sha256=claim.parent_tool_configuration_sha256,
                configured_parent_tool_names=frozenset(claim.configured_parent_tool_names),
                allow_inherited_mcp=claim.allow_inherited_mcp,
                allow_native_orchestrator_delegation=claim.allow_native_orchestrator_delegation,
                route_class="existing-owner-codex-zero-additional-metered",
                route_receipt_sha256=route_receipt,
                max_additional_metered_microusd=0,
                expires_monotonic=claim.expires_monotonic,
                gateway_turn_id=claim.gateway_turn_id,
                core_generation=claim.core_generation,
                core_source_generation=claim.core_source_generation,
                mission_binding=claim.mission_binding,
            )
            if claim.mission_binding is not None:
                with self._lock:
                    if len(self._mission_claims) >= 128:
                        self._mission_claims.popitem(last=False)
                    self._mission_claims[claim.claim_handle] = (resources_claim, claim)
            return resources_claim
        except Exception:
            raise CoreNativeObservationUnavailable("root claim does not match the live native parent") from None

    def authorize_mission_claim(self, resources_claim: object, *, task_sha256: str
                                ) -> RootVerifiedMissionDispatchAuthorization:
        from hermes_installer.components.resources_internal_dispatch import (
            RootSelectedInternalProfileDispatchClaim as ResourcesDispatchClaim,
        )
        if (type(resources_claim) is not ResourcesDispatchClaim
                or resources_claim.mission_binding is None
                or not _HASH.fullmatch(task_sha256 or "")):
            raise CoreNativeObservationUnavailable("typed bound mission claim is required")
        with self._lock:
            row = self._mission_claims.get(resources_claim.claim_id)
            if resources_claim.claim_id in self._authorized_mission_claims:
                raise CoreNativeObservationUnavailable("mission claim authorization was already consumed")
        if row is None or row[0] is not resources_claim or row[1].mission_binding != resources_claim.mission_binding:
            raise CoreNativeObservationUnavailable("mission claim was not issued by this root client")
        native_claim = row[1]
        if (native_claim.arguments_sha256 != task_sha256
                or native_claim.gateway_turn_id != resources_claim.gateway_turn_id
                or native_claim.owner_subject_sha256 != resources_claim.owner_subject_sha256
                or native_claim.core_generation != resources_claim.core_generation
                or native_claim.core_source_generation != resources_claim.core_source_generation
                or native_claim.mission_binding.task_sha256 != task_sha256):
            raise CoreNativeObservationUnavailable("mission claim does not bind the approved goal")
        authorization = self._client.authorize_mission_dispatch(claim=native_claim)
        if not authorization.matches_claim(native_claim, task_sha256, now=time.monotonic()):
            raise CoreNativeObservationUnavailable("root mission authorization is not current")
        with self._lock:
            self._authorized_mission_claims.add(resources_claim.claim_id)
        return authorization


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
    "CoreNativeResourcesDelegateRegistration", "current_resources_delegate_registration",
    "NativeSourceMember", "ObservedProviderAttempt", "OwnerTurnHandle",
    "RootSelectedInternalProfileDispatchClaim", "RootVerifiedMissionDispatchAuthorization",
    "RootVerifiedNativeChildAuthorization", "RootVerifiedMasterReadCall",
    "CoreVerifiedJarvisMasterPlanningCompletion",
    "RootCoreNativeObservationRegistry", "_native_delegate_execution_gate",
    "RootInternalProfileClaimSource", "serve_core_native_observer",
    "install_native_codex_process_observer", "register_native_resources_observer",
    "register_tool_call_from_current_parent",
]
