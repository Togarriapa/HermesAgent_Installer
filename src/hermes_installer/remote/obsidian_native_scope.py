"""Sealed client-side decoders for root-issued Obsidian startup and call scopes."""
from __future__ import annotations

from dataclasses import dataclass
import math
import re
import time
from typing import Any, Mapping

from .jarvis_mission_executor import MissionBinding

_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{32,64}\Z", re.ASCII)
_IDENT = re.compile(r"[A-Za-z0-9_-]{1,96}\Z", re.ASCII)
_VAULT_ROOT = "/home/admin/.hermes/jarvis-second-brain"
_BINDING_SEAL = object()
_SCOPE_SEAL = object()
_DRAFT_ORIGIN_SEAL = object()


class ObsidianRootScopeUnavailable(PermissionError):
    """Root could not issue a current fixed-owner Obsidian scope."""


@dataclass(frozen=True, slots=True)
class RootSelectedObsidianVaultBinding:
    binding_id: str
    registration_sha256: str
    owner_subject_sha256: str
    core_generation: str
    core_source_generation: str
    core_pid: int
    core_start_ticks: str
    selected_owner_uid: int
    vault_root: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        now = time.monotonic()
        if (not _OPAQUE.fullmatch(self.binding_id or "")
                or not all(_HASH.fullmatch(value or "") for value in (
                    self.registration_sha256, self.owner_subject_sha256,
                    self.core_generation, self.core_source_generation))
                or type(self.core_pid) is not int or self.core_pid <= 1
                or not isinstance(self.core_start_ticks, str) or not self.core_start_ticks.isdecimal()
                or type(self.selected_owner_uid) is not int or self.selected_owner_uid != 1000
                or self.vault_root != _VAULT_ROOT
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or not now < self.expires_monotonic <= min(self.issued_monotonic + 30.0, now + 30.0)
                or self.issued_monotonic > now
                or self._seal is not _BINDING_SEAL):
            raise ObsidianRootScopeUnavailable("root Obsidian startup binding is malformed or stale")

    def is_current_for(self, *, owner_subject_sha256: str, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return bool(self._seal is _BINDING_SEAL and current < self.expires_monotonic
                    and owner_subject_sha256 == self.owner_subject_sha256)


@dataclass(frozen=True, slots=True)
class RootObsidianCallScope:
    observed_call_handle: str
    owner_turn_handle: str
    tool_call_id: str
    tool_name: str
    arguments_sha256: str
    owner_subject_sha256: str
    registration_sha256: str
    startup_binding_id: str
    core_generation: str
    core_source_generation: str
    source_generation_sha256: str
    mode: str
    execution_id: str
    source_instance_id: str
    mission_binding: MissionBinding | None
    selected_note_ids: frozenset[str] | None
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        now = time.monotonic()
        if (not _OPAQUE.fullmatch(self.observed_call_handle or "")
                or not _OPAQUE.fullmatch(self.owner_turn_handle or "")
                or not _IDENT.fullmatch(self.tool_call_id or "")
                or not _IDENT.fullmatch(self.tool_name or "")
                or not all(_HASH.fullmatch(value or "") for value in (
                    self.arguments_sha256, self.owner_subject_sha256,
                    self.registration_sha256, self.core_generation,
                    self.core_source_generation, self.source_generation_sha256))
                or not _OPAQUE.fullmatch(self.startup_binding_id or "")
                or self.mode not in {"master_read", "expert_read", "master_effect"}
                or not _IDENT.fullmatch(self.execution_id or "")
                or not _IDENT.fullmatch(self.source_instance_id or "")
                or (self.mission_binding is not None and type(self.mission_binding) is not MissionBinding)
                or (self.selected_note_ids is not None and
                    (type(self.selected_note_ids) is not frozenset
                     or len(self.selected_note_ids) > 200
                     or any(type(note_id) is not str or not _IDENT.fullmatch(note_id)
                            for note_id in self.selected_note_ids)))
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or not now < self.expires_monotonic <= min(self.issued_monotonic + 5.0, now + 5.0)
                or self.issued_monotonic > now
                or self._seal is not _SCOPE_SEAL):
            raise ObsidianRootScopeUnavailable("root Obsidian call scope is malformed or stale")
        if self.mode in {"master_read", "master_effect"}:
            if (self.execution_id != self.owner_turn_handle or self.source_instance_id != "hermes"
                    or self.mission_binding is not None or self.selected_note_ids is not None):
                raise ObsidianRootScopeUnavailable("master Obsidian scope differs from its current owner turn")
        else:
            if (self.mission_binding is None or self.mission_binding.schema != 2
                    or self.source_instance_id not in (self.mission_binding.selected_source_ids or ())
                    or self.selected_note_ids is None):
                raise ObsidianRootScopeUnavailable("Expert Obsidian scope lacks its actual mission and note selection")

    def matches(self, observed_call: Any, binding: RootSelectedObsidianVaultBinding,
                *, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return bool(self._seal is _SCOPE_SEAL
            and type(binding) is RootSelectedObsidianVaultBinding
            and binding._seal is _BINDING_SEAL
            and self.startup_binding_id == binding.binding_id
            and self.registration_sha256 == binding.registration_sha256
            and self.owner_subject_sha256 == binding.owner_subject_sha256
            and self.core_generation == binding.core_generation
            and self.core_source_generation == binding.core_source_generation
            and current < min(self.expires_monotonic, binding.expires_monotonic)
            and getattr(observed_call, "handle", None) == self.observed_call_handle
            and getattr(observed_call, "owner_turn_handle", None) == self.owner_turn_handle
            and getattr(observed_call, "tool_call_id", None) == self.tool_call_id
            and getattr(observed_call, "tool_name", None) == self.tool_name
            and getattr(observed_call, "arguments_sha256", None) == self.arguments_sha256)


@dataclass(frozen=True, slots=True)
class RootObsidianDraftOrigin:
    """Short-lived proof that ROOT resolved this owner's draft to retained native lineage."""

    draft_id: str
    owner_subject_sha256: str
    registration_sha256: str
    origin_execution_id: str
    origin_source_id: str
    origin_source_revision: str
    source_generation_sha256: str
    mission_sha256: str | None
    content_sha256: str
    base_sha256: str | None
    origin_record_sha256: str
    state: str
    issued_monotonic: float
    expires_monotonic: float
    _seal: object

    def __post_init__(self) -> None:
        now = time.monotonic()
        if (not _IDENT.fullmatch(self.draft_id or "")
                or not all(_HASH.fullmatch(value or "") for value in (
                    self.owner_subject_sha256, self.registration_sha256,
                    self.source_generation_sha256, self.content_sha256,
                    self.origin_record_sha256))
                or not _IDENT.fullmatch(self.origin_execution_id or "")
                or not _IDENT.fullmatch(self.origin_source_id or "")
                or not isinstance(self.origin_source_revision, str)
                or not 1 <= len(self.origin_source_revision) <= 128
                or any(ord(char) < 0x20 for char in self.origin_source_revision)
                or (self.mission_sha256 is not None and not _HASH.fullmatch(self.mission_sha256 or ""))
                or (self.base_sha256 is not None and not _HASH.fullmatch(self.base_sha256 or ""))
                or self.state != "private-draft"
                or any(type(value) not in (int, float) or not math.isfinite(value)
                       for value in (self.issued_monotonic, self.expires_monotonic))
                or not now < self.expires_monotonic <= min(self.issued_monotonic + 5.0, now + 5.0)
                or self.issued_monotonic > now
                or self._seal is not _DRAFT_ORIGIN_SEAL):
            raise ObsidianRootScopeUnavailable("root Obsidian draft origin is malformed or stale")

    def matches(self, *, draft_id: str, owner_subject_sha256: str,
                registration_sha256: str, content_sha256: str,
                base_sha256: str | None, now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        return bool(self._seal is _DRAFT_ORIGIN_SEAL and current < self.expires_monotonic
            and self.draft_id == draft_id
            and self.owner_subject_sha256 == owner_subject_sha256
            and self.registration_sha256 == registration_sha256
            and self.content_sha256 == content_sha256
            and self.base_sha256 == base_sha256 and self.state == "private-draft")


def _decode_startup_binding(row: Mapping[str, Any]) -> RootSelectedObsidianVaultBinding:
    expected = {"schema", "nonce", "ok", "binding_id", "registration_sha256",
        "owner_subject_sha256", "core_generation", "core_source_generation", "core_pid",
        "core_start_ticks", "selected_owner_uid", "vault_root", "issued_monotonic",
        "expires_monotonic"}
    if (type(row) is not dict or set(row) != expected or type(row["schema"]) is not int
            or row["schema"] != 1 or row["ok"] is not True
            or any(type(row[key]) not in (int, float) or isinstance(row[key], bool)
                   for key in ("issued_monotonic", "expires_monotonic"))):
        raise ObsidianRootScopeUnavailable("root Obsidian startup binding response schema differs")
    try:
        return RootSelectedObsidianVaultBinding(
            binding_id=row["binding_id"], registration_sha256=row["registration_sha256"],
            owner_subject_sha256=row["owner_subject_sha256"], core_generation=row["core_generation"],
            core_source_generation=row["core_source_generation"], core_pid=row["core_pid"],
            core_start_ticks=row["core_start_ticks"], selected_owner_uid=row["selected_owner_uid"],
            vault_root=row["vault_root"], issued_monotonic=float(row["issued_monotonic"]),
            expires_monotonic=float(row["expires_monotonic"]), _seal=_BINDING_SEAL)
    except Exception:
        raise ObsidianRootScopeUnavailable("root Obsidian startup binding is invalid") from None


def _decode_call_scope(row: Mapping[str, Any], *, binding: RootSelectedObsidianVaultBinding,
                       observed_call: Any) -> RootObsidianCallScope:
    expected = {"schema", "nonce", "ok", "observed_call_handle", "owner_turn_handle",
        "tool_call_id", "tool_name", "arguments_sha256", "owner_subject_sha256",
        "registration_sha256", "startup_binding_id", "core_generation", "core_source_generation",
        "source_generation_sha256", "mode", "execution_id", "source_instance_id", "mission_binding",
        "selected_note_ids", "issued_monotonic", "expires_monotonic"}
    if (type(row) is not dict or set(row) != expected or type(row["schema"]) is not int
            or row["schema"] != 1 or row["ok"] is not True
            or any(type(row[key]) not in (int, float) or isinstance(row[key], bool)
                   for key in ("issued_monotonic", "expires_monotonic"))
            or (row["selected_note_ids"] is not None
                and (type(row["selected_note_ids"]) is not list
                     or len(row["selected_note_ids"]) > 200
                     or any(type(note_id) is not str for note_id in row["selected_note_ids"])
                     or len(set(row["selected_note_ids"])) != len(row["selected_note_ids"])))):
        raise ObsidianRootScopeUnavailable("root Obsidian call scope response schema differs")
    try:
        mission = (None if row["mission_binding"] is None else
                   MissionBinding.from_wire(row["mission_binding"]))
        notes = (None if row["selected_note_ids"] is None else
                 frozenset(row["selected_note_ids"]))
        scope = RootObsidianCallScope(
            observed_call_handle=row["observed_call_handle"], owner_turn_handle=row["owner_turn_handle"],
            tool_call_id=row["tool_call_id"], tool_name=row["tool_name"],
            arguments_sha256=row["arguments_sha256"], owner_subject_sha256=row["owner_subject_sha256"],
            registration_sha256=row["registration_sha256"], startup_binding_id=row["startup_binding_id"],
            core_generation=row["core_generation"], core_source_generation=row["core_source_generation"],
            source_generation_sha256=row["source_generation_sha256"], mode=row["mode"],
            execution_id=row["execution_id"], source_instance_id=row["source_instance_id"],
            mission_binding=mission, selected_note_ids=notes,
            issued_monotonic=float(row["issued_monotonic"]),
            expires_monotonic=float(row["expires_monotonic"]), _seal=_SCOPE_SEAL)
    except Exception:
        raise ObsidianRootScopeUnavailable("root Obsidian call scope is invalid") from None
    if not scope.matches(observed_call, binding):
        raise ObsidianRootScopeUnavailable("root Obsidian call scope does not match this exact call")
    return scope


def _decode_draft_origin(row: Mapping[str, Any]) -> RootObsidianDraftOrigin:
    expected = {"schema", "nonce", "ok", "draft_id", "owner_subject_sha256",
        "registration_sha256", "origin_execution_id", "origin_source_id",
        "origin_source_revision", "source_generation_sha256", "mission_sha256",
        "content_sha256", "base_sha256", "origin_record_sha256", "state",
        "issued_monotonic", "expires_monotonic"}
    if (type(row) is not dict or set(row) != expected or type(row["schema"]) is not int
            or row["schema"] != 1 or row["ok"] is not True
            or not isinstance(row.get("nonce"), str)
            or any(type(row[key]) not in (int, float) or isinstance(row[key], bool)
                   for key in ("issued_monotonic", "expires_monotonic"))):
        raise ObsidianRootScopeUnavailable("root Obsidian draft-origin response schema differs")
    try:
        return RootObsidianDraftOrigin(
            draft_id=row["draft_id"], owner_subject_sha256=row["owner_subject_sha256"],
            registration_sha256=row["registration_sha256"],
            origin_execution_id=row["origin_execution_id"], origin_source_id=row["origin_source_id"],
            origin_source_revision=row["origin_source_revision"],
            source_generation_sha256=row["source_generation_sha256"],
            mission_sha256=row["mission_sha256"], content_sha256=row["content_sha256"],
            base_sha256=row["base_sha256"], origin_record_sha256=row["origin_record_sha256"],
            state=row["state"], issued_monotonic=float(row["issued_monotonic"]),
            expires_monotonic=float(row["expires_monotonic"]), _seal=_DRAFT_ORIGIN_SEAL)
    except Exception:
        raise ObsidianRootScopeUnavailable("root Obsidian draft origin is invalid or stale") from None


__all__ = ["ObsidianRootScopeUnavailable", "RootObsidianCallScope",
           "RootObsidianDraftOrigin", "RootSelectedObsidianVaultBinding"]
