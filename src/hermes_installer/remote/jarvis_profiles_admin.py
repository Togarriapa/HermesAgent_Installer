"""Owner-only Profile file editor over a trusted current-Core source provider.

This leaf owns the browser/API contract and its preview/CAS choreography. The
provider is supplied by the root/Core custody layer and receives only closed
profile/file selectors; HTTP callers can never submit a filesystem path.
"""
from __future__ import annotations

import asyncio
import difflib
import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Literal, Protocol

from .jarvis_chat import ChatPrincipal, JarvisChatDenied, JarvisChatService, _secure_headers, _unique_pairs
from .jarvis_feature_contract import JarvisFeatureAssets

MAX_PROFILE_COUNT = 64
MAX_PROFILE_FILE_BYTES = 64 * 1024
MAX_PROFILE_REQUEST_BYTES = 96 * 1024
MAX_PROFILE_DIFF_BYTES = 128 * 1024
MAX_PREVIEWS = 128
PREVIEW_TTL_SECONDS = 300.0
FILE_NAMES = {"soul": "SOUL.md", "description": "description.md", "instructions": "instructions.md"}
_HASH = re.compile(r"^[0-9a-f]{64}$")
_OPAQUE = re.compile(r"^[0-9a-f]{64}$")
_PREVIEW = re.compile(r"^[A-Za-z0-9_-]{32,64}$")
_IDEMPOTENCY = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
_PROFILE_ROUTES = (
    ("GET", "/chat/api/profiles"),
    ("GET", "/chat/api/profiles/{profile_id}/files"),
    ("GET", "/chat/api/profiles/{profile_id}/files/{file_kind}"),
    ("POST", "/chat/api/profiles/{profile_id}/preview"),
    ("POST", "/chat/api/profiles/{profile_id}/save"),
)


@dataclass(frozen=True, slots=True)
class ProfileAdminDescriptor:
    """One real profile selected from the current native manifest by the provider."""

    profile_key: str  # internal stable native key; never serialized to the browser
    display_name: str
    kind: Literal["jarvis", "expert"]
    source_generation: str
    file_kinds: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ProfileAdminFile:
    """Exact existing regular source file returned through Core/root custody."""

    profile_key: str
    file_kind: str
    file_name: str
    source_generation: str
    content: str
    sha256: str
    effective: bool
    protected_suffix: str = ""
    managed_primary: bool = False


@dataclass(frozen=True, slots=True)
class ProfileAdminWriteResult:
    """Closed result of a journaled source-generation CAS and effective readback."""

    state: Literal["active", "archived", "unknown-pending", "conflict", "unavailable"]
    source_generation: str | None
    sha256: str | None
    recovery_id: str | None
    effective_readback: bool


@dataclass(frozen=True, slots=True)
class NativeSkillDescriptor:
    skill_id: str
    display_name: str
    sha256: str
    source: Literal["resources", "owner-added"]
    editable: bool
    overlay_active: bool = False


@dataclass(frozen=True, slots=True)
class NativeSkillFile:
    skill_id: str
    file_name: str
    content: str
    sha256: str
    source_generation: str
    source: Literal["resources", "owner-added"]
    effective: bool
    overlay_active: bool = False


class JarvisProfileAdminProvider(Protocol):
    """Trusted source adapter; implementations must enforce native path custody.

    ``list_profiles`` must resolve only actual existing manifest entries and
    ``read_file`` must use bounded no-follow regular-file reads. ``write_generation``
    must journal recoverable prior bytes, CAS the full current source generation,
    publish a new overlay generation, preserve permission policy, invalidate prior
    authority claims and return only after effective native readback.
    """

    def list_profiles(self, *, subject: str, core_generation: str, access_jwt: str,
                      accepted_ingress: Any) -> tuple[ProfileAdminDescriptor, ...]: ...
    def read_file(self, *, subject: str, core_generation: str, profile_key: str,
                  file_kind: str, access_jwt: str, accepted_ingress: Any) -> ProfileAdminFile: ...
    def write_generation(self, *, subject: str, core_generation: str, profile_key: str,
                         file_kind: str, expected_sha256: str, content: str,
                         idempotency_key: str, access_jwt: str,
                         accepted_ingress: Any) -> ProfileAdminWriteResult: ...


class CoreGatewayProfileAdminProvider:
    """Bridge the finite adapter to the approved root profile-inspector RPC."""

    def __init__(self, config: Any):
        from .core_gateway import CoreGatewayConfig
        if type(config) is not CoreGatewayConfig:
            raise TypeError("current Core gateway configuration required")
        self._config = config

    def _call(self, *, action: str, access_jwt: str, accepted_ingress: Any,
              profile_key: str | None = None, file_kind: str | None = None,
              skill_id: str | None = None,
              expected_sha256: str | None = None, content: str | None = None,
              idempotency_key: str | None = None, restore_id: str | None = None) -> Any:
        from .core_gateway_inspector import CoreGatewayInspector
        return CoreGatewayInspector(self._config).owner_profile_admin(access_jwt,
            accepted_ingress, action=action, profile_id=profile_key,
            file_kind=file_kind, skill_id=skill_id, expected_sha256=expected_sha256,
            content=content, idempotency_key=idempotency_key, restore_id=restore_id)

    def list_skills(self, *, core_generation: str, access_jwt: str,
                    accepted_ingress: Any) -> tuple[NativeSkillDescriptor, ...]:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        rows = self._call(action="skills-list", access_jwt=access_jwt, accepted_ingress=accepted_ingress)
        if type(rows) not in {list, tuple} or len(rows) > 8192:
            raise JarvisChatDenied("current native skill inventory is invalid")
        result = []
        for row in rows:
            if (type(row) is not dict or set(row) != {"skill_id", "name", "sha256", "source", "editable", "overlay_active"}
                    or not isinstance(row.get("skill_id"), str)
                    or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", row["skill_id"]) is None
                    or row.get("name") != row["skill_id"] or not _HASH.fullmatch(row.get("sha256", ""))
                    or row.get("source") not in {"resources", "owner-added"}
                    or type(row.get("editable")) is not bool
                    or row["editable"] is not True
                    or type(row.get("overlay_active")) is not bool
                    or (row["source"] == "owner-added" and row["overlay_active"])):
                raise JarvisChatDenied("current native skill inventory is invalid")
            result.append(NativeSkillDescriptor(row["skill_id"], row["name"], row["sha256"],
                row["source"], row["editable"], row["overlay_active"]))
        return tuple(result)

    def read_skill(self, *, core_generation: str, skill_id: str, access_jwt: str,
                   accepted_ingress: Any) -> NativeSkillFile:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        row = self._call(action="skill-read", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, skill_id=skill_id)
        if (type(row) is not dict or set(row) != {"skill_id", "file_name", "content", "sha256",
                "signature", "source_generation", "source", "effective", "overlay_active"}
                or row.get("skill_id") != skill_id
                or row.get("file_name") != f"skills/{skill_id}/SKILL.md"
                or type(row.get("signature")) is not list or len(row["signature"]) != 9
                or row.get("source") not in {"resources", "owner-added"}
                or not isinstance(row.get("content"), str)
                or not _valid_text(row["content"])
                or not _HASH.fullmatch(row.get("sha256", ""))
                or hashlib.sha256(row["content"].encode("utf-8")).hexdigest() != row["sha256"]
                or not _valid_generation(row.get("source_generation"))
                or type(row.get("effective")) is not bool
                or type(row.get("overlay_active")) is not bool):
            raise JarvisChatDenied("current native skill source is unavailable")
        return NativeSkillFile(row["skill_id"], row["file_name"], row["content"], row["sha256"],
            row["source_generation"], row["source"], row["effective"], row["overlay_active"])

    def write_skill(self, *, core_generation: str, skill_id: str, expected_sha256: str,
                    content: str, idempotency_key: str, access_jwt: str,
                    accepted_ingress: Any) -> ProfileAdminWriteResult:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        row = self._call(action="skill-write", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, skill_id=skill_id,
            expected_sha256=expected_sha256, content=content, idempotency_key=idempotency_key)
        if type(row) is not dict or set(row) != {"state", "skill_id", "source_generation", "sha256",
                "recovery_id", "effective_readback"}:
            raise JarvisChatDenied("native skill write result is unavailable")
        return ProfileAdminWriteResult(row["state"], row["source_generation"], row["sha256"],
            row["recovery_id"], row["effective_readback"])

    def archive_skill(self, *, core_generation: str, skill_id: str, expected_sha256: str,
                      idempotency_key: str, access_jwt: str,
                      accepted_ingress: Any) -> ProfileAdminWriteResult:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        row = self._call(action="skill-archive", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, skill_id=skill_id,
            expected_sha256=expected_sha256, idempotency_key=idempotency_key)
        if type(row) is not dict or set(row) != {"state", "skill_id", "source_generation", "sha256",
                "recovery_id", "effective_readback"}:
            raise JarvisChatDenied("native skill archive result is unavailable")
        return ProfileAdminWriteResult(row["state"], row["source_generation"], row["sha256"],
            row["recovery_id"], row["effective_readback"])

    def list_archived_skills(self, *, core_generation: str, skill_id: str, source: str = "resources",
                             access_jwt: str, accepted_ingress: Any) -> tuple[dict[str, str], ...]:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        if source not in {"resources", "owner-added"}:
            raise JarvisChatDenied("skill archive source is invalid")
        row = self._call(action="skill-restore-list", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, skill_id=skill_id)
        versions = row.get("versions") if type(row) is dict and row.get("skill_id") == skill_id else None
        if type(versions) is not list or len(versions) > 4096:
            raise JarvisChatDenied("archived Resources versions are unavailable")
        result = []
        for item in versions:
            if (type(item) is not dict or set(item) != {"restore_id", "sha256"}
                    or not isinstance(item.get("restore_id"), str)
                    or (re.fullmatch(r"[0-9a-f]{64}", item["restore_id"]) is None
                        if source == "resources" else
                        re.fullmatch(r"[A-Za-z0-9_-]{16,96}", item["restore_id"]) is None)
                    or not _HASH.fullmatch(item.get("sha256", ""))):
                raise JarvisChatDenied("archived Resources version inventory is invalid")
            result.append(dict(item))
        return tuple(result)

    def list_skill_archives(self, *, core_generation: str, access_jwt: str,
                            accepted_ingress: Any) -> tuple[dict[str, Any], ...]:
        """List restorable versions independently of the now-archived live row."""
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        row = self._call(action="skills-archives-list", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress)
        archives = row.get("archives") if type(row) is dict else None
        if type(archives) is not list or len(archives) > 8192:
            raise JarvisChatDenied("native skill archive inventory is unavailable")
        result = []
        seen = set()
        for item in archives:
            if (type(item) is not dict or set(item) != {"skill_id", "source", "versions"}
                    or not isinstance(item.get("skill_id"), str)
                    or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", item["skill_id"]) is None
                    or item.get("source") not in {"resources", "owner-added"}
                    or item["skill_id"] in seen or type(item.get("versions")) is not list
                    or not 0 < len(item["versions"]) <= 4096):
                raise JarvisChatDenied("native skill archive row is invalid")
            seen.add(item["skill_id"])
            versions = []
            for version in item["versions"]:
                if (type(version) is not dict or set(version) != {"restore_id", "sha256"}
                        or not isinstance(version.get("restore_id"), str)
                        or (re.fullmatch(r"[0-9a-f]{64}", version["restore_id"]) is None
                            if item["source"] == "resources" else
                            re.fullmatch(r"[A-Za-z0-9_-]{16,96}", version["restore_id"]) is None)
                        or not _HASH.fullmatch(version.get("sha256", ""))):
                    raise JarvisChatDenied("native skill archive version is invalid")
                versions.append(dict(version))
            result.append({"skill_id": item["skill_id"], "source": item["source"],
                "versions": tuple(versions)})
        return tuple(result)

    def restore_skill(self, *, core_generation: str, skill_id: str, expected_sha256: str,
                      restore_id: str, idempotency_key: str, access_jwt: str,
                      accepted_ingress: Any) -> ProfileAdminWriteResult:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("skill Core generation changed")
        row = self._call(action="skill-restore", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, skill_id=skill_id,
            expected_sha256=expected_sha256, idempotency_key=idempotency_key,
            restore_id=restore_id)
        if type(row) is not dict or set(row) != {"state", "skill_id", "source_generation", "sha256",
                "recovery_id", "effective_readback"}:
            raise JarvisChatDenied("Resources skill restore is unavailable")
        return ProfileAdminWriteResult(row["state"], row["source_generation"], row["sha256"],
            row["recovery_id"], row["effective_readback"])

    def list_profiles(self, *, subject: str, core_generation: str, access_jwt: str,
                      accepted_ingress: Any) -> tuple[ProfileAdminDescriptor, ...]:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("profile Core generation changed")
        rows = self._call(action="list", access_jwt=access_jwt, accepted_ingress=accepted_ingress)
        if type(rows) not in {list, tuple} or len(rows) > MAX_PROFILE_COUNT:
            raise JarvisChatDenied("current native profile inventory is invalid")
        result = []
        for row in rows:
            if (type(row) is not dict or set(row) != {"profile_id", "display_name", "kind", "source_generation", "files"}
                    or type(row["files"]) is not list or len(row["files"]) > len(FILE_NAMES)):
                raise JarvisChatDenied("current native profile inventory is invalid")
            file_kinds = []
            for item in row["files"]:
                if (type(item) is not dict or set(item) != {"kind", "name", "sha256"}
                        or not _profile_kind(item.get("kind"))
                        or item.get("name") != FILE_NAMES[item["kind"]]
                        or not _HASH.fullmatch(item.get("sha256", ""))):
                    raise JarvisChatDenied("current native profile inventory is invalid")
                file_kinds.append(item["kind"])
            result.append(ProfileAdminDescriptor(row["profile_id"], row["display_name"],
                row["kind"], row["source_generation"], tuple(file_kinds)))
        return tuple(result)

    def read_file(self, *, subject: str, core_generation: str, profile_key: str,
                  file_kind: str, access_jwt: str, accepted_ingress: Any) -> ProfileAdminFile:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("profile Core generation changed")
        row = self._call(action="read", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, profile_key=profile_key, file_kind=file_kind)
        if (type(row) is not dict or set(row) != {"profile_id", "file_kind", "file_name", "content",
                "protected_suffix", "managed_primary", "sha256", "signature", "source_generation", "effective"}
                or type(row["signature"]) is not list or len(row["signature"]) != 9):
            raise JarvisChatDenied("current profile file is unavailable")
        return ProfileAdminFile(row["profile_id"], row["file_kind"], row["file_name"],
            row["source_generation"], row["content"], row["sha256"], row["effective"],
            row["protected_suffix"], row["managed_primary"])

    def write_generation(self, *, subject: str, core_generation: str, profile_key: str,
                         file_kind: str, expected_sha256: str, content: str,
                         idempotency_key: str, access_jwt: str,
                         accepted_ingress: Any) -> ProfileAdminWriteResult:
        if accepted_ingress.core_generation != core_generation:
            raise JarvisChatDenied("profile Core generation changed")
        row = self._call(action="write", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, profile_key=profile_key,
            file_kind=file_kind, expected_sha256=expected_sha256,
            content=content, idempotency_key=idempotency_key)
        if type(row) is not dict or set(row) != {"state", "profile_id", "file_kind",
                "source_generation", "sha256", "recovery_id", "effective_readback"}:
            raise JarvisChatDenied("profile save result is unavailable")
        return ProfileAdminWriteResult(row["state"], row["source_generation"], row["sha256"],
                                       row["recovery_id"], row["effective_readback"])


@dataclass(frozen=True, slots=True)
class _PreviewGrant:
    subject_sha256: str
    core_generation: str
    profile_key: str
    file_kind: str
    base_sha256: str
    content_sha256: str
    expires_monotonic: float


def _valid_text(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        raw = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    return (len(raw) <= MAX_PROFILE_FILE_BYTES and "\x00" not in value
            and not any(ord(char) < 0x20 and char not in "\n\r\t" for char in value))


def _valid_generation(value: Any) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256 and not any(ord(c) < 0x20 for c in value)


def _profile_kind(value: Any) -> bool:
    return isinstance(value, str) and value in FILE_NAMES


def _descriptor(value: Any) -> ProfileAdminDescriptor:
    if type(value) is not ProfileAdminDescriptor:
        raise JarvisChatDenied("current native profile inventory is invalid")
    if (not isinstance(value.profile_key, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,95}", value.profile_key)
            or not isinstance(value.display_name, str) or not 1 <= len(value.display_name) <= 96
            or any(ord(char) < 0x20 for char in value.display_name)
            or value.kind not in {"jarvis", "expert"}
            or not _valid_generation(value.source_generation)
            or type(value.file_kinds) is not tuple or len(value.file_kinds) > len(FILE_NAMES)
            or len(set(value.file_kinds)) != len(value.file_kinds)
            or any(not _profile_kind(item) for item in value.file_kinds)):
        raise JarvisChatDenied("current native profile inventory is invalid")
    if value.kind == "jarvis" and value.profile_key != "hermes":
        raise JarvisChatDenied("current Jarvis profile identity is invalid")
    if value.kind == "expert" and value.profile_key == "hermes":
        raise JarvisChatDenied("current internal profile identity is invalid")
    return value


def _file(value: Any, *, profile_key: str, file_kind: str) -> ProfileAdminFile:
    if type(value) is not ProfileAdminFile:
        raise JarvisChatDenied("current profile file is unavailable")
    if (value.profile_key != profile_key or value.file_kind != file_kind
            or value.file_name != FILE_NAMES[file_kind]
            or not _valid_generation(value.source_generation)
            or not _valid_text(value.content) or not _valid_text(value.protected_suffix)
            or hashlib.sha256((value.content + value.protected_suffix).encode("utf-8")).hexdigest() != value.sha256
            or type(value.managed_primary) is not bool
            or (value.managed_primary and not value.protected_suffix)
            or type(value.effective) is not bool):
        raise JarvisChatDenied("current profile file is unavailable")
    return value


class JarvisProfileAdmin:
    """Owner and generation bound façade with a one-use diff review receipt."""

    def __init__(self, provider: JarvisProfileAdminProvider):
        if not all(callable(getattr(provider, name, None)) for name in
                   ("list_profiles", "read_file", "write_generation")):
            raise TypeError("trusted current-Core profile source provider required")
        self._provider = provider
        self._opaque_key = secrets.token_bytes(32)
        self._lock = threading.RLock()
        self._previews: dict[str, _PreviewGrant] = {}
        self._profiles: dict[tuple[str, str, str], ProfileAdminDescriptor] = {}

    def _opaque_id(self, subject: str, core_generation: str, profile_key: str) -> str:
        raw = "\0".join((subject, core_generation, profile_key)).encode("utf-8")
        return hmac.new(self._opaque_key, raw, hashlib.sha256).hexdigest()

    def _resolve(self, *, subject: str, core_generation: str, profile_id: str,
                 access_jwt: str, accepted_ingress: Any) -> ProfileAdminDescriptor:
        if not _OPAQUE.fullmatch(profile_id):
            raise JarvisChatDenied("profile is unavailable")
        key = (hashlib.sha256(subject.encode()).hexdigest(), core_generation, profile_id)
        with self._lock:
            row = self._profiles.get(key)
        if row is None:
            raise JarvisChatDenied("profile is unavailable")
        # Root checks the current manifest on every file operation. The local map
        # only resolves an app-issued opaque ID to the corresponding native key.
        return row

    def list_profiles(self, *, subject: str, core_generation: str, access_jwt: str,
                      accepted_ingress: Any) -> dict[str, Any]:
        rows = self._provider.list_profiles(subject=subject, core_generation=core_generation,
            access_jwt=access_jwt, accepted_ingress=accepted_ingress)
        if type(rows) is not tuple or len(rows) > MAX_PROFILE_COUNT:
            raise JarvisChatDenied("current native profile inventory is invalid")
        seen: set[str] = set()
        projected = []
        for raw in rows:
            row = _descriptor(raw)
            if row.profile_key in seen:
                raise JarvisChatDenied("current native profile inventory is ambiguous")
            seen.add(row.profile_key)
            projected.append({
                "id": self._opaque_id(subject, core_generation, row.profile_key),
                "name": row.display_name, "kind": row.kind,
                "sourceGeneration": row.source_generation,
                "files": [{"kind": kind, "name": FILE_NAMES[kind],
                           "editable": True}
                          for kind in row.file_kinds],
            })
            with self._lock:
                owner_sha = hashlib.sha256(subject.encode()).hexdigest()
                self._profiles[(owner_sha, core_generation,
                    self._opaque_id(subject, core_generation, row.profile_key))] = row
        if sum(row["kind"] == "jarvis" for row in projected) != 1:
            raise JarvisChatDenied("current Jarvis profile inventory is unavailable")
        return {"coreGeneration": core_generation, "profiles": projected}

    def read_file(self, *, subject: str, core_generation: str,
                  profile_id: str, file_kind: str, access_jwt: str,
                  accepted_ingress: Any) -> dict[str, Any]:
        if not _profile_kind(file_kind):
            raise JarvisChatDenied("profile file is unavailable")
        profile = self._resolve(subject=subject, core_generation=core_generation,
                                profile_id=profile_id, access_jwt=access_jwt,
                                accepted_ingress=accepted_ingress)
        if file_kind not in profile.file_kinds:
            raise JarvisChatDenied("profile file is unavailable")
        value = _file(self._provider.read_file(subject=subject,
            core_generation=core_generation, profile_key=profile.profile_key,
            file_kind=file_kind, access_jwt=access_jwt,
            accepted_ingress=accepted_ingress), profile_key=profile.profile_key, file_kind=file_kind)
        editable = True
        return {"profileId": profile_id, "fileKind": file_kind, "fileName": value.file_name,
                "content": value.content, "sha256": value.sha256,
                "protectedSuffix": value.protected_suffix, "managedPrimary": value.managed_primary,
                "sourceGeneration": value.source_generation, "effective": value.effective, "editable": editable}

    def preview(self, *, subject: str, core_generation: str, profile_id: str,
                file_kind: str, base_sha256: str, content: str, access_jwt: str,
                accepted_ingress: Any) -> dict[str, Any]:
        if (not _profile_kind(file_kind) or not _HASH.fullmatch(base_sha256)
                or not _valid_text(content)):
            raise JarvisChatDenied("profile change preview is invalid")
        profile = self._resolve(subject=subject, core_generation=core_generation,
                                profile_id=profile_id, access_jwt=access_jwt,
                                accepted_ingress=accepted_ingress)
        if file_kind not in profile.file_kinds:
            raise JarvisChatDenied("profile file is unavailable")
        current = _file(self._provider.read_file(subject=subject,
            core_generation=core_generation, profile_key=profile.profile_key,
            file_kind=file_kind, access_jwt=access_jwt,
            accepted_ingress=accepted_ingress), profile_key=profile.profile_key, file_kind=file_kind)
        if not hmac.compare_digest(current.sha256, base_sha256):
            raise JarvisChatDenied("profile file changed; reload before reviewing")
        old_lines = current.content.splitlines(keepends=True)
        new_lines = content.splitlines(keepends=True)
        diff = "".join(difflib.unified_diff(old_lines, new_lines,
            fromfile=f"current/{FILE_NAMES[file_kind]}",
            tofile=f"proposed/{FILE_NAMES[file_kind]}", n=3))
        if len(diff.encode("utf-8")) > MAX_PROFILE_DIFF_BYTES:
            raise JarvisChatDenied("profile change preview exceeds its bound")
        content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        token = secrets.token_urlsafe(32)
        grant = _PreviewGrant(hashlib.sha256(subject.encode()).hexdigest(), core_generation,
            profile.profile_key, file_kind, current.sha256, content_sha256,
            time.monotonic() + PREVIEW_TTL_SECONDS)
        with self._lock:
            now = time.monotonic()
            self._previews = {key: value for key, value in self._previews.items()
                              if value.expires_monotonic > now}
            if len(self._previews) >= MAX_PREVIEWS:
                raise JarvisChatDenied("profile review capacity is full")
            self._previews[token] = grant
        return {"previewToken": token, "baseSha256": current.sha256,
                "contentSha256": content_sha256, "sourceGeneration": current.source_generation,
                "diff": diff, "expiresInSeconds": int(PREVIEW_TTL_SECONDS)}

    def save(self, *, subject: str, core_generation: str, profile_id: str,
             file_kind: str, base_sha256: str, content: str,
             preview_token: str, idempotency_key: str, access_jwt: str,
             accepted_ingress: Any) -> dict[str, Any]:
        if (not _profile_kind(file_kind) or not _HASH.fullmatch(base_sha256)
                or not _valid_text(content) or not _PREVIEW.fullmatch(preview_token)
                or not _IDEMPOTENCY.fullmatch(idempotency_key)):
            raise JarvisChatDenied("profile save request is invalid")
        profile = self._resolve(subject=subject, core_generation=core_generation,
                                profile_id=profile_id, access_jwt=access_jwt,
                                accepted_ingress=accepted_ingress)
        if file_kind not in profile.file_kinds:
            raise JarvisChatDenied("profile file is unavailable")
        content_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        subject_sha = hashlib.sha256(subject.encode()).hexdigest()
        with self._lock:
            grant = self._previews.pop(preview_token, None)
        if (grant is None or grant.expires_monotonic <= time.monotonic()
                or grant.subject_sha256 != subject_sha
                or grant.core_generation != core_generation
                or grant.profile_key != profile.profile_key or grant.file_kind != file_kind
                or not hmac.compare_digest(grant.base_sha256, base_sha256)
                or not hmac.compare_digest(grant.content_sha256, content_sha256)):
            raise JarvisChatDenied("profile review expired or changed; review the diff again")
        result = self._provider.write_generation(subject=subject,
            core_generation=core_generation, profile_key=profile.profile_key,
            file_kind=file_kind, expected_sha256=base_sha256, content=content,
            idempotency_key=idempotency_key, access_jwt=access_jwt,
            accepted_ingress=accepted_ingress)
        if type(result) is not ProfileAdminWriteResult:
            raise JarvisChatDenied("profile save result is unavailable")
        if result.state != "active":
            return {"state": result.state, "recoveryId": result.recovery_id,
                    "sourceGeneration": result.source_generation}
        if (result.sha256 != content_sha256 or not _valid_generation(result.source_generation)
                or type(result.effective_readback) is not bool or result.effective_readback is not True
                or not isinstance(result.recovery_id, str)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,96}", result.recovery_id)):
            raise JarvisChatDenied("effective profile readback is unavailable")
        if result.sha256 != content_sha256:
            raise JarvisChatDenied("effective profile readback changed")
        return {"state": "active", "sha256": result.sha256,
                "sourceGeneration": result.source_generation,
                "recoveryId": result.recovery_id,
                "effectiveReadback": True,
                "authorityState": "prior source claims invalidated"}


async def _read_json(request: Any, expected: set[str]) -> dict[str, Any]:
    from aiohttp import web
    if (request.content_type != "application/json" or request.content_length is None
            or request.content_length < 2 or request.content_length > MAX_PROFILE_REQUEST_BYTES
            or request.headers.get("Transfer-Encoding") is not None):
        raise web.HTTPBadRequest(text="invalid profile request", headers=_secure_headers())
    try:
        raw = await asyncio.wait_for(request.read(), timeout=1.5)
        if len(raw) > MAX_PROFILE_REQUEST_BYTES:
            raise ValueError
        body = json.loads(raw, object_pairs_hook=_unique_pairs)
    except Exception:
        raise web.HTTPBadRequest(text="invalid profile request", headers=_secure_headers()) from None
    if type(body) is not dict or set(body) != expected:
        raise web.HTTPBadRequest(text="invalid profile request", headers=_secure_headers())
    return body


def _same_origin_owner_post(request: Any) -> None:
    from aiohttp import web
    launch = request.app.get("core_gateway_launch")
    hostname = getattr(getattr(launch, "config", None), "hostname", None)
    host_rows = request.headers.getall("Host", [])
    expected_origin = f"https://{hostname}" if isinstance(hostname, str) else None
    if (expected_origin is None or len(host_rows) != 1
            or host_rows[0].casefold() != hostname.casefold()
            or request.headers.get("Origin") != expected_origin
            or request.headers.get("Sec-Fetch-Site") != "same-origin"):
        raise web.HTTPForbidden(text="same-origin owner action required", headers=_secure_headers())


async def _current_owner(request: Any, service: JarvisChatService):
    """Recheck authenticated owner, admitted ingress, and live root Core witness."""
    from aiohttp import web
    from .core_gateway import CoreAcceptedIngressObservation
    from .core_gateway_inspector import verify_current_core_overview

    principal = service._current(request)
    accepted = request.get("core_ingress")
    launch = request.app.get("core_gateway_launch")
    if (type(accepted) is not CoreAcceptedIngressObservation or launch is None
            or accepted.core_generation != principal.core_generation):
        raise web.HTTPServiceUnavailable(text="current Core is unavailable", headers=_secure_headers())
    try:
        observation = await asyncio.wait_for(asyncio.to_thread(
            verify_current_core_overview, launch.config, peer_pid=accepted.peer_pid,
            peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
            accepted_ingress=accepted), timeout=5.0)
        if observation.core_generation != principal.core_generation:
            raise ValueError
    except Exception:
        raise web.HTTPServiceUnavailable(text="current Core is unavailable", headers=_secure_headers()) from None

    def verify_current() -> None:
        current = service._current(request)
        if (current.subject != principal.subject
                or current.core_generation != principal.core_generation
                or observation.verify_current(launch.config, peer_pid=accepted.peer_pid,
                    peer_uid=accepted.peer_uid, peer_gid=accepted.peer_gid,
                    accepted_ingress=accepted) is not True):
            raise JarvisChatDenied("current owner or Core generation changed")

    assertions = request.headers.getall("Cf-Access-Jwt-Assertion", [])
    if (len(assertions) != 1 or not isinstance(assertions[0], str)
            or hashlib.sha256(assertions[0].encode("ascii", "ignore")).hexdigest()
                != accepted.principal.token_fingerprint):
        raise web.HTTPForbidden(text="current owner authorization is unavailable", headers=_secure_headers())
    return principal, accepted, launch, verify_current, assertions[0]


def install_jarvis_profiles_admin_routes(app: Any, service: JarvisChatService,
                                         admin: JarvisProfileAdmin | None = None) -> None:
    """Install finite owner routes; central gateway route ownership remains separate."""
    from aiohttp import web

    if not isinstance(service, JarvisChatService):
        raise TypeError("verified Jarvis chat service required")
    if admin is None:
        admin = app.get("jarvis_profile_admin")
    if type(admin) is not JarvisProfileAdmin:
        raise TypeError("trusted current-Core profile admin adapter required")

    def profile_id(request: Any) -> str:
        value = request.match_info.get("profile_id", "")
        if not _OPAQUE.fullmatch(value):
            raise JarvisChatDenied("profile is unavailable")
        return value

    async def list_profiles(request: Any) -> Any:
        try:
            principal, accepted, _launch, verify_current, access_jwt = await _current_owner(request, service)
            payload = await asyncio.wait_for(asyncio.to_thread(admin.list_profiles,
                subject=principal.subject, core_generation=principal.core_generation,
                access_jwt=access_jwt, accepted_ingress=accepted), timeout=3.0)
            verify_current()
            return web.json_response(payload, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPServiceUnavailable(text="Profiles are unavailable", headers=_secure_headers()) from None

    async def read_file(request: Any) -> Any:
        try:
            principal, accepted, _launch, verify_current, access_jwt = await _current_owner(request, service)
            payload = await asyncio.wait_for(asyncio.to_thread(admin.read_file,
                subject=principal.subject, core_generation=principal.core_generation,
                profile_id=profile_id(request), file_kind=request.match_info.get("file_kind", ""),
                access_jwt=access_jwt, accepted_ingress=accepted), timeout=3.0)
            verify_current()
            return web.json_response(payload, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPForbidden(text="Profile file is unavailable", headers=_secure_headers()) from None

    async def list_files(request: Any) -> Any:
        try:
            principal, accepted, _launch, verify_current, access_jwt = await _current_owner(request, service)
            snapshot = await asyncio.wait_for(asyncio.to_thread(admin.list_profiles,
                subject=principal.subject, core_generation=principal.core_generation,
                access_jwt=access_jwt, accepted_ingress=accepted), timeout=3.0)
            selected = next((row for row in snapshot["profiles"] if row["id"] == profile_id(request)), None)
            if selected is None:
                raise JarvisChatDenied("profile is unavailable")
            verify_current()
            return web.json_response({"coreGeneration": principal.core_generation,
                "profile": {"id": selected["id"], "name": selected["name"], "kind": selected["kind"],
                            "sourceGeneration": selected["sourceGeneration"]},
                "files": selected["files"]}, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPForbidden(text="Profile files are unavailable", headers=_secure_headers()) from None

    async def preview(request: Any) -> Any:
        try:
            _same_origin_owner_post(request)
            principal, accepted, _launch, verify_current, access_jwt = await _current_owner(request, service)
            body = await _read_json(request, {"file_kind", "base_sha256", "content"})
            payload = await asyncio.wait_for(asyncio.to_thread(admin.preview,
                subject=principal.subject, core_generation=principal.core_generation,
                profile_id=profile_id(request), file_kind=body["file_kind"],
                base_sha256=body["base_sha256"], content=body["content"],
                access_jwt=access_jwt, accepted_ingress=accepted), timeout=4.0)
            verify_current()
            return web.json_response(payload, headers=_secure_headers())
        except web.HTTPException:
            raise
        except Exception:
            raise web.HTTPConflict(text="Profile changed or preview is unavailable; reload and review again",
                                   headers=_secure_headers()) from None

    async def save(request: Any) -> Any:
        try:
            _same_origin_owner_post(request)
            principal, accepted, _launch, verify_current, access_jwt = await _current_owner(request, service)
            body = await _read_json(request, {"file_kind", "base_sha256", "content",
                                              "preview_token", "idempotency_key"})
            verify_current()
            result = await asyncio.wait_for(asyncio.to_thread(admin.save,
                subject=principal.subject, core_generation=principal.core_generation,
                profile_id=profile_id(request), file_kind=body["file_kind"],
                base_sha256=body["base_sha256"], content=body["content"],
                preview_token=body["preview_token"], idempotency_key=body["idempotency_key"],
                access_jwt=access_jwt, accepted_ingress=accepted), timeout=8.0)
            verify_current()
            return web.json_response(result, headers=_secure_headers())
        except web.HTTPException:
            raise
        except JarvisChatDenied:
            raise web.HTTPConflict(text="Profile save was not confirmed; inspect current status before retrying",
                                   headers=_secure_headers()) from None
        except Exception:
            raise web.HTTPServiceUnavailable(text="Profile save status is unknown; inspect before retrying",
                                             headers=_secure_headers()) from None

    app.router.add_get("/chat/api/profiles", list_profiles, allow_head=False)
    app.router.add_get("/chat/api/profiles/{profile_id}/files", list_files, allow_head=False)
    app.router.add_get("/chat/api/profiles/{profile_id}/files/{file_kind}", read_file, allow_head=False)
    app.router.add_post("/chat/api/profiles/{profile_id}/preview", preview)
    app.router.add_post("/chat/api/profiles/{profile_id}/save", save)


_VIEW = '''<section class="profile-admin" aria-labelledby="profile-admin-title">
  <header><p class="profile-admin-kicker">OWNER ADMINISTRATION · SOURCE FILES</p>
    <h1 id="profile-admin-title">Profiles</h1>
    <p>Review and edit existing Jarvis and internal Expert profile files. Experts remain internal workers; every conversation stays with Jarvis.</p></header>
  <p data-profile-status role="status" aria-live="polite">Checking the current Core profile source…</p>
  <div class="profile-admin-layout">
    <aside aria-label="Profiles and files"><label for="profile-admin-select">Profile</label>
      <select data-profile-select id="profile-admin-select"><option value="">Loading profiles…</option></select>
      <label for="profile-file-select">Existing file</label>
      <select data-file-select id="profile-file-select" disabled><option value="">Choose a profile first</option></select>
      <p class="profile-admin-generation">Source generation <code data-profile-generation>Unknown</code></p>
      <p class="profile-admin-note">Only files reported by the current native profile manifest appear here. A profile edit cannot widen tools or permissions.</p>
    </aside>
    <main><div class="profile-editor-toolbar"><div><h2 data-editor-title>Select a profile file</h2>
      <p data-editor-state>Current effective text will appear here.</p></div>
      <button type="button" data-profile-review disabled>Review changes</button></div>
      <label class="profile-editor-label" for="profile-source-editor">Owner-editable profile text</label>
      <textarea data-profile-editor id="profile-source-editor" spellcheck="false" disabled></textarea>
      <section data-protected-section hidden aria-label="Protected managed Jarvis overlay">
        <h3>Protected managed Jarvis overlay</h3>
        <p class="profile-admin-note">This managed section is verified against the pinned Jarvis source and is not editable here.</p>
        <pre data-protected-content></pre>
      </section>
      <section class="profile-diff" aria-labelledby="profile-diff-title"><div><h3 id="profile-diff-title">Review diff</h3>
        <button type="button" data-profile-save disabled>Save reviewed generation</button></div>
        <pre data-profile-diff aria-live="polite">Choose a file to inspect its current contents.</pre></section>
    </main>
  </div>
</section>'''

_CSS = '''.profile-admin{max-width:1180px;margin:0 auto;color:var(--text,#edf5f6)}.profile-admin header{max-width:760px;margin-bottom:20px}.profile-admin h1{margin:0;font-size:clamp(25px,4vw,38px);letter-spacing:-.03em}.profile-admin header>p:last-child,.profile-admin-note,.profile-admin-generation{color:#9ab0b4;line-height:1.55}.profile-admin-kicker{margin:0 0 7px;color:#62dbe1;font-size:10px;letter-spacing:.13em}.profile-admin-layout{display:grid;grid-template-columns:minmax(210px,270px) minmax(0,1fr);gap:18px}.profile-admin-layout aside,.profile-admin-layout main{min-width:0;border:1px solid var(--line);background:rgba(10,27,33,.74);padding:16px;border-radius:10px}.profile-admin label{display:block;color:#a6bdc0;font-size:12px;margin:0 0 7px}.profile-admin select,.profile-admin textarea{width:100%;border:1px solid #315058;border-radius:6px;background:#08171c;color:#e4f3f3;font:inherit}.profile-admin select{min-height:42px;padding:8px;margin-bottom:18px}.profile-admin code{overflow-wrap:anywhere;color:#bdebee}.profile-admin-note{font-size:12px}.profile-editor-toolbar,.profile-diff>div{display:flex;align-items:center;justify-content:space-between;gap:12px}.profile-editor-toolbar h2,.profile-diff h3{margin:0;font-size:15px}.profile-editor-toolbar p{margin:5px 0 12px;color:#93aaae;font-size:12px}.profile-admin button{min-height:42px;padding:8px 13px;border:1px solid #3c858b;border-radius:6px;background:#12464c;color:#e3ffff;cursor:pointer}.profile-admin button:disabled{opacity:.5;cursor:not-allowed}.profile-editor-label{margin-top:6px!important}.profile-admin textarea{display:block;min-height:360px;padding:13px;resize:vertical;line-height:1.55;font:13px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}.profile-diff{margin-top:16px;border-top:1px solid var(--line);padding-top:14px}.profile-diff pre{white-space:pre-wrap;overflow-wrap:anywhere;max-height:360px;overflow:auto;padding:12px;border:1px solid var(--line);border-radius:6px;background:#061115;color:#cce1e3;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}.profile-admin [role=status]{min-height:1.5em;color:#9eb7ba;font-size:12px}@media(max-width:760px){.profile-admin-layout{grid-template-columns:1fr}.profile-admin-layout aside{display:grid;grid-template-columns:1fr 1fr;gap:0 12px}.profile-admin-layout aside>label{grid-column:span 2}.profile-admin-generation,.profile-admin-note{grid-column:span 2}.profile-admin-layout main{padding:12px}.profile-admin textarea{min-height:300px}.profile-editor-toolbar{align-items:flex-start;flex-direction:column}}@media(prefers-reduced-motion:reduce){.profile-admin *{scroll-behavior:auto!important;transition:none!important}}'''

_MOUNT_JS = r'''function mount(root, api) {
  let active = true, profiles = [], selected = null, file = null, baseSha = null, previewToken = null;
  const q = (s) => root.querySelector(s), status = q("[data-profile-status]"), profileSelect = q("[data-profile-select]"), fileSelect = q("[data-file-select]"), editor = q("[data-profile-editor]"), review = q("[data-profile-review]"), save = q("[data-profile-save]"), diff = q("[data-profile-diff]"), protectedSection=q("[data-protected-section]"), protectedContent=q("[data-protected-content]");
  const text = (s, v) => { const n=q(s); if(n)n.textContent=v; };
  const token = () => { const b=new Uint8Array(24);crypto.getRandomValues(b);return Array.from(b,x=>x.toString(16).padStart(2,"0")).join(""); };
  const safeId = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  const safeHash = (v) => typeof v === "string" && /^[0-9a-f]{64}$/.test(v);
  const changed = () => { previewToken=null;save.disabled=true;review.disabled=!(file&&file.editable===true&&baseSha&&editor.value!==file.content); };
  async function loadFile() {
    file=null;baseSha=null;previewToken=null;editor.value="";editor.disabled=true;review.disabled=true;save.disabled=true;protectedSection.hidden=true;protectedContent.textContent="";
    const row=profiles.find((item)=>item.id===profileSelect.value), kind=fileSelect.value;
    selected=row||null;if(!row||!kind)return;
    status.textContent="Reading the selected native profile file…";
    try { const value=await api.get(`/chat/api/profiles/${encodeURIComponent(row.id)}/files/${encodeURIComponent(kind)}`);
      if(!active||profileSelect.value!==row.id||fileSelect.value!==kind)return;
      if(!value||value.profileId!==row.id||value.fileKind!==kind||typeof value.content!=="string"||typeof value.protectedSuffix!=="string"||typeof value.managedPrimary!=="boolean"||value.editable!==true||!safeHash(value.sha256)||typeof value.sourceGeneration!=="string")throw Error();
      const documentHash=await crypto.subtle.digest("SHA-256",new TextEncoder().encode(value.content+value.protectedSuffix));
      const documentSha=Array.from(new Uint8Array(documentHash),b=>b.toString(16).padStart(2,"0")).join("");
      if(documentSha!==value.sha256)throw Error();
      file=value;baseSha=value.sha256;editor.value=value.content;editor.disabled=value.editable!==true;protectedSection.hidden=!value.managedPrimary;protectedContent.textContent=value.protectedSuffix;
      text("[data-editor-title]",value.fileName);text("[data-editor-state]",value.managedPrimary?"Jarvis owner prefix · managed overlay stays protected":(value.effective?"Current effective source · read only until you review a change":"Existing source is not confirmed effective"));

      text("[data-profile-generation]",value.sourceGeneration);diff.textContent="No changes reviewed.";status.textContent="Actual file contents loaded from the current profile source.";
    } catch (_) { if(active){status.textContent="Profile source unavailable; no file was changed.";diff.textContent="Current content could not be verified.";} }
  }
  async function loadProfiles() {
    try { const data=await api.get("/chat/api/profiles");
      if(!active||!data||!Array.isArray(data.profiles)||data.profiles.length>64||!data.profiles.every(x=>x&&safeId(x.id)&&typeof x.name==="string"&&["jarvis","expert"].includes(x.kind)&&Array.isArray(x.files)))throw Error();
      profiles=data.profiles;profileSelect.replaceChildren(new Option("Choose a profile", ""));
      for(const row of profiles){const option=new Option(`${row.name} · ${row.kind==="jarvis"?"Jarvis master":"internal Expert"}`,row.id);profileSelect.add(option);}
      profileSelect.disabled=!profiles.length;status.textContent=profiles.length?"Select Jarvis or an internal Expert profile to inspect its existing files.":"No editable native profile files are available.";
    } catch(_){if(active)status.textContent="Current native profiles are unavailable.";}
  }
  profileSelect.addEventListener("change",()=>{
    selected=profiles.find(x=>x.id===profileSelect.value)||null;fileSelect.replaceChildren(new Option(selected?"Choose a file":"Choose a profile first",""));
    if(selected)for(const item of selected.files){if(item&&["soul","description","instructions"].includes(item.kind)&&typeof item.name==="string")fileSelect.add(new Option(item.name,item.kind));}
    fileSelect.disabled=!selected||fileSelect.options.length<2;loadFile();
  });
  fileSelect.addEventListener("change",loadFile);editor.addEventListener("input",changed);
  review.addEventListener("click",async()=>{
    if(!file||file.editable!==true||!selected||!baseSha||editor.value===file.content)return;
    review.disabled=true;save.disabled=true;status.textContent="Building a current source diff…";
    try { const value=await api.post(`/chat/api/profiles/${encodeURIComponent(selected.id)}/preview`,{file_kind:file.fileKind,base_sha256:baseSha,content:editor.value});
      if(!active||!value||typeof value.diff!=="string"||typeof value.previewToken!=="string"||!safeHash(value.contentSha256)||value.baseSha256!==baseSha)throw Error();
      previewToken=value.previewToken;diff.textContent=value.diff||"No textual difference.";save.disabled=false;status.textContent="Review the full diff. Saving creates a recoverable profile generation.";
    } catch(_){previewToken=null;diff.textContent="Source changed or preview expired. Reload the file and review again.";status.textContent="A current diff could not be confirmed.";}
    changed();if(previewToken)save.disabled=false;
  });
  save.addEventListener("click",async()=>{
    if(!file||file.editable!==true||!selected||!baseSha||!previewToken||save.disabled)return;
    save.disabled=true;review.disabled=true;status.textContent="Saving the reviewed profile generation and verifying effective readback…";
    try { const result=await api.post(`/chat/api/profiles/${encodeURIComponent(selected.id)}/save`,{file_kind:file.fileKind,base_sha256:baseSha,content:editor.value,preview_token:previewToken,idempotency_key:token()});
      previewToken=null;
      if(!active)return;
      if(result&&result.state==="active"&&result.effectiveReadback===true&&safeHash(result.sha256)){
        status.textContent="Profile generation saved and effective source read back. Previous source authority claims were invalidated.";
        await loadFile();
      } else { status.textContent=result&&result.state==="conflict"?"Profile source changed. Reload before reviewing again.":"Save is pending or unknown. Inspect current source status before trying again."; }
    } catch(_){previewToken=null;status.textContent="Save was not confirmed. Inspect current source status before retrying.";}
  });
  loadProfiles();
  return () => { active=false;profileSelect.replaceChildren();fileSelect.replaceChildren();editor.value="";diff.textContent=""; };
}'''

PROFILE_ADMIN_FEATURE = JarvisFeatureAssets(
    feature_id="profiles-admin", nav_label="Profiles", title="Owner Profile Administration",
    view_html=_VIEW, css=_CSS, api_routes=_PROFILE_ROUTES,
    mount_js=_MOUNT_JS, unmount_js="function unmount(root, cleanup) { if (typeof cleanup === 'function') cleanup(); }",
)


def reviewed_profiles_admin_feature() -> JarvisFeatureAssets:
    """Return the immutable, reviewed feature fragment for central UI composition."""
    return PROFILE_ADMIN_FEATURE
