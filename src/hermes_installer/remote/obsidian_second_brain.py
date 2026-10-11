"""Persistent, owner-scoped Obsidian-compatible knowledge vault.

This is a storage leaf, not an authorization or route layer. ROOT composes one
instance from a fixed owner-managed data-root registration and binds the finite
methods below to the already admitted native caller. In particular,
``promote_reviewed_draft`` is a final native effect and MUST only be reachable
through the existing Jarvis final-effect middleware; an argument or JSON flag
cannot grant it. Request data never selects a filesystem root.

The public store is plain UTF-8 Markdown and Obsidian ``[[wikilinks]]``. Its
index is rebuilt from bounded current file reads on each operation, so it is
never authority or the sole copy of a note.
"""
from __future__ import annotations

import base64
import ctypes
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

VAULT_DIRECTORY = "obsidian-vault"
NOTE_DIRECTORIES = ("Notes", "Projects", "Sources", "Daily")
MAX_NOTE_BYTES = 1_048_576
MAX_QUERY_CHARS = 256
MAX_PAGE_SIZE = 50
MAX_SCAN_NOTES = 2_000
MAX_SCAN_BYTES = 32 * 1024 * 1024
MAX_SCAN_ENTRIES = 20_000
MAX_GRAPH_NODES = 200
MAX_GRAPH_EDGES = 400
MAX_DRAFT_BYTES = 256 * 1024
MAX_PRIVATE_FILE_BYTES = 2 * 1024 * 1024
MAX_OWNER_DRAFTS = 200
MAX_BACKUP_BYTES = 64 * 1024 * 1024

_ID = re.compile(r"[A-Za-z0-9_-]{1,96}\Z", re.ASCII)
_HASH = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_WIKILINK = re.compile(r"!?\[\[([^\]]{1,512})\]\]")
_MARKDOWN_LINK = re.compile(r"(?<!!)\[([^\]]{0,256})\]\(([^)\s]{1,1024})(?:\s+[^)]*)?\)")
_TITLE = re.compile(r"^\s{0,3}#{1,6}\s+(.+?)\s*#*\s*$")
_TAG = re.compile(r"(?<![\w/])#([A-Za-z0-9_/-]{1,80})")
_HIDDEN_EXCLUDED = frozenset({".obsidian", ".hermes-private", ".trash"})
_EXCHANGE = 2  # Linux RENAME_EXCHANGE; required for conditional replacements.


class ObsidianVaultError(RuntimeError):
    """A bounded vault operation could not be completed safely."""


class ObsidianVaultConflict(ObsidianVaultError):
    """A note changed since its reviewed base; no final write was made."""


@dataclass(frozen=True, slots=True)
class ObsidianVaultConfig:
    """Trusted composition input supplied by ROOT, never from browser/model data."""

    managed_data_root: Path
    owner_scope_sha256: str
    owner_uid: int

    def __post_init__(self) -> None:
        if (not isinstance(self.managed_data_root, Path) or not self.managed_data_root.is_absolute()
                or not _HASH.fullmatch(self.owner_scope_sha256 or "")
                or type(self.owner_uid) is not int or self.owner_uid != 1000):
            raise ValueError("fixed selected-owner Obsidian root configuration is malformed")

    @property
    def vault_root(self) -> Path:
        return self.managed_data_root / VAULT_DIRECTORY


@dataclass(frozen=True, slots=True)
class NoteSummary:
    note_id: str
    title: str
    updated_at: float
    content_sha256: str
    excerpt: str
    tags: tuple[str, ...]
    aliases: tuple[str, ...]

    def to_projection(self) -> dict[str, Any]:
        return {"noteId": self.note_id, "title": self.title, "updatedAt": self.updated_at,
                "contentSha256": self.content_sha256, "excerpt": self.excerpt,
                "tags": list(self.tags), "aliases": list(self.aliases)}


@dataclass(frozen=True, slots=True)
class NotePage:
    notes: tuple[NoteSummary, ...]
    next_cursor: str | None
    partial: bool
    scanned: int

    def to_projection(self) -> dict[str, Any]:
        return {"notes": [note.to_projection() for note in self.notes],
                "nextCursor": self.next_cursor, "partial": self.partial,
                "scanned": self.scanned}


@dataclass(frozen=True, slots=True)
class NoteRead:
    note_id: str
    title: str
    content_sha256: str
    markdown: str
    updated_at: float

    def to_projection(self) -> dict[str, Any]:
        return {"noteId": self.note_id, "title": self.title,
                "contentSha256": self.content_sha256, "markdown": self.markdown,
                "updatedAt": self.updated_at}


@dataclass(frozen=True, slots=True)
class VaultLink:
    from_note_id: str
    to_note_id: str
    kind: str
    label: str

    def to_projection(self) -> dict[str, str]:
        return {"fromNoteId": self.from_note_id, "toNoteId": self.to_note_id,
                "kind": self.kind, "label": self.label}


@dataclass(frozen=True, slots=True)
class UnresolvedVaultLink:
    from_note_id: str
    label: str

    def to_projection(self) -> dict[str, str]:
        return {"fromNoteId": self.from_note_id, "label": self.label}


@dataclass(frozen=True, slots=True)
class NoteLinks:
    note_id: str
    links: tuple[VaultLink, ...]
    backlinks: tuple[VaultLink, ...]
    unresolved: tuple[UnresolvedVaultLink, ...]

    def to_projection(self) -> dict[str, Any]:
        return {"noteId": self.note_id, "links": [link.to_projection() for link in self.links],
                "backlinks": [link.to_projection() for link in self.backlinks],
                "unresolved": [link.to_projection() for link in self.unresolved]}


@dataclass(frozen=True, slots=True)
class GraphSnapshot:
    nodes: tuple[dict[str, Any], ...]
    edges: tuple[VaultLink, ...]
    unresolved: tuple[UnresolvedVaultLink, ...]
    partial: bool
    scanned: int

    def to_projection(self) -> dict[str, Any]:
        return {"nodes": [dict(node) for node in self.nodes],
                "edges": [edge.to_projection() for edge in self.edges],
                "unresolved": [link.to_projection() for link in self.unresolved],
                "partial": self.partial, "scanned": self.scanned}


@dataclass(frozen=True, slots=True)
class VaultDraft:
    draft_id: str
    execution_id: str
    source_instance_id: str
    title: str
    content_sha256: str
    base_note_id: str | None
    base_sha256: str | None
    citations: tuple[str, ...]
    created_at: float

    def to_projection(self) -> dict[str, Any]:
        # Draft bodies remain private to the execution/review path.
        return {"draftId": self.draft_id, "executionId": self.execution_id,
                "sourceInstanceId": self.source_instance_id, "title": self.title,
                "contentSha256": self.content_sha256, "baseNoteId": self.base_note_id,
                "baseSha256": self.base_sha256, "citations": list(self.citations),
                "createdAt": self.created_at}


@dataclass(frozen=True, slots=True)
class DraftPage:
    drafts: tuple[VaultDraft, ...]
    next_cursor: str | None
    partial: bool

    def to_projection(self) -> dict[str, Any]:
        return {"drafts": [draft.to_projection() for draft in self.drafts],
                "nextCursor": self.next_cursor, "partial": self.partial}


@dataclass(frozen=True, slots=True)
class OwnerDraftReview:
    draft: VaultDraft
    markdown: str

    def to_projection(self) -> dict[str, Any]:
        return {**self.draft.to_projection(), "markdown": self.markdown}


@dataclass(frozen=True, slots=True)
class VaultSnapshot:
    archive: bytes
    sha256: str
    files: int
    size_bytes: int


@dataclass(frozen=True, slots=True)
class _Note:
    note_id: str
    relative_path: str
    markdown: str
    title: str
    updated_at: float
    content_sha256: str
    tags: tuple[str, ...]
    aliases: tuple[str, ...]

    def summary(self) -> NoteSummary:
        return NoteSummary(self.note_id, self.title, self.updated_at, self.content_sha256,
                           _excerpt(self.markdown), self.tags, self.aliases)


def prepare_obsidian_vault(config: ObsidianVaultConfig) -> "ObsidianVaultStore":
    """Idempotently prepare one fixed vault below ROOT's selected owner data root.

    The managed data root must already exist and be owned by the installer service
    user. Existing note bytes, Obsidian settings, and unrelated files are preserved.
    """
    if type(config) is not ObsidianVaultConfig:
        raise TypeError("trusted fixed-owner Obsidian configuration is required")
    if os.geteuid() != 1000:
        raise ObsidianVaultError("vault preparation must run as the selected Hermes owner UID 1000")
    _validate_managed_root(config)
    vault = config.vault_root
    if vault.is_symlink():
        raise ObsidianVaultError("selected-owner vault path cannot be a symlink")
    try:
        vault.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _validate_directory(vault, config.owner_uid)
    _validate_private_directory(vault)
    store = ObsidianVaultStore(config)
    for relative in (*NOTE_DIRECTORIES, ".obsidian", ".hermes-private",
                     ".hermes-private/drafts", ".hermes-private/revisions",
                     ".hermes-private/journal"):
        store._ensure_directory(relative)
    return store


def prepare_selected_owner_data_root() -> Path:
    """Create only the fixed private data root during UID-1000 service startup."""
    if os.geteuid() != 1000:
        raise ObsidianVaultError("selected-owner data-root preparation requires UID 1000")
    home = Path("/home")
    admin_home = home / "admin"
    parent = admin_home / ".hermes"
    target = parent / "jarvis-second-brain"
    if home.is_symlink() or admin_home.is_symlink() or parent.is_symlink() or not parent.is_dir():
        raise ObsidianVaultError("selected-owner Hermes home is unavailable")
    _validate_directory(admin_home, 1000)
    _validate_directory(parent, 1000)
    try:
        target.mkdir(mode=0o700)
    except FileExistsError:
        pass
    _validate_directory(target, 1000)
    _validate_private_directory(target)
    return target


class ObsidianVaultStore:
    """Bounded store over a single fixed selected-owner vault."""

    def __init__(self, config: ObsidianVaultConfig):
        if type(config) is not ObsidianVaultConfig:
            raise TypeError("trusted fixed-owner Obsidian configuration is required")
        self._config = config
        self._root = config.vault_root
        _validate_managed_root(config)
        _validate_directory(self._root, config.owner_uid)
        _validate_private_directory(self._root)

    def list_notes(self, *, limit: int = 20, cursor: str | None = None,
                   note_scope: frozenset[str] | None = None) -> NotePage:
        limit = _limit(limit)
        offset = _cursor(cursor)
        notes, partial, scanned = self._scan()
        notes, scoped = _scope_notes(notes, note_scope)
        notes.sort(key=lambda note: (-note.updated_at, note.note_id))
        selected = notes[offset:offset + limit]
        next_offset = offset + len(selected)
        next_cursor = f"v1:{next_offset}" if next_offset < len(notes) else None
        return NotePage(tuple(note.summary() for note in selected), next_cursor,
                        partial or scoped, scanned)

    def read_note(self, note_id: str, *, note_scope: frozenset[str] | None = None) -> NoteRead:
        note = self._lookup(note_id)
        if note_scope is not None and (type(note_scope) is not frozenset or note_id not in note_scope):
            raise ObsidianVaultError("note is outside the admitted selected-note scope")
        return NoteRead(note.note_id, note.title, note.content_sha256,
                        note.markdown, note.updated_at)

    def search_notes(self, query: str, *, limit: int = 20,
                     cursor: str | None = None,
                     note_scope: frozenset[str] | None = None) -> NotePage:
        if (type(query) is not str or not query.strip() or len(query) > MAX_QUERY_CHARS
                or any(ord(char) < 0x20 and char not in "\t" for char in query)):
            raise ObsidianVaultError("search query is empty, malformed, or exceeds its fixed bound")
        needle = query.casefold().strip()
        limit, offset = _limit(limit), _cursor(cursor)
        notes, partial, scanned = self._scan()
        notes, scoped = _scope_notes(notes, note_scope)
        matches = [note for note in notes
                   if needle in "\n".join((note.title, note.markdown,
                                             " ".join(note.tags), " ".join(note.aliases))).casefold()]
        matches.sort(key=lambda note: (note.title.casefold(), note.note_id))
        selected = matches[offset:offset + limit]
        next_offset = offset + len(selected)
        next_cursor = f"v1:{next_offset}" if next_offset < len(matches) else None
        return NotePage(tuple(note.summary() for note in selected), next_cursor,
                        partial or scoped, scanned)

    def links_for(self, note_id: str, *, note_scope: frozenset[str] | None = None) -> NoteLinks:
        notes, _partial, _scanned = self._scan()
        notes, _scoped = _scope_notes(notes, note_scope)
        by_id = {note.note_id: note for note in notes}
        source = by_id.get(note_id) if type(note_id) is str and _ID.fullmatch(note_id) else None
        if source is None or source.note_id != note_id:
            raise ObsidianVaultError("note is not present in the selected-owner vault")
        resolved, unresolved = _build_links(notes)
        return NoteLinks(note_id,
                         tuple(edge for edge in resolved if edge.from_note_id == note_id),
                         tuple(edge for edge in resolved if edge.to_note_id == note_id),
                         tuple(edge for edge in unresolved if edge.from_note_id == note_id))

    def graph_snapshot(self, *, note_scope: frozenset[str] | None = None) -> GraphSnapshot:
        notes, partial, scanned = self._scan()
        notes, scoped = _scope_notes(notes, note_scope)
        nodes = tuple({"noteId": note.note_id, "title": note.title,
                       "tags": list(note.tags)} for note in notes[:MAX_GRAPH_NODES])
        selected_ids = {node["noteId"] for node in nodes}
        links, unresolved = _build_links(notes[:MAX_GRAPH_NODES])
        graph_partial = partial or scoped or len(notes) > MAX_GRAPH_NODES
        bounded: list[VaultLink] = []
        for link in links:
            if len(bounded) >= MAX_GRAPH_EDGES:
                graph_partial = True
                break
            if link.from_note_id in selected_ids and link.to_note_id in selected_ids:
                bounded.append(link)
        return GraphSnapshot(nodes, tuple(bounded), tuple(unresolved[:MAX_GRAPH_EDGES]),
                             graph_partial or len(unresolved) > MAX_GRAPH_EDGES, scanned)

    def create_private_draft(self, *, execution_id: str, source_instance_id: str,
                             title: str, markdown: str, base_note_id: str | None = None,
                             base_sha256: str | None = None,
                             citations: Iterable[str] = ()) -> VaultDraft:
        """Save one execution-private Expert/Jarvis draft; no final note is changed.

        ROOT must derive both execution/source IDs from its admitted native call,
        never from free-form browser data. This method intentionally does not
        expose draft bodies through owner list, search, links, or graph projections.
        """
        execution_id = _safe_identifier(execution_id, "execution")
        source_instance_id = _safe_identifier(source_instance_id, "source instance")
        clean_title = _title_text(title)
        encoded = _markdown_bytes(markdown, MAX_DRAFT_BYTES)
        if base_note_id is None:
            if base_sha256 is not None:
                raise ObsidianVaultError("new-note draft cannot carry a base digest")
        else:
            if not _ID.fullmatch(base_note_id) or not _HASH.fullmatch(base_sha256 or ""):
                raise ObsidianVaultError("draft update requires the exact note ID and base digest")
            current = self._lookup(base_note_id)
            if current.content_sha256 != base_sha256:
                raise ObsidianVaultConflict("note changed before the draft base was captured")
        citation_rows = _citations(citations)
        existing_drafts, drafts_partial = self._count_private_drafts()
        if drafts_partial or existing_drafts >= MAX_SCAN_NOTES:
            raise ObsidianVaultError("private draft store is at its fixed capacity or incomplete")
        draft_id = secrets.token_urlsafe(24)
        created = time.time()
        record = {
            "schema": 1, "ownerScopeSha256": self._config.owner_scope_sha256,
            "executionId": execution_id, "sourceInstanceId": source_instance_id,
            "title": clean_title, "markdown": encoded.decode("utf-8"),
            "contentSha256": _sha256(encoded), "baseNoteId": base_note_id,
            "baseSha256": base_sha256, "citations": list(citation_rows),
            "createdAt": created, "state": "private-draft",
        }
        raw = _canonical(record)
        if len(raw) > MAX_DRAFT_BYTES + 32 * 1024:
            raise ObsidianVaultError("draft metadata exceeds its fixed bound")
        self._write_private(f"drafts/{execution_id}/{draft_id}.json", raw, create_only=True)
        return VaultDraft(draft_id, execution_id, source_instance_id, clean_title,
                          record["contentSha256"], base_note_id, base_sha256,
                          citation_rows, created)

    def read_private_draft(self, *, execution_id: str, draft_id: str,
                           source_instance_id: str | None = None) -> dict[str, Any]:
        """Read a draft only for the exact execution folder selected by ROOT."""
        execution_id = _safe_identifier(execution_id, "execution")
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id or ""):
            raise ObsidianVaultError("private draft ID is malformed")
        record = self._read_private(f"drafts/{execution_id}/{draft_id}.json",
                                    MAX_DRAFT_BYTES + 32 * 1024)
        draft = _decode_draft(record, owner_scope=self._config.owner_scope_sha256,
                              execution_id=execution_id)
        if source_instance_id is not None and draft["sourceInstanceId"] != source_instance_id:
            raise ObsidianVaultError("private draft belongs to another execution source")
        return draft

    def list_owner_drafts(self, *, limit: int = 20,
                          cursor: str | None = None) -> DraftPage:
        """List pending drafts for the fixed owner; ROOT exposes this to owner UI only."""
        limit, offset = _limit(limit), _cursor(cursor)
        files, partial = self._owner_draft_files()
        rows: list[VaultDraft] = []
        for execution_id, draft_id, relative in files:
            try:
                record = self._read_private(relative.removeprefix(".hermes-private/"),
                                            MAX_DRAFT_BYTES + 32 * 1024)
                data = _decode_draft(record, owner_scope=self._config.owner_scope_sha256,
                                     execution_id=execution_id)
                if data["state"] != "private-draft":
                    continue
                rows.append(_draft_projection(draft_id, data))
            except ObsidianVaultError:
                partial = True
        rows.sort(key=lambda draft: (-draft.created_at, draft.draft_id))
        selected = tuple(rows[offset:offset + limit])
        end = offset + len(selected)
        cursor_out = f"v1:{end}" if end < len(rows) else None
        return DraftPage(selected, cursor_out, partial)

    def read_owner_draft(self, *, draft_id: str) -> OwnerDraftReview:
        """Read one pending draft for an owner-only review route."""
        files, _partial = self._owner_draft_files()
        matches = [(execution_id, relative) for execution_id, current_id, relative in files
                   if current_id == draft_id]
        if len(matches) != 1:
            raise ObsidianVaultError("pending owner draft is unavailable or ambiguous")
        execution_id, relative = matches[0]
        data = _decode_draft(
            self._read_private(relative.removeprefix(".hermes-private/"),
                               MAX_DRAFT_BYTES + 32 * 1024),
            owner_scope=self._config.owner_scope_sha256, execution_id=execution_id)
        if data["state"] != "private-draft":
            raise ObsidianVaultError("draft is no longer awaiting owner review")
        return OwnerDraftReview(_draft_projection(draft_id, data), data["markdown"])

    def promote_reviewed_draft(self, *, execution_id: str, draft_id: str,
                               expected_draft_sha256: str, destination: str,
                               expected_base_sha256: str | None,
                               observed_call: object, permit: object) -> NoteRead:
        """Promote exact bytes after ROOT's existing final-effect review middleware.

        The native registration must pass the exact root-observed call and
        one-use FinalEffectPermit consumed by
        ``install_jarvis_final_effect_middleware``. The caller wraps these two
        proof objects around the already reviewed arguments; request data cannot
        construct either. This method accepts no permission dictionaries,
        booleans or model-authored review claims.
        """
        from hermes_installer.native_invocations import (
            canonical_tool_arguments, current_native_tool_dispatch,
        )
        from hermes_installer.remote.core_native_observer import ObservedNativeToolCall
        from hermes_installer.remote.jarvis_final_effects import FinalEffectPermit, review_digest

        execution_id = _safe_identifier(execution_id, "execution")
        relative = _note_relative_path(destination)
        # ROOT derives the private execution path from the admitted owner/child
        # context. The permit binds the exact public draft/digest/destination/base
        # CAS, while caller scope and the owner turn bind this private execution.
        exact_arguments = {
            "draft_id": draft_id,
            "expected_draft_sha256": expected_draft_sha256,
            "destination": destination,
            "expected_base_sha256": expected_base_sha256,
        }
        canonical = canonical_tool_arguments(exact_arguments)
        arguments_sha256 = _sha256(canonical)
        if (type(observed_call) is not ObservedNativeToolCall
                or type(permit) is not FinalEffectPermit
                or observed_call.tool_name != "obsidian_promote_reviewed_draft"
                or observed_call.arguments_sha256 != arguments_sha256
                or permit.owner_subject_sha256 != self._config.owner_scope_sha256
                or permit.source_profile_id != "hermes"
                or not permit.matches_call(
                    observed_call, tool_name="obsidian_promote_reviewed_draft",
                    arguments_sha256=arguments_sha256,
                    review_sha256=review_digest("obsidian_promote_reviewed_draft", arguments_sha256))):
            raise ObsidianVaultError("promotion lacks the exact current root owner permit")
        dispatch = current_native_tool_dispatch()
        if (dispatch is None or dispatch.tool_call_id != observed_call.tool_call_id
                or dispatch.tool_name != observed_call.tool_name
                or dispatch.canonical_arguments != canonical):
            raise ObsidianVaultError("promotion is outside the exact admitted native tool dispatch")
        if not _HASH.fullmatch(expected_draft_sha256 or ""):
            raise ObsidianVaultError("promotion requires the exact reviewed draft digest")
        record = self.read_private_draft(execution_id=execution_id, draft_id=draft_id)
        if record["contentSha256"] != expected_draft_sha256:
            raise ObsidianVaultConflict("private draft changed after Jarvis review")
        current = self._read_optional_note(relative)
        if current is None:
            if expected_base_sha256 is not None or record["baseSha256"] is not None:
                raise ObsidianVaultConflict("draft base no longer matches the absent destination")
            self._atomic_note_write(relative, record["markdown"].encode("utf-8"), expected_sha256=None)
        else:
            if (not _HASH.fullmatch(expected_base_sha256 or "")
                    or record["baseSha256"] != expected_base_sha256
                    or current[1] != expected_base_sha256):
                raise ObsidianVaultConflict("Obsidian note changed after review; draft is preserved")
            self._atomic_note_write(relative, record["markdown"].encode("utf-8"),
                                    expected_sha256=expected_base_sha256)
        saved = self._read_optional_note(relative)
        if saved is None:
            raise ObsidianVaultError("promoted note is missing after atomic write")
        markdown, digest, updated = saved
        if digest != expected_draft_sha256:
            raise ObsidianVaultConflict("promoted note changed during post-write verification")
        self._write_private(f"drafts/{execution_id}/{draft_id}.json",
                            _canonical({**record, "state": "promoted",
                                        "promotedSha256": digest,
                                        "promotedAt": time.time(),
                                        "destinationId": _opaque_id(relative)}),
                            replace=True)
        return NoteRead(_opaque_id(relative), record["title"], digest, markdown, updated)

    def dashboard_projection(self) -> dict[str, Any]:
        notes, partial, scanned = self._scan()
        links, unresolved = _build_links(notes)
        draft_count, draft_partial = self._count_private_drafts()
        return {
            "state": "partial" if partial or draft_partial else "ready",
            "observedAt": time.time(), "noteCount": len(notes), "linkCount": len(links),
            "unresolvedLinkCount": len(unresolved), "draftCount": draft_count,
            "coverage": {"scanned": scanned, "limit": MAX_SCAN_NOTES,
                         "partial": partial or draft_partial},
        }

    def create_backup(self) -> VaultSnapshot:
        """Create a bounded ZIP snapshot including settings and private recovery state."""
        import io
        import zipfile

        entries, partial, _scanned = self._files_for_backup()
        if partial:
            raise ObsidianVaultError("vault backup is incomplete; no snapshot was returned")
        archive_io = io.BytesIO()
        with zipfile.ZipFile(archive_io, "w", compression=zipfile.ZIP_DEFLATED,
                             compresslevel=6) as archive:
            manifest = []
            total = 0
            for relative, content in entries:
                total += len(content)
                if total > MAX_BACKUP_BYTES:
                    raise ObsidianVaultError("vault backup exceeds its fixed size bound")
                archive.writestr(relative, content)
                manifest.append({"path": relative, "sha256": _sha256(content),
                                 "size": len(content)})
            archive.writestr(".hermes-manifest.json", _canonical({
                "schema": 1, "ownerScopeSha256": self._config.owner_scope_sha256,
                "files": manifest,
            }))
        data = archive_io.getvalue()
        if len(data) > MAX_BACKUP_BYTES:
            raise ObsidianVaultError("compressed vault backup exceeds its fixed size bound")
        return VaultSnapshot(data, _sha256(data), len(entries), total)

    def restore_backup(self, snapshot: VaultSnapshot) -> int:
        """Restore only into an empty prepared vault; existing owner data is retained."""
        import io
        import zipfile

        if (type(snapshot) is not VaultSnapshot or not isinstance(snapshot.archive, bytes)
                or len(snapshot.archive) > MAX_BACKUP_BYTES
                or _sha256(snapshot.archive) != snapshot.sha256):
            raise ObsidianVaultError("backup snapshot digest or type is invalid")
        try:
            with zipfile.ZipFile(io.BytesIO(snapshot.archive), "r") as archive:
                members = archive.infolist()
                if len(members) > MAX_SCAN_ENTRIES:
                    raise ObsidianVaultError("backup contains too many entries")
                if len({item.filename for item in members}) != len(members):
                    raise ObsidianVaultError("backup contains duplicate paths")
                if any(stat.S_IFMT(item.external_attr >> 16) == stat.S_IFLNK
                       for item in members):
                    raise ObsidianVaultError("backup may not contain symbolic links")
                manifest_info = archive.getinfo(".hermes-manifest.json")
                if manifest_info.file_size > 2 * 1024 * 1024:
                    raise ObsidianVaultError("backup manifest exceeds its fixed bound")
                raw_manifest = archive.read(".hermes-manifest.json")
                manifest = json.loads(raw_manifest.decode("utf-8", "strict"))
                if (type(manifest) is not dict or manifest.get("schema") != 1
                        or manifest.get("ownerScopeSha256") != self._config.owner_scope_sha256
                        or type(manifest.get("files")) is not list
                        or len(manifest["files"]) != len(members) - 1):
                    raise ObsidianVaultError("backup manifest does not match this owner vault")
                indexed: dict[str, bytes] = {}
                declared_total = 0
                for row in manifest["files"]:
                    if (type(row) is not dict or set(row) != {"path", "sha256", "size"}
                            or type(row["path"]) is not str):
                        raise ObsidianVaultError("backup manifest entry is malformed")
                    relative = _backup_relative(row["path"])
                    if not _HASH.fullmatch(row["sha256"] or "") or type(row["size"]) is not int or row["size"] < 0:
                        raise ObsidianVaultError("backup manifest digest or size is malformed")
                    item_info = archive.getinfo(relative)
                    member_bound = (MAX_PRIVATE_FILE_BYTES if relative.startswith(
                        (".obsidian/", ".hermes-private/")) else MAX_NOTE_BYTES)
                    declared_total += item_info.file_size
                    if (item_info.file_size > member_bound or row["size"] > member_bound
                            or declared_total > MAX_BACKUP_BYTES):
                        raise ObsidianVaultError("backup member exceeds its declared fixed bound")
                    content = archive.read(relative)
                    if (type(row["size"]) is not int or len(content) != row["size"]
                            or _sha256(content) != row["sha256"]):
                        raise ObsidianVaultError("backup member digest does not match its manifest")
                    indexed[relative] = content
                if set(indexed) | {".hermes-manifest.json"} != {item.filename for item in members}:
                    raise ObsidianVaultError("backup members differ from the owner manifest")
        except ObsidianVaultError:
            raise
        except Exception:
            raise ObsidianVaultError("backup archive is malformed") from None
        existing, partial, _ = self._files_for_backup()
        existing_map = dict(existing)
        if partial or any(not path.startswith(".obsidian/") for path in existing_map
                          if path not in indexed):
            raise ObsidianVaultConflict("restore target already contains note data; no files changed")
        for relative, content in indexed.items():
            current = existing_map.get(relative)
            if current is not None and current != content:
                raise ObsidianVaultConflict("restore target settings conflict; no notes changed")
        for relative, content in sorted(indexed.items()):
            current = self._read_raw_optional(relative)
            if current is not None:
                if current != content:
                    raise ObsidianVaultConflict("restore target settings conflict; no notes changed")
                continue
            self._write_raw(relative, content, create_only=True)
        return len(indexed)

    def recover_journal(self) -> dict[str, int]:
        """Reconcile interrupted conditional writes from their durable exact-byte journal."""
        rows = self._list_private_json("revisions", limit=MAX_SCAN_ENTRIES)
        report = {"committed": 0, "rolledBack": 0, "conflicts": 0, "partial": 0}
        if rows is None:
            report["partial"] = 1
            return report
        for relative in rows:
            try:
                raw = self._read_private(relative.removeprefix(".hermes-private/"),
                                         MAX_PRIVATE_FILE_BYTES)
                record = json.loads(raw.decode("utf-8", "strict"))
                if (type(record) is not dict or record.get("schema") != 1
                        or record.get("ownerScopeSha256") != self._config.owner_scope_sha256
                        or record.get("state") not in {"prepared", "committed", "conflict", "rolled-back"}):
                    raise ValueError
                if record["state"] != "prepared":
                    continue
                note_path = _note_relative_path(record["relativePath"])
                current = self._read_raw_optional(note_path)
                current_digest = None if current is None else _sha256(current)
                prior_digest = record.get("priorSha256")
                proposed_digest = record.get("proposedSha256")
                if (not _HASH.fullmatch(proposed_digest or "")
                        or (prior_digest is not None and not _HASH.fullmatch(prior_digest or ""))):
                    raise ValueError
                if current_digest == proposed_digest:
                    state = "committed"
                    report["committed"] += 1
                elif current_digest == prior_digest:
                    state = "rolled-back"
                    report["rolledBack"] += 1
                else:
                    state = "conflict"
                    report["conflicts"] += 1
                self._write_private(relative.removeprefix(".hermes-private/"),
                                    _canonical({**record, "state": state,
                                                "recoveredAt": time.time()}), replace=True)
            except Exception:
                report["partial"] += 1
        return report

    def _scan(self) -> tuple[list[_Note], bool, int]:
        candidates, partial, scanned_entries = self._candidate_markdown_paths()
        notes: list[_Note] = []
        scanned_bytes = 0
        for relative in candidates:
            try:
                result = self._read_raw(relative, MAX_NOTE_BYTES)
                scanned_bytes += len(result[0])
                if scanned_bytes > MAX_SCAN_BYTES:
                    partial = True
                    break
                raw, mtime = result
                markdown = raw.decode("utf-8", "strict")
                note = _make_note(relative, markdown, mtime)
                notes.append(note)
            except ObsidianVaultError:
                partial = True
            except UnicodeError:
                partial = True
        if len(notes) >= MAX_SCAN_NOTES:
            partial = True
            notes = notes[:MAX_SCAN_NOTES]
        ids: set[str] = set()
        for note in notes:
            if note.note_id in ids:
                raise ObsidianVaultError("vault contains a note ID collision")
            ids.add(note.note_id)
        return notes, partial, min(scanned_entries, MAX_SCAN_ENTRIES)

    def _candidate_markdown_paths(self) -> tuple[list[str], bool, int]:
        result: list[str] = []
        partial = False
        entries_seen = 0
        root = self._open_root_fd()

        def walk(fd: int, prefix: str, depth: int) -> None:
            nonlocal entries_seen, partial
            if depth > 16:
                partial = True
                return
            try:
                names = sorted(os.listdir(fd), key=str.casefold)
            except OSError:
                partial = True
                return
            for name in names:
                entries_seen += 1
                if entries_seen > MAX_SCAN_ENTRIES:
                    partial = True
                    return
                if name in _HIDDEN_EXCLUDED:
                    continue
                relative = f"{prefix}/{name}" if prefix else name
                if not _safe_rel(relative):
                    partial = True
                    continue
                try:
                    itemfd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                     | getattr(os, "O_NONBLOCK", 0)
                                     | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                except (OSError, TypeError):
                    # For directories we must open O_DIRECTORY; try that path safely.
                    try:
                        itemfd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                         | getattr(os, "O_NOFOLLOW", 0)
                                         | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                    except OSError:
                        partial = True
                        continue
                    try:
                        walk(itemfd, relative, depth + 1)
                    finally:
                        os.close(itemfd)
                    continue
                try:
                    mode = os.fstat(itemfd).st_mode
                    if stat.S_ISDIR(mode):
                        os.close(itemfd)
                        itemfd = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                         | getattr(os, "O_NOFOLLOW", 0)
                                         | getattr(os, "O_CLOEXEC", 0), dir_fd=fd)
                        walk(itemfd, relative, depth + 1)
                    elif stat.S_ISREG(mode) and name.casefold().endswith(".md"):
                        if len(result) >= MAX_SCAN_NOTES:
                            partial = True
                            return
                        result.append(relative)
                    elif not stat.S_ISREG(mode):
                        partial = True
                except OSError:
                    partial = True
                finally:
                    try:
                        os.close(itemfd)
                    except OSError:
                        pass

        try:
            walk(root, "", 0)
        finally:
            os.close(root)
        return result, partial, entries_seen

    def _lookup(self, note_id: str) -> _Note:
        if type(note_id) is not str or not _ID.fullmatch(note_id):
            raise ObsidianVaultError("note ID is malformed")
        notes, _partial, _scanned = self._scan()
        found = [note for note in notes if note.note_id == note_id]
        if len(found) != 1:
            raise ObsidianVaultError("note is not present in the selected-owner vault")
        return found[0]

    def _ensure_directory(self, relative: str) -> None:
        if not _safe_rel(relative):
            raise ObsidianVaultError("internal vault directory is malformed")
        root = self._open_root_fd()
        try:
            current = root
            opened: list[int] = []
            for part in PurePosixPath(relative).parts:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=current)
                except FileExistsError:
                    pass
                except OSError as exc:
                    raise ObsidianVaultError("vault directory could not be created safely") from exc
                try:
                    child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                    | getattr(os, "O_NOFOLLOW", 0)
                                    | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
                except OSError as exc:
                    raise ObsidianVaultError("vault directory is missing or a symlink") from exc
                _check_owner(os.fstat(child), self._expected_uid, directory=True)
                if relative == ".hermes-private" or relative.startswith(".hermes-private/"):
                    if stat.S_IMODE(os.fstat(child).st_mode) & 0o077:
                        os.close(child)
                        raise ObsidianVaultError("execution-private vault directories must be owner-only")
                opened.append(child)
                current = child
            for fd in reversed(opened):
                os.close(fd)
        finally:
            os.close(root)

    def _read_raw(self, relative: str, maximum: int) -> tuple[bytes, float]:
        parent, basename = self._open_parent(relative)
        try:
            try:
                fd = os.open(basename, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                             | getattr(os, "O_NONBLOCK", 0)
                             | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
            except OSError as exc:
                raise ObsidianVaultError("vault note is unavailable") from exc
            try:
                before = os.fstat(fd)
                _check_owner(before, self._expected_uid, directory=False)
                if relative.startswith(".hermes-private/") and stat.S_IMODE(before.st_mode) & 0o077:
                    raise ObsidianVaultError("execution-private records must be owner-only")
                if before.st_size > maximum:
                    raise ObsidianVaultError("vault file exceeds its fixed size bound")
                chunks: list[bytes] = []
                remaining = maximum + 1
                while remaining:
                    part = os.read(fd, min(65_536, remaining))
                    if not part:
                        break
                    chunks.append(part)
                    remaining -= len(part)
                data = b"".join(chunks)
                after = os.fstat(fd)
                if (len(data) > maximum or (before.st_dev, before.st_ino, before.st_size,
                        before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size,
                                                after.st_mtime_ns)):
                    raise ObsidianVaultConflict("vault file changed during the read")
                return data, before.st_mtime
            finally:
                os.close(fd)
        finally:
            os.close(parent)

    def _read_optional_note(self, relative: str) -> tuple[str, str, float] | None:
        raw = self._read_raw_optional_with_time(relative)
        if raw is None:
            return None
        try:
            markdown = raw[0].decode("utf-8", "strict")
        except UnicodeError:
            raise ObsidianVaultError("vault note is not valid UTF-8") from None
        return markdown, _sha256(raw[0]), raw[1]

    def _read_raw_optional_with_time(self, relative: str) -> tuple[bytes, float] | None:
        try:
            return self._read_raw(relative, MAX_NOTE_BYTES)
        except ObsidianVaultError as exc:
            if isinstance(exc.__cause__, FileNotFoundError):
                return None
            raise

    def _read_raw_optional(self, relative: str) -> bytes | None:
        value = self._read_raw_optional_with_time(relative)
        return None if value is None else value[0]

    def _read_private(self, relative: str, maximum: int) -> bytes:
        if not relative.startswith(("drafts/", "revisions/", "journal/")):
            raise ObsidianVaultError("private read is outside the fixed hidden store")
        return self._read_raw(f".hermes-private/{relative}", maximum)[0]

    def _list_private_json(self, section: str, *, limit: int) -> list[str] | None:
        if section not in {"drafts", "revisions", "journal"}:
            raise ObsidianVaultError("private section is outside the fixed hidden store")
        root = self._open_root_fd()
        try:
            private = os.open(".hermes-private", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=root)
            try:
                section_fd = os.open(section, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                     | getattr(os, "O_NOFOLLOW", 0), dir_fd=private)
                try:
                    files = sorted((name for name in os.listdir(section_fd)
                                    if name.endswith(".json")), key=str.casefold)
                    if len(files) > limit:
                        return None
                    return [f".hermes-private/{section}/{name}" for name in files]
                finally:
                    os.close(section_fd)
            finally:
                os.close(private)
        except OSError:
            return None
        finally:
            os.close(root)

    @property
    def _expected_uid(self) -> int:
        return self._config.owner_uid if self._config.owner_uid is not None else os.getuid()

    def _open_root_fd(self) -> int:
        try:
            root = os.open(self._root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
        except OSError as exc:
            raise ObsidianVaultError("selected-owner vault is unavailable or symlinked") from exc
        try:
            _check_owner(os.fstat(root), self._expected_uid, directory=True)
        except Exception:
            os.close(root)
            raise
        return root

    def _open_parent(self, relative: str, *, create: bool = False) -> tuple[int, str]:
        if not _safe_rel(relative):
            raise ObsidianVaultError("vault path must be normalized and relative")
        parts = PurePosixPath(relative).parts
        current = self._open_root_fd()
        try:
            for part in parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=current)
                    except FileExistsError:
                        pass
                try:
                    child = os.open(part, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                    | getattr(os, "O_NOFOLLOW", 0)
                                    | getattr(os, "O_CLOEXEC", 0), dir_fd=current)
                except OSError as exc:
                    raise ObsidianVaultError("vault path has a missing or symlinked directory") from exc
                child_info = os.fstat(child)
                _check_owner(child_info, self._expected_uid, directory=True)
                if (PurePosixPath(relative).parts[0] == ".hermes-private"
                        and stat.S_IMODE(child_info.st_mode) & 0o077):
                    os.close(child)
                    raise ObsidianVaultError("execution-private vault directories must be owner-only")
                os.close(current)
                current = child
            return current, parts[-1]
        except Exception:
            os.close(current)
            raise

    def _write_private(self, relative: str, content: bytes, *, create_only: bool = False,
                       replace: bool = False) -> None:
        if not relative.startswith(("drafts/", "revisions/", "journal/")):
            raise ObsidianVaultError("private write is outside the fixed hidden store")
        self._write_raw(f".hermes-private/{relative}", content,
                        create_only=create_only, replace=replace)

    def _write_raw(self, relative: str, content: bytes, *, create_only: bool = False,
                   replace: bool = False) -> None:
        if not _safe_rel(relative) or not isinstance(content, bytes):
            raise ObsidianVaultError("atomic vault write input is malformed")
        parent, basename = self._open_parent(relative, create=True)
        temporary = ".hermes-vault-" + secrets.token_hex(16)
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                         0o600, dir_fd=parent)
            try:
                _write_all(fd, content)
                os.fsync(fd)
            finally:
                os.close(fd)
            if create_only:
                try:
                    os.link(temporary, basename, src_dir_fd=parent, dst_dir_fd=parent,
                            follow_symlinks=False)
                except FileExistsError as exc:
                    raise ObsidianVaultConflict("vault destination already exists") from exc
                os.unlink(temporary, dir_fd=parent)
            elif replace:
                try:
                    os.replace(temporary, basename, src_dir_fd=parent, dst_dir_fd=parent)
                except OSError as exc:
                    raise ObsidianVaultError("private metadata replacement failed") from exc
            else:
                raise ObsidianVaultError("public notes require the conditional write path")
            os.fsync(parent)
        except Exception:
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            raise
        finally:
            os.close(parent)

    def _atomic_note_write(self, relative: str, content: bytes,
                           *, expected_sha256: str | None) -> None:
        relative = _note_relative_path(relative)
        if len(content) > MAX_NOTE_BYTES:
            raise ObsidianVaultError("final note exceeds the 1 MiB bound")
        parent, basename = self._open_parent(relative, create=True)
        temporary = ".hermes-write-" + secrets.token_hex(16)
        backup = f"revisions/{time.time_ns()}-{secrets.token_hex(8)}.json"
        lockfd = None
        try:
            rootfd = self._open_root_fd()
            try:
                lockfd = os.open(".hermes-vault.lock", os.O_RDWR | os.O_CREAT
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=rootfd)
            finally:
                os.close(rootfd)
            _check_owner(os.fstat(lockfd), self._expected_uid, directory=False)
            fcntl.flock(lockfd, fcntl.LOCK_EX)
            current = self._read_raw_optional(relative)
            current_digest = None if current is None else _sha256(current)
            if current_digest != expected_sha256:
                raise ObsidianVaultConflict("Obsidian note changed after review")
            prepared = {
                "schema": 1, "ownerScopeSha256": self._config.owner_scope_sha256,
                "relativePath": relative,
                "priorSha256": current_digest,
                "priorBase64": base64.b64encode(current).decode("ascii") if current is not None else None,
                "proposedSha256": _sha256(content), "state": "prepared",
            }
            self._write_private(backup, _canonical(prepared), create_only=True)
            staged_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                | getattr(os, "O_NOFOLLOW", 0), 0o600, dir_fd=parent)
            try:
                _write_all(staged_fd, content)
                os.fsync(staged_fd)
                staged_stat = os.fstat(staged_fd)
            finally:
                os.close(staged_fd)
            if expected_sha256 is None:
                try:
                    os.link(temporary, basename, src_dir_fd=parent, dst_dir_fd=parent,
                            follow_symlinks=False)
                except FileExistsError as exc:
                    raise ObsidianVaultConflict("note was created concurrently") from exc
                os.unlink(temporary, dir_fd=parent)
                self._write_private(backup, _canonical({**prepared, "state": "committed",
                                                         "committedAt": time.time()}), replace=True)
            else:
                _rename_exchange(parent, temporary, basename)
                try:
                    displaced = _read_at(parent, temporary, MAX_NOTE_BYTES,
                                         self._expected_uid)
                except Exception:
                    try:
                        target_stat = os.stat(basename, dir_fd=parent, follow_symlinks=False)
                        if (target_stat.st_dev, target_stat.st_ino) == (staged_stat.st_dev,
                                                                        staged_stat.st_ino):
                            _rename_exchange(parent, temporary, basename)
                    except OSError:
                        pass
                    raise ObsidianVaultConflict("note target changed to an unsafe file during promotion") from None
                if _sha256(displaced) != expected_sha256:
                    try:
                        target_stat = os.stat(basename, dir_fd=parent, follow_symlinks=False)
                        if (target_stat.st_dev, target_stat.st_ino) == (staged_stat.st_dev,
                                                                        staged_stat.st_ino):
                            _rename_exchange(parent, temporary, basename)
                    except OSError:
                        pass
                    conflict = _canonical({
                        "schema": 1, "pathSha256": _sha256(relative.encode("utf-8")),
                        "expectedBaseSha256": expected_sha256,
                        "observedSha256": _sha256(displaced),
                        "observedBase64": base64.b64encode(displaced).decode("ascii"),
                        "proposedSha256": _sha256(content), "state": "conflict",
                    })
                    self._write_private(f"journal/{time.time_ns()}-{secrets.token_hex(8)}.json",
                                        conflict, create_only=True)
                    raise ObsidianVaultConflict("external edit conflicted with reviewed write; both drafts are retained")
                self._write_private(backup, _canonical({
                    "schema": 1, "ownerScopeSha256": self._config.owner_scope_sha256,
                    "relativePath": relative,
                    "priorSha256": expected_sha256,
                    "priorBase64": base64.b64encode(displaced).decode("ascii"),
                    "proposedSha256": _sha256(content), "state": "committed",
                }), replace=True)
                os.unlink(temporary, dir_fd=parent)
            os.fsync(parent)
        except OSError as exc:
            if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
                raise ObsidianVaultError("vault path changed or contains a symlink") from None
            raise ObsidianVaultError("conditional vault write did not complete safely") from exc
        finally:
            if lockfd is not None:
                try:
                    fcntl.flock(lockfd, fcntl.LOCK_UN)
                    os.close(lockfd)
                except OSError:
                    pass
            try:
                os.unlink(temporary, dir_fd=parent)
            except OSError:
                pass
            os.close(parent)

    def _count_private_drafts(self) -> tuple[int, bool]:
        count = 0
        entries_seen = 0
        partial = False
        root = self._open_root_fd()
        try:
            private = os.open(".hermes-private", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=root)
            try:
                drafts = os.open("drafts", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0), dir_fd=private)
                try:
                    for _execution in os.listdir(drafts):
                        entries_seen += 1
                        if entries_seen > MAX_SCAN_ENTRIES:
                            return count, True
                        try:
                            exefd = os.open(_execution, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                            | getattr(os, "O_NOFOLLOW", 0), dir_fd=drafts)
                        except OSError:
                            partial = True
                            continue
                        try:
                            for name in os.listdir(exefd):
                                entries_seen += 1
                                if entries_seen > MAX_SCAN_ENTRIES:
                                    return count, True
                                if name.endswith(".json"):
                                    count += 1
                                    if count > MAX_SCAN_NOTES:
                                        count = MAX_SCAN_NOTES
                                        return count, True
                        finally:
                            os.close(exefd)
                finally:
                    os.close(drafts)
            finally:
                os.close(private)
        except OSError:
            return 0, True
        finally:
            os.close(root)
        return count, partial

    def _owner_draft_files(self) -> tuple[list[tuple[str, str, str]], bool]:
        """Enumerate opaque draft IDs without following paths outside the fixed vault."""
        files: list[tuple[str, str, str]] = []
        entries_seen = 0
        partial = False
        root = self._open_root_fd()
        try:
            private = os.open(".hermes-private", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=root)
            try:
                drafts = os.open("drafts", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0), dir_fd=private)
                try:
                    executions = sorted(os.listdir(drafts), key=str.casefold)
                    if len(executions) > MAX_OWNER_DRAFTS:
                        executions = executions[:MAX_OWNER_DRAFTS]
                        partial = True
                    for execution_id in executions:
                        entries_seen += 1
                        if entries_seen > MAX_SCAN_ENTRIES:
                            partial = True
                            return files, partial
                        if not _ID.fullmatch(execution_id):
                            partial = True
                            continue
                        try:
                            execution_fd = os.open(execution_id, os.O_RDONLY
                                                   | getattr(os, "O_DIRECTORY", 0)
                                                   | getattr(os, "O_NOFOLLOW", 0), dir_fd=drafts)
                        except OSError:
                            partial = True
                            continue
                        try:
                            _check_owner(os.fstat(execution_fd), self._expected_uid, directory=True)
                            names = sorted(os.listdir(execution_fd), key=str.casefold)
                            for name in names:
                                entries_seen += 1
                                if entries_seen > MAX_SCAN_ENTRIES:
                                    partial = True
                                    return files, partial
                                if not name.endswith(".json"):
                                    partial = True
                                    continue
                                draft_id = name[:-5]
                                if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id):
                                    partial = True
                                    continue
                                files.append((execution_id, draft_id,
                                              f".hermes-private/drafts/{execution_id}/{name}"))
                                if len(files) >= MAX_OWNER_DRAFTS:
                                    partial = True
                                    return files, partial
                        finally:
                            os.close(execution_fd)
                finally:
                    os.close(drafts)
            finally:
                os.close(private)
        except OSError:
            return files, True
        finally:
            os.close(root)
        return files, partial

    def _files_for_backup(self) -> tuple[list[tuple[str, bytes]], bool, int]:
        paths, partial, scanned = self._candidate_markdown_paths()
        selected = list(paths)
        # Preserve the complete .obsidian tree, including user settings and plugins.
        cfgfd = self._open_child_dir(".obsidian")
        if cfgfd is not None:
            try:
                extra, extra_partial = _walk_backup_files(cfgfd, ".obsidian")
                selected.extend(extra)
                partial = partial or extra_partial
            finally:
                os.close(cfgfd)
        private_fd = self._open_child_dir(".hermes-private")
        if private_fd is not None:
            try:
                for section in ("drafts", "revisions", "journal"):
                    try:
                        section_fd = os.open(section, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                             | getattr(os, "O_NOFOLLOW", 0), dir_fd=private_fd)
                    except OSError:
                        partial = True
                        continue
                    try:
                        rows, section_partial = _walk_backup_files(
                            section_fd, f".hermes-private/{section}")
                        selected.extend(path for path in rows if path.endswith(".json"))
                        partial = partial or section_partial
                    finally:
                        os.close(section_fd)
            finally:
                os.close(private_fd)
        files: list[tuple[str, bytes]] = []
        total = 0
        for relative in sorted(set(selected)):
            try:
                raw, _mtime = self._read_raw(
                    relative, MAX_PRIVATE_FILE_BYTES if relative.startswith((".obsidian/", ".hermes-private/"))
                    else MAX_NOTE_BYTES)
            except ObsidianVaultError:
                partial = True
                continue
            total += len(raw)
            if total > MAX_BACKUP_BYTES:
                return files, True, scanned
            files.append((relative, raw))
        return files, partial, scanned

    def _open_child_dir(self, name: str) -> int | None:
        root = self._open_root_fd()
        try:
            try:
                result = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                 | getattr(os, "O_NOFOLLOW", 0), dir_fd=root)
            except FileNotFoundError:
                return None
            _check_owner(os.fstat(result), self._expected_uid, directory=True)
            return result
        finally:
            os.close(root)


def _validate_managed_root(config: ObsidianVaultConfig) -> None:
    parent = config.managed_data_root
    if parent == Path("/home/admin/.hermes/jarvis-second-brain"):
        _validate_fixed_owner_parents()
    if parent.is_symlink() or not parent.is_dir():
        raise ObsidianVaultError("selected-owner managed data root must be an existing directory")
    _validate_directory(parent, config.owner_uid)
    _validate_private_directory(parent)


def _validate_fixed_owner_parents() -> None:
    """Check every fixed path component without following symbolic links."""
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open("/", flags)
    try:
        expected = (("home", 0), ("admin", 1000), (".hermes", 1000))
        for component, uid in expected:
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
            info = os.fstat(fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise ObsidianVaultError("fixed selected-owner vault parent custody changed")
    except OSError as exc:
        raise ObsidianVaultError("fixed selected-owner vault parent is unavailable") from exc
    finally:
        os.close(fd)


def _validate_directory(path: Path, owner_uid: int | None) -> None:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ObsidianVaultError("managed vault directory is unavailable") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise ObsidianVaultError("managed vault path must be a real directory")
    _check_owner(info, os.getuid() if owner_uid is None else owner_uid, directory=True)


def _validate_private_directory(path: Path) -> None:
    try:
        mode = stat.S_IMODE(path.lstat().st_mode)
    except OSError as exc:
        raise ObsidianVaultError("managed vault directory is unavailable") from exc
    if mode != 0o700:
        raise ObsidianVaultError("managed Obsidian directories must have mode 0700")


def _check_owner(info: os.stat_result, uid: int, *, directory: bool) -> None:
    if (info.st_uid != uid or (directory and not stat.S_ISDIR(info.st_mode))
            or (not directory and not stat.S_ISREG(info.st_mode))
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ObsidianVaultError("vault object ownership or permissions are unsafe")


def _safe_rel(value: str) -> bool:
    if (type(value) is not str or not value or "\\" in value or "\x00" in value
            or value.startswith("/") or len(value) > 1024):
        return False
    path = PurePosixPath(value)
    return (not path.is_absolute() and path.as_posix() == value
            and all(part not in {"", ".", ".."} for part in path.parts))


def _note_relative_path(value: str) -> str:
    if not _safe_rel(value) or not value.casefold().endswith(".md"):
        raise ObsidianVaultError("note destination must be a normalized relative Markdown path")
    parts = PurePosixPath(value).parts
    if any(part.startswith(".") or part in _HIDDEN_EXCLUDED for part in parts):
        raise ObsidianVaultError("note destination cannot enter a hidden or internal directory")
    if len("/".join(parts).encode("utf-8", "strict")) > 240:
        raise ObsidianVaultError("note destination exceeds its fixed path bound")
    return value


def _backup_relative(value: str) -> str:
    if not _safe_rel(value) or value == ".hermes-manifest.json":
        raise ObsidianVaultError("backup path is not an allowed vault-relative path")
    if value.startswith(".hermes-private/"):
        parts = PurePosixPath(value).parts
        if (len(parts) < 3 or parts[1] not in {"drafts", "revisions", "journal"}
                or not parts[-1].endswith(".json")):
            raise ObsidianVaultError("backup may contain only fixed private JSON records")
    elif value.startswith(".") and not value.startswith(".obsidian/"):
        raise ObsidianVaultError("backup may not contain arbitrary hidden vault files")
    elif not value.startswith(".obsidian/") and not value.casefold().endswith(".md"):
        raise ObsidianVaultError("backup may contain only Markdown notes and Obsidian settings")
    return value


def _safe_identifier(value: str, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ObsidianVaultError(f"{label} identifier is malformed")
    return value


def _opaque_id(relative_path: str) -> str:
    return hashlib.sha256(relative_path.encode("utf-8", "strict")).hexdigest()[:32]


def _limit(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_PAGE_SIZE:
        raise ObsidianVaultError(f"page limit must be between 1 and {MAX_PAGE_SIZE}")
    return value


def _scope_notes(notes: list[_Note], note_scope: frozenset[str] | None) -> tuple[list[_Note], bool]:
    if note_scope is None:
        return notes, False
    if (type(note_scope) is not frozenset
            or any(type(note_id) is not str or not _ID.fullmatch(note_id) for note_id in note_scope)):
        raise ObsidianVaultError("selected-note scope must be root-derived and immutable")
    return [note for note in notes if note.note_id in note_scope], True


def _cursor(value: str | None) -> int:
    if value is None:
        return 0
    match = re.fullmatch(r"v1:(0|[1-9][0-9]{0,5})", value) if type(value) is str else None
    if match is None:
        raise ObsidianVaultError("page cursor is malformed")
    return int(match.group(1))


def _title_text(value: str) -> str:
    if type(value) is not str:
        raise ObsidianVaultError("note title must be text")
    title = " ".join("".join(ch for ch in value if ch >= " " and ch != "\x7f").split())
    if not title or len(title) > 160:
        raise ObsidianVaultError("note title must contain 1 to 160 printable characters")
    return title


def _markdown_bytes(value: str, maximum: int) -> bytes:
    if type(value) is not str or not value.strip():
        raise ObsidianVaultError("Markdown must contain text")
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        raise ObsidianVaultError("Markdown is not valid UTF-8") from None
    if len(encoded) > maximum or "\x00" in value:
        raise ObsidianVaultError("Markdown exceeds its fixed size bound or contains NUL")
    return encoded


def _citations(values: Iterable[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise ObsidianVaultError("source citations must be a bounded sequence")
    result: list[str] = []
    try:
        items = tuple(values)
    except Exception:
        raise ObsidianVaultError("source citations are malformed") from None
    if len(items) > 32:
        raise ObsidianVaultError("source citation count exceeds its fixed bound")
    for item in items:
        if type(item) is not str or not item or len(item) > 512 or any(ord(c) < 0x20 for c in item):
            raise ObsidianVaultError("source citation is malformed")
        result.append(item)
    return tuple(result)


def _make_note(relative: str, markdown: str, mtime: float) -> _Note:
    raw = markdown.encode("utf-8", "strict")
    title = _extract_title(relative, markdown)
    tags, aliases = _frontmatter_terms(markdown)
    if not tags:
        tags = tuple(dict.fromkeys(_TAG.findall(markdown)))[:64]
    return _Note(_opaque_id(relative), relative, markdown, title, mtime, _sha256(raw),
                 tags, aliases)


def _extract_title(relative: str, markdown: str) -> str:
    front = _frontmatter(markdown)
    title = front.get("title")
    if title:
        return _plain(title, 160) or PurePosixPath(relative).stem[:160]
    for line in markdown.splitlines()[:80]:
        match = _TITLE.fullmatch(line)
        if match:
            return _plain(match.group(1), 160) or PurePosixPath(relative).stem[:160]
    return PurePosixPath(relative).stem[:160]


def _frontmatter(markdown: str) -> dict[str, str]:
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    end = next((index for index in range(1, min(len(lines), 81))
                if lines[index].strip() in {"---", "..."}), None)
    if end is None:
        return {}
    result: dict[str, str] = {}
    for line in lines[1:end]:
        if ":" not in line or line[:1].isspace():
            continue
        key, value = line.split(":", 1)
        if key.strip().casefold() == "title":
            result["title"] = _yaml_scalar(value.strip())
    return result


def _frontmatter_terms(markdown: str) -> tuple[tuple[str, ...], tuple[str, ...]]:
    lines = markdown.splitlines()
    if not lines or lines[0].strip() != "---":
        return (), ()
    end = next((index for index in range(1, min(len(lines), 81))
                if lines[index].strip() in {"---", "..."}), None)
    if end is None:
        return (), ()
    props: dict[str, list[str]] = {"tags": [], "aliases": []}
    active: str | None = None
    for line in lines[1:end]:
        if line[:1].isspace() and active is not None:
            match = re.match(r"^\s*-\s*(.+?)\s*$", line)
            if match:
                props[active].append(_yaml_scalar(match.group(1)))
            continue
        active = None
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip().casefold()
        if key not in props:
            continue
        active = key
        scalar = value.strip()
        if scalar.startswith("[") and scalar.endswith("]"):
            props[key].extend(_yaml_scalar(item.strip()) for item in scalar[1:-1].split(",") if item.strip())
            active = None
        elif scalar:
            props[key].append(_yaml_scalar(scalar))
    tags = tuple(dict.fromkeys(_plain(value.lstrip("#"), 80)
                               for value in props["tags"] if value))[:64]
    aliases = tuple(dict.fromkeys(_plain(value, 160)
                                  for value in props["aliases"] if value))[:64]
    return tags, aliases


def _yaml_scalar(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return _plain(value, 512)


def _plain(value: str, max_chars: int) -> str:
    return " ".join("".join(char for char in value if char >= " " and char != "\x7f").split())[:max_chars]


def _excerpt(markdown: str) -> str:
    body = re.sub(r"(?s)^---\s*\n.*?\n---\s*\n", "", markdown, count=1)
    body = re.sub(r"!?(?:\[\[|\]\])", " ", body)
    body = re.sub(r"[<>]", " ", body)
    return _plain(body, 320)


def _build_links(notes: list[_Note]) -> tuple[list[VaultLink], list[UnresolvedVaultLink]]:
    direct: dict[str, list[str]] = {}
    by_stem: dict[str, list[str]] = {}
    by_alias: dict[str, list[str]] = {}
    by_path: dict[str, list[str]] = {}
    for note in notes:
        direct[note.note_id] = []
        path = PurePosixPath(note.relative_path)
        by_stem.setdefault(path.stem.casefold(), []).append(note.note_id)
        by_path.setdefault(path.as_posix().casefold(), []).append(note.note_id)
        for alias in note.aliases:
            by_alias.setdefault(alias.casefold(), []).append(note.note_id)
    by_id = {note.note_id: note for note in notes}
    resolved: list[VaultLink] = []
    unresolved: list[UnresolvedVaultLink] = []
    for note in notes:
        candidates: list[tuple[str, str, str]] = []
        for match in _WIKILINK.finditer(note.markdown):
            raw = match.group(1).split("|", 1)[0].split("#", 1)[0].strip()
            label = match.group(1).split("|", 1)[-1].strip() if "|" in match.group(1) else raw
            if raw:
                candidates.append((raw, "wikilink", _plain(label, 160)))
        for match in _MARKDOWN_LINK.finditer(note.markdown):
            raw = match.group(2).strip().split("#", 1)[0].split("?", 1)[0]
            if not raw or raw.startswith(("/", "\\")) or ":" in raw:
                continue
            if not raw.casefold().endswith(".md"):
                continue
            target = _resolve_relative_link(note.relative_path, raw)
            if target is not None:
                candidates.append((target, "markdown", _plain(match.group(1), 160)))
        seen: set[tuple[str, str, str]] = set()
        for target, kind, label in candidates:
            key = (target, kind, label)
            if key in seen:
                continue
            seen.add(key)
            if kind == "markdown":
                matches = by_path.get(target.casefold(), [])
            else:
                normalized = _link_target(target)
                matches = (by_path.get(normalized.casefold(), [])
                           or by_stem.get(PurePosixPath(normalized).stem.casefold(), [])
                           or by_alias.get(normalized.casefold(), []))
            if len(matches) == 1 and matches[0] in by_id:
                resolved.append(VaultLink(note.note_id, matches[0], kind, label[:160]))
            else:
                unresolved.append(UnresolvedVaultLink(note.note_id, label[:160]))
    return resolved, unresolved


def _link_target(value: str) -> str:
    value = value.replace("\\", "/").strip()
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        return ""
    normalized = path.as_posix()
    if not normalized.casefold().endswith(".md"):
        normalized += ".md"
    return normalized


def _resolve_relative_link(source: str, target: str) -> str | None:
    import posixpath

    target = target.replace("\\", "/")
    if target.startswith("/") or "\x00" in target:
        return None
    normalized = posixpath.normpath(posixpath.join(str(PurePosixPath(source).parent), target))
    if normalized in {"..", "."} or normalized.startswith("../") or not _safe_rel(normalized):
        return None
    return normalized


def _decode_draft(raw: bytes, *, owner_scope: str, execution_id: str) -> dict[str, Any]:
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except Exception:
        raise ObsidianVaultError("private draft is malformed") from None
    fields = {"schema", "ownerScopeSha256", "executionId", "sourceInstanceId", "title",
              "markdown", "contentSha256", "baseNoteId", "baseSha256", "citations",
              "createdAt", "state"}
    if type(value) is not dict or value.get("state") not in {"private-draft", "promoted"}:
        raise ObsidianVaultError("private draft custody or digest is invalid")
    expected = (fields if value["state"] == "private-draft" else fields | {
        "promotedSha256", "promotedAt", "destinationId"})
    markdown = value.get("markdown")
    created = value.get("createdAt")
    try:
        _safe_identifier(value.get("executionId"), "execution")
        _safe_identifier(value.get("sourceInstanceId"), "source instance")
        _title_text(value.get("title"))
        encoded = _markdown_bytes(markdown, MAX_DRAFT_BYTES)
        citations = _citations(value.get("citations"))
    except ObsidianVaultError:
        raise ObsidianVaultError("private draft custody or digest is invalid") from None
    base_id, base_sha = value.get("baseNoteId"), value.get("baseSha256")
    if (set(value) != expected or value.get("schema") != 1
            or value.get("ownerScopeSha256") != owner_scope
            or value.get("executionId") != execution_id
            or value.get("contentSha256") != _sha256(encoded)
            or (base_id is None) != (base_sha is None)
            or (base_id is not None and (type(base_id) is not str or not _ID.fullmatch(base_id)
                                          or not _HASH.fullmatch(base_sha or "")))
            or type(created) not in (int, float) or not time.time() - 315_360_000 <= created <= time.time() + 60
            or list(citations) != value.get("citations")
            or (value["state"] == "promoted" and
                (not _HASH.fullmatch(value.get("promotedSha256") or "")
                 or type(value.get("promotedAt")) not in (int, float)
                 or type(value.get("destinationId")) is not str
                 or not _ID.fullmatch(value["destinationId"])) )):
        raise ObsidianVaultError("private draft custody or digest is invalid")
    return value


def _draft_projection(draft_id: str, data: dict[str, Any]) -> VaultDraft:
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,64}", draft_id or ""):
        raise ObsidianVaultError("private draft ID is malformed")
    if (type(data.get("createdAt")) not in (int, float)
            or type(data.get("citations")) is not list):
        raise ObsidianVaultError("private draft metadata is malformed")
    if (not _HASH.fullmatch(data.get("contentSha256") or "")
            or (data.get("baseSha256") is not None
                and not _HASH.fullmatch(data.get("baseSha256") or ""))):
        raise ObsidianVaultError("private draft digest metadata is malformed")
    citations = _citations(data["citations"])
    return VaultDraft(draft_id, data["executionId"], data["sourceInstanceId"],
                      data["title"], data["contentSha256"], data["baseNoteId"],
                      data["baseSha256"], citations, data["createdAt"])


def _walk_backup_files(root_fd: int, prefix: str) -> tuple[list[str], bool]:
    paths: list[str] = []
    partial = False
    entries_seen = 0

    def walk(fd: int, relative: str, depth: int) -> None:
        nonlocal partial, entries_seen
        if depth > 8:
            partial = True
            return
        try:
            names = sorted(os.listdir(fd), key=str.casefold)
        except OSError:
            partial = True
            return
        for name in names:
            entries_seen += 1
            if entries_seen > MAX_SCAN_ENTRIES or len(paths) >= MAX_SCAN_ENTRIES:
                partial = True
                return
            current = f"{relative}/{name}"
            if not _safe_rel(current):
                partial = True
                continue
            try:
                item = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                               | getattr(os, "O_NONBLOCK", 0), dir_fd=fd)
            except OSError:
                try:
                    item = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                   | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                except OSError:
                    partial = True
                    continue
                try:
                    walk(item, current, depth + 1)
                finally:
                    os.close(item)
                continue
            try:
                mode = os.fstat(item).st_mode
                if stat.S_ISREG(mode):
                    if os.fstat(item).st_size > MAX_PRIVATE_FILE_BYTES:
                        partial = True
                    else:
                        paths.append(current)
                elif stat.S_ISDIR(mode):
                    os.close(item)
                    item = os.open(name, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                   | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
                    walk(item, current, depth + 1)
                else:
                    partial = True
            finally:
                try:
                    os.close(item)
                except OSError:
                    pass
    walk(root_fd, prefix, 0)
    return paths, partial


def _write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short vault write")
        view = view[written:]


def _read_at(directory_fd: int, name: str, maximum: int, expected_uid: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_NONBLOCK", 0), dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        _check_owner(info, expected_uid, directory=False)
        if info.st_size > maximum:
            raise ObsidianVaultError("displaced Obsidian file exceeds its bound")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            part = os.read(fd, min(65_536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        content = b"".join(chunks)
        if len(content) > maximum:
            raise ObsidianVaultError("displaced Obsidian file exceeds its bound")
        return content
    finally:
        os.close(fd)


def _rename_exchange(directory_fd: int, first: str, second: str) -> None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (OSError, AttributeError):
        raise ObsidianVaultError("atomic compare-and-swap is unavailable on this Pi runtime") from None
    renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                          ctypes.c_uint)
    renameat2.restype = ctypes.c_int
    result = renameat2(directory_fd, os.fsencode(first), directory_fd, os.fsencode(second), _EXCHANGE)
    if result != 0:
        code = ctypes.get_errno()
        if code in {errno.ENOSYS, errno.EINVAL, errno.EOPNOTSUPP}:
            raise ObsidianVaultError("atomic compare-and-swap is unavailable on this filesystem")
        raise OSError(code, os.strerror(code))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8", "strict")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


__all__ = [
    "DraftPage", "GraphSnapshot", "MAX_GRAPH_EDGES", "MAX_GRAPH_NODES", "MAX_NOTE_BYTES",
    "MAX_PAGE_SIZE", "MAX_QUERY_CHARS", "NoteLinks", "NotePage", "NoteRead",
    "NoteSummary", "ObsidianVaultConfig", "ObsidianVaultConflict", "ObsidianVaultError",
    "ObsidianVaultStore", "OwnerDraftReview", "UnresolvedVaultLink", "VAULT_DIRECTORY", "VaultDraft",
    "VaultLink", "VaultSnapshot", "prepare_obsidian_vault",
]
