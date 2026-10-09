"""Bounded, read-only search for selected reference-catalog source trees.

Search operates only on an already verified, privately staged source mapping. It
never follows links, loads arbitrary code, provisions listed APIs, or contacts
catalog entries.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import replace
from dataclasses import dataclass
from pathlib import Path
from pathlib import PurePosixPath
from typing import Mapping, Any

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.source_bundle import ComponentSourceError, VerifiedComponentSource


REFERENCE_CATALOGS = frozenset({
    "public-apis-public-apis",
    "awesome-harness-engineering",
    "awesome-design",
})
_TEXT_SUFFIXES = frozenset({".md", ".markdown", ".rst", ".txt", ".json", ".yaml", ".yml", ".toml", ".csv", ".tsv"})
_MAX_TEXT_FILE = 1_048_576
_MAX_TOTAL_TEXT = 16_777_216
_MAX_HITS = 50
_MAX_QUERY = 160


class ReferenceSearchError(ValueError):
    """The requested reference search is invalid or cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class ReferenceHit:
    component_id: str
    source_url: str
    revision: str
    path: str
    line: int
    excerpt: str


@dataclass(frozen=True, slots=True)
class ReferenceSearchResult:
    component_id: str
    query: str
    hits: tuple[ReferenceHit, ...]
    scanned_files: int
    complete: bool


@dataclass(frozen=True, slots=True)
class InstalledReferenceCatalog:
    """A reference index bound to an immutable installer-owned generation."""

    component_id: str
    source_url: str
    revision: str
    root: Path
    generation_digest: str
    redistribution_license_review_required: bool
    _store: Any

    def search(self, query: str, *, limit: int = 20) -> ReferenceSearchResult:
        """Verify the owned generation, then search bounded local source text."""
        identity = f"component-{self.component_id}-{self.revision[:12]}"
        try:
            actual_root, manifest, digest = self._store._verify(identity)
        except Exception as exc:
            raise ReferenceSearchError("installed reference generation failed its ownership/integrity check") from exc
        if actual_root != self.root or digest != self.generation_digest:
            raise ReferenceSearchError("installed reference generation identity changed")
        files: dict[str, bytes] = {}
        complete_source = True
        total = 0
        for name, metadata in sorted(manifest["files"].items()):
            path = PurePosixPath(name)
            if path.suffix.casefold() not in _TEXT_SUFFIXES:
                continue
            # Generation manifests bind hashes and modes, not sizes. Read one
            # bounded file at a time and avoid retaining a large catalog copy.
            try:
                if path.is_absolute() or ".." in path.parts or path.as_posix() != name:
                    raise ReferenceSearchError("installed reference generation contains an unsafe path")
                file_path = actual_root / name
                file_size = file_path.stat().st_size
                if file_size > _MAX_TEXT_FILE or total + file_size > _MAX_TOTAL_TEXT:
                    complete_source = False
                    continue
                body = file_path.read_bytes()
            except OSError:
                raise ReferenceSearchError("installed reference file could not be read safely") from None
            files[name] = body
            total += len(body)
        result = search_reference_catalog(self.component_id, files, query, limit=limit)
        if not complete_source and result.complete:
            return replace(result, complete=False)
        return result


def install_reference_catalog(source: VerifiedComponentSource, store: object) -> InstalledReferenceCatalog:
    """Stage one pinned reference source privately and return its real local search adapter.

    A `NOASSERTION` or unresolved license never prevents private profile-local
    import, but remains visible as a redistribution review requirement.
    """
    if not isinstance(source, VerifiedComponentSource):
        raise ReferenceSearchError("reference catalog installation requires a verified pinned source")
    if source.component_id not in REFERENCE_CATALOGS:
        raise ReferenceSearchError("source is not one of the selected reference catalogs")
    contract = resolve_component_adapter(source.component_id)
    if source.source_identity != contract.source_identity or source.revision != contract.revision:
        raise ReferenceSearchError("reference source identity differs from the reviewed source pin")
    if (source.license != contract.license
            or source.redistribution_license_review_required != contract.redistribution_license_review_required
            or type(source.redistribution_license_review_required) is not bool):
        raise ReferenceSearchError("reference source license evidence differs from the reviewed contract")
    if not isinstance(source.archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source.archive_sha256):
        raise ReferenceSearchError("reference source archive digest is invalid")
    source_files = {name: body for name, body in source.files.items() if name != "INSTALLER-SOURCE-PROVENANCE.json"}
    source_modes = {name: mode for name, mode in source.file_modes.items() if name in source_files}
    if set(source_modes) != set(source_files):
        raise ReferenceSearchError("reference source file modes are incomplete")
    content_digest = hashlib.sha256()
    for name in sorted(source_files):
        if not isinstance(source_files[name], bytes) or type(source_modes[name]) is not int:
            raise ReferenceSearchError("reference source file metadata is invalid")
        content_digest.update(name.encode("utf-8") + b"\0")
        content_digest.update(f"{source_modes[name]:o}".encode("ascii") + b"\0")
        content_digest.update(hashlib.sha256(source_files[name]).digest())
    if content_digest.hexdigest() != source.content_sha256:
        raise ReferenceSearchError("reference source content digest differs from its verified source")
    license_files = tuple(sorted(
        name for name in source_files
        if PurePosixPath(name).name.casefold().startswith(("license", "copying", "notice"))
    ))
    if source.license_files != license_files:
        raise ReferenceSearchError("reference license file inventory differs from its source tree")
    from hermes_installer.registry.source import _git_tree
    try:
        tree, _ = _git_tree(source_files, source_modes)
    except Exception as exc:
        raise ReferenceSearchError("reference source tree is invalid") from exc
    if tree != source.source_tree_sha:
        raise ReferenceSearchError("reference source files differ from the pinned Git tree")
    provenance_bytes = source.files.get("INSTALLER-SOURCE-PROVENANCE.json")
    try:
        provenance = json.loads(provenance_bytes.decode("utf-8")) if isinstance(provenance_bytes, bytes) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        provenance = None
    expected_provenance = {
        "schema": 1,
        "component_id": source.component_id,
        "source_identity": source.source_identity,
        "source_url": contract.selected_source_url,
        "revision": source.revision,
        "source_selection": contract.source_selection,
        "source_archive_sha256": source.archive_sha256,
        "source_content_sha256": source.content_sha256,
        "source_tree_sha": source.source_tree_sha,
        "declared_license": contract.license,
        "license_files": list(license_files),
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    if provenance != expected_provenance:
        raise ReferenceSearchError("reference source provenance does not match its pinned contract")
    try:
        root = source.stage(store).resolve(strict=True)
        if root.is_symlink() or not root.is_relative_to(store.root.resolve(strict=True)):
            raise ReferenceSearchError("reference generation escaped installer-owned data")
        actual_root, manifest, digest = store._verify(source.generation_id)
    except ReferenceSearchError:
        raise
    except (AttributeError, OSError, ComponentSourceError, ValueError) as exc:
        raise ReferenceSearchError("reference catalog could not be staged and verified") from exc
    if actual_root != root or set(manifest["files"]) != set(source.files):
        raise ReferenceSearchError("staged reference generation differs from its verified source")
    return InstalledReferenceCatalog(
        component_id=source.component_id,
        source_url=contract.selected_source_url,
        revision=contract.revision or "",
        root=root,
        generation_digest=digest,
        redistribution_license_review_required=source.redistribution_license_review_required,
        _store=store,
    )


def search_reference_catalog(
    component_id: str,
    files: Mapping[str, bytes],
    query: str,
    *,
    limit: int = 20,
) -> ReferenceSearchResult:
    """Search catalog text with deterministic order and immutable source citations."""
    if component_id not in REFERENCE_CATALOGS:
        raise ReferenceSearchError("component is not a selected reference catalog")
    contract = resolve_component_adapter(component_id)
    if contract.unresolved_reason():
        raise ReferenceSearchError(contract.unresolved_reason())
    if not isinstance(query, str) or not query.strip() or len(query) > _MAX_QUERY or "\x00" in query:
        raise ReferenceSearchError("query must contain 1..160 non-NUL characters")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= _MAX_HITS:
        raise ReferenceSearchError("limit must be between 1 and 50")

    needle = query.casefold().strip()
    hits: list[ReferenceHit] = []
    total_bytes = 0
    scanned = 0
    complete = True
    for path in sorted(files):
        candidate = PurePosixPath(path)
        if candidate.is_absolute() or not candidate.parts or ".." in candidate.parts or candidate.as_posix() != path:
            raise ReferenceSearchError("source tree contains an unsafe path")
        if candidate.suffix.casefold() not in _TEXT_SUFFIXES:
            continue
        body = files[path]
        if not isinstance(body, bytes):
            raise ReferenceSearchError("source file content must be bytes")
        if len(body) > _MAX_TEXT_FILE or total_bytes + len(body) > _MAX_TOTAL_TEXT:
            complete = False
            continue
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            complete = False
            continue
        total_bytes += len(body)
        scanned += 1
        for line_number, line in enumerate(text.splitlines(), 1):
            if needle not in line.casefold():
                continue
            hits.append(ReferenceHit(
                component_id=component_id,
                source_url=contract.selected_source_url,
                revision=contract.revision,
                path=path,
                line=line_number,
                excerpt=line.strip()[:240],
            ))
            if len(hits) >= limit:
                # The remaining tree was not scanned, so the result is bounded, not exhaustive.
                return ReferenceSearchResult(component_id, query, tuple(hits), scanned, False)
    return ReferenceSearchResult(component_id, query, tuple(hits), scanned, complete)
