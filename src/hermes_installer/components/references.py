"""Bounded, read-only search for selected reference-catalog source trees.

Search operates only on an already verified, privately staged source mapping. It
never follows links, loads arbitrary code, provisions listed APIs, or contacts
catalog entries.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from hermes_installer.components.adapters import resolve_component_adapter


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
                return ReferenceSearchResult(component_id, query, tuple(hits), scanned, complete)
    return ReferenceSearchResult(component_id, query, tuple(hits), scanned, complete)
