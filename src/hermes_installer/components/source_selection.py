"""Resolve reviewed component source choices without silently changing identity."""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from urllib.parse import urlsplit

from hermes_installer.components.adapters import (
    ComponentAdapterContract,
    resolve_component_adapter,
)


class SourceSelectionError(ValueError):
    """A requested source is ambiguous, unpinned, or not explicitly approved."""


_REVISION = re.compile(r"^[a-f0-9]{40}$")
_IDENTITY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


@dataclass(frozen=True, slots=True)
class SelectedComponentSource:
    component: ComponentAdapterContract
    selected_identity: str
    selected_url: str
    revision: str
    source_selection: str
    license: str | None


def _github_source(identity: str, url: str, revision: str) -> None:
    if not _IDENTITY.fullmatch(identity) or not _REVISION.fullmatch(revision):
        raise SourceSelectionError("source selection requires owner/repository and a full commit SHA")
    parsed = urlsplit(url)
    parts = parsed.path.strip("/").split("/")
    if (parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.port is not None
        or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment
        or len(parts) != 2 or "/".join(parts).casefold() != identity.casefold()):
        raise SourceSelectionError("source URL must be the exact HTTPS GitHub owner/repository")


def select_component_source(
    name: str,
    *,
    identity: str,
    url: str,
    revision: str,
    explicit_selection: bool,
    license: str | None = None,
) -> SelectedComponentSource:
    """Select a pinned identity; changing the reviewed pin requires user choice.

    Passing the current identity/pin is a deterministic lookup. Any other
    identity or revision is rejected unless the caller records explicit user
    source selection. A custom source with unknown license remains private-only.
    """
    contract = resolve_component_adapter(name)
    _github_source(identity, url, revision)
    matches_current = (
        contract.source_identity is not None
        and identity.casefold() == contract.source_identity.casefold()
        and revision == contract.revision
        and url.rstrip("/").casefold() == contract.selected_source_url.rstrip("/").casefold()
    )
    if not matches_current and not explicit_selection:
        raise SourceSelectionError("changing the reviewed source requires explicit source selection")
    if identity.casefold() == (contract.source_identity or "").casefold() and revision != contract.revision and not explicit_selection:
        raise SourceSelectionError("updating a source revision requires explicit source selection")
    selected = replace(
        contract,
        source_urls=tuple(dict.fromkeys((*contract.source_urls, url))),
        selected_source_url=url,
        source_identity=identity,
        revision=revision,
        source_default_branch=contract.source_default_branch if matches_current else None,
        source_selection="explicit-source-override" if not matches_current else contract.source_selection,
        source_resolved=True,
        license=license if not matches_current else contract.license,
        source_status=("explicitly selected pin; compatibility and license review pending"
                       if not matches_current else contract.source_status),
    )
    return SelectedComponentSource(
        component=selected,
        selected_identity=identity,
        selected_url=url,
        revision=revision,
        source_selection=selected.source_selection,
        license=selected.license,
    )


def select_alternate_source(name: str, *, identity: str) -> SelectedComponentSource:
    """Select a pre-reviewed alternate pin by exact identity, never by alias."""
    contract = resolve_component_adapter(name)
    candidate = next((offer for offer in contract.alternate_sources
                      if offer.identity and offer.identity.casefold() == identity.casefold()), None)
    if candidate is None or not candidate.url or not candidate.revision:
        raise SourceSelectionError("requested repository is not a pinned alternate for this component")
    return select_component_source(
        name,
        identity=candidate.identity or "",
        url=candidate.url,
        revision=candidate.revision,
        explicit_selection=True,
        license=candidate.license,
    )
