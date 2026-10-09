"""Selected public-apis source as a private, searchable reference catalog.

This adapter exposes indexing and local search only. It has no API client,
account setup, server launcher, or provisioning operation.
"""
from __future__ import annotations

from typing import Any

from hermes_installer.components.references import (
    InstalledReferenceCatalog,
    ReferenceSearchError,
    ReferenceSearchResult,
    install_reference_catalog,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


COMPONENT_ID = "public-apis-public-apis"


def install_public_apis_catalog(
    source: VerifiedComponentSource,
    store: Any,
) -> InstalledReferenceCatalog:
    """Stage only the reviewed public-apis pin into the selected profile store."""
    if not isinstance(source, VerifiedComponentSource) or source.component_id != COMPONENT_ID:
        raise ReferenceSearchError("public APIs require their verified selected source")
    return install_reference_catalog(source, store)


def search_public_apis_catalog(
    catalog: InstalledReferenceCatalog,
    query: str,
    *,
    limit: int = 20,
) -> ReferenceSearchResult:
    """Search the local pinned tree and return file/line source provenance."""
    if not isinstance(catalog, InstalledReferenceCatalog) or catalog.component_id != COMPONENT_ID:
        raise ReferenceSearchError("search requires an installed public APIs catalog")
    return catalog.search(query, limit=limit)
