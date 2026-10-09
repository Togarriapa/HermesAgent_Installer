"""Safe local data search for the pinned UI/UX Pro Max skill source."""
from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from typing import Mapping

from hermes_installer.components.portable_skill_adapters import (
    PortableSkillError,
    validate_pinned_source,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource


SOURCE_IDENTITY = "nextlevelbuilder/ui-ux-pro-max-skill"
SOURCE_REVISION = "50d8a7de0900119855614541f15a1a616691eb33"
UPSTREAM_CLI_PACKAGE = "ui-ux-pro-max-cli"
SEARCH_SCRIPT = "src/ui-ux-pro-max/scripts/search.py"
CLI_MANIFEST = "cli/package.json"
_DOMAINS: Mapping[str, str] = {
    "style": "styles.csv",
    "color": "colors.csv",
    "chart": "charts.csv",
    "landing": "landing.csv",
    "product": "products.csv",
    "ux": "ux-guidelines.csv",
    "typography": "typography.csv",
    "icons": "icons.csv",
    "gsap": "motion.csv",
    "react": "react-performance.csv",
    "web": "app-interface.csv",
    "google-fonts": "google-fonts.csv",
}


@dataclass(frozen=True, slots=True)
class DesignSearchResult:
    component_id: str
    source_identity: str
    revision: str
    domain: str
    query: str
    source_path: str
    source_sha256: str
    rows: tuple[Mapping[str, str], ...]


def review_ui_ux_source(source: VerifiedComponentSource) -> str:
    """Confirm the pinned search helper, source data, and CLI package name."""
    validate_pinned_source("ui-ux-pro-max", source)
    manifest = _json_file(source.files, CLI_MANIFEST)
    package_name = manifest.get("name")
    if package_name != UPSTREAM_CLI_PACKAGE:
        raise PortableSkillError("pinned installer manifest has an unknown package name")
    if SEARCH_SCRIPT not in source.files:
        raise PortableSkillError("pinned Python search helper is missing")
    if "src/ui-ux-pro-max/data/catalog-summary.json" not in source.files:
        raise PortableSkillError("pinned shared design data is missing")
    return package_name


def search_design_data(
    source: VerifiedComponentSource,
    query: str,
    *,
    domain: str = "style",
    limit: int = 3,
) -> DesignSearchResult:
    """Search the selected source's bundled CSV locally and return provenance."""
    review_ui_ux_source(source)
    filename = _DOMAINS.get(domain)
    if filename is None:
        raise PortableSkillError("design search domain is not in the reviewed catalog")
    if not isinstance(query, str) or not query.strip():
        raise PortableSkillError("design search query must contain text")
    if not isinstance(limit, int) or not 1 <= limit <= 20:
        raise PortableSkillError("design search result limit must be between 1 and 20")
    path = f"src/ui-ux-pro-max/data/{filename}"
    body = source.files.get(path)
    if not isinstance(body, bytes):
        raise PortableSkillError(f"pinned design data is missing: {path}")
    try:
        rows = list(csv.DictReader(io.StringIO(body.decode("utf-8-sig"))))
    except (UnicodeError, csv.Error) as exc:
        raise PortableSkillError(f"pinned design data cannot be read: {path}") from exc
    terms = tuple(term.casefold() for term in query.split() if term)
    ranked: list[tuple[int, int, Mapping[str, str]]] = []
    for index, row in enumerate(rows):
        haystack = " ".join(value for value in row.values() if value).casefold()
        score = sum(haystack.count(term) for term in terms)
        if score:
            ranked.append((score, -index, row))
    ranked.sort(key=lambda item: (item[0], item[1]), reverse=True)
    return DesignSearchResult(
        "ui-ux-pro-max", source.source_identity, source.revision, domain, query,
        path, hashlib.sha256(body).hexdigest(), tuple(item[2] for item in ranked[:limit]),
    )


def _json_file(files: Mapping[str, bytes], path: str) -> dict:
    body = files.get(path)
    if not isinstance(body, bytes):
        raise PortableSkillError(f"pinned source manifest is missing: {path}")
    try:
        value = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise PortableSkillError(f"pinned source manifest is invalid: {path}") from exc
    if not isinstance(value, dict):
        raise PortableSkillError(f"pinned source manifest is invalid: {path}")
    return value
