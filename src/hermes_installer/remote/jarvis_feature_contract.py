"""Typed contract for fixed, static Jarvis dashboard feature fragments.

Feature modules are reviewed installer assets, not plugins: their routes are
literal allowlists and their markup must not interpolate request data.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


@dataclass(frozen=True, slots=True)
class JarvisFeatureAssets:
    """One fixed dashboard view, its static assets, and bounded API surface."""

    feature_id: str
    nav_label: str
    title: str
    view_html: str
    css: str
    api_routes: tuple[tuple[str, str], ...]
    mount_js: str
    unmount_js: str


_FEATURE_ID = re.compile(r"[a-z][a-z0-9-]{0,39}\Z")
_ROUTE = re.compile(r"/chat/api/[a-z0-9/_{}-]+\Z")
_PLACEHOLDER = re.compile(r"\{([a-z][a-z0-9_]*)\}")
_DANGEROUS_MARKUP = re.compile(r"<\s*script\b|\son[a-z]+\s*=|javascript\s*:", re.IGNORECASE)


def validate_feature_assets(features: tuple[JarvisFeatureAssets, ...]) -> None:
    """Reject ambiguous IDs, methods, paths, or incomplete static modules."""
    seen_ids: set[str] = set()
    for feature in features:
        if not isinstance(feature, JarvisFeatureAssets):
            raise ValueError("dashboard feature registry contains an untyped entry")
        if not _FEATURE_ID.fullmatch(feature.feature_id) or feature.feature_id in seen_ids:
            raise ValueError("dashboard feature ID is invalid or duplicated")
        seen_ids.add(feature.feature_id)
        if not all(isinstance(value, str) and value.strip() for value in (
            feature.nav_label, feature.title, feature.view_html, feature.mount_js,
            feature.unmount_js,
        )):
            raise ValueError("dashboard feature is missing reviewed static content")
        if _DANGEROUS_MARKUP.search(feature.view_html):
            raise ValueError("dashboard feature markup contains executable or inline-event content")
        if (not feature.mount_js.lstrip().startswith("function mount(")
                or not feature.unmount_js.lstrip().startswith("function unmount(")):
            raise ValueError("dashboard feature lifecycle must use its fixed mount/unmount functions")
        if len(feature.view_html.encode("utf-8")) > 30_000 or len(feature.mount_js.encode("utf-8")) > 30_000 or len(feature.unmount_js.encode("utf-8")) > 10_000:
            raise ValueError("dashboard feature static assets exceed their fixed size bounds")
        if not isinstance(feature.css, str) or len(feature.css.encode("utf-8")) > 30_000:
            raise ValueError("dashboard feature CSS is invalid or exceeds its fixed bound")
        if not isinstance(feature.api_routes, tuple):
            raise ValueError("dashboard feature routes must be a fixed tuple")
        seen_routes: set[tuple[str, str]] = set()
        for route in feature.api_routes:
            if (not isinstance(route, tuple) or len(route) != 2
                    or route[0] not in {"GET", "POST"}
                    or not isinstance(route[1], str)
                    or not _ROUTE.fullmatch(route[1])
                    or route in seen_routes):
                raise ValueError("dashboard feature API route is invalid or duplicated")
            segments = route[1].split("/")
            if any(segment in {"", ".", ".."} for segment in segments[1:]):
                raise ValueError("dashboard feature route contains an ambiguous path segment")
            if any("{" in segment or "}" in segment for segment in segments
                   if not _PLACEHOLDER.fullmatch(segment)):
                raise ValueError("dashboard feature route has an invalid path placeholder")
            seen_routes.add(route)
