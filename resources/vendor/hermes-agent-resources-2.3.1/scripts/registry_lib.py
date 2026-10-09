#!/usr/bin/env python3
from __future__ import annotations

import re
from copy import deepcopy
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
API_VERSION = "hermes.togarriapa/v1"
RESOURCE_DIRS = {
    "Profile": "profiles",
    "Skill": "skills",
    "Plugin": "plugins",
    "MCP": "mcps",
    "Cron": "crons",
    "Webhook": "webhooks",
    "Channel": "channels",
    "Bundle": "bundles",
}
DEPENDENCY_KINDS = {
    "profiles": "Profile",
    "skills": "Skill",
    "plugins": "Plugin",
    "mcps": "MCP",
    "crons": "Cron",
    "webhooks": "Webhook",
    "channels": "Channel",
    "bundles": "Bundle",
}
NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")
SELECTOR_RE = re.compile(r"^([a-z0-9]+(?:-[a-z0-9]+)*)@(\^?)(\d+\.\d+\.\d+)$")


def load_yaml(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: YAML root must be a mapping")
    return data


def version_tuple(version: str) -> tuple[int, int, int]:
    core = version.split("-", 1)[0].split("+", 1)[0]
    a, b, c = core.split(".")
    return int(a), int(b), int(c)


def selector_matches(candidate: str, requested: str, caret: bool) -> bool:
    c = version_tuple(candidate)
    r = version_tuple(requested)
    if not caret:
        return c == r
    if r[0] > 0:
        return c[0] == r[0] and c >= r
    if r[1] > 0:
        return c[0] == 0 and c[1] == r[1] and c >= r
    return c[0] == 0 and c[1] == 0 and c[2] == r[2]


def catalog() -> dict[str, Any]:
    return load_yaml(ROOT / "catalog.yaml")


def discovery_roots() -> dict[str, str]:
    doc = catalog()
    configured = (((doc.get("spec") or {}).get("discovery") or {}).get("roots") or {})
    roots: dict[str, str] = {}
    for kind, default in RESOURCE_DIRS.items():
        value = configured.get(kind, default)
        if not isinstance(value, str) or not value:
            raise ValueError(f"catalog.yaml: discovery root for {kind} must be a non-empty string")
        roots[kind] = value
    return roots


def discover_resources() -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    roots = discovery_roots()
    for expected_kind, directory in roots.items():
        base = ROOT / directory
        if not base.is_dir():
            raise ValueError(f"catalog.yaml: discovery root is missing: {directory}")
        for path in sorted(base.glob("*.yaml")):
            doc = load_yaml(path)
            metadata = doc.get("metadata") or {}
            result.append({
                "rel": path.relative_to(ROOT).as_posix(),
                "path": path,
                "expected_kind": expected_kind,
                "kind": doc.get("kind"),
                "name": metadata.get("name"),
                "version": metadata.get("version"),
                "doc": doc,
            })
    return result


def versions_index(resources: list[dict[str, Any]]) -> dict[tuple[str, str], set[str]]:
    versions: dict[tuple[str, str], set[str]] = {}
    for item in resources:
        if isinstance(item.get("kind"), str) and isinstance(item.get("name"), str) and isinstance(item.get("version"), str):
            versions.setdefault((item["kind"], item["name"]), set()).add(item["version"])
    return versions


def resource_map(resources: list[dict[str, Any]]) -> dict[tuple[str, str, str], dict[str, Any]]:
    return {(r["kind"], r["name"], r["version"]): r for r in resources if isinstance(r.get("kind"), str) and isinstance(r.get("name"), str) and isinstance(r.get("version"), str)}


def select_resource(resources: list[dict[str, Any]], kind: str, selector: str) -> dict[str, Any]:
    match = SELECTOR_RE.fullmatch(selector)
    if not match:
        raise ValueError(f"invalid selector: {selector}")
    name, caret_marker, requested = match.groups()
    candidates = [r for r in resources if r.get("kind") == kind and r.get("name") == name and isinstance(r.get("version"), str) and selector_matches(r["version"], requested, bool(caret_marker))]
    if not candidates:
        raise ValueError(f"selector {selector} does not resolve to {kind}")
    return max(candidates, key=lambda r: version_tuple(r["version"]))


def merge_values(low: Any, high: Any) -> Any:
    if isinstance(low, dict) and isinstance(high, dict):
        out = deepcopy(low)
        for key, value in high.items():
            out[key] = merge_values(out[key], value) if key in out else deepcopy(value)
        return out
    if isinstance(low, list) and isinstance(high, list):
        out = deepcopy(low)
        for item in high:
            if item not in out:
                out.append(deepcopy(item))
        return out
    return deepcopy(high)


def resolve_inherited_spec(resource: dict[str, Any], resources: list[dict[str, Any]], stack: tuple[tuple[str, str, str], ...] = ()) -> dict[str, Any]:
    key = (str(resource.get("kind")), str(resource.get("name")), str(resource.get("version")))
    if key in stack:
        raise ValueError(f"inheritance cycle: {' -> '.join('/'.join(k) for k in stack + (key,))}")
    spec = deepcopy((resource.get("doc") or {}).get("spec") or {})
    selector = spec.get("extends")
    if selector is None:
        return spec
    parent = select_resource(resources, str(resource.get("kind")), str(selector))
    parent_spec = resolve_inherited_spec(parent, resources, stack + (key,))
    return merge_values(parent_spec, spec)


def _overlay_matches(name: str, tags: set[str], match: dict[str, Any]) -> bool:
    contains = match.get("nameContains") or []
    tag_any = set(match.get("tagsAny") or [])
    return any(isinstance(fragment, str) and fragment in name for fragment in contains) or bool(tags & tag_any)


def quality_policy_files() -> list[Path]:
    configured = ((catalog().get("spec") or {}).get("qualityPolicyFiles") or ["QUALITY_POLICY.yaml"])
    if not isinstance(configured, list) or not configured:
        raise ValueError("catalog.yaml: spec.qualityPolicyFiles must be a non-empty list")
    return [ROOT / str(path) for path in configured]


def load_quality_policy() -> dict[str, Any]:
    merged: dict[str, Any] = {"domainOverlays": []}
    for index, path in enumerate(quality_policy_files()):
        if not path.is_file():
            raise ValueError(f"missing quality policy file: {path.relative_to(ROOT)}")
        doc = load_yaml(path)
        kind = doc.get("kind")
        if index == 0 and kind != "RegistryQualityPolicy":
            raise ValueError(f"{path.name}: first quality policy must be RegistryQualityPolicy")
        if index > 0 and kind not in {"RegistryQualityPolicy", "RegistryQualityPolicyExtension"}:
            raise ValueError(f"{path.name}: invalid quality policy kind {kind!r}")
        spec = doc.get("spec") or {}
        overlays = spec.get("domainOverlays") or []
        base = {k: v for k, v in spec.items() if k != "domainOverlays"}
        merged = merge_values(merged, base)
        if not isinstance(overlays, list):
            raise ValueError(f"{path.name}: domainOverlays must be a list")
        merged.setdefault("domainOverlays", []).extend(deepcopy(overlays))
    return merged


def effective_spec(kind: str, name: str, tags: set[str], resolved_spec: dict[str, Any], policy: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    spec = merge_values({}, policy.get("universal") or {})
    spec = merge_values(spec, ((policy.get("defaults") or {}).get(kind) or {}))
    applied: list[str] = []
    for overlay in policy.get("domainOverlays") or []:
        if not isinstance(overlay, dict):
            continue
        if _overlay_matches(name, tags, overlay.get("match") or {}):
            spec = merge_values(spec, overlay.get("apply") or {})
            applied.append(str(overlay.get("name") or "unnamed"))
    return merge_values(spec, resolved_spec), applied


def names_by_kind(resources: list[dict[str, Any]]) -> dict[str, set[str]]:
    result: dict[str, set[str]] = {}
    for item in resources:
        if isinstance(item.get("kind"), str) and isinstance(item.get("name"), str):
            result.setdefault(item["kind"], set()).add(item["name"])
    return result
