"""Fixed, provenance-preserving Jarvis master-semantics compiler overlay.

The overlay is installer-owned and applies only to the pinned upstream Hermes,
Orchestrator, and hermes-runtime declarations. Upstream bytes and identifiers
remain intact in the source snapshot; this module never edits that snapshot.
"""
from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from importlib.resources import files
from typing import Any, Mapping


OVERLAY_PATH = "registry/bundle_data/jarvis-master-semantics.json"
UPSTREAM_REPOSITORY = "https://github.com/Togarriapa/HermesAgent_Resources"
UPSTREAM_VERSION = "2.3.1"
UPSTREAM_REVISION = "113f42d33be9e0c8f0f47f5ca998e687323dec83"
UPSTREAM_TREE = "c0c994b5e0b96b90cfd2fc564ea8632dff124308"
OVERLAY_ID = "jarvis-master-semantics-v1"
APPROVAL_COMMIT = "76fa3f9237d5c6a0cf608f1039f72f70f68a2523"
OVERLAY_SHA256 = "3b8d50f01a9e14084efd2d5b9974abed1885a43efe65d45772705e94c0d4f028"


class JarvisSemanticsError(ValueError):
    """Pinned semantic overlay cannot be applied without ambiguity."""


def _read_overlay() -> tuple[dict[str, Any], bytes, str]:
    try:
        raw = files("hermes_installer").joinpath(
            "registry", "bundle_data", "jarvis-master-semantics.json").read_bytes()
        value = json.loads(raw)
    except Exception as exc:
        raise JarvisSemanticsError(f"fixed Jarvis semantics overlay is unavailable: {type(exc).__name__}") from None
    expected_upstream = {
        "repository": UPSTREAM_REPOSITORY,
        "catalog_version": UPSTREAM_VERSION,
        "revision": UPSTREAM_REVISION,
        "git_tree": UPSTREAM_TREE,
    }
    if (not isinstance(value, dict) or value.get("schema") != 1
            or value.get("overlay_id") != OVERLAY_ID
            or value.get("approval_commit") != APPROVAL_COMMIT
            or value.get("upstream") != expected_upstream
            or not isinstance(value.get("profiles"), dict)
            or set(value["profiles"]) != {"hermes", "orchestrator"}
            or not isinstance(value.get("bundles"), dict)
            or set(value["bundles"]) != {"hermes-runtime"}
            or not isinstance(value.get("authority_note"), str)):
        raise JarvisSemanticsError("fixed Jarvis semantics overlay metadata or source pin differs")
    digest = hashlib.sha256(raw).hexdigest()
    if digest != OVERLAY_SHA256:
        raise JarvisSemanticsError("fixed Jarvis semantics overlay bytes differ from their reviewed digest")
    return value, raw, digest


def overlay_identity() -> dict[str, str]:
    value, _raw, digest = _read_overlay()
    return {
        "overlay_id": value["overlay_id"],
        "approval_commit": value["approval_commit"],
        "path": OVERLAY_PATH,
        "sha256": digest,
        "upstream_revision": UPSTREAM_REVISION,
        "upstream_tree": UPSTREAM_TREE,
    }


def _apply_profile(profile_id: str, spec: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    overlay, _raw, _digest = _read_overlay()
    if source.get("revision") != UPSTREAM_REVISION or source.get("source_tree") != UPSTREAM_TREE:
        raise JarvisSemanticsError("semantic overlay source identity differs from pinned upstream")
    rules = overlay["profiles"].get(profile_id)
    result = deepcopy(dict(spec))
    if rules is None:
        return result
    if profile_id == "hermes":
        requires = result.get("requires")
        skills = requires.get("skills") if isinstance(requires, Mapping) else None
        response_contract = "hermes-response-contract@^1.0.0"
        if not isinstance(skills, list) or skills.count(response_contract) != 1:
            raise JarvisSemanticsError("pinned Hermes response-contract dependency differs")
        result["requires"] = {**dict(requires),
                              "skills": [item for item in skills if item != response_contract]}
        expected_output = {
            "contract": "hermes-six-section-v1",
            "requiredSections": [
                "Initial Question or Request", "Quick Answer / Result / Action",
                "Detailed Answer / Result / Action", "Agent Profiles That Contributed",
                "Opinions Against the Final Answer / Solution and Why", "Permissions Needed to Proceed",
            ],
            "alwaysRenderAllSections": True,
            "defaultStyle": "clear-cohesive-user-facing",
        }
        if result.get("output") != expected_output:
            raise JarvisSemanticsError("pinned Hermes output contract differs")
        result["output"] = deepcopy(rules["output"])
    if profile_id == "orchestrator":
        requires = result.get("requires")
        plugins = requires.get("plugins") if isinstance(requires, Mapping) else None
        kanban_plugin = "epic-kanban@^1.0.0"
        if not isinstance(plugins, list) or plugins.count(kanban_plugin) != 1:
            raise JarvisSemanticsError("pinned Orchestrator Kanban plugin dependency differs")
        result["requires"] = {**dict(requires),
                              "plugins": [item for item in plugins if item != kanban_plugin]}
    instructions = result.get("instructions")
    if not isinstance(instructions, list) or any(not isinstance(item, str) for item in instructions):
        raise JarvisSemanticsError(f"pinned {profile_id} instructions have an unsupported shape")
    for phrase in rules["remove_instructions"]:
        if instructions.count(phrase) != 1:
            raise JarvisSemanticsError(f"pinned {profile_id} source phrase is missing or ambiguous")
        instructions.remove(phrase)
    if any(phrase in instructions for phrase in rules["append_instructions"]):
        raise JarvisSemanticsError(f"pinned {profile_id} overlay appears to be applied twice")
    result["instructions"] = [*instructions, *rules["append_instructions"]]
    if profile_id == "orchestrator":
        kanban = result.get("kanban")
        if not isinstance(kanban, Mapping) or kanban.get("createOnEpicStart") is not True:
            raise JarvisSemanticsError("pinned Orchestrator Kanban source differs")
        result["kanban"] = {**dict(kanban), **rules["kanban"]}
    return result


def effective_profile_spec(profile_id: str, spec: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    """Return the Jarvis identity projection plus fixed master workflow overlay."""
    from .native import effective_native_profile_spec

    effective = effective_native_profile_spec(profile_id, spec)
    return _apply_profile(profile_id, effective, source)


def effective_bundle_spec(bundle_id: str, spec: Mapping[str, Any], source: Mapping[str, Any]) -> dict[str, Any]:
    overlay, _raw, _digest = _read_overlay()
    if source.get("revision") != UPSTREAM_REVISION or source.get("source_tree") != UPSTREAM_TREE:
        raise JarvisSemanticsError("semantic overlay source identity differs from pinned upstream")
    result = deepcopy(dict(spec))
    rules = overlay["bundles"].get(bundle_id)
    if rules is None:
        return result
    orchestration = result.get("orchestration")
    if not isinstance(orchestration, Mapping) or orchestration.get("perEpicKanban") is not True:
        raise JarvisSemanticsError("pinned Hermes runtime bundle Kanban source differs")
    result["orchestration"] = {**dict(orchestration), **rules["orchestration"]}
    return result
