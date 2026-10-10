"""Strict semantic result checks for the pinned Graphify code-only probe.

This validates Graphify's persisted graph output. It does not claim that a
runtime was installed, that the graph was produced by a trusted process, or
that the target hardware accepted the application.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


PINNED_GRAPHIFY_REVISION = "5b74d7d74911cf435c8f1636b6f96ea202cc6246"
GRAPHIFY_GRAPH_SCHEMA_VERSION = 1
PROBE_RESULT_SCHEMA_VERSION = 1
EXPECTED_SOURCE_FILES = ("entrypoint.py", "helper.py")


class GraphifyProbeResultError(ValueError):
    """The pinned Graphify run did not produce the expected local graph."""


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise GraphifyProbeResultError(f"Graphify {label} must be an object")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise GraphifyProbeResultError(f"Graphify {label} must be a non-empty string")
    return value


def build_graphify_probe_result(graph_bytes: bytes) -> dict[str, Any]:
    """Validate graph.json and return the exact, versioned result envelope.

    The pinned Graphify v8 source persists ``graph.schema_version`` and emits
    canonical ``nodes`` and ``links`` (with ``edges`` accepted for its
    documented/raw graph form). This probe requires concrete source nodes for
    both fixture members and a source-backed EXTRACTED import edge joining
    them. Merely producing valid JSON or a non-empty graph is insufficient.
    """
    if type(graph_bytes) is not bytes or not graph_bytes or len(graph_bytes) > 8 * 1024 * 1024:
        raise GraphifyProbeResultError("Graphify graph output is absent or exceeds the 8 MiB probe bound")
    try:
        graph = json.loads(graph_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise GraphifyProbeResultError("Graphify graph output is not valid UTF-8 JSON") from None
    root = _object(graph, "graph root")
    metadata = _object(root.get("graph"), "graph metadata")
    if type(metadata.get("schema_version")) is not int or metadata["schema_version"] != GRAPHIFY_GRAPH_SCHEMA_VERSION:
        raise GraphifyProbeResultError("Graphify graph schema version is not the pinned v8 schema")
    nodes = root.get("nodes")
    links = root.get("links", root.get("edges"))
    if not isinstance(nodes, list) or not isinstance(links, list):
        raise GraphifyProbeResultError("Graphify output must contain node and edge arrays")

    by_source: dict[str, Mapping[str, Any]] = {}
    for raw in nodes:
        node = _object(raw, "node")
        source_file = node.get("source_file")
        if source_file in EXPECTED_SOURCE_FILES:
            if source_file in by_source:
                raise GraphifyProbeResultError("Graphify output duplicated a fixture source node")
            by_source[source_file] = node
    if set(by_source) != set(EXPECTED_SOURCE_FILES):
        raise GraphifyProbeResultError("Graphify output omitted one or more fixed fixture source nodes")
    for filename, node in by_source.items():
        _string(node.get("id"), f"{filename} node id")
        _string(node.get("label"), f"{filename} node label")

    entry_id = by_source["entrypoint.py"]["id"]
    helper_id = by_source["helper.py"]["id"]
    matching = []
    for raw in links:
        edge = _object(raw, "edge")
        if (edge.get("source") == entry_id and edge.get("target") == helper_id
                and edge.get("relation") == "imports_from"):
            matching.append(edge)
    if len(matching) != 1:
        raise GraphifyProbeResultError("Graphify output must have exactly one entrypoint-to-helper import edge")
    edge = matching[0]
    if edge.get("confidence") != "EXTRACTED" or edge.get("source_file") != "entrypoint.py":
        raise GraphifyProbeResultError("Graphify import edge is not source-backed extracted evidence")

    result = {
        "schema_version": PROBE_RESULT_SCHEMA_VERSION,
        "application_id": "graphify",
        "source_revision": PINNED_GRAPHIFY_REVISION,
        "graph_schema_version": GRAPHIFY_GRAPH_SCHEMA_VERSION,
        "graph_sha256": hashlib.sha256(graph_bytes).hexdigest(),
        "fixture_sources": list(EXPECTED_SOURCE_FILES),
        "verified_relation": {
            "source": "entrypoint.py",
            "target": "helper.py",
            "relation": "imports_from",
            "confidence": "EXTRACTED",
        },
        "network": "deny",
    }
    validate_graphify_probe_result(result)
    return result


def validate_graphify_probe_result(result: Any) -> None:
    """Enforce the exact public result envelope; extra or missing keys fail."""
    root = _object(result, "probe result")
    expected = {
        "schema_version", "application_id", "source_revision", "graph_schema_version",
        "graph_sha256", "fixture_sources", "verified_relation", "network",
    }
    if set(root) != expected:
        raise GraphifyProbeResultError("Graphify probe result has missing or unexpected fields")
    if (type(root["schema_version"]) is not int or root["schema_version"] != PROBE_RESULT_SCHEMA_VERSION
            or root["application_id"] != "graphify"
            or root["source_revision"] != PINNED_GRAPHIFY_REVISION
            or type(root["graph_schema_version"]) is not int
            or root["graph_schema_version"] != GRAPHIFY_GRAPH_SCHEMA_VERSION
            or root["network"] != "deny"):
        raise GraphifyProbeResultError("Graphify probe result identity, version, or network policy is invalid")
    digest = root["graph_sha256"]
    if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise GraphifyProbeResultError("Graphify probe result graph digest is malformed")
    if root["fixture_sources"] != list(EXPECTED_SOURCE_FILES):
        raise GraphifyProbeResultError("Graphify probe result fixture membership is invalid")
    relation = _object(root["verified_relation"], "verified relation")
    if (set(relation) != {"source", "target", "relation", "confidence"}
            or dict(relation) != {
                "source": "entrypoint.py", "target": "helper.py",
                "relation": "imports_from", "confidence": "EXTRACTED",
            }):
        raise GraphifyProbeResultError("Graphify probe result relation is invalid")
