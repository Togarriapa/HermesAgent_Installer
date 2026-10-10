"""Strict semantic contract tests for the fixed Graphify probe asset."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermes_installer.components.probes.graphify_result import (
    GraphifyProbeResultError,
    build_graphify_probe_result,
    validate_graphify_probe_result,
)


def _valid_graph() -> bytes:
    return json.dumps({
        "graph": {"schema_version": 1, "graphify_version": "0.9.82"},
        "nodes": [
            {"id": "entry-id", "label": "entrypoint.py", "source_file": "entrypoint.py"},
            {"id": "helper-id", "label": "helper.py", "source_file": "helper.py"},
        ],
        "links": [{
            "source": "entry-id", "target": "helper-id", "relation": "imports_from",
            "confidence": "EXTRACTED", "source_file": "entrypoint.py",
        }],
    }, sort_keys=True).encode()


def test_probe_asset_has_fixed_local_import_and_result_is_strict():
    package = Path(__file__).parents[2] / "src/hermes_installer/components/probes/graphify_fixture"
    entry = (package / "entrypoint.py").read_text()
    helper = (package / "helper.py").read_text()
    assert "from helper import build_graph" in entry
    assert "return build_graph()" in entry
    assert "graphify-fixture-connected" in helper
    assert "socket" not in entry + helper
    assert "urllib" not in entry + helper

    graph = _valid_graph()
    result = build_graphify_probe_result(graph)
    assert result["graph_sha256"] == hashlib.sha256(graph).hexdigest()
    assert result["verified_relation"] == {
        "source": "entrypoint.py", "target": "helper.py",
        "relation": "imports_from", "confidence": "EXTRACTED",
    }
    validate_graphify_probe_result(result)
    with pytest.raises(GraphifyProbeResultError, match="unexpected fields"):
        validate_graphify_probe_result({**result, "runtime_installed": True})


@pytest.mark.parametrize("mutate, reason", [
    (lambda g: g["graph"].update(schema_version=2), "schema version"),
    (lambda g: g["nodes"].pop(), "omitted"),
    (lambda g: g["links"][0].update(confidence="INFERRED"), "source-backed"),
    (lambda g: g["links"][0].update(relation="calls"), "exactly one"),
])
def test_graph_result_requires_expected_source_backed_relation(mutate, reason):
    graph = json.loads(_valid_graph())
    mutate(graph)
    with pytest.raises(GraphifyProbeResultError, match=reason):
        build_graphify_probe_result(json.dumps(graph).encode())


def test_graph_result_rejects_malformed_oversized_and_non_json_outputs():
    for data in (b"", b"not-json", b" " * (8 * 1024 * 1024 + 1)):
        with pytest.raises(GraphifyProbeResultError):
            build_graphify_probe_result(data)


def test_result_schema_is_closed_and_binds_pinned_upstream():
    path = Path(__file__).parents[2] / "src/hermes_installer/components/probes/graphify_probe_result.schema.json"
    schema = json.loads(path.read_text())
    assert schema["additionalProperties"] is False
    assert schema["properties"]["source_revision"]["const"] == "5b74d7d74911cf435c8f1636b6f96ea202cc6246"
    assert schema["properties"]["network"]["const"] == "deny"
