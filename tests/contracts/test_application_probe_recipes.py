from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pytest

from hermes_installer.authority.application_probe_recipes import (
    ApplicationProbeRecipeUnavailable,
    resolve_application_qualification_effect_recipe,
    validate_application_qualification_effect_result,
    verify_qualification_effect_member,
    verify_qualification_effect_member_set,
)


ROOT = Path(__file__).resolve().parents[2]
ROWS = {
    "graphify": ("qualify-graphify-v1", "graphify-code-fixture", "python", "Graphify-Labs/graphify", "5b74d7d74911cf435c8f1636b6f96ea202cc6246"),
    "browser-use": ("qualify-browser-use-v1", "browser-fixture", "python", "browser-use/browser-use", "c75e8476e26d18b7617643bc2ae082fae8eae431"),
    "scrapegraph-ai": ("qualify-scrapegraph-v1", "scrapegraph-local-fixture", "python", "ScrapeGraphAI/Scrapegraph-ai", "194055e203afce41ed4e70365dbc416bad756115"),
    "hyperframes": ("qualify-hyperframes-v1", "hyperframes-render-fixture", "node", "heygen-com/hyperframes", "46f6cb356785bed79e1ce7b79d7e7accc697786a"),
}


def _recipe(app: str):
    workflow, _workload, runtime, identity, revision = ROWS[app]
    return resolve_application_qualification_effect_recipe(app, workflow_id=workflow,
        runtime_kind=runtime, source_identity=identity, source_revision=revision)


def test_four_fixed_workflows_bind_exact_pinned_members():
    for app, (_workflow, workload, _runtime, _identity, _revision) in ROWS.items():
        recipe = _recipe(app)
        assert recipe.workload_id == workload
        assert recipe.members and len({m.member_id for m in recipe.members}) == len(recipe.members)
        for member in recipe.members:
            body = (ROOT / member.relative_path).read_bytes()
            assert len(body) == member.size_bytes
            assert hashlib.sha256(body).hexdigest() == member.sha256
            verify_qualification_effect_member(recipe, member.member_id, body)


def test_recipe_rejects_wrong_workflow_runtime_or_source_revision():
    row = ROWS["hyperframes"]
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="no complete reviewed"):
        resolve_application_qualification_effect_recipe("hyperframes", workflow_id=row[0],
            runtime_kind="python", source_identity=row[3], source_revision=row[4])
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="no complete reviewed"):
        resolve_application_qualification_effect_recipe("hyperframes", workflow_id="other",
            runtime_kind=row[2], source_identity=row[3], source_revision=row[4])
    recipe = _recipe("graphify")
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="reviewed release pin"):
        verify_qualification_effect_member(recipe, recipe.entrypoint_member_id, b"changed")
    complete = {row.member_id: (ROOT / row.relative_path).read_bytes() for row in recipe.members}
    verify_qualification_effect_member_set(recipe, complete)
    complete.pop(recipe.entrypoint_member_id)
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="closure is incomplete"):
        verify_qualification_effect_member_set(recipe, complete)


def test_graphify_result_reads_private_actual_graph_and_checks_edge(tmp_path):
    work = tmp_path / "graph"
    output = work / "graphify-out"
    output.mkdir(parents=True, mode=0o700)
    os.chmod(work, 0o700)
    os.chmod(output, 0o700)
    graph = {
        "graph": {"schema_version": 1},
        "nodes": [
            {"id": "entry", "label": "entrypoint", "source_file": "entrypoint.py"},
            {"id": "helper", "label": "helper", "source_file": "helper.py"},
        ],
        "links": [{"source": "entry", "target": "helper", "relation": "imports_from",
                   "confidence": "EXTRACTED", "source_file": "entrypoint.py"}],
    }
    (output / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    result = validate_application_qualification_effect_result(_recipe("graphify"),
        [{"exit_code": 0, "stdout": "", "stderr": ""}], work_roots={"graphify": str(work)})
    assert json.loads(result.canonical_result)["verified_relation"]["confidence"] == "EXTRACTED"
    graph["links"].clear()
    (output / "graph.json").write_text(json.dumps(graph), encoding="utf-8")
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="semantic contract"):
        validate_application_qualification_effect_result(_recipe("graphify"),
            [{"exit_code": 0}], work_roots={"graphify": str(work)})


def test_browser_use_result_binds_owned_loopback_fixture_and_effect():
    url = "http://127.0.0.1:43127/fixture"
    proof = {
        "schema_version": 1, "navigation_url": url, "navigation_succeeded": True,
        "page_title": "Hermes qualification fixture", "initial_text": "ready",
        "click_succeeded": True, "interaction_text": "interaction-ok",
        "screenshot_format": "png", "screenshot_bytes": 128, "screenshot_sha256": "a" * 64,
    }
    stage = {"exit_code": 0, "stdout": "HERMES_BROWSER_USE_PROOF=" + json.dumps(proof) + "\n"}
    result = validate_application_qualification_effect_result(_recipe("browser-use"), [stage],
        expected_fixture_url=url)
    assert json.loads(result.canonical_result)["click_succeeded"] is True
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="owned fixture"):
        validate_application_qualification_effect_result(_recipe("browser-use"), [stage],
            expected_fixture_url="http://127.0.0.1:43128/fixture")


def test_scrapegraph_result_requires_local_mock_zero_network_and_zero_cost():
    proof = {
        "schema_version": 1, "source_revision": ROWS["scrapegraph-ai"][4],
        "upstream_class": "scrapegraphai.graphs.SmartScraperGraph",
        "upstream_source": "/private/app/scrapegraphai/__init__.py",
        "nodes": ["Fetch", "GenerateAnswer"], "source_kind": "local_dir",
        "local_fetch_calls": 1, "model": "allowlisted-fixture-mock", "model_calls": 1,
        "observed_fixture_values": True,
        "structured_result": {"name": "Cedar Mug", "price": "$18.50"},
        "network_attempts": 0, "telemetry_enabled": False, "metered_cost_usd": 0,
    }
    stage = {"exit_code": 0, "stdout": "HERMES_SCRAPEGRAPH_AI_PROOF=" + json.dumps(proof) + "\n"}
    result = validate_application_qualification_effect_result(_recipe("scrapegraph-ai"), [stage])
    assert json.loads(result.canonical_result)["source_kind"] == "local_dir"
    proof["network_attempts"] = 1
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="semantic contract"):
        validate_application_qualification_effect_result(_recipe("scrapegraph-ai"),
            [{"exit_code": 0, "stdout": "HERMES_SCRAPEGRAPH_AI_PROOF=" + json.dumps(proof) + "\n"}])


def test_hyperframes_result_requires_all_three_actual_stage_outputs_and_changed_frames(tmp_path):
    work = tmp_path / "render"
    work.mkdir(mode=0o700)
    (work / "rendered.mp4").write_bytes(b"bounded-fixture-render-bytes")
    media = {"streams": [{"index": 0, "codec_name": "h264", "codec_type": "video",
        "width": 320, "height": 180, "pix_fmt": "yuv420p", "avg_frame_rate": "24/1",
        "nb_read_frames": "48"}], "format": {"duration": "2.0", "size": "28"}}
    framehash = "#tb 0: 1/24\n#dimensions 0: 320x180\n#stream#, dts, pts, duration, size, hash\n0, 12, 12, 1, 86400, " + "a" * 32 + "\n0, 36, 36, 1, 86400, " + "b" * 32 + "\n"
    stages = [
        {"exit_code": 0, "stdout": "", "stderr": ""},
        {"exit_code": 0, "stdout": json.dumps(media), "stderr": ""},
        {"exit_code": 0, "stdout": framehash, "stderr": ""},
    ]
    result = validate_application_qualification_effect_result(_recipe("hyperframes"), stages,
        work_roots={"hyperframes": str(work), "hyperframes-fixture": str(tmp_path / "fixture")})
    assert json.loads(result.canonical_result)["distinct_sampled_frames"] == 2
    stages[2] = {"exit_code": 0, "stdout": framehash.replace("b" * 32, "a" * 32), "stderr": ""}
    with pytest.raises(ApplicationProbeRecipeUnavailable, match="semantic contract"):
        validate_application_qualification_effect_result(_recipe("hyperframes"), stages,
            work_roots={"hyperframes": str(work)})
