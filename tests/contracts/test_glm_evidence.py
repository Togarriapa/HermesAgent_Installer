from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest

from hermes_installer.models.artifacts import ArtifactManifest, MODEL_BYTES, MODEL_ID, MODEL_REVISION
from hermes_installer.models.performance import (
    BenchmarkReport, BenchmarkThresholds, RequestMetrics, _parse_sse_response, classify_benchmark,
)

ROOT = Path(__file__).resolve().parents[2]


def test_exact_reviewed_glm_manifest_inventory() -> None:
    manifest = ArtifactManifest.from_metadata(ROOT / "planning/glm52-artifact-metadata.json")
    assert manifest.model_id == MODEL_ID
    assert manifest.revision == MODEL_REVISION
    assert len(manifest.files) == 149
    assert manifest.total_bytes == MODEL_BYTES == 429_276_220_139
    assert manifest.declared_storage_bytes == 429_276_080_522
    assert manifest.fully_verifiable
    assert {f.digest_algorithm for f in manifest.files} <= {"sha256", "git-sha1"}
    assert any(f.name == "out-mtp-00000.safetensors" for f in manifest.files)


def test_sse_tool_call_fragments_are_joined_and_arguments_are_checked() -> None:
    class Lines:
        def __init__(self, events):
            self.events = iter([b"data: " + json.dumps(e).encode() + b"\n", b"data: [DONE]\n"])
        def readline(self):
            return next(self.events, b"")

    events = [
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "benchmark_", "arguments": '{"a":'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "add", "arguments": '1,"b":2}'}}]}}]},
        {"usage": {"prompt_tokens": 5, "completion_tokens": 3}, "choices": []},
    ]
    _, _, prompt, completion, valid = _parse_sse_response(Lines(events), started_at=1.0, clock=lambda: 2.0)
    assert (prompt, completion, valid) == (5, 3, True)


def test_classifier_never_promotes_on_host_benchmark_or_missing_telemetry(tmp_path: Path, monkeypatch) -> None:
    # Even a caller-authored complete report and legacy boolean cannot convert this host into Pi evidence.
    item = type("Item", (), {"name": "tiny", "size": 1, "digest": "0" * 64, "digest_algorithm": "sha256", "url": ""})()
    from hermes_installer.models.artifacts import ArtifactManifest
    manifest = ArtifactManifest(MODEL_ID, MODEL_REVISION, "q", "int8", (item,), 1)
    metric = RequestMetrics(1.0, 3.0, 10, 2, 1.0, True, True, 1024, None, None)
    report = BenchmarkReport("complete", MODEL_ID, MODEL_REVISION, "bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850",
        "aarch64", "Pi", "machine-id", metric, (metric,), 1.0, 1.0, 1.0, "unclassified", {})
    monkeypatch.setattr("hermes_installer.models.performance.platform.machine", lambda: "arm64")
    monkeypatch.setattr("hermes_installer.models.performance.socket.gethostname", lambda: "not-Pi")
    assert classify_benchmark(report, BenchmarkThresholds(), manifest=manifest, measured_target=True) == "pending_target_measurement"


def test_classifier_requires_telemetry_and_applies_measured_thresholds(monkeypatch) -> None:
    from dataclasses import replace
    import hermes_installer.models.performance as performance
    item = type("Item", (), {"name": "tiny", "size": 1, "digest": "0" * 64, "digest_algorithm": "sha256", "url": ""})()
    manifest = ArtifactManifest(MODEL_ID, MODEL_REVISION, "q", "int8", (item,), 1)
    metric = RequestMetrics(2.0, 8.0, 20, 12, 2.0, True, True, 2 * 1024**3,
                            "throttled=0x0", "throttled=0x0")
    machine_id_path = Path("/etc/machine-id")
    machine_id = machine_id_path.read_text().strip() if machine_id_path.is_file() else "fixture-id"
    report = BenchmarkReport("complete", MODEL_ID, MODEL_REVISION, "bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850",
        "aarch64", socket.gethostname(), machine_id, metric, (metric, metric, metric), 2.0, 5.0,
        10_000_000.0, "unclassified", {})
    monkeypatch.setattr(performance.platform, "machine", lambda: "aarch64")
    thresholds = BenchmarkThresholds()
    assert classify_benchmark(report, thresholds, manifest=manifest) == "measured_interactive_candidate"
    no_throttle = replace(report, cold=replace(metric, throttling_after=None))
    assert classify_benchmark(no_throttle, thresholds, manifest=manifest) == "pending_throttling_measurement"
    slow = replace(report, warm_first_token_p95_seconds=31.0)
    assert classify_benchmark(slow, thresholds, manifest=manifest) == "experimental_manual_below_threshold"
