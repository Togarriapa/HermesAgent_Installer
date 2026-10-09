from __future__ import annotations

import json
import socket
import urllib.request
from pathlib import Path

import pytest

from hermes_installer.models.artifacts import ArtifactManifest, MODEL_BYTES, MODEL_ID, MODEL_REVISION
from hermes_installer.models.performance import (
    BenchmarkReport, BenchmarkThresholds, RequestMetrics, _decode_http_response,
    _parse_sse_response, classify_benchmark, make_colibri_connector_opener,
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
            self.events = iter([b"data: " + json.dumps(event).encode() + b"\n" for event in events] + [b"data: [DONE]\n"])
        def readline(self):
            return next(self.events, b"")

    events = [
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "benchmark_", "arguments": '{"a":'}}]}}]},
        {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "add", "arguments": '1,"b":2}'}}]}}]},
        {"usage": {"prompt_tokens": 5, "completion_tokens": 3}, "choices": []},
    ]
    _, _, prompt, completion, valid = _parse_sse_response(Lines(events), started_at=1.0, clock=lambda: 2.0)
    assert (prompt, completion, valid) == (5, 3, True)


def test_colibri_chat_route_uses_exact_connector_and_bounded_http_framing() -> None:
    body = b'data: {"choices":[{"delta":{"content":"ok"}}]}\n\ndata: [DONE]\n\n'
    response = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + (
        f"{len(body):X}\r\n".encode() + body + b"\r\n0\r\n\r\n")

    class Stream:
        generation = "g-7"
        expires_monotonic = 30.0
        max_frame_bytes = 256
        remaining_byte_budget = 4096
        def __init__(self): self.sent = bytearray(); self.offset = 0; self.closed = False
        def write(self, value): self.sent.extend(value)
        def read(self, maximum):
            value = response[self.offset:self.offset + maximum]
            self.offset += len(value)
            return value
        def close(self): self.closed = True

    class Connector:
        def __init__(self): self.stream = Stream(); self.args = None
        def open(self, **kwargs): self.args = kwargs; return self.stream

    connector = Connector()
    opener = make_colibri_connector_opener(connector, enrollment_id="colibri-enrollment",
        generation="g-7", session_id="chat-session", clock=lambda: 10.0)
    request = urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions",
        data=b'{"stream":true}', method="POST", headers={
            "Authorization": "Bearer protected-memory-token", "Content-Type": "application/json",
            "Accept": "text/event-stream"})
    result = opener(request, timeout=12)
    assert result.readline() == body.splitlines(keepends=True)[0]
    assert connector.args == {
        "enrollment_id": "colibri-enrollment", "generation": "g-7", "target_id": "colibri-main",
        "approved_route_id": "colibri-openai-v1", "session_id": "chat-session", "deadline": 22.0,
    }
    sent = connector.stream.sent.decode("ascii")
    assert sent.startswith("POST /v1/chat/completions HTTP/1.1\r\n")
    assert "Authorization: Bearer protected-memory-token\r\n" in sent
    assert "\r\nContent-Length: 15\r\nConnection: close\r\n\r\n" in sent
    assert connector.stream.closed


def test_colibri_connector_rejects_caller_route_and_mismatched_generation() -> None:
    class Stream:
        generation = "other-generation"
        expires_monotonic = 30.0
        max_frame_bytes = 512
        remaining_byte_budget = 4096
        def __init__(self): self.closed = False
        def write(self, data): pass
        def read(self, maximum): return b""
        def close(self): self.closed = True

    class Connector:
        def __init__(self): self.stream = Stream(); self.calls = 0
        def open(self, **kwargs): self.calls += 1; return self.stream

    connector = Connector()
    opener = make_colibri_connector_opener(connector, enrollment_id="e", generation="g",
        session_id="s", clock=lambda: 10.0)
    wrong_path = urllib.request.Request("http://127.0.0.1:8000/v1/models", data=b"{}", method="POST",
        headers={"Authorization": "Bearer t", "Content-Type": "application/json", "Accept": "text/event-stream"})
    with pytest.raises(ValueError, match="fixed OpenAI chat-completions"):
        opener(wrong_path, timeout=5)
    assert connector.calls == 0
    request = urllib.request.Request("http://127.0.0.1:8000/v1/chat/completions", data=b"{}", method="POST",
        headers={"Authorization": "Bearer t", "Content-Type": "application/json", "Accept": "text/event-stream"})
    with pytest.raises(RuntimeError, match="invalid generation"):
        opener(request, timeout=5)
    assert connector.calls == 1 and connector.stream.closed


def test_colibri_http_response_rejects_error_and_truncated_chunk() -> None:
    with pytest.raises(RuntimeError, match="HTTP 403"):
        _decode_http_response(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
    with pytest.raises(ValueError, match="truncated or oversized"):
        _decode_http_response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nno\r\n")


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


def test_classifier_requires_telemetry_and_applies_measured_thresholds(monkeypatch, tmp_path: Path) -> None:
    from dataclasses import replace
    import hermes_installer.models.performance as performance
    item = type("Item", (), {"name": "tiny", "size": 1, "digest": "0" * 64, "digest_algorithm": "sha256", "url": ""})()
    manifest = ArtifactManifest(MODEL_ID, MODEL_REVISION, "q", "int8", (item,), 1)
    metric = RequestMetrics(2.0, 8.0, 20, 12, 2.0, True, True, 2 * 1024**3,
                            "throttled=0x0", "throttled=0x0")
    machine_id_path = tmp_path / "machine-id"
    machine_id_path.write_text("fixture-id\n")
    machine_id = machine_id_path.read_text().strip()
    report = BenchmarkReport("complete", MODEL_ID, MODEL_REVISION, "bf2442915d6e3dd4cdfd2eb9c2a3d2aa44a25850",
        "aarch64", socket.gethostname(), machine_id, metric, (metric, metric, metric), 2.0, 5.0,
        10_000_000.0, "unclassified", {})
    monkeypatch.setattr(performance.platform, "machine", lambda: "aarch64")
    monkeypatch.setattr(performance, "Path", lambda path: machine_id_path if str(path) == "/etc/machine-id" else Path(path))
    thresholds = BenchmarkThresholds()
    assert classify_benchmark(report, thresholds, manifest=manifest) == "measured_interactive_candidate"
    no_throttle = replace(report, cold=replace(metric, throttling_after=None))
    assert classify_benchmark(no_throttle, thresholds, manifest=manifest) == "pending_throttling_measurement"
    slow = replace(report, warm_first_token_p95_seconds=31.0)
    assert classify_benchmark(slow, thresholds, manifest=manifest) == "experimental_manual_below_threshold"
