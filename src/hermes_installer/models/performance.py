"""Executable, evidence-preserving GLM-5.2 cold/warm target benchmark."""
from __future__ import annotations

import json
import math
import os
import platform
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Mapping

from .artifacts import ArtifactManifest, MODEL_ID, MODEL_REVISION


@dataclass(frozen=True, slots=True)
class BenchmarkThresholds:
    warm_first_token_seconds: float = 30.0
    minimum_generation_tokens_per_second: float = 1.0
    core_chat_p95_seconds: float = 10.0

    def __post_init__(self) -> None:
        values = (self.warm_first_token_seconds, self.minimum_generation_tokens_per_second,
                  self.core_chat_p95_seconds)
        if any(not math.isfinite(v) or v <= 0 for v in values):
            raise ValueError("benchmark thresholds must be finite positive values")


@dataclass(frozen=True, slots=True)
class RequestMetrics:
    first_token_seconds: float
    total_seconds: float
    prompt_tokens: int | None
    generated_tokens: int | None
    tokens_per_second: float | None
    tool_call_attempted: bool
    tool_call_valid: bool
    resident_memory_bytes: int | None
    throttling_before: str | None
    throttling_after: str | None


@dataclass(frozen=True, slots=True)
class BenchmarkReport:
    status: str
    requested_model: str
    model_revision: str
    engine_revision: str
    target_architecture: str
    target_hostname: str
    target_id: str
    cold: RequestMetrics | None
    warm_trials: tuple[RequestMetrics, ...]
    warm_first_token_p95_seconds: float | None
    core_chat_p95_seconds: float | None
    ssd_read_bytes_per_second: float | None
    threshold_result: str
    threshold_values: Mapping[str, float]
    warnings: tuple[str, ...] = ()

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, indent=2) + "\n"


def _percentile95(values: Iterable[float]) -> float | None:
    ordered = sorted(values)
    if not ordered:
        return None
    # Nearest-rank p95, documented to avoid silently applying a library-specific convention.
    return ordered[max(0, math.ceil(0.95 * len(ordered)) - 1)]


def classify_benchmark(report: BenchmarkReport, thresholds: BenchmarkThresholds,
                        *, manifest: ArtifactManifest, measured_target: bool | None = None) -> str:
    if (manifest.model_id != MODEL_ID or manifest.revision != MODEL_REVISION
            or report.requested_model != MODEL_ID or report.model_revision != MODEL_REVISION):
        return "rejected_model_identity"
    machine_id = Path("/etc/machine-id")
    actual_id = machine_id.read_text(encoding="ascii").strip() if machine_id.is_file() else ""
    native_arm = platform.machine().casefold() in {"aarch64", "arm64"}
    if (not native_arm or report.target_architecture.casefold() not in {"aarch64", "arm64"}
            or report.target_hostname != socket.gethostname() or not report.target_id
            or report.target_id != actual_id or report.status != "complete"):
        return "pending_target_measurement"
    if report.cold is None or not report.warm_trials or report.ssd_read_bytes_per_second is None:
        return "pending_required_metrics"
    if any(trial.generated_tokens is None or trial.prompt_tokens is None for trial in (report.cold, *report.warm_trials)):
        return "pending_token_accounting"
    all_trials = (report.cold, *report.warm_trials)
    tool_trials = [trial for trial in all_trials if trial and trial.tool_call_attempted]
    if not tool_trials or any(not trial.tool_call_valid for trial in tool_trials):
        return "experimental_manual_tool_behavior_failed"
    if any(trial.resident_memory_bytes is None or trial.prompt_tokens is None or trial.generated_tokens is None for trial in all_trials):
        return "pending_required_metrics"
    if report.core_chat_p95_seconds is None:
        return "pending_auxiliary_responsiveness_measurement"
    if any(trial.throttling_before is None or trial.throttling_after is None
           for trial in (report.cold, *report.warm_trials)):
        return "pending_throttling_measurement"
    if any(trial.throttling_after != "throttled=0x0" for trial in (report.cold, *report.warm_trials)):
        return "experimental_manual_throttled"
    if (report.warm_first_token_p95_seconds is None
            or report.warm_first_token_p95_seconds > thresholds.warm_first_token_seconds
            or any(t.tokens_per_second is None or t.tokens_per_second < thresholds.minimum_generation_tokens_per_second for t in report.warm_trials)
            or (report.core_chat_p95_seconds is not None and report.core_chat_p95_seconds > thresholds.core_chat_p95_seconds)):
        return "experimental_manual_below_threshold"
    return "measured_interactive_candidate"


def _parse_sse_response(response: object, *, started_at: float, clock: Callable[[], float]) -> tuple[float, float, int | None, int | None, bool]:
    first_token = None
    final_usage = None
    called: dict[str, dict[str, str]] = {}
    while True:
        line = response.readline()  # type: ignore[attr-defined]
        if not line:
            break
        if not line.startswith(b"data:"):
            continue
        raw = line[5:].strip()
        if raw == b"[DONE]":
            break
        try:
            event = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("Colibri returned malformed server-sent events") from exc
        usage = event.get("usage")
        if isinstance(usage, dict):
            final_usage = usage
        choices = event.get("choices") or []
        for choice in choices:
            delta = choice.get("delta", {})
            content = delta.get("content")
            if content and first_token is None:
                first_token = clock() - started_at
            if delta.get("tool_calls") and first_token is None:
                first_token = clock() - started_at
            for call in delta.get("tool_calls", ()):
                fn = call.get("function", {})
                key = str(call.get("index", call.get("id", "0")))
                current = called.setdefault(key, {"name": "", "arguments": ""})
                current["name"] += str(fn.get("name", ""))
                current["arguments"] += str(fn.get("arguments", ""))
    ended = clock()
    prompt = final_usage.get("prompt_tokens") if final_usage else None
    generated = final_usage.get("completion_tokens") if final_usage else None
    valid_tool = False
    for call in called.values():
        if call["name"] != "benchmark_add":
            continue
        try:
            args = json.loads(call["arguments"])
        except json.JSONDecodeError:
            continue
        if args == {"a": 1, "b": 2}:
            valid_tool = True
            break
    return (first_token if first_token is not None else ended - started_at, ended - started_at,
            prompt if isinstance(prompt, int) else None,
            generated if isinstance(generated, int) else None, valid_tool)


def run_chat_trial(endpoint: str, token: str, *, prompt: str, tool_request: bool = False,
                   request_timeout: float = 600, max_tokens: int = 128,
                   memory_reader: Callable[[], int | None] = lambda: None,
                   throttle_reader: Callable[[], str | None] = lambda: None,
                   clock: Callable[[], float] = time.monotonic,
                   opener: Callable[..., object] = urllib.request.urlopen) -> RequestMetrics:
    if not endpoint.startswith("http://127.0.0.1:") and not endpoint.startswith("http://[::1]:"):
        raise ValueError("Colibri benchmark endpoint must be loopback HTTP")
    if not token or "\n" in token:
        raise ValueError("Colibri benchmark requires an in-memory protected API key")
    if request_timeout <= 0 or request_timeout > 600 or max_tokens < 1 or max_tokens > 2048:
        raise ValueError("benchmark request bounds are invalid")
    tools = ([{"type": "function", "function": {"name": "benchmark_add", "description": "Add two numbers", "parameters": {"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}}, "required": ["a", "b"]}}}] if tool_request else [])
    body: dict[str, object] = {"model": "glm-5.2-colibri", "messages": [{"role": "user", "content": prompt}], "max_tokens": max_tokens, "stream": True, "stream_options": {"include_usage": True}}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = {"type": "function", "function": {"name": "benchmark_add"}}
    request = urllib.request.Request(endpoint.rstrip("/") + "/v1/chat/completions",
        data=json.dumps(body).encode(), method="POST", headers={
            "Authorization": "Bearer " + token, "Content-Type": "application/json", "Accept": "text/event-stream"})
    throttling_before = throttle_reader()
    started = clock()
    response = opener(request, timeout=request_timeout)
    try:
        ttft, total, prompt_tokens, output_tokens, valid_tool = _parse_sse_response(response, started_at=started, clock=clock)
    finally:
        close = getattr(response, "close", None)
        if close:
            close()
    tps = (output_tokens / max(total - ttft, 1e-9)) if output_tokens is not None and total > ttft else None
    return RequestMetrics(ttft, total, prompt_tokens, output_tokens, tps, tool_request, valid_tool,
                          memory_reader(), throttling_before, throttle_reader())


def measure_ssd_read(path: Path, *, bytes_to_read: int = 256 * 1024 * 1024,
                     runner: Callable[..., object]) -> float:
    """Run a bounded, direct, read-only fio sample against one verified model shard."""
    if bytes_to_read <= 0 or bytes_to_read > 2 * 1024 * 1024 * 1024 or bytes_to_read % (1024 * 1024):
        raise ValueError("SSD benchmark is limited to an aligned 2 GiB read-only sample")
    if path.is_symlink() or not path.is_file() or path.stat().st_size < bytes_to_read:
        raise ValueError("SSD benchmark needs a real selected-model file at least as large as the bounded sample")
    fio = shutil.which("fio")
    if not fio:
        raise RuntimeError("fio is required for a direct-I/O SSD measurement; install it through the managed host and rerun")
    result = runner([fio, "--name=hermes-glm52-readonly", "--filename=" + str(path),
        "--readonly", "--rw=read", "--direct=1", "--ioengine=sync", "--bs=1m",
        "--size=" + str(bytes_to_read), "--output-format=json", "--output=-"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
    returncode = getattr(result, "returncode", getattr(result, "exit_code", None))
    stdout = getattr(result, "stdout", "") or ""
    if isinstance(stdout, bytes):
        stdout = stdout.decode("utf-8", errors="replace")
    if returncode:
        raise OSError("fio direct read-only SSD measurement failed")
    try:
        report = json.loads(stdout)
        read = report["jobs"][0]["read"]
        rate = read.get("bw_bytes")
        if rate is None:
            rate = float(read["bw"]) * 1024
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("fio did not return valid measured read throughput") from exc
    if not isinstance(rate, (int, float)) or not math.isfinite(rate) or rate <= 0:
        raise ValueError("fio returned an invalid SSD throughput")
    return float(rate)


def build_report(*, manifest: ArtifactManifest, engine_revision: str, target_architecture: str,
                 target_hostname: str, target_id: str, cold: RequestMetrics | None,
                 warm_trials: Iterable[RequestMetrics], ssd_read_bytes_per_second: float | None,
                 thresholds: BenchmarkThresholds, measured_target: bool,
                 core_chat_during_auxiliary_trials: Iterable[float] = (), warnings: Iterable[str] = ()) -> BenchmarkReport:
    warm = tuple(warm_trials)
    ttft_p95 = _percentile95(trial.first_token_seconds for trial in warm)
    core_p95 = _percentile95(core_chat_during_auxiliary_trials)
    status = "complete" if cold and warm and ssd_read_bytes_per_second is not None else "incomplete"
    report = BenchmarkReport(status, manifest.model_id, manifest.revision, engine_revision,
        target_architecture, target_hostname, target_id, cold, warm, ttft_p95, core_p95,
        ssd_read_bytes_per_second, "unclassified", {
            "warm_first_token_seconds": thresholds.warm_first_token_seconds,
            "minimum_generation_tokens_per_second": thresholds.minimum_generation_tokens_per_second,
            "core_chat_p95_seconds": thresholds.core_chat_p95_seconds,
        }, tuple(warnings))
    result = classify_benchmark(report, thresholds, manifest=manifest, measured_target=measured_target)
    from dataclasses import replace
    return replace(report, threshold_result=result)


def save_report(report: BenchmarkReport, destination: Path) -> None:
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    if destination.is_symlink() or temporary.is_symlink():
        raise PermissionError("benchmark evidence path must not be a symlink")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(report.to_json())
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, destination)


def interactive_default_eligible(report: BenchmarkReport) -> bool:
    return report.threshold_result == "measured_interactive_candidate" and report.status == "complete"


def run_glm_benchmark_workflow(*, manifest: ArtifactManifest, engine_revision: str,
                               target_architecture: str, target_hostname: str, target_id: str,
                               service, api_key: str, model_file: Path, warm_trials: int = 5,
                               thresholds: BenchmarkThresholds = BenchmarkThresholds(),
                               memory_reader: Callable[[], int | None] = lambda: None,
                               throttle_reader: Callable[[], str | None] = lambda: None,
                               fio_runner: Callable[..., object],
                               chat_opener: Callable[..., object] = urllib.request.urlopen) -> BenchmarkReport:
    """Run a fresh cold start, warm tool trials, and core chats during a read-only SSD test."""
    if warm_trials < 3 or warm_trials > 20:
        raise ValueError("the measured warm trial count must be between 3 and 20")
    if (manifest.model_id != MODEL_ID or manifest.revision != MODEL_REVISION
            or service.plan.model_id != "mastouri/GLM-5.2-colibri-int4-g64-with-int8-mtp"
            or service.plan.model_revision != MODEL_REVISION):
        raise ValueError("the benchmark route must use the exact requested GLM-5.2 artifact")
    if model_file.is_symlink() or not model_file.is_file():
        raise ValueError("SSD benchmark input must be a regular file from the selected model generation")
    try:
        relative_model = model_file.resolve(strict=True).relative_to(service.plan.model_directory.resolve(strict=True)).as_posix()
    except (OSError, ValueError) as exc:
        raise ValueError("SSD benchmark file is outside the service's selected model generation") from exc
    artifact = next((item for item in manifest.files if item.name == relative_model), None)
    if artifact is None or model_file.stat().st_size != artifact.size:
        raise ValueError("SSD benchmark file is not an exact pinned GLM-5.2 artifact")
    service.stop("prepare fresh cold benchmark")
    service.start()
    try:
        endpoint = f"http://127.0.0.1:{service.plan.bind_port}"
        cold = run_chat_trial(endpoint, api_key, prompt="Reply with a short greeting, then call benchmark_add with a=1 and b=2.",
            tool_request=True, memory_reader=memory_reader, throttle_reader=throttle_reader, opener=chat_opener)
        warm = tuple(run_chat_trial(endpoint, api_key,
            prompt="Call benchmark_add with a=1 and b=2, then answer with the sum.", tool_request=True,
            memory_reader=memory_reader, throttle_reader=throttle_reader, opener=chat_opener)
            for _ in range(warm_trials))
        # Direct I/O overlaps with short core requests. Colibri remains serial at its
        # generation API, so each chat is issued one at a time while fio reads the shard.
        from concurrent.futures import ThreadPoolExecutor
        core_latencies: list[float] = []
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="glm52-fio") as pool:
            storage = pool.submit(measure_ssd_read, model_file, runner=fio_runner)
            for _ in range(5):
                trial = run_chat_trial(endpoint, api_key, prompt="Reply with the word ready.", tool_request=False,
                    memory_reader=memory_reader, throttle_reader=throttle_reader, opener=chat_opener)
                core_latencies.append(trial.total_seconds)
            throughput = storage.result(timeout=125)
        return build_report(manifest=manifest, engine_revision=engine_revision,
            target_architecture=target_architecture, target_hostname=target_hostname, target_id=target_id,
            cold=cold, warm_trials=warm, ssd_read_bytes_per_second=throughput, thresholds=thresholds,
            measured_target=None, core_chat_during_auxiliary_trials=core_latencies)
    finally:
        service.stop("GLM-5.2 benchmark completed")
