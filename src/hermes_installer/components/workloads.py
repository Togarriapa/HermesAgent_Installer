"""Bounded on-demand dispatch for installer-registered component workloads.

Requests contain only a fixed workload ID and its narrow parameters. They
never carry executable, argv, environment, limits, or capability declarations.
The injected runner receives reviewed ``ComponentInvocation`` values only.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
import json
import math
import re
import os
import stat
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from threading import Lock
from typing import Callable, Mapping

from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    build_graphify_code_fixture,
    build_hyperframes_probe_invocation,
    build_hyperframes_render_fixture,
    stage_graphify_fixture,
)
from hermes_installer.components.browser_use import build_browser_use_fixture_invocation
from hermes_installer.components.runtime_source import VerifiedComponentGeneration
from hermes_installer.components.scrapegraph_ai import (
    build_scrapegraph_ai_fixture_invocation,
    verify_scrapegraph_ai_fixture_result,
)


@dataclass(frozen=True, slots=True)
class Workload:
    """Untrusted request shape; executable policy is resolved from the registry."""

    id: str
    arguments: Mapping[str, object] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class _Definition:
    argument_names: frozenset[str]
    capabilities: frozenset[str]
    memory_mb: int
    timeout_seconds: int
    network_scope: str
    account_requirement: str | None
    metered_cost_usd: Decimal
    build: Callable[[Mapping[str, object], Mapping[str, str], Mapping[str, str],
                     Mapping[str, VerifiedComponentGeneration]], tuple[ComponentInvocation, ...]]
    verify: Callable[[object, Mapping[str, str]], object] | None = None


def _browser_fixture(args, runtime_roots, work_roots, source_generations):
    url = args.get("fixture_url")
    if not isinstance(url, str):
        raise ValueError("browser-fixture requires a literal loopback fixture_url")
    invocation = build_browser_use_fixture_invocation(
        runtime_roots["browser-use"], url, work_roots["browser-use"]
    )
    return (invocation,)


def _verify_browser_fixture(result: object, work_roots: Mapping[str, str]) -> object:
    from hermes_installer.components.browser_use import verify_browser_use_fixture_result
    try:
        return verify_browser_use_fixture_result(result)
    except Exception as exc:
        raise RuntimeError("Browser Use fixture did not prove navigation, interaction, and screenshot") from exc


def _graphify_fixture(args, runtime_roots, work_roots, source_generations):
    if args:
        raise ValueError("graphify-code-fixture takes no caller-controlled paths")
    stage_graphify_fixture(work_roots["graphify-fixture"])
    return build_graphify_code_fixture(
        runtime_roots["graphify"], work_roots["graphify-fixture"], work_roots["graphify"]
    )


def _verify_graphify_fixture(result: object, work_roots: Mapping[str, str]) -> object:
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise RuntimeError("Graphify query did not exit successfully")
    work_root = Path(work_roots["graphify"])
    graph_path = work_root / "graphify-out" / "graph.json"
    try:
        root_info = work_root.lstat()
        graph_info = graph_path.lstat()
        output_dir = graph_path.parent.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                or root_info.st_mode & 0o077 or work_root.resolve(strict=True) != work_root
                or not stat.S_ISDIR(output_dir.st_mode) or output_dir.st_uid != os.geteuid()
                or output_dir.st_mode & 0o077 or graph_path.parent.resolve(strict=True) != graph_path.parent
                or not stat.S_ISREG(graph_info.st_mode) or graph_info.st_uid != os.geteuid()
                or graph_info.st_nlink != 1 or graph_info.st_mode & 0o022
                or graph_info.st_size > 16 * 1024 * 1024):
            raise RuntimeError("Graphify output is not a bounded private regular file")
        fd = os.open(graph_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if (opened.st_ino != graph_info.st_ino or opened.st_dev != graph_info.st_dev
                    or opened.st_nlink != 1 or not stat.S_ISREG(opened.st_mode)
                    or opened.st_size > 16 * 1024 * 1024):
                raise RuntimeError("Graphify output changed during verification")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                document = json.load(stream)
        finally:
            os.close(fd)
    except FileNotFoundError as exc:
        raise RuntimeError("Graphify did not produce graph.json") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("Graphify output cannot be safely parsed") from exc
    if not isinstance(document, dict) or not isinstance(document.get("nodes"), list):
        raise RuntimeError("Graphify output has no node catalog")
    node_ids: dict[str, str] = {}
    for node in document["nodes"]:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            continue
        source = node.get("source_file")
        if isinstance(source, str) and PurePosixPath(source.replace("\\", "/")).name in {"entrypoint.py", "helper.py"}:
            node_ids[PurePosixPath(source.replace("\\", "/")).name] = node["id"]
    if set(node_ids) != {"entrypoint.py", "helper.py"}:
        raise RuntimeError("Graphify graph does not contain both fixture source files")
    edges = document.get("edges", document.get("links", []))
    if not isinstance(edges, list):
        raise RuntimeError("Graphify output has no edge catalog")
    connected = any(isinstance(edge, dict)
                    and {edge.get("source"), edge.get("target")} ==
                    {node_ids["entrypoint.py"], node_ids["helper.py"]}
                    for edge in edges)
    if not connected:
        raise RuntimeError("Graphify graph does not connect the fixture entrypoint and helper")
    return {"fixture_sources": 2, "fixture_connection": True,
            "node_count": len(document["nodes"]), "edge_count": len(edges)}


def _hyperframes_fixture(args, runtime_roots, work_roots, source_generations):
    if args:
        raise ValueError("hyperframes-render-fixture takes no caller-controlled paths")
    return (
        build_hyperframes_render_fixture(
            runtime_roots["hyperframes"], work_roots["hyperframes-fixture"],
            work_roots["hyperframes"],
        ),
        build_hyperframes_probe_invocation(
            runtime_roots["ffprobe"], work_roots["hyperframes"],
        ),
    )


def _verify_hyperframes_fixture(result: object, work_roots: Mapping[str, str]) -> object:
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise RuntimeError("Hyperframes output probe did not exit successfully")
    output = result.get("stdout")
    if not isinstance(output, str):
        raise RuntimeError("Hyperframes output probe returned no structured media metadata")
    try:
        metadata = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Hyperframes output probe returned invalid JSON") from exc
    if not isinstance(metadata, dict):
        raise RuntimeError("Hyperframes output probe returned invalid media metadata")
    streams = metadata.get("streams")
    fmt = metadata.get("format")
    if not isinstance(streams, list) or not streams or not isinstance(fmt, dict):
        raise RuntimeError("Hyperframes output is missing a video stream or duration")
    video = next((stream for stream in streams if isinstance(stream, dict)
                  and stream.get("codec_type") == "video"), None)
    if video is None:
        raise RuntimeError("Hyperframes output has no video stream")
    duration_value = fmt.get("duration")
    frames_value = video.get("nb_read_frames")
    try:
        duration = float(duration_value) if isinstance(duration_value, (str, int, float)) else math.nan
    except ValueError:
        duration = math.nan
    frames = int(frames_value) if isinstance(frames_value, str) and re.fullmatch(r"[0-9]{1,4}", frames_value) else frames_value
    width, height = video.get("width"), video.get("height")
    if (isinstance(duration_value, bool) or not math.isfinite(duration) or not 0 < duration <= 30
            or isinstance(frames, bool) or not isinstance(frames, int) or not 1 <= frames <= 900
            or isinstance(width, bool) or not isinstance(width, int) or not 1 <= width <= 1920
            or isinstance(height, bool) or not isinstance(height, int) or not 1 <= height <= 1080
            or not isinstance(video.get("codec_name"), str) or not video["codec_name"]):
        raise RuntimeError("Hyperframes output dimensions, frame count, codec, or duration are outside fixture bounds")
    return {"duration_seconds": float(duration), "frames": frames,
            "width": width, "height": height, "codec": video["codec_name"]}


def _scrapegraph_fixture(args, runtime_roots, work_roots, source_generations):
    if args:
        raise ValueError("scrapegraph-local-fixture takes no caller-controlled paths or model settings")
    generation = source_generations.get("scrapegraph-ai")
    if not isinstance(generation, VerifiedComponentGeneration):
        raise RuntimeError("ScrapeGraphAI pinned installer source generation is not enrolled")
    return (build_scrapegraph_ai_fixture_invocation(
        runtime_roots["scrapegraph-ai-python"], generation, work_roots["scrapegraph-ai"],
    ),)


def _verify_scrapegraph_fixture(result: object, work_roots: Mapping[str, str]) -> object:
    try:
        proof = verify_scrapegraph_ai_fixture_result(result)
        return {"component_id": "scrapegraph-ai", "fixture_state": "functional_fixture_passed", **proof}
    except Exception as exc:
        raise RuntimeError("ScrapeGraphAI fixture did not prove the pinned local graph effect") from exc


_REGISTERED: Mapping[str, _Definition] = MappingProxyType({
    "browser-fixture": _Definition(
        frozenset({"fixture_url"}),
        frozenset({"component.browser-use.local-fixture", "network:localhost"}),
        2048, 180, "localhost", None, Decimal("0"), _browser_fixture,
        _verify_browser_fixture,
    ),
    "graphify-code-fixture": _Definition(
        frozenset(),
        frozenset({"component.graphify.read-fixture", "component.graphify.write-private-work", "component.graphify.read-private-work"}),
        1024, 120, "deny", None, Decimal("0"), _graphify_fixture,
        _verify_graphify_fixture,
    ),
    "hyperframes-render-fixture": _Definition(
        frozenset(),
        frozenset({"component.hyperframes.read-fixture", "component.hyperframes.write-private-work",
                   "component.hyperframes.read-private-work"}),
        2048, 180, "deny", None, Decimal("0"), _hyperframes_fixture,
        _verify_hyperframes_fixture,
    ),
    "scrapegraph-local-fixture": _Definition(
        frozenset(),
        frozenset({"component.scrapegraph-ai.read-fixture", "component.scrapegraph-ai.fixture-model"}),
        1024, 60, "deny", None, Decimal("0"), _scrapegraph_fixture,
        _verify_scrapegraph_fixture,
    ),
})


class WorkloadScheduler:
    """Resolve fixed workload recipes before checking grants and dispatching."""

    def __init__(
        self,
        run: Callable[[ComponentInvocation], object],
        granted: frozenset[str],
        *,
        runtime_roots: Mapping[str, str],
        work_roots: Mapping[str, str],
        memory_budget_mb: int,
        max_workers: int = 1,
        metered_budget_usd: Decimal = Decimal("0"),
        eligible_accounts: frozenset[str] = frozenset(),
        source_generations: Mapping[str, VerifiedComponentGeneration] | None = None,
    ) -> None:
        if memory_budget_mb <= 0 or max_workers <= 0:
            raise ValueError("scheduler resource limits must be positive")
        if not isinstance(metered_budget_usd, Decimal) or not metered_budget_usd.is_finite() or metered_budget_usd < 0:
            raise ValueError("metered budget must be a finite non-negative amount")
        self.run = run
        self.granted = frozenset(granted)
        self.runtime_roots = dict(runtime_roots)
        self.work_roots = dict(work_roots)
        self.memory_budget_mb = memory_budget_mb
        self.max_workers = max_workers
        self.metered_budget_usd = metered_budget_usd
        self.eligible_accounts = frozenset(eligible_accounts)
        self.source_generations = dict(source_generations or {})
        if any(not isinstance(source, VerifiedComponentGeneration)
               or source.component_id != key for key, source in self.source_generations.items()):
            raise TypeError("source generations must be installer-bound component generation receipts")
        self._active = 0
        self._metered_spend = Decimal("0")
        self._lock = Lock()

    @property
    def metered_spend_usd(self) -> Decimal:
        with self._lock:
            return self._metered_spend

    def execute(self, request: Workload) -> object:
        if not isinstance(request, Workload):
            raise TypeError("workload request must use the typed Workload request")
        definition = _REGISTERED.get(request.id)
        if definition is None:
            raise PermissionError("workload ID is not in the installer-owned registry")
        if not isinstance(request.arguments, Mapping) or set(request.arguments) != definition.argument_names:
            raise ValueError("workload parameters do not match its fixed registered recipe")
        missing = definition.capabilities - self.granted
        if missing:
            raise PermissionError("capability denied: " + ", ".join(sorted(missing)))
        if definition.memory_mb > self.memory_budget_mb:
            raise MemoryError("workload exceeds the reserved memory budget")
        if definition.account_requirement and definition.account_requirement not in self.eligible_accounts:
            raise PermissionError("required account is not eligible for this workload")
        if self._metered_spend + definition.metered_cost_usd > self.metered_budget_usd:
            raise PermissionError("workload exceeds the remaining metered budget")

        # Command construction is reviewed code with roots supplied by the
        # trusted installer. The request cannot select an executable or path.
        invocations = definition.build(
            request.arguments, self.runtime_roots, self.work_roots, self.source_generations,
        )
        if (not invocations or len(invocations) > 4
                or any(not isinstance(item, ComponentInvocation) for item in invocations)):
            raise RuntimeError("registered workload builder returned invalid invocations")
        if any(item.timeout_seconds > definition.timeout_seconds
               or item.memory_limit_mb > definition.memory_mb
               or item.network not in {"deny", definition.network_scope}
                or item.component_id not in {"browser-use", "graphify", "hyperframes", "scrapegraph-ai"}
               or not set(item.capability_scopes).issubset(definition.capabilities)
               for item in invocations):
            raise PermissionError("registered invocation exceeds its workload policy")

        with self._lock:
            if self._active >= self.max_workers:
                raise RuntimeError("workload concurrency limit reached")
            if self._metered_spend + definition.metered_cost_usd > self.metered_budget_usd:
                raise PermissionError("workload exceeds the remaining metered budget")
            self._active += 1
            self._metered_spend += definition.metered_cost_usd
        try:
            result = None
            for invocation in invocations:
                result = self.run(invocation)
                if not isinstance(result, Mapping) or result.get("exit_code") != 0:
                    raise RuntimeError("registered workload stage failed; dependent stages were not launched")
            return definition.verify(result, self.work_roots) if definition.verify is not None else result
        finally:
            with self._lock:
                self._active -= 1
