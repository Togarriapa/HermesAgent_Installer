"""Reviewed isolated-runtime profiles and deterministic fixture commands.

A profile describes required upstream locks and limits. Building a fixture
command does not install dependencies or run the component; invocation is
injected through the installer-owned managed-process supervisor.
"""
from __future__ import annotations

import hashlib
import json
import tomllib

from hermes_installer.components.isolated_locks import lockfile_errors
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping, Protocol


@dataclass(frozen=True, slots=True)
class IsolatedRuntimeProfile:
    component_id: str
    manifest_paths: tuple[str, ...]
    lock_paths: tuple[str, ...]
    runtime: str
    version_constraint: str
    on_demand: bool
    required_host_tools: tuple[str, ...] = ()
    live_requirements: tuple[str, ...] = ()
    network_default: str = "deny"


# These paths were confirmed from each repository's selected pinned tree.
ISOLATED_RUNTIME_PROFILES: Mapping[str, IsolatedRuntimeProfile] = {
    "graphify": IsolatedRuntimeProfile(
        "graphify", ("pyproject.toml",), ("uv.lock",), "python", ">=3.10",
        True, ("uv",),
    ),
    "browser-use": IsolatedRuntimeProfile(
        "browser-use", ("pyproject.toml",), (), "python", ">=3.11,<4",
        True, ("ARM64-compatible Chromium",),
    ),
    "hyperframes": IsolatedRuntimeProfile(
        "hyperframes", ("package.json", "packages/cli/package.json"),
        ("bun.lock",), "node", ">=22", True, ("FFmpeg", "ARM64-compatible Chromium"),
    ),
    "omniroute": IsolatedRuntimeProfile(
        "omniroute", ("package.json",), ("package-lock.json",), "node",
        ">=22.22.2 <23 OR >=24 <27", True, (),
        ("explicitly selected route providers and credential references",),
    ),
    "screenshot-to-code": IsolatedRuntimeProfile(
        "screenshot-to-code",
        ("backend/pyproject.toml", "frontend/package.json"),
        ("backend/poetry.lock", "frontend/pnpm-lock.yaml"),
        "python+node", "Python ^3.10; frontend per pinned package manifest",
        True, (), ("selected vision model and credential reference",),
    ),
    "scrapegraph-ai": IsolatedRuntimeProfile(
        "scrapegraph-ai", ("pyproject.toml",), ("uv.lock",), "python",
        ">=3.12,<4", True, ("uv",),
        ("explicitly selected extraction provider and credential reference",),
    ),
}


@dataclass(frozen=True, slots=True)
class RuntimeReview:
    component_id: str
    source_url: str
    source_revision: str
    manifest_digests: tuple[tuple[str, str], ...]
    lock_digests: tuple[tuple[str, str], ...]
    blockers: tuple[str, ...]
    live_requirements: tuple[str, ...]
    evidence_state: str


class RuntimeProfileError(ValueError):
    """The source tree cannot satisfy its reviewed isolated runtime profile."""


def review_isolated_runtime(component_id: str, files: Mapping[str, bytes]) -> RuntimeReview:
    profile = ISOLATED_RUNTIME_PROFILES.get(component_id)
    if profile is None:
        raise RuntimeProfileError("no source-reviewed isolated runtime profile exists")
    from hermes_installer.components.adapters import resolve_component_adapter
    contract = resolve_component_adapter(component_id)
    if contract.unresolved_reason():
        raise RuntimeProfileError(contract.unresolved_reason())

    blockers: list[str] = []
    manifests: list[tuple[str, str]] = []
    locks: list[tuple[str, str]] = []
    for path in profile.manifest_paths:
        body = files.get(path)
        if body is None:
            blockers.append(f"required upstream manifest is absent: {path}")
            continue
        if not isinstance(body, bytes):
            raise RuntimeProfileError(f"manifest is not byte content: {path}")
        manifests.append((path, hashlib.sha256(body).hexdigest()))
    for path in profile.lock_paths:
        body = files.get(path)
        if body is None:
            blockers.append(f"exact isolated dependency lock is absent: {path}")
            continue
        if not isinstance(body, bytes):
            raise RuntimeProfileError(f"lockfile is not byte content: {path}")
        if not body:
            blockers.append(f"isolated dependency lock is empty: {path}")
            continue
        locks.append((path, hashlib.sha256(body).hexdigest()))
        blockers.extend(f"{path}: {problem}" for problem in lockfile_errors(path, body))

    def toml(path: str) -> dict:
        try:
            return tomllib.loads(files[path].decode("utf-8"))
        except (KeyError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            blockers.append(f"upstream TOML file is invalid: {path}")
            return {}

    if component_id == "graphify" and {"pyproject.toml", "uv.lock"}.issubset(files):
        project = toml("pyproject.toml").get("project", {})
        lock = toml("uv.lock")
        package = next((p for p in lock.get("package", []) if p.get("name") == "graphifyy"), {})
        if project.get("name") != "graphifyy" or project.get("version") != "0.9.82":
            blockers.append("graphify pyproject does not match the selected pinned package")
        if package.get("version") != "0.9.82":
            blockers.append("uv.lock does not bind graphifyy 0.9.82")
        if lock.get("requires-python") != ">=3.10":
            blockers.append("uv.lock Python range differs from the source project range")
    if component_id == "browser-use" and "pyproject.toml" in files:
        project = toml("pyproject.toml").get("project", {})
        if project.get("requires-python") != ">=3.11,<4.0":
            blockers.append("Browser Use Python constraint differs from the reviewed pinned manifest")
        blockers.append("generate and verify an isolated ARM64 dependency lock before installation")
    if component_id == "scrapegraph-ai" and {"pyproject.toml", "uv.lock"}.issubset(files):
        project = toml("pyproject.toml").get("project", {})
        lock = toml("uv.lock")
        if project.get("name") != "scrapegraphai" or project.get("version") != "2.3.1":
            blockers.append("ScrapeGraphAI pyproject does not match the selected pinned package")
        if ">=3.12" not in lock.get("requires-python", "") or "<4.0" not in lock.get("requires-python", ""):
            blockers.append("uv.lock Python range differs from the source project range")
        if not any("aarch64" in marker and "linux" in marker
                   for marker in lock.get("resolution-markers", [])):
            blockers.append("uv.lock lacks an explicit Linux aarch64 resolution marker")
    if component_id == "omniroute" and "package.json" in files:
        try:
            package = json.loads(files["package.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            package = {}
            blockers.append("OmniRoute package.json is invalid")
        if package.get("engines", {}).get("node") != ">=22.22.2 <23 || >=24.0.0 <27":
            blockers.append("OmniRoute Node engine constraint differs from the reviewed pinned manifest")
    if component_id == "hyperframes" and "packages/cli/package.json" in files:
        try:
            package = json.loads(files["packages/cli/package.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            package = {}
            blockers.append("Hyperframes CLI package.json is invalid")
        if package.get("engines", {}).get("node") != ">=22":
            blockers.append("Hyperframes CLI Node engine constraint differs from the reviewed pinned manifest")
    state = "lockfile-integrity-reviewed; functional-probe-pending" if not blockers else "pending-isolated-runtime"
    return RuntimeReview(
        component_id=component_id,
        source_url=contract.selected_source_url,
        source_revision=contract.revision or "",
        manifest_digests=tuple(manifests),
        lock_digests=tuple(locks),
        blockers=tuple(dict.fromkeys(blockers)),
        live_requirements=profile.live_requirements,
        evidence_state=state,
    )


@dataclass(frozen=True, slots=True)
class ComponentInvocation:
    component_id: str
    executable: str
    argv: tuple[str, ...]
    cwd: str
    environment: tuple[tuple[str, str], ...]
    credential_references: tuple[str, ...]
    capability_scopes: tuple[str, ...]
    sensitivity: str
    network: str
    timeout_seconds: int
    memory_limit_mb: int


class ManagedComponentSupervisor(Protocol):
    """Structural seam to adapt the installer-owned ManagedProcessSpec/Handle."""

    async def invoke(self, spec: ComponentInvocation) -> object:
        """Resolve named secrets in the supervisor and return structured exit evidence."""


def _absolute_path(value: str, label: str) -> str:
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in value:
        raise RuntimeProfileError(f"{label} must be a normalized absolute path")
    return path.as_posix()


def build_graphify_code_fixture(
    runtime_root: str,
    fixture_root: str,
    work_root: str,
) -> tuple[ComponentInvocation, ComponentInvocation]:
    """Build the pinned Graphify offline code-index/query fixture."""
    runtime = _absolute_path(runtime_root, "runtime root")
    fixture = _absolute_path(fixture_root, "fixture root")
    work = _absolute_path(work_root, "work root")
    executable = runtime.rstrip("/") + "/bin/graphify"
    graph = work.rstrip("/") + "/graphify-out/graph.json"
    common = (("GRAPHIFY_QUERY_LOG_DISABLE", "1"),)
    return (
        ComponentInvocation(
            "graphify", executable, ("extract", "--code-only", fixture), work,
            common, (), ("component.graphify.read-fixture", "component.graphify.write-private-work"),
            "PRIVATE", "deny", 90, 1024,
        ),
        ComponentInvocation(
            "graphify", executable,
            ("query", "what connects the fixture entrypoint to its helper?", "--graph", graph),
            work, common, (), ("component.graphify.read-private-work",),
            "PRIVATE", "deny", 30, 512,
        ),
    )


def build_hyperframes_render_fixture(
    runtime_root: str,
    fixture_root: str,
    work_root: str,
) -> ComponentInvocation:
    """Build the documented, local-only Hyperframes CLI render probe."""
    runtime = _absolute_path(runtime_root, "runtime root")
    fixture = _absolute_path(fixture_root, "fixture root")
    work = _absolute_path(work_root, "work root")
    return ComponentInvocation(
        "hyperframes",
        runtime.rstrip("/") + "/bin/hyperframes",
        ("render", "-c", fixture.rstrip("/") + "/composition.html", "-o", work.rstrip("/") + "/rendered.mp4"),
        work,
        (),
        (),
        ("component.hyperframes.read-fixture", "component.hyperframes.write-private-work"),
        "PRIVATE",
        "deny",
        180,
        2048,
    )
