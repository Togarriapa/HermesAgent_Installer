"""Pinned, profile-local adapter for Panniantong/Agent-Reach.

The upstream CLI is an installer and a broad environment doctor. This adapter
keeps installation inside a component venv, exposes its complete portable skill
tree through the normal component importer, and treats doctor output as
advisory. A doctor's channel status is not proof of a functional read or an
authenticated account; those observations are recorded independently.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from hermes_installer.components.adapters import (
    ComponentAdapterContract,
    resolve_component_adapter,
)
from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    ManagedComponentSupervisor,
    RuntimeProfileError,
    _absolute_path,
)


COMPONENT_ID = "panniantong-agent-reach"
UPSTREAM_IDENTITY = "Panniantong/Agent-Reach"
UPSTREAM_URL = "https://github.com/Panniantong/Agent-Reach"
UPSTREAM_REVISION = "94f06c1969dfc1834001269d79d3ad0972d9dee6"
UPSTREAM_PACKAGE = (
    "agent-reach @ git+https://github.com/Panniantong/Agent-Reach.git@"
    + UPSTREAM_REVISION
)
_CHANNEL = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_DOCTOR_STATUSES = frozenset({"ok", "warn", "off", "error"})
_CREDENTIAL_STATES = frozenset({"configured", "missing", "pending", "error"})


class AgentReachError(RuntimeProfileError):
    """The selected Agent-Reach source or diagnostic result is invalid."""


@dataclass(frozen=True, slots=True)
class ChannelDiagnostic:
    channel: str
    doctor_status: str
    active_backend: str | None
    functional_read_status: str
    functional_read_scope: str
    credential_status: str
    account_status: str


def agent_reach_contract() -> ComponentAdapterContract:
    """Return the exact selected upstream identity and revision from planning."""
    contract = resolve_component_adapter(COMPONENT_ID)
    if (
        contract.source_identity != UPSTREAM_IDENTITY
        or contract.selected_source_url.rstrip("/") != UPSTREAM_URL
        or contract.revision != UPSTREAM_REVISION
    ):
        raise AgentReachError("Agent-Reach contract differs from the reviewed upstream pin")
    return contract


def agent_reach_skill_spec():
    """Return the standard source-import spec for the complete upstream skill tree."""
    contract = agent_reach_contract()
    spec = contract.as_component_spec()
    if spec.id != COMPONENT_ID or spec.revision != UPSTREAM_REVISION:
        raise AgentReachError("Agent-Reach skill spec does not match its pinned source")
    return spec


def verify_agent_reach_source(
    files: Mapping[str, bytes],
    *,
    source_identity: str,
    revision: str,
) -> tuple[str, ...]:
    """Check source identity, CLI entry point, package URL and portable skill files."""
    if source_identity != UPSTREAM_IDENTITY or revision != UPSTREAM_REVISION:
        raise AgentReachError("source is not the selected Panniantong/Agent-Reach revision")
    manifest = files.get("pyproject.toml")
    if not isinstance(manifest, bytes):
        raise AgentReachError("pinned Agent-Reach pyproject.toml is missing")
    try:
        import tomllib

        project = tomllib.loads(manifest.decode("utf-8"))["project"]
        urls = project["urls"]
        scripts = project["scripts"]
    except (KeyError, UnicodeDecodeError, ValueError, TypeError) as exc:
        raise AgentReachError("pinned Agent-Reach package metadata is invalid") from exc
    if (
        project.get("name") != "agent-reach"
        or project.get("license") != {"text": "MIT"}
        or project.get("requires-python") != ">=3.10"
        or urls.get("Repository", "").rstrip("/").casefold() != UPSTREAM_URL.casefold()
        or scripts.get("agent-reach") != "agent_reach.cli:main"
    ):
        raise AgentReachError("package metadata does not identify the selected upstream CLI")
    skill_files = tuple(sorted(
        name for name in files
        if name in {"agent_reach/skill/SKILL.md", "agent_reach/skill/SKILL_en.md"}
    ))
    if not skill_files:
        raise AgentReachError("pinned Agent-Reach source has no portable skill entry point")
    return skill_files


def discover_agent_reach_skills(files: Mapping[str, bytes]):
    """Discover the pinned package's complete, reference-audited skill tree."""
    verify_agent_reach_source(
        files, source_identity=UPSTREAM_IDENTITY, revision=UPSTREAM_REVISION
    )
    from hermes_installer.components.skill_handlers import discover_component_skills

    discovery = discover_component_skills(COMPONENT_ID, files)
    if not discovery.skills or not discovery.reference_audit.complete:
        raise AgentReachError("pinned Agent-Reach skill tree is incomplete")
    return discovery


def _inside(root: str, candidate: str, label: str) -> tuple[str, str]:
    root_path = PurePosixPath(_absolute_path(root, "Agent-Reach runtime root"))
    candidate_path = PurePosixPath(_absolute_path(candidate, label))
    if candidate_path == root_path or root_path not in candidate_path.parents:
        raise AgentReachError(f"{label} must be inside the isolated Agent-Reach runtime")
    return root_path.as_posix(), candidate_path.as_posix()


def build_agent_reach_install_invocation(
    uv_executable: str,
    runtime_root: str,
    runtime_python: str,
) -> ComponentInvocation:
    """Install the upstream VCS pin into its dedicated environment only.

    The explicit PEP 508 VCS source avoids resolving an unrelated same-name
    package from an index. The supplied Python must belong to this component's
    environment; Hermes' shared managed Python is never modified.
    """
    root, python = _inside(runtime_root, runtime_python, "Agent-Reach Python")
    uv = _absolute_path(uv_executable, "uv executable")
    agent_reach_contract()
    return ComponentInvocation(
        component_id=COMPONENT_ID,
        executable=uv,
        argv=(uv, "pip", "install", "--python", python, UPSTREAM_PACKAGE),
        cwd=root,
        environment=(),
        credential_references=(),
        capability_scopes=("component.panniantong-agent-reach.install", "network:python-packages"),
        sensitivity="PRIVATE",
        network="python-packages",
        timeout_seconds=1800,
        memory_limit_mb=2048,
    )


def build_agent_reach_doctor_invocation(
    cli_executable: str,
    runtime_root: str,
) -> ComponentInvocation:
    """Describe a read-only CLI doctor run under loopback-only network access."""
    root, cli = _inside(runtime_root, cli_executable, "Agent-Reach CLI")
    agent_reach_contract()
    return ComponentInvocation(
        component_id=COMPONENT_ID,
        executable=cli,
        argv=(cli, "doctor", "--json"),
        cwd=root,
        environment=(),
        credential_references=(),
        capability_scopes=("component.panniantong-agent-reach.diagnostic",),
        sensitivity="PRIVATE",
        # The upstream doctor checks many channels. Restricting its run to
        # localhost prevents it from silently making broad external probes.
        network="localhost",
        timeout_seconds=90,
        memory_limit_mb=512,
    )


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "fixture redirects are not followed", headers, fp)


def read_loopback_fixture(url: str, expected_text: str, *, timeout_seconds: float = 2.0) -> None:
    """Perform one bounded harmless GET against a literal loopback fixture."""
    parsed = urlsplit(url)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.username is not None
        or parsed.password is not None
        or not parsed.port
        or parsed.query
        or parsed.fragment
        or any(part == ".." for part in parsed.path.split("/"))
    ):
        raise AgentReachError("Agent-Reach diagnostic fixture must be a plain 127.0.0.1 URL")
    request = Request(url, headers={"Accept": "text/plain"}, method="GET")
    opener = build_opener(_NoRedirect())
    try:
        with opener.open(request, timeout=timeout_seconds) as response:
            if response.geturl() != url:
                raise AgentReachError("Agent-Reach fixture response changed its URL")
            body = response.read(64 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise AgentReachError("Agent-Reach local fixture read failed") from exc
    if len(body) > 64 * 1024:
        raise AgentReachError("Agent-Reach fixture response exceeded 65536 bytes")
    if expected_text.encode("utf-8") not in body:
        raise AgentReachError("Agent-Reach fixture read did not contain its expected marker")


def parse_agent_reach_doctor(payload: str | bytes) -> dict[str, dict[str, Any]]:
    """Parse only the non-sensitive fields needed from upstream ``doctor --json``."""
    try:
        decoded = json.loads(payload)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AgentReachError("Agent-Reach doctor did not return valid JSON") from exc
    if not isinstance(decoded, dict):
        raise AgentReachError("Agent-Reach doctor JSON must be an object")
    parsed: dict[str, dict[str, Any]] = {}
    for channel, result in decoded.items():
        if not isinstance(channel, str) or not _CHANNEL.fullmatch(channel) or not isinstance(result, dict):
            raise AgentReachError("Agent-Reach doctor returned an invalid channel entry")
        status = result.get("status")
        if status not in _DOCTOR_STATUSES:
            raise AgentReachError(f"Agent-Reach doctor returned an invalid status for {channel}")
        active_backend = result.get("active_backend")
        if active_backend is not None and not isinstance(active_backend, str):
            raise AgentReachError(f"Agent-Reach doctor returned an invalid backend for {channel}")
        # Deliberately discard `message`, descriptions, and credential-bearing
        # fields before the report crosses the adapter boundary.
        parsed[channel] = {"status": status, "active_backend": active_backend}
    return parsed


def diagnose_selected_channels(
    doctor_payload: str | bytes,
    selected_channels: tuple[str, ...] | list[str],
    *,
    fixture_reads: Mapping[str, tuple[str, str]] | None = None,
    live_reads: Mapping[str, Callable[[], object]] | None = None,
    credential_statuses: Mapping[str, str] | None = None,
) -> tuple[ChannelDiagnostic, ...]:
    """Keep doctor, functional-read, and credential/account evidence separate."""
    doctor = parse_agent_reach_doctor(doctor_payload)
    fixtures = fixture_reads or {}
    live = live_reads or {}
    credentials = credential_statuses or {}
    if len(set(selected_channels)) != len(selected_channels):
        raise AgentReachError("Agent-Reach diagnostic selection contains duplicate channels")
    output: list[ChannelDiagnostic] = []
    for channel in selected_channels:
        if not isinstance(channel, str) or not _CHANNEL.fullmatch(channel):
            raise AgentReachError("Agent-Reach diagnostic selection contains an invalid channel")
        if channel in fixtures and channel in live:
            raise AgentReachError(f"channel {channel} cannot use fixture and live read evidence together")
        read_status = "pending"
        read_scope = "pending"
        if channel in fixtures:
            try:
                url, marker = fixtures[channel]
                read_loopback_fixture(url, marker)
            except Exception:
                read_status, read_scope = "failed", "fixture"
            else:
                read_status, read_scope = "fixture_passed", "fixture"
        elif channel in live:
            try:
                live[channel]()
            except Exception:
                read_status, read_scope = "failed", "live"
            else:
                read_status, read_scope = "live_passed", "live"
        credential_status = credentials.get(channel, "pending")
        if credential_status not in _CREDENTIAL_STATES:
            raise AgentReachError(f"credential status for {channel} is not a safe status label")
        row = doctor.get(channel, {})
        output.append(ChannelDiagnostic(
            channel=channel,
            doctor_status=row.get("status", "missing"),
            active_backend=row.get("active_backend"),
            functional_read_status=read_status,
            functional_read_scope=read_scope,
            credential_status=credential_status,
            # A configured credential or a doctor result alone does not prove
            # that the remote account is accepted and usable.
            account_status="pending",
        ))
    return tuple(output)


async def run_agent_reach_diagnostic(
    supervisor: ManagedComponentSupervisor,
    cli_executable: str,
    runtime_root: str,
    selected_channels: tuple[str, ...] | list[str],
    *,
    fixture_reads: Mapping[str, tuple[str, str]] | None = None,
    live_reads: Mapping[str, Callable[[], object]] | None = None,
    credential_statuses: Mapping[str, str] | None = None,
) -> tuple[ChannelDiagnostic, ...]:
    """Run upstream's JSON doctor, then perform only explicitly selected reads."""
    invocation = build_agent_reach_doctor_invocation(cli_executable, runtime_root)
    result = await supervisor.invoke(invocation)
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise AgentReachError("Agent-Reach doctor process did not exit successfully")
    stdout = result.get("stdout")
    if not isinstance(stdout, (str, bytes)):
        raise AgentReachError("Agent-Reach doctor process returned no JSON output")
    return diagnose_selected_channels(
        stdout,
        selected_channels,
        fixture_reads=fixture_reads,
        live_reads=live_reads,
        credential_statuses=credential_statuses,
    )
