"""On-demand Browser Use fixture adapter for an isolated Python runtime.

Only a literal loopback HTTP fixture is accepted. The caller supplies the
already-installed runtime and a managed-process supervisor; this module never
installs a browser or enables the optional cloud browser route.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from collections.abc import Mapping
from urllib.parse import urlsplit

from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    ManagedComponentSupervisor,
    RuntimeProfileError,
    _absolute_path,
)
from hermes_installer.components.locked_runtime import load_browser_use_lock_bundle


_FIXTURE = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}/fixture$")
_PROBE_ASSET = Path(__file__).with_name("browser_use_qualification_probe.py")
_PROOF_KEYS = frozenset({
    "schema_version", "navigation_url", "navigation_succeeded", "page_title",
    "initial_text", "click_succeeded", "interaction_text", "screenshot_format",
    "screenshot_bytes", "screenshot_sha256",
})


def build_browser_use_sync_invocation(
    uv_executable: str,
    runtime_root: str,
    hermes_python: str,
) -> ComponentInvocation:
    """Describe a locked, per-component sync using Hermes's managed Python.

    This emits no installer side effect; the caller must pass the path returned
    by `stage_browser_use_runtime` and an authorized managed-process runner.
    """
    uv = _absolute_path(uv_executable, "uv executable")
    root = _absolute_path(runtime_root, "Browser Use runtime root")
    python = _absolute_path(hermes_python, "Hermes managed Python")
    load_browser_use_lock_bundle()
    return ComponentInvocation(
        component_id="browser-use",
        executable=uv,
        argv=(uv, "sync", "--locked", "--no-dev", "--python", python, "--project", root),
        cwd=root,
        environment=(("BROWSER_USE_DISABLE_EXTENSIONS", "1"),),
        credential_references=(),
        capability_scopes=("component.browser-use.install", "network:python-packages"),
        sensitivity="PRIVATE",
        network="python-packages",
        timeout_seconds=1800,
        memory_limit_mb=3072,
    )


def build_browser_use_fixture_invocation(
    python_executable: str,
    fixture_url: str,
    work_root: str,
) -> ComponentInvocation:
    """Create an isolated, network-scoped invocation for a local browser fixture."""
    executable = _absolute_path(python_executable, "Browser Use Python executable")
    work = _absolute_path(work_root, "Browser Use work root")
    if not _FIXTURE.fullmatch(fixture_url):
        raise RuntimeProfileError("Browser Use fixture must be plain HTTP on literal IPv4 loopback")
    parsed = urlsplit(fixture_url)
    try:
        port = int(parsed.port or 0)
    except ValueError as exc:
        raise RuntimeProfileError("Browser Use fixture port is outside TCP range") from exc
    if port > 65535:
        raise RuntimeProfileError("Browser Use fixture port is outside TCP range")
    if any(segment == ".." for segment in parsed.path.split("/")):
        raise RuntimeProfileError("Browser Use fixture path cannot traverse directories")
    if (parsed.path != "/fixture" or parsed.query or parsed.fragment
            or not _PROBE_ASSET.is_file()):
        raise RuntimeProfileError("Browser Use qualification probe asset or fixed fixture path is unavailable")
    return ComponentInvocation(
        component_id="browser-use",
        executable=executable,
        argv=(executable, str(_PROBE_ASSET), fixture_url),
        cwd=work,
        environment=(("BROWSER_USE_DISABLE_EXTENSIONS", "1"), ("BROWSER_USE_HEADLESS", "1")),
        credential_references=(),
        capability_scopes=("component.browser-use.local-fixture", "network:localhost"),
        sensitivity="PRIVATE",
        network="localhost",
        timeout_seconds=180,
        memory_limit_mb=2048,
    )


def verify_browser_use_fixture_result(result: object) -> dict[str, object]:
    """Validate a managed-process result's explicit navigation/click/screenshot proof."""
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise RuntimeProfileError("Browser Use fixture process did not exit successfully")
    output = result.get("stdout")
    if not isinstance(output, str):
        raise RuntimeProfileError("Browser Use fixture process returned no structured proof")
    marker = "HERMES_BROWSER_USE_PROOF="
    payloads = [line[len(marker):] for line in output.splitlines() if line.startswith(marker)]
    if len(payloads) != 1:
        raise RuntimeProfileError("Browser Use fixture process returned ambiguous proof output")
    try:
        proof = json.loads(payloads[0])
    except json.JSONDecodeError as exc:
        raise RuntimeProfileError("Browser Use fixture proof is invalid JSON") from exc
    if (not isinstance(proof, dict) or set(proof) != _PROOF_KEYS
            or type(proof.get("schema_version")) is not int or proof["schema_version"] != 1
            or not isinstance(proof.get("navigation_url"), str)
            or not _FIXTURE.fullmatch(proof["navigation_url"])
            or proof.get("navigation_succeeded") is not True
            or proof.get("page_title") != "Hermes qualification fixture"
            or proof.get("initial_text") != "ready"
            or proof.get("click_succeeded") is not True
            or proof.get("interaction_text") != "interaction-ok"
            or proof.get("screenshot_format") != "png"
            or type(proof.get("screenshot_bytes")) is not int
            or not 64 < proof["screenshot_bytes"] <= 8 * 1024 * 1024
            or not isinstance(proof.get("screenshot_sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", proof["screenshot_sha256"])):
        raise RuntimeProfileError("Browser Use fixture proof does not establish required effects")
    return proof


async def run_browser_use_fixture(
    supervisor: ManagedComponentSupervisor,
    python_executable: str,
    fixture_url: str,
    work_root: str,
) -> dict[str, object]:
    """Run and verify the local fixture through the injected managed supervisor."""
    invocation = build_browser_use_fixture_invocation(python_executable, fixture_url, work_root)
    result = await supervisor.invoke(invocation)
    proof = verify_browser_use_fixture_result(result)
    if proof["navigation_url"] != fixture_url:
        raise RuntimeProfileError("Browser Use fixture proof URL does not match the owned fixture receipt")
    return proof
