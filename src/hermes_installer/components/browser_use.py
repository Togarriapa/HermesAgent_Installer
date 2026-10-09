"""On-demand Browser Use fixture adapter for an isolated Python runtime.

Only a literal loopback HTTP fixture is accepted. The caller supplies the
already-installed runtime and a managed-process supervisor; this module never
installs a browser or enables the optional cloud browser route.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from urllib.parse import urlsplit

from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    ManagedComponentSupervisor,
    RuntimeProfileError,
    _absolute_path,
)


_FIXTURE = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}/[A-Za-z0-9._~/-]*$")
_PROBE = r'''import asyncio, json, sys
from browser_use import Browser, BrowserProfile

async def main():
    browser = Browser(browser_profile=BrowserProfile(headless=True, enable_default_extensions=False))
    try:
        await browser.start()
        page = await browser.new_page(sys.argv[1])
        heading = await page.get_elements_by_css_selector("#proof")
        button = await page.get_elements_by_css_selector("#action")
        assert len(heading) == 1 and len(button) == 1
        await button[0].click()
        text = await heading[0].evaluate("() => this.textContent")
        image = await page.screenshot(format="png")
        assert text == "interaction-ok" and image and len(image) > 64
        print("HERMES_BROWSER_USE_PROOF=" + json.dumps({"navigation": True, "interaction": text, "screenshot_bytes": len(image)}, sort_keys=True))
    finally:
        await browser.kill()

asyncio.run(asyncio.wait_for(main(), timeout=150))
'''


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
    return ComponentInvocation(
        component_id="browser-use",
        executable=executable,
        argv=(executable, "-c", _PROBE, fixture_url),
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
    if (
        not isinstance(proof, dict)
        or proof.get("navigation") is not True
        or proof.get("interaction") != "interaction-ok"
        or not isinstance(proof.get("screenshot_bytes"), int)
        or proof["screenshot_bytes"] <= 64
    ):
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
    return verify_browser_use_fixture_result(result)
