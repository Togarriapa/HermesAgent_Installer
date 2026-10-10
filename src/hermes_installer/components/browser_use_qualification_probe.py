"""Fixed provider-free browser qualification probe for the pinned Browser Use runtime.

This file is staged as a first-party source member beside the locked Browser Use
runtime. Its only target is the exact owned HTTP loopback fixture supplied by
the root qualification context; process/network confinement remains the
managed supervisor's responsibility.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import sys
from urllib.parse import urlsplit


_FIXTURE_URL = re.compile(r"^http://127\.0\.0\.1:[1-9][0-9]{0,4}/fixture$")
_MARKER = "HERMES_BROWSER_USE_PROOF="
_MAX_SCREENSHOT_BYTES = 8 * 1024 * 1024
_MAX_SCREENSHOT_BASE64_CHARS = ((_MAX_SCREENSHOT_BYTES + 2) // 3) * 4


def _validate_fixture_url(value: str) -> str:
    if not isinstance(value, str) or not _FIXTURE_URL.fullmatch(value):
        raise ValueError("qualification probe requires the owned IPv4 loopback fixture URL")
    parsed = urlsplit(value)
    if parsed.port is None or parsed.port > 65535 or parsed.query or parsed.fragment:
        raise ValueError("qualification probe fixture URL is invalid")
    return value


def _decode_screenshot(payload: object) -> bytes:
    if (not isinstance(payload, str)
            or len(payload) > _MAX_SCREENSHOT_BASE64_CHARS):
        raise ValueError("browser screenshot base64 payload exceeds its pre-decode bound")
    try:
        screenshot = base64.b64decode(payload, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError("browser screenshot is not valid base64") from None
    if (not screenshot.startswith(b"\x89PNG\r\n\x1a\n")
            or not 64 < len(screenshot) <= _MAX_SCREENSHOT_BYTES):
        raise ValueError("browser screenshot is outside its PNG size bound")
    return screenshot


async def _run(fixture_url: str) -> dict[str, object]:
    # These imports intentionally happen inside the locked component runtime.
    from browser_use import Browser, BrowserProfile

    browser = Browser(browser_profile=BrowserProfile(
        is_local=True,
        use_cloud=False,
        headless=True,
        allowed_domains=["127.0.0.1"],
        keep_alive=False,
        captcha_solver=False,
        enable_default_extensions=False,
        chromium_sandbox=True,
        proxy=None,
    ))
    try:
        await browser.start()
        page = await browser.new_page(fixture_url)
        if await page.get_url() != fixture_url:
            raise RuntimeError("browser did not remain on the owned fixture URL")
        if await page.get_title() != "Hermes qualification fixture":
            raise RuntimeError("owned fixture title did not match")

        proof_nodes = await page.get_elements_by_css_selector("#proof")
        buttons = await page.get_elements_by_css_selector("#action")
        if len(proof_nodes) != 1 or len(buttons) != 1:
            raise RuntimeError("owned fixture DOM did not match the fixed probe contract")
        before = await proof_nodes[0].evaluate("() => this.textContent")
        if before != "ready":
            raise RuntimeError("owned fixture did not begin in its expected state")

        await buttons[0].click()
        after = await proof_nodes[0].evaluate("() => this.textContent")
        if after != "interaction-ok":
            raise RuntimeError("browser click did not produce the expected fixture effect")

        screenshot_b64 = await page.screenshot(format="png")
        screenshot = _decode_screenshot(screenshot_b64)
        import hashlib

        return {
            "schema_version": 1,
            "navigation_url": fixture_url,
            "navigation_succeeded": True,
            "page_title": "Hermes qualification fixture",
            "initial_text": before,
            "click_succeeded": True,
            "interaction_text": after,
            "screenshot_format": "png",
            "screenshot_bytes": len(screenshot),
            "screenshot_sha256": hashlib.sha256(screenshot).hexdigest(),
        }
    finally:
        await browser.kill()


async def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("expected exactly one owned fixture URL")
    fixture_url = _validate_fixture_url(sys.argv[1])
    result = await asyncio.wait_for(_run(fixture_url), timeout=150)
    print(_MARKER + json.dumps(result, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    asyncio.run(main())
