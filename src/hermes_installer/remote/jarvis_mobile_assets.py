"""Fixed authenticated install metadata and Settings-adjacent mobile guidance.

This leaf exports two reviewed same-origin static assets and a static settings
fragment. It has no API routes, service worker, offline cache, or audio/device
permissions. The shared shell and route allowlist are wired separately.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from types import MappingProxyType
from typing import Literal, Mapping


MOBILE_MANIFEST_PATH: Literal["/chat/manifest.webmanifest"] = "/chat/manifest.webmanifest"
MOBILE_ICON_PATH: Literal["/chat/assets/jarvis-app-icon.svg"] = "/chat/assets/jarvis-app-icon.svg"

# Insert this exact credentialed same-origin link in the reviewed /chat <head>.
MOBILE_MANIFEST_LINK_HTML = (
    '<link rel="manifest" href="/chat/manifest.webmanifest" '
    'crossorigin="use-credentials">'
)

SETTINGS_FRAGMENT_HTML = """<section class="mobile-settings-card" data-mobile-settings="jarvis"
  aria-labelledby="mobile-settings-title">
  <h2 id="mobile-settings-title">Use Jarvis on this device</h2>
  <p>Jarvis adapts to the available screen width. Tap the chat message box to use your device keyboard; text chat remains available when speech is unsupported or turned off.</p>
  <details>
    <summary>Add a home-screen shortcut</summary>
    <p>Open this browser’s menu and choose its Add to Home Screen or install option if one is offered. The wording and launch style depend on the browser.</p>
    <p>The shortcut opens the protected Jarvis site. A live connection and normal sign-in are required; chat and authentication are not available offline.</p>
  </details>
  <p>Optional push-to-talk and read-aloud settings are above in Voice preferences. Browser speech recognition may use a platform service outside Jarvis. Android assistant-role access and locked-screen wake are separate features and have not been qualified for this installer.</p>
</section>"""

SETTINGS_FRAGMENT_CSS = """
.mobile-settings-card{max-width:720px;margin:16px auto;padding:21px;border:1px solid var(--line);border-radius:15px;background:rgba(12,31,38,.78);color:var(--text,#edf5f6)}
.mobile-settings-card h2{margin:0;color:#acc2c6;font-size:13px;font-weight:600}
.mobile-settings-card p{color:#8ba5aa;font-size:13px;line-height:1.6}
.mobile-settings-card summary{min-height:44px;display:flex;align-items:center;cursor:pointer;color:#d7edef;font-weight:600;touch-action:manipulation}
.mobile-settings-card summary:focus-visible{outline:2px solid var(--cyan);outline-offset:3px;border-radius:4px}
@media(max-width:760px){.mobile-settings-card{padding:17px;border-radius:12px}}
"""

_MANIFEST_BODY = b'''{"id":"/chat/","name":"Jarvis","short_name":"Jarvis","description":"Protected Hermes Jarvis chat","start_url":"/chat/","scope":"/chat/","display":"standalone","background_color":"#071319","theme_color":"#071319","icons":[{"src":"/chat/assets/jarvis-app-icon.svg","sizes":"any","type":"image/svg+xml","purpose":"any maskable"}]}'''

_ICON_BODY = b'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" role="img" aria-labelledby="title">
<title id="title">Jarvis</title>
<rect width="512" height="512" rx="96" fill="#071319"/>
<circle cx="256" cy="256" r="174" fill="#0b2229" stroke="#38cbd3" stroke-opacity=".45" stroke-width="5"/>
<circle cx="256" cy="256" r="135" fill="none" stroke="#54dce3" stroke-opacity=".38" stroke-width="4"/>
<circle cx="256" cy="256" r="87" fill="#0d333a" stroke="#6ce8eb" stroke-opacity=".8" stroke-width="7"/>
<circle cx="256" cy="256" r="22" fill="#79f0ed"/>
</svg>'''


@dataclass(frozen=True, slots=True)
class ReviewedMobileStaticAsset:
    """One literal static asset served only through the existing authenticated route."""

    path: Literal["/chat/manifest.webmanifest", "/chat/assets/jarvis-app-icon.svg"]
    content_type: Literal["application/manifest+json", "image/svg+xml"]
    body: bytes
    max_bytes: int


_MOBILE_STATIC_ASSETS: Mapping[str, ReviewedMobileStaticAsset] = MappingProxyType({
    MOBILE_MANIFEST_PATH: ReviewedMobileStaticAsset(
        path=MOBILE_MANIFEST_PATH,
        content_type="application/manifest+json",
        body=_MANIFEST_BODY,
        max_bytes=2048,
    ),
    MOBILE_ICON_PATH: ReviewedMobileStaticAsset(
        path=MOBILE_ICON_PATH,
        content_type="image/svg+xml",
        body=_ICON_BODY,
        max_bytes=4096,
    ),
})


def _validate_mobile_static_assets() -> None:
    expected = {
        MOBILE_MANIFEST_PATH: ("application/manifest+json", 2048),
        MOBILE_ICON_PATH: ("image/svg+xml", 4096),
    }
    if set(_MOBILE_STATIC_ASSETS) != set(expected):
        raise ValueError("mobile static asset paths differ from the reviewed literal allowlist")
    for path, asset in _MOBILE_STATIC_ASSETS.items():
        content_type, max_bytes = expected[path]
        if (type(asset) is not ReviewedMobileStaticAsset or asset.path != path
                or asset.content_type != content_type or asset.max_bytes != max_bytes
                or not isinstance(asset.body, bytes) or not 0 < len(asset.body) <= max_bytes):
            raise ValueError("mobile static asset metadata or size is invalid")
    icon = _MOBILE_STATIC_ASSETS[MOBILE_ICON_PATH].body.lower()
    if (any(token in icon for token in (
        b"<script", b"<foreignobject", b"javascript:", b"<!doctype",
        b"<?xml-stylesheet",
    )) or re.search(rb"\son[a-z]+\s*=|\b(?:xlink:)?href\s*=|\bsrc\s*=|\burl\s*\(", icon)):
        raise ValueError("mobile SVG icon contains active or external content")
    try:
        manifest = json.loads(_MOBILE_STATIC_ASSETS[MOBILE_MANIFEST_PATH].body)
    except (TypeError, ValueError):
        raise ValueError("mobile manifest is not valid JSON") from None
    if (not isinstance(manifest, dict)
            or manifest.get("id") != "/chat/"
            or manifest.get("start_url") != "/chat/"
            or manifest.get("scope") != "/chat/"
            or manifest.get("display") != "standalone"
            or manifest.get("icons") != [{
                "src": MOBILE_ICON_PATH,
                "sizes": "any",
                "type": "image/svg+xml",
                "purpose": "any maskable",
            }]):
        raise ValueError("mobile manifest identity, scope, display, or icon is invalid")
    if "service_worker" in manifest:
        raise ValueError("mobile manifest must not declare a service worker")


_validate_mobile_static_assets()


def reviewed_mobile_static_asset(path: str) -> tuple[str, bytes]:
    """Return one exact typed asset; aliases, queries, and arbitrary paths fail closed."""
    if not isinstance(path, str):
        raise ValueError("route is outside the reviewed mobile asset set")
    asset = _MOBILE_STATIC_ASSETS.get(path)
    if asset is None:
        raise ValueError("route is outside the reviewed mobile asset set")
    if len(asset.body) > asset.max_bytes:
        raise ValueError("reviewed mobile asset exceeded its fixed size bound")
    return asset.content_type, asset.body


def reviewed_mobile_static_asset_paths() -> tuple[str, ...]:
    """Expose the exact route literals for the central same-origin route allowlist."""
    return MOBILE_MANIFEST_PATH, MOBILE_ICON_PATH
