import json

import pytest

from hermes_installer.remote.jarvis_mobile_assets import (
    MOBILE_ICON_PATH,
    MOBILE_MANIFEST_LINK_HTML,
    MOBILE_MANIFEST_PATH,
    SETTINGS_FRAGMENT_CSS,
    SETTINGS_FRAGMENT_HTML,
    reviewed_mobile_static_asset,
    reviewed_mobile_static_asset_paths,
)


def test_mobile_assets_have_two_exact_same_origin_routes_and_fixed_mime_types():
    assert reviewed_mobile_static_asset_paths() == (MOBILE_MANIFEST_PATH, MOBILE_ICON_PATH)
    manifest_type, manifest = reviewed_mobile_static_asset(MOBILE_MANIFEST_PATH)
    icon_type, icon = reviewed_mobile_static_asset(MOBILE_ICON_PATH)

    assert manifest_type == "application/manifest+json"
    assert icon_type == "image/svg+xml"
    assert isinstance(manifest, bytes) and len(manifest) <= 2048
    assert isinstance(icon, bytes) and len(icon) <= 4096


@pytest.mark.parametrize("path", [
    "/chat/manifest.webmanifest?cache=1",
    "/chat/assets/jarvis-app-icon.svg/",
    "/chat/assets/other.svg",
    "/chat/%6danifest.webmanifest",
    "https://example.invalid/chat/manifest.webmanifest",
    None,
])
def test_mobile_static_asset_resolver_rejects_aliases_and_nonliteral_paths(path):
    with pytest.raises(ValueError, match="outside the reviewed mobile asset set"):
        reviewed_mobile_static_asset(path)


def test_manifest_is_scoped_to_protected_chat_and_has_one_exact_local_icon():
    content_type, body = reviewed_mobile_static_asset(MOBILE_MANIFEST_PATH)
    manifest = json.loads(body)
    assert content_type == "application/manifest+json"
    assert manifest["id"] == manifest["start_url"] == "/chat/"
    assert manifest["scope"] == "/chat/"
    assert manifest["display"] == "standalone"
    assert manifest["icons"] == [{
        "src": MOBILE_ICON_PATH,
        "sizes": "any",
        "type": "image/svg+xml",
        "purpose": "any maskable",
    }]
    assert "service_worker" not in manifest
    assert MOBILE_MANIFEST_LINK_HTML == (
        '<link rel="manifest" href="/chat/manifest.webmanifest" '
        'crossorigin="use-credentials">'
    )


def test_icon_is_a_small_scriptless_local_vector_with_no_external_references():
    content_type, icon = reviewed_mobile_static_asset(MOBILE_ICON_PATH)
    lowered = icon.lower()
    assert content_type == "image/svg+xml"
    assert b"<svg " in lowered and b'viewbox="0 0 512 512"' in lowered
    assert b"<title" in lowered and b"jarvis" in lowered
    for forbidden in (b"<script", b"<foreignobject", b"javascript:", b"xlink:href", b"http://", b"https://"):
        assert forbidden not in lowered


def test_settings_fragment_keeps_install_help_adjacent_to_voice_and_has_no_top_level_feature():
    assert 'data-mobile-settings="jarvis"' in SETTINGS_FRAGMENT_HTML
    assert "Voice preferences" in SETTINGS_FRAGMENT_HTML
    assert "if one is offered" in SETTINGS_FRAGMENT_HTML
    assert "depends on the browser" in SETTINGS_FRAGMENT_HTML
    assert "not available offline" in SETTINGS_FRAGMENT_HTML
    assert "Android assistant-role access and locked-screen wake are separate features" in SETTINGS_FRAGMENT_HTML
    assert 'id="speech-consent"' not in SETTINGS_FRAGMENT_HTML
    assert 'id="speech-output"' not in SETTINGS_FRAGMENT_HTML
    assert "min-height:44px" in SETTINGS_FRAGMENT_CSS
    assert "@media(max-width:760px)" in SETTINGS_FRAGMENT_CSS
