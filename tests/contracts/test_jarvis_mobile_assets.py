from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_mobile_assets import FEATURE_ASSETS


def test_mobile_guidance_is_a_fixed_accessible_feature_with_no_api_surface():
    feature = FEATURE_ASSETS
    validate_feature_assets((feature,))

    assert feature.feature_id == "mobile"
    assert feature.nav_label == "On this device"
    assert feature.api_routes == ()
    assert 'aria-labelledby="mobile-title"' in feature.view_html
    assert 'role="status" aria-live="polite"' in feature.view_html
    assert "<details>" in feature.view_html and "<summary>" in feature.view_html
    assert "<script" not in feature.view_html.lower()


def test_install_guidance_is_browser_dependent_and_never_claims_offline_support():
    source = FEATURE_ASSETS.view_html + FEATURE_ASSETS.mount_js
    assert "if one is offered" in source
    assert "depend on the browser" in source
    assert "does not provide offline chat" in source
    assert "display-mode: standalone" in source
    assert "serviceWorker" not in source
    assert "beforeinstallprompt" not in source
    assert "caches.open" not in source


def test_mobile_voice_copy_keeps_browser_speech_separate_from_native_wake():
    markup = FEATURE_ASSETS.view_html
    assert "Settings under Voice preferences" in markup
    assert "outside Jarvis" in markup
    assert "Android assistant-role access and locked-screen wake are separate features" in markup
    assert "A browser shortcut does not enable background listening." in markup
    assert 'id="speech-consent"' not in markup
    assert 'id="speech-output"' not in markup


def test_mobile_fragment_has_touch_sized_guidance_and_cleans_up_layout_observation():
    assert "min-height:44px" in FEATURE_ASSETS.css
    assert "env(safe-area-inset-bottom)" in FEATURE_ASSETS.css
    assert "prefers-reduced-motion:reduce" in FEATURE_ASSETS.css
    assert "(max-width: 760px)" in FEATURE_ASSETS.mount_js
    assert "compact.addEventListener('change', render)" in FEATURE_ASSETS.mount_js
    assert "compact.removeEventListener('change', render)" in FEATURE_ASSETS.mount_js
