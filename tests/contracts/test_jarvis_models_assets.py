from __future__ import annotations

from hermes_installer.remote.jarvis_models_assets import FEATURE_ASSETS


def test_models_draft_restores_only_a_trusted_current_choice_after_catalog_rebuild():
    source = FEATURE_ASSETS.mount_js
    assert 'last.state === "selected-for-session"' in source
    assert 'last.state === "deferred-next-turn"' in source
    assert 'last === null && data.profileModel' in source
    assert "choice.selectedIndex = preferredOption ? preferredOption.index : -1" in source
    assert "The conversation selection is not confirmed as a selectable model; choose explicitly." in source
    assert "No current conversation model is known; choose explicitly." in source

