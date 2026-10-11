from hermes_installer.remote import jarvis_capability_details_assets as assets


def test_capability_detail_fragment_uses_only_existing_read_routes():
    assert assets.API_PATHS == (
        "/chat/api/capabilities",
        "/chat/api/native-capabilities",
        "/chat/api/resources/learning",
    )
    assert 'read.get("/chat/api/capabilities")' in assets.MOUNT_JS
    assert 'read.get("/chat/api/native-capabilities")' in assets.MOUNT_JS
    assert 'read.get("/chat/api/resources/learning")' in assets.MOUNT_JS
    assert ".post(" not in assets.MOUNT_JS


def test_capability_details_keep_missing_metadata_and_pending_readiness_explicit():
    assert "Verified offline Hermes Resources bundle 2.3.1" in assets.MOUNT_JS
    assert "Bundled presence does not prove discovery, enablement, or working behavior." in assets.MOUNT_JS
    assert "Not supplied by this bounded catalog projection" in assets.MOUNT_JS
    assert "Internal profile declaration. It is not a family-selectable service." in assets.MOUNT_JS
    assert "tool inventory unknown" in assets.MOUNT_JS
    assert "skill discovery unknown" in assets.MOUNT_JS


def test_learning_diff_fragment_is_owner_read_only_and_uses_text_nodes():
    assert "root verified current owner ingress and skill custody" in assets.MOUNT_JS
    assert "awaiting-native-approval" in assets.MOUNT_JS
    assert "Review remains in /skills pending." in assets.MOUNT_JS
    assert "No proposal was approved or applied." in assets.MOUNT_JS
    assert "textContent" in assets.MOUNT_JS
    assert "innerHTML" not in assets.MOUNT_JS
    assert "canApply !== false" in assets.MOUNT_JS
    assert "canRollback !== false" in assets.MOUNT_JS


def test_fragment_is_static_accessible_and_bounded_in_the_browser():
    assert 'type="search"' in assets.VIEW_HTML
    assert 'role="status" aria-live="polite"' in assets.VIEW_HTML
    assert 'aria-labelledby="capability-detail-title"' in assets.VIEW_HTML
    assert "matched.slice(0, 100)" in assets.MOUNT_JS
    assert "256*1024" in assets.MOUNT_JS
    assert "removeEventListener" in assets.MOUNT_JS
