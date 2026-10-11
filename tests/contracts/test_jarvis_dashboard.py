from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone

from hermes_installer.remote.jarvis_chat import JarvisChatStore
from hermes_installer.remote.jarvis_dashboard import (
    _verified_bundle_inventory,
    build_capabilities,
    build_overview,
    build_settings,
)


UTC = timezone.utc


def _insert_turn(store: JarvisChatStore, *, owner: str, conversation: str,
                 turn_id: str, status: str, created: float) -> None:
    with store._connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO conversations "
            "(id,owner,backend_id,session_key,title,created,updated,core_generation) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (conversation, owner, f"backend-{conversation}", f"session-{conversation}",
             "Jarvis", created, created, "generation"),
        )
        db.execute(
            "INSERT INTO turns "
            "(id,owner,conversation_id,idempotency_hash,request_hash,status,heartbeat_nonce,"
            "heartbeat_expiry,jwt_expiry,runtime_session_id,core_generation,partial,error_code,created,updated) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (turn_id, owner, conversation, f"idem-{turn_id}", f"request-{turn_id}", status,
             "", 0.0, 0.0, "", "generation", "", "", created, created),
        )


def test_overview_has_seven_zero_filled_utc_days_and_filters_other_principals(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    subject = "owner@example.test"
    owner = store._owner(subject)
    other_owner = store._owner("other@example.test")
    today = date(2026, 10, 11)
    noon = datetime.combine(today, time(12), UTC)
    older = (noon - timedelta(days=8)).timestamp()
    recent = (noon - timedelta(days=2)).timestamp()
    active = (noon - timedelta(days=1)).timestamp()
    _insert_turn(store, owner=owner, conversation="owner-chat", turn_id="owner-done",
                 status="completed", created=recent)
    _insert_turn(store, owner=owner, conversation="owner-chat", turn_id="owner-live",
                 status="running", created=active)
    _insert_turn(store, owner=owner, conversation="owner-chat", turn_id="owner-old",
                 status="failed", created=older)
    _insert_turn(store, owner=other_owner, conversation="other-chat", turn_id="other-done",
                 status="completed", created=recent)

    result = build_overview(store, subject, observed_at=noon)

    assert result["core"] == {
        "status": "process-observed",
        "readiness": "current-core-witness",
        "observedAt": "2026-10-11T12:00:00Z",
        "version": None,
        "resourcesState": "pending",
        "resourceCounts": None,
        "resourcesRevision": None,
        "discoveryObservedAt": None,
        "activePromptMatchesBundledPrimary": None,
    }
    assert result["chat"]["conversationCount"] == 1
    assert result["chat"]["turnCounts"] == {
        "total": 3, "completed": 1, "failed": 1, "cancelled": 0, "active": 1,
    }
    days = result["chat"]["turnCountsByDay"]
    assert len(days) == 7
    assert [item["date"] for item in days] == [
        (today - timedelta(days=offset)).isoformat() for offset in range(6, -1, -1)
    ]
    assert all(set(item) == {"date", "total", "completed", "failed", "cancelled"} for item in days)
    assert days[4] == {"date": "2026-10-09", "total": 1,
                       "completed": 1, "failed": 0, "cancelled": 0}
    assert days[5] == {"date": "2026-10-10", "total": 1,
                       "completed": 0, "failed": 0, "cancelled": 0}
    assert all(item["total"] == 0 for item in (days[0], days[1], days[2], days[3], days[6]))


def test_empty_overview_reports_zero_real_counts_and_pending_settings(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    result = build_overview(store, "owner@example.test",
                            observed_at=datetime(2026, 10, 11, 0, 1, tzinfo=UTC))

    assert result["chat"]["conversationCount"] == 0
    assert result["chat"]["turnCounts"] == {
        "total": 0, "completed": 0, "failed": 0, "cancelled": 0, "active": 0,
    }
    assert result["chat"]["lastTurnAt"] is None
    assert all(item["total"] == 0 for item in result["chat"]["turnCountsByDay"])
    assert build_settings() == {
        "readiness": "pending",
        "provider": {"value": None, "status": "pending"},
        "model": {"value": None, "status": "pending"},
        "coreVersion": {"value": None, "status": "pending"},
    }


def test_discovery_and_verified_core_version_never_claim_functional_capability(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    projection = {
        "core_version": "7085fbf77532", "provider": None, "model": None,
        "account_state": "unknown", "resources_state": "discovered",
        "resource_counts": {"native_skills": 396, "internal_profiles": 207,
            "source_profiles_preserved": 208, "other_declarations_preserved": 88},
        "resources_revision": "a" * 40, "artifact_sha256": "b" * 64,
        "discovery_observed_at_utc": "2026-10-11T12:00:00Z",
        "active_prompt_matches_bundled_primary": False,
    }

    overview = build_overview(store, "owner@example.test",
        observed_at=datetime(2026, 10, 11, 12, tzinfo=UTC), core_projection=projection)
    settings = build_settings(projection)
    capabilities = build_capabilities(projection)

    assert overview["core"]["resourcesState"] == "discovered"
    assert overview["capabilities"]["readiness"] == "pending"
    assert overview["capabilities"]["discoveredResourceCounts"] == projection["resource_counts"]
    assert settings["coreVersion"] == {"value": "7085fbf77532", "status": "verified"}
    assert settings["provider"] == {"value": None, "status": "pending"}
    assert capabilities["nativeDiscovery"]["state"] == "discovered"
    assert {item["state"] for item in capabilities["items"]} == {"bundled"}


def test_capabilities_use_fixed_packaged_inventory_and_public_jarvis_alias():
    inventory = _verified_bundle_inventory()
    assert inventory["source"] == {
        "kind": "offline-bundle", "catalogVersion": "2.3.1",
        "revision": "113f42d33be9e0c8f0f47f5ca998e687323dec83",
    }
    assert len(inventory["items"]) == 692
    primary = next(item for item in inventory["items"]
                   if item["kind"] == "profiles" and item["id"] == "hermes")
    assert primary["displayName"] == "Jarvis"
    assert primary["readiness"] == "pending"
