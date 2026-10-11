from __future__ import annotations

from datetime import datetime, timezone

from hermes_installer.remote.jarvis_chat import JarvisChatStore
from hermes_installer.remote.jarvis_dashboard import build_overview
from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets
from hermes_installer.remote.jarvis_overview_assets import FEATURE_ASSETS


UTC = timezone.utc


def _insert_turn(store: JarvisChatStore, *, owner: str, conversation: str,
                 turn_id: str, status: str, created: float, updated: float) -> None:
    with store._connect() as db:
        db.execute(
            "INSERT OR IGNORE INTO conversations "
            "(id,owner,backend_id,session_key,title,created,updated,core_generation) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (conversation, owner, f"backend-{conversation}", f"session-{conversation}",
             "Jarvis", created, updated, "generation"),
        )
        db.execute(
            "INSERT INTO turns "
            "(id,owner,conversation_id,idempotency_hash,request_hash,status,heartbeat_nonce,"
            "heartbeat_expiry,jwt_expiry,runtime_session_id,core_generation,partial,error_code,created,updated) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (turn_id, owner, conversation, f"idem-{turn_id}", f"request-{turn_id}", status,
             "", 0.0, 0.0, "", "generation", "", "", created, updated),
        )


def _mission_tables(store: JarvisChatStore) -> None:
    with store._connect() as db:
        db.executescript("""
          CREATE TABLE jarvis_missions(
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, revision INTEGER NOT NULL,
            status TEXT NOT NULL, plan_sha256 TEXT, source_binding TEXT);
          CREATE TABLE jarvis_mission_approvals(
            id TEXT PRIMARY KEY, owner TEXT NOT NULL, mission_id TEXT NOT NULL,
            revision INTEGER NOT NULL, plan_sha256 TEXT NOT NULL, source_binding TEXT NOT NULL,
            status TEXT NOT NULL, expires REAL NOT NULL);
        """)


def test_overview_reports_bounded_owner_counts_and_real_elapsed_durations(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    subject = "owner@example.test"
    owner = store._owner(subject)
    other = store._owner("other@example.test")
    observed = datetime(2026, 10, 11, 12, tzinfo=UTC)
    start = datetime(2026, 10, 5, 0, tzinfo=UTC).timestamp()

    _insert_turn(store, owner=owner, conversation="owned", turn_id="at-window-start",
                 status="cancelled", created=start, updated=start + 1.25)
    _insert_turn(store, owner=owner, conversation="owned", turn_id="finished",
                 status="completed", created=datetime(2026, 10, 11, 10, tzinfo=UTC).timestamp(),
                 updated=datetime(2026, 10, 11, 10, 0, 10, tzinfo=UTC).timestamp())
    _insert_turn(store, owner=owner, conversation="owned", turn_id="failed",
                 status="failed", created=datetime(2026, 10, 10, 23, tzinfo=UTC).timestamp(),
                 updated=datetime(2026, 10, 10, 23, 0, 20, tzinfo=UTC).timestamp())
    _insert_turn(store, owner=owner, conversation="owned", turn_id="long-duration",
                 status="completed", created=datetime(2026, 10, 11, 9, tzinfo=UTC).timestamp(),
                 updated=datetime(2026, 10, 11, 9, 10, 1, tzinfo=UTC).timestamp())
    _insert_turn(store, owner=owner, conversation="owned", turn_id="active",
                 status="running", created=datetime(2026, 10, 11, 11, tzinfo=UTC).timestamp(),
                 updated=datetime(2026, 10, 11, 11, tzinfo=UTC).timestamp())
    _insert_turn(store, owner=owner, conversation="owned", turn_id="before-window",
                 status="completed", created=start - 1, updated=start)
    _insert_turn(store, owner=owner, conversation="owned", turn_id="after-observation",
                 status="completed", created=observed.timestamp() + 1,
                 updated=observed.timestamp() + 2)
    _insert_turn(store, owner=other, conversation="foreign", turn_id="foreign",
                 status="failed", created=datetime(2026, 10, 11, 9, tzinfo=UTC).timestamp(),
                 updated=datetime(2026, 10, 11, 9, 0, 30, tzinfo=UTC).timestamp())

    result = build_overview(store, subject, observed_at=observed)
    statistics = result["chat"]["statistics"]

    assert statistics["window"] == {
        "startAt": "2026-10-05T00:00:00Z",
        "endAt": "2026-10-11T12:00:00Z",
        "timezone": "UTC",
        "basis": "turn accepted during the seven UTC calendar days ending at observation time",
    }
    assert statistics["observedAt"] == "2026-10-11T12:00:00Z"
    assert statistics["turnCounts"] == {
        "total": 5, "active": 1, "completed": 2, "failed": 1,
        "cancelled": 1, "unknown": 0,
    }
    duration = statistics["duration"]
    assert duration["sampleLimit"] == 100
    assert duration["partial"] is True
    assert duration["omittedCount"] == 1
    assert duration["basis"] == "turn accepted to terminal status; elapsed time includes queue time"
    assert [(item["status"], item["durationMs"]) for item in duration["samples"]] == [
        ("cancelled", 1250), ("failed", 20_000), ("completed", 10_000),
    ]
    assert result["chat"]["turnCounts"]["total"] == 7
    assert result["resources"]["dispatch"]["count"] is None
    assert result["schedules"]["pausedCount"] is None


def test_overview_mission_count_requires_live_current_owner_approval(tmp_path):
    store = JarvisChatStore(tmp_path / "chat.sqlite3")
    subject = "owner@example.test"
    owner = store._owner(subject)
    other = store._owner("other@example.test")
    observed = datetime(2026, 10, 11, 12, tzinfo=UTC)
    _mission_tables(store)
    with store._connect() as db:
        db.executemany(
            "INSERT INTO jarvis_missions VALUES(?,?,?,?,?,?)",
            [
                ("current", owner, 2, "preview_pending", "a" * 64, "source-2"),
                ("stale", owner, 3, "preview_pending", "c" * 64, "source-3"),
                ("foreign", other, 1, "preview_pending", "d" * 64, "source-1"),
            ],
        )
        db.executemany(
            "INSERT INTO jarvis_mission_approvals VALUES(?,?,?,?,?,?,?,?)",
            [
                ("valid", owner, "current", 2, "a" * 64, "source-2", "approved", observed.timestamp() + 30),
                ("valid-repeat", owner, "current", 2, "a" * 64, "source-2", "approved", observed.timestamp() + 30),
                ("expired", owner, "current", 2, "a" * 64, "source-2", "approved", observed.timestamp() - 1),
                ("spent", owner, "current", 2, "a" * 64, "source-2", "spent", observed.timestamp() + 30),
                ("stale", owner, "stale", 2, "b" * 64, "source-2", "approved", observed.timestamp() + 30),
                ("foreign", other, "foreign", 1, "d" * 64, "source-1", "approved", observed.timestamp() + 30),
            ],
        )

    result = build_overview(store, subject, observed_at=observed)

    assert result["missions"] == {"state": "observed", "approvedPendingCount": 1}


def test_overview_fragment_is_a_fixed_accessible_asset():
    validate_feature_assets((FEATURE_ASSETS,))
    assert FEATURE_ASSETS.feature_id == "overview"
    assert FEATURE_ASSETS.api_routes == (("GET", "/chat/api/overview"),)
    assert "<table>" in FEATURE_ASSETS.view_html
    assert "data-observation role=\"status\"" in FEATURE_ASSETS.view_html
