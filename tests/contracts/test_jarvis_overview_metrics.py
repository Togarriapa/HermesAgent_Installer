from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import subprocess
import tempfile

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
    assert FEATURE_ASSETS.api_routes == (("GET", "/chat/api/overview"), ("GET", "/chat/api/activity"))
    assert "<table>" in FEATURE_ASSETS.view_html
    assert "data-observation role=\"status\"" in FEATURE_ASSETS.view_html


def test_overview_reactor_uses_observed_activity_and_keeps_controls_accessible():
    html = FEATURE_ASSETS.view_html
    css = FEATURE_ASSETS.css
    js = FEATURE_ASSETS.mount_js

    assert 'class="overview-stage" data-activity="unknown"' in html
    assert 'data-reactor-state role="status" aria-live="polite"' in html
    assert 'data-core-status role="status" aria-live="polite"' in html
    assert 'data-command-form' in html and 'data-new-conversation' in html
    assert 'data-command-prompt=' in html
    assert "min-height:54px" in css and "min-height:44px" in css
    assert "@media(max-width:620px)" in css and "@media(max-width:360px)" in css
    assert "transition-duration:0s!important;transition-delay:0s!important" in css
    assert 'stage.dataset.activity = \'unknown\'' in js
    assert 'stage.dataset.activity = \'active\'' in js
    assert 'stage.dataset.activity = \'quiet\'' in js
    assert "await api.get('/chat/api/overview')" in js
    assert "await api.command(text)" in js
    assert "await api.newConversation()" in js
    assert "commandInput.value = button.dataset.commandPrompt" in js


def test_overview_presence_is_gated_by_fresh_core_witness():
    css = FEATURE_ASSETS.css
    js = FEATURE_ASSETS.mount_js

    assert "core.status === 'process-observed'" in js
    assert "age <= 120000" in js
    assert "core.readiness === 'current-core-witness'" in js
    assert "Service process observed" in js
    assert "Ready · standby." in js
    assert "setTimeout(recheckCoreFreshness" in js
    assert "stage.dataset.coreState = 'unverified'" in js
    assert '.overview-stage[data-in-viewport="true"][data-core-state="verified"]:is([data-activity="quiet"],[data-activity="active"])' in css
    assert '[data-feature-root="overview"] .overview-stage:not([data-in-viewport="true"]) .reactor-orbit{animation:none!important;transform:none!important}' in css
    assert 'html:not([data-page-visible="true"]) [data-feature-root="overview"] .overview-stage .reactor-orbit' in css
    assert '@media(prefers-reduced-motion:reduce){[data-feature-root="overview"] .reactor-dial,[data-feature-root="overview"] .reactor-orbit-inner,[data-feature-root="overview"] .reactor-orbit-outer{animation:none!important;transform:none!important}' in css
    app_reduce_rule = next(rule for rule in css.split("}") if 'html[data-jarvis-motion="reduce"]' in rule)
    assert all(selector in app_reduce_rule for selector in (".reactor-dial", ".reactor-orbit-inner", ".reactor-orbit-outer"))
    assert "animation:none!important;transform:none!important" in app_reduce_rule
    assert '[data-feature-root="overview"][data-stale="true"] .overview-stage .reactor-dial' in css
    assert '[data-feature-root="overview"] .quick-actions{display:flex;flex-wrap:wrap;overflow:visible' in css


def test_overview_presence_stops_when_hidden_or_offline_until_fresh_readback():
    css = FEATURE_ASSETS.css
    js = FEATURE_ASSETS.mount_js

    assert '[data-feature-root="overview"]:not([data-network-online="true"]) .overview-stage .reactor-orbit' in css
    assert 'html:not([data-page-visible="true"]) [data-feature-root="overview"] .overview-stage .reactor-orbit' in css
    assert "root.dataset.pageVisible = String(document.visibilityState === 'visible')" in js
    assert "document.addEventListener('visibilitychange',onVisibilityChange)" in js
    assert "window.addEventListener('offline',onNetworkChange)" in js
    assert "window.addEventListener('online',onNetworkChange)" in js
    assert "root.dataset.networkOnline = 'checking'" in js
    assert "refreshGeneration += 1" in js
    assert "generation === refreshGeneration && document.visibilityState === 'visible' && navigator.onLine !== false" in js
    assert js.index("const data = await api.get('/chat/api/overview')") < js.index("root.dataset.networkOnline = 'true';", js.index("const data = await api.get('/chat/api/overview')"))
    assert "markCoreStale('hidden')" in js
    assert "markCoreStale('offline')" in js


def test_overview_ecosystem_uses_only_current_native_activity_and_cancels_stale_views():
    html, css, js = FEATURE_ASSETS.view_html, FEATURE_ASSETS.css, FEATURE_ASSETS.mount_js
    assert 'data-ecosystem-card' in html and 'data-handoff-graph' in html
    assert 'Unavailable in the current activity response.' in html
    assert 'selected Team records, so those relationships are not inferred here.' in html
    assert "await api.get('/chat/api/activity')" in js
    assert "overviewScopeIsCurrent(mountScope, generation, ecosystemGeneration, stopped)" in js
    assert "ecosystemObserver.observe(ecosystemCard)" in js
    assert "clearInterval(ecosystemPollTimer)" in js
    assert '[data-activity-flow="active"][data-ecosystem-state="current"][data-in-viewport="true"] .handoff-edge:after' in css
    assert "html:not([data-page-visible=\"true\"]) [data-feature-root=\"overview\"] .ecosystem-card" in css
    assert "prefers-reduced-motion:reduce" in css and 'data-jarvis-motion="reduce"' in css

    helpers = js[:js.index('function mount(container, api, state, mountScope)')]
    harness = r'''const assert = require('node:assert/strict');
const now = 1_800_000_000_000;
const activeScope = {signal:{aborted:false},isCurrent:()=>true};
assert.equal(overviewScopeIsCurrent(activeScope, 2, 2, false), true);
assert.equal(overviewScopeIsCurrent(activeScope, 1, 2, false), false, 'a superseded request cannot render');
assert.equal(overviewScopeIsCurrent({signal:{aborted:false},isCurrent:()=>false}, 2, 2, false), false,
  'leaving and remounting the view invalidates the previous source');
assert.equal(overviewScopeIsCurrent({signal:{aborted:true},isCurrent:()=>true}, 2, 2, false), false);
assert.equal(overviewScopeIsCurrent(activeScope, 2, 2, true), false);
const page = {nextPage:null,events:[
  {turnId:'private-turn-a',type:'subagent.start',status:'running',sequence:1,observed_at:now/1000-10},
  {turnId:'private-turn-a',type:'subagent.tool',status:'running',sequence:2,observed_at:now/1000-5,duration_ms:17},
  {turnId:'private-turn-b',type:'subagent.complete',status:'completed',sequence:1,observed_at:now/1000-20},
  {turnId:'private-turn-c',type:'user.message',status:'completed',sequence:1,observed_at:now/1000-1},
]};
const current = projectHandoffActivity(page, now, true);
assert.equal(current.state, 'current');
assert.equal(current.active, true);
assert.equal(current.starts, 1);
assert.equal(current.completions, 1);
assert.equal(current.turnCount, 2);
assert.equal(current.groups[0].latest.type, 'subagent.tool');
assert.equal(JSON.stringify(current).includes('private-turn-a'), false, 'private turn identifiers stay out of the view model');
assert.equal(projectHandoffActivity({events:[],nextPage:null}, now, true).state, 'empty');
const stale = projectHandoffActivity({events:[{turnId:'old',type:'subagent.start',status:'running',observed_at:now/1000-121}],nextPage:null}, now, true);
assert.equal(stale.state, 'stale');
assert.equal(stale.active, false, 'historical running statuses never animate');
assert.equal(projectHandoffActivity(page, now, false).state, 'stale', 'activity cannot be current without the core witness');
assert.equal(projectHandoffActivity({events:null}, now, true).state, 'unavailable');
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "overview-ecosystem-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + helpers + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
