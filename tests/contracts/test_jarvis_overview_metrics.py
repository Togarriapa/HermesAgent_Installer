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
    assert FEATURE_ASSETS.mount_js.startswith("function mount(")
    assert "  function overviewScopeIsCurrent(" in FEATURE_ASSETS.mount_js
    assert "  function projectNativeEcosystem(" in FEATURE_ASSETS.mount_js
    assert FEATURE_ASSETS.feature_id == "overview"
    assert FEATURE_ASSETS.api_routes == (("GET", "/chat/api/overview"), ("GET", "/chat/api/ecosystem"))
    assert "<table>" in FEATURE_ASSETS.view_html
    assert "data-observation role=\"status\"" in FEATURE_ASSETS.view_html


def test_overview_reactor_uses_observed_activity_and_keeps_controls_accessible():
    html = FEATURE_ASSETS.view_html
    css = FEATURE_ASSETS.css
    js = FEATURE_ASSETS.mount_js

    assert 'class="overview-stage" data-activity="unknown"' in html
    assert '<section class="command-centre-shell" aria-label="Jarvis command centre">' in html
    assert html.index('class="overview-stage"') < html.index('class="command-panel"') < html.index('class="ecosystem-card"')
    assert 'id="jarvis-ecosystem-feature-host" data-feature-host="ecosystem-fleet"' in html
    assert "command-centre-shell:before" in css and "command-centre-shell:after" in css
    assert "#jarvis-ecosystem-feature-host" in css
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


def test_overview_reactor_has_authored_static_iris_and_measured_flank_cards():
    html, css = FEATURE_ASSETS.view_html, FEATURE_ASSETS.css
    assert html.count('class="reactor-iris-blade"') == 6
    for layer in ("reactor-segment-north", "reactor-segment-east", "reactor-segment-south",
                  "reactor-segment-west", "reactor-instrument-track", "reactor-chamber",
                  "reactor-core", "reactor-lens", "reactor-aperture"):
        assert f'class="{layer}"' in html
    assert ".reactor-segment{fill:none;stroke:" in css
    iris_rule = css[css.index(".reactor-iris-blade{"):css.index(".reactor-core{")]
    assert "stroke:" in iris_rule and "animation:" not in iris_rule
    for metric in ("total", "completed", "active", "failed"):
        assert f'data-metric="{metric}">Unknown' in html
    assert 'data-conversation-count>Unknown' in html
    assert ".command-centre-shell .overview-readout{position:relative" in css


def test_overview_command_submission_preserves_text_on_denial_and_recovers():
    js = FEATURE_ASSETS.mount_js
    start = js.index("  async function submitCommand(event) {")
    end = js.index("\n  const newConversation", start)
    submit = js[start:end]
    harness = r'''const assert = require('node:assert/strict');
let stopped = false, failCommand = false;
const sent = [], observation = {textContent:''}, button = {disabled:false};
const commandInput = {value:'', disabled:false};
const commandForm = {querySelector:() => button};
const api = {command:async text => {sent.push(text); if(failCommand) throw new Error('denied'); return true;}};
const $ = selector => selector === '[data-observation]' ? observation : null;
''' + submit + r'''
const submitEvent = {prevented:false,preventDefault(){this.prevented=true;}};
(async()=>{
 commandInput.value='  Review my current tasks  ';
 await submitCommand(submitEvent);
 assert.equal(submitEvent.prevented,true);
 assert.deepEqual(sent,['Review my current tasks'],'the existing command bridge receives the exact owner text');
 assert.equal(commandInput.value,'','accepted send clears the composer');
 failCommand=true; commandInput.value='Keep this draft';
 await submitCommand({preventDefault(){}});
 assert.equal(sent.length,2);
 assert.equal(commandInput.value,'Keep this draft','a denied send preserves the typed text');
 assert.match(observation.textContent,/text remains here/i);
 const before=sent.length; button.disabled=true; commandInput.value='Do not duplicate';
 await submitCommand({preventDefault(){}});
 assert.equal(sent.length,before,'a pending send is not replayed');
 console.log('OVERVIEW_COMMAND_HARNESS_COMPLETE');
})().catch(error=>{console.error(error);process.exitCode=1;});
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "overview-command-harness.js"
        path.write_text(harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False,
                                timeout=15)
    assert result.returncode == 0, result.stderr
    assert "OVERVIEW_COMMAND_HARNESS_COMPLETE" in result.stdout


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
    os_reduce_rule = next(rule for rule in css.split("}")
                         if '@media(prefers-reduced-motion:reduce)' in rule and ".reactor-orbit-inner" in rule)
    assert all(selector in os_reduce_rule for selector in (".reactor-dial", ".reactor-orbit-inner", ".reactor-orbit-outer"))
    assert "animation:none!important;transform:none!important" in os_reduce_rule
    app_reduce_rule = next(rule for rule in css.split("}")
                           if 'html[data-jarvis-motion="reduce"]' in rule and ".reactor-dial" in rule)
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


def test_overview_projects_only_real_shared_jarvis_interaction_states():
    css, js = FEATURE_ASSETS.css, FEATURE_ASSETS.mount_js
    assert "function projectAssistantPresence(state)" in js
    assert "['listening','thinking','speaking','error'].includes(state) ? state : null" in js
    assert "document.getElementById('assistant-hud')?.dataset.state" in js
    assert "assistantHudObserver.observe(assistantHud, {attributes:true, attributeFilter:['data-state']})" in js
    assert "if (assistantHudObserver) assistantHudObserver.disconnect()" in js
    assert "stage.dataset.assistantState = assistantState || 'none'" in js
    assert '[data-assistant-state="thinking"] .reactor-orbit-outer' in css
    assert '[data-assistant-state="listening"] .reactor-orbit-outer' in css
    assert '[data-assistant-state="speaking"] .reactor-orbit-inner' in css
    assert '[data-assistant-state="error"] .reactor-core' in css
    assert "Needs attention · Jarvis reported an interaction error." in js
    assert "stage.dataset.assistantState = 'none'" in js


def test_overview_ecosystem_uses_named_root_observations_and_cancels_stale_views():
    html, css, js = FEATURE_ASSETS.view_html, FEATURE_ASSETS.css, FEATURE_ASSETS.mount_js
    assert 'data-ecosystem-card' in html and 'data-handoff-graph' in html
    assert 'Expert instances' in html and 'data-selected-team' in html
    assert 'Team membership appears only when independently verified; animated handoffs require a separate recorded directed relation.' in html
    assert "await api.get('/chat/api/ecosystem')" in js
    assert 'display_name' in js and 'profile_id' in js and 'summary.observed_completed_executions' in js
    assert 'No independently verified Team membership is available.' in js
    assert "overviewScopeIsCurrent(mountScope, generation, ecosystemGeneration, stopped)" in js
    assert "ecosystemObserver.observe(ecosystemCard)" in js
    assert "clearInterval(ecosystemPollTimer)" in js
    assert '[data-activity-flow="active"]:is([data-ecosystem-state="current"],[data-ecosystem-state="partial"])[data-in-viewport="true"] .handoff-route[data-has-observed-relation="true"][data-instance-state="running"] .handoff-edge:after' in css
    edge_stop_rule = next(rule for rule in css.split("}")
                          if 'html:not([data-page-visible="true"]) [data-feature-root="overview"] .handoff-edge:after' in rule)
    assert '[data-feature-root="overview"]:not([data-network-online="true"]) .handoff-edge:after' in edge_stop_rule
    assert '[data-feature-root="overview"] [data-ecosystem-card]:not([data-in-viewport="true"]) .handoff-edge:after' in edge_stop_rule
    assert "animation:none!important;transform:none!important;opacity:0!important" in edge_stop_rule
    assert "prefers-reduced-motion:reduce" in css and 'data-jarvis-motion="reduce"' in css

    helper_start = js.index('  function overviewScopeIsCurrent(')
    helper_end = js.index('\n  const root =', helper_start)
    helpers = js[helper_start:helper_end]
    assert "function projectNativeEcosystem(" in helpers
    helper_harness = (
        "function productionOverviewHelpers() {\n"
        + helpers
        + "\nreturn {overviewScopeIsCurrent, projectNativeEcosystem};\n}\n"
        + "const {overviewScopeIsCurrent, projectNativeEcosystem} = productionOverviewHelpers();\n"
    )
    harness = r'''const now = 1_800_000_000_000;
const activeScope = {signal:{aborted:false},isCurrent:()=>true};
assert.equal(overviewScopeIsCurrent(activeScope, 2, 2, false), true);
assert.equal(overviewScopeIsCurrent(activeScope, 1, 2, false), false, 'a superseded request cannot render');
assert.equal(overviewScopeIsCurrent({signal:{aborted:false},isCurrent:()=>false}, 2, 2, false), false,
  'leaving and remounting the view invalidates the previous source');
assert.equal(overviewScopeIsCurrent({signal:{aborted:true},isCurrent:()=>true}, 2, 2, false), false);
assert.equal(overviewScopeIsCurrent(activeScope, 2, 2, true), false);
const iso = new Date(now - 5_000).toISOString();
const page = {schema:2,observation:{state:'observed',observed_at:iso,partial:false},teams:[{name:'Unjoined team'}],relations:[],pending:{team_membership:'no_verified_instance_join'},
  instances:[{id:'private-instance',display_name:'Researcher',profile_id:'researcher',state:'running',stale:false,
    events:[{kind:'response',status:'observed',at:iso,duration_ms:1700,tool_count:0}]}],
  summary:{observed_instances:1,completed_executions:null,observed_completed_executions:2,
    response_duration_ms:1700,response_duration_coverage:1}};
const current = projectNativeEcosystem(page, now, true);
assert.equal(current.state, 'current');
assert.equal(current.active, true);
assert.equal(current.instances[0].display_name, 'Researcher');
assert.equal(current.teams.length, 0);
assert.equal(current.hasVerifiedTeamMembership, false, 'an unjoined Team name is not selected');
assert.equal(current.teams.length, 0, 'an unjoined Team remains pending');
assert.equal(current.instances[0].hasObservedRelation, false, 'an instance without a directed relation has no animated edge');
const admitted = projectNativeEcosystem({...page,pending:{team_membership:'verified'},teams:[{name:'admitted-team'}]}, now, true);
assert.equal(admitted.hasVerifiedTeamMembership, true);
assert.deepEqual(admitted.teams.map(team => team.name), ['admitted-team'], 'verified membership appears before a discussion edge exists');
assert.equal(admitted.instances[0].hasObservedRelation, false, 'membership alone does not create an animated handoff');
const unverifiedWitness = projectNativeEcosystem({...page,pending:{team_membership:'verified'},teams:[{name:'admitted-team'}]}, now, false);
assert.equal(unverifiedWitness.hasVerifiedTeamMembership, false, 'a stale Core witness cannot present membership as current');
assert.equal(unverifiedWitness.teams.length, 0);
const related = projectNativeEcosystem({...page,teams:[],instances:[...page.instances,
  {id:'private-recipient',display_name:'Reviewer',profile_id:'reviewer',state:'completed',stale:false,events:[]}],
  relations:[{from:'private-instance',to:'private-recipient',kind:'completed_message',state:'current'}]}, now, true);
assert.equal(related.hasVerifiedTeamMembership, false, 'a relation does not imply verified Team membership');
assert.equal(related.teams.length, 0);
assert.equal(related.instances.every(instance => instance.hasObservedRelation), true, 'only actual relation endpoints can animate');
const historical = projectNativeEcosystem({...page,instances:[...page.instances,
  {id:'private-recipient',display_name:'Reviewer',profile_id:'reviewer',state:'completed',stale:false,events:[]}],
  relations:[{from:'private-instance',to:'private-recipient',kind:'completed_message',state:'historical'}]}, now, true);
assert.equal(historical.instances[0].hasObservedRelation, false, 'historical relations do not animate as current handoffs');
assert.equal(projectNativeEcosystem({...page,observation:{state:'quiet',observed_at:iso}}, now, true).state, 'empty');
const stale = projectNativeEcosystem({...page,observation:{state:'observed',observed_at:new Date(now-121_000).toISOString()}}, now, true);
assert.equal(stale.state, 'stale');
assert.equal(stale.active, false, 'historical running statuses never animate');
assert.equal(projectNativeEcosystem(page, now, false).state, 'stale', 'ecosystem data cannot be current without the core witness');
const partial = projectNativeEcosystem({...page,observation:{state:'partial',observed_at:iso}}, now, true);
assert.equal(partial.state, 'partial');
assert.equal(partial.active, true, 'a fresh, explicitly non-stale running instance remains observable in a partial snapshot');
assert.equal(projectNativeEcosystem({observation:{state:'broken'},instances:[]}, now, true).state, 'unavailable');
assert.equal(JSON.stringify({...current, ...admitted, ...related}).includes('private-instance'), false, 'private execution ids stay out of the view model');
assert.equal(JSON.stringify(related).includes('private-recipient'), false, 'private relation endpoint ids stay out of the view model');
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "overview-ecosystem-harness.js"
        path.write_text("const assert = require('node:assert/strict');\n" + helper_harness + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_overview_ecosystem_first_load_failure_is_explicit_and_retains_prior_data():
    js = FEATURE_ASSETS.mount_js
    assert "invalidateHandoffs('unavailable')" in js
    start = js.index('  function invalidateHandoffs(reason) {')
    end = js.index('\n  async function refreshEcosystem()', start)
    invalidate = js[start:end]
    harness = r'''const elements = {
  '[data-ecosystem-status]': {textContent:'Loading'},
  '[data-expert-identity]': {textContent:'Loading'},
  '[data-selected-team]': {textContent:'Loading'},
  '[data-ecosystem-summary]': {textContent:'Loading'},
};
let ecosystemGeneration = 0;
let ecosystemRefreshing = true;
let ecosystemHasSnapshot = false;
const ecosystemCard = {dataset:{}};
function $(selector) { return elements[selector]; }
'''
    checks = r'''
invalidateHandoffs('unavailable');
assert.equal(ecosystemCard.dataset.ecosystemState, 'unavailable');
assert.equal(elements['[data-ecosystem-status]'].textContent, 'Current native Expert activity is unverified.');
assert.equal(elements['[data-expert-identity]'].textContent, 'Instance names and states are unavailable.');
assert.equal(elements['[data-selected-team]'].textContent, 'Team membership is unavailable.');
assert.equal(elements['[data-ecosystem-summary]'].textContent, 'No current native instance summary is available.');
assert.equal(ecosystemRefreshing, false);
ecosystemHasSnapshot = true;
elements['[data-expert-identity]'].textContent = '1 observed native instance.';
elements['[data-selected-team]'].textContent = 'Team Alpha';
elements['[data-ecosystem-summary]'].textContent = '1 completed execution';
invalidateHandoffs('unavailable');
assert.equal(elements['[data-expert-identity]'].textContent, '1 observed native instance.');
assert.equal(elements['[data-selected-team]'].textContent, 'Team Alpha');
assert.equal(elements['[data-ecosystem-summary]'].textContent, '1 completed execution');
'''
    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "overview-ecosystem-failure-harness.js"
        path.write_text(
            "const assert = require('node:assert/strict');\n" + harness + invalidate + checks,
            encoding="utf-8",
        )
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
