"""Source contracts for fixed Jarvis status and one-use schedule pause."""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from aiohttp import web
from aiohttp.test_utils import TestClient, TestServer

from hermes_installer.remote.core_client import CoreRpcClient
from hermes_installer.remote.jarvis_bots import (
    FEATURE_ROUTES,
    build_status_snapshot,
    install_jarvis_bots_routes,
)
from hermes_installer.remote.jarvis_channels import CHANNEL_STATUS_PENDING, project_channel_status
from hermes_installer.remote.jarvis_chat import ChatPrincipal, JarvisChatService, JarvisChatStore
from hermes_installer.remote.jarvis_schedules import project_schedules
from hermes_installer.remote.jarvis_schedule_actions import ScheduleActionLedger, schedule_revision


def test_schedule_projection_is_bounded_and_excludes_sensitive_native_fields():
    projected, missing_timezone = project_schedules([{
        "job_id": "native-job-id-must-not-leak",
        "name": "sensitive prompt preview must not be used as a title",
        "enabled": False,
        "schedule": "*/15 * * * *",
        "next_run_at": "2026-10-11T18:30:00Z",
        "last_run_at": 1_791_737_400,
        "last_status": "success",
        "state": "paused",
        "paused_at": 1_791_737_000,
        "prompt_preview": "private instruction",
        "script": "do-not-run",
        "workdir": "/private/path",
        "delivery": {"to": "private-destination"},
    }])

    assert missing_timezone is True
    assert len(projected) == 1
    assert set(projected[0]) == {
        "opaque_id", "label", "enabled", "timezone", "schedule_summary", "next_run_at", "last_state",
    }
    assert projected[0]["label"] == "Scheduled job 1"
    assert projected[0]["enabled"] is False
    assert projected[0]["timezone"] is None
    assert projected[0]["schedule_summary"] == "*/15 * * * *"
    assert projected[0]["next_run_at"] == "2026-10-11T18:30:00Z"
    assert projected[0]["last_state"] == "success"
    assert "private" not in repr(projected)
    assert "native-job-id" not in repr(projected)


def test_schedule_unknown_enabled_and_timestamp_remain_unknown():
    projected, missing_timezone = project_schedules([{
        "job_id": "opaque",
        "name": "Scheduled job",
        "enabled": None,
        "schedule": None,
        "next_run_at": "not-a-timestamp",
        "last_status": "unknown",
    }])
    assert missing_timezone is True
    assert projected[0]["enabled"] is None
    assert projected[0]["schedule_summary"] == "Schedule details unavailable"
    assert projected[0]["next_run_at"] is None
    assert projected[0]["last_state"] is None


def test_status_snapshot_reports_observed_profile_and_schedule_with_exact_pending_sources():
    result = build_status_snapshot(
        core_generation="generation-1",
        observed_at="2026-10-11T12:00:00Z",
        profile={"name": "default", "display_name": "Jarvis", "is_default": True,
                 "provider": "secret-provider", "model": "private-model", "path": "/private/profile"},
        schedules=[{"name": "Scheduled job", "enabled": True, "schedule": "0 * * * *",
                    "next_run_at": None, "last_status": None, "prompt": "private"}],
    )

    assert set(result) == {
        "schema", "observed_at", "core_generation", "profiles", "channels", "schedules", "pending_reasons",
    }
    assert result["schema"] == 1
    assert result["profiles"][0]["display_name"] == "Jarvis"
    assert result["profiles"][0]["kind"] == "profile"
    assert result["profiles"][0]["bot_mode_available"] is False
    assert set(result["profiles"][0]) == {
        "opaque_id", "display_name", "kind", "state", "bot_mode_available",
    }
    assert result["channels"] == []
    assert result["schedules"][0]["enabled"] is True
    assert result["schedules"][0]["timezone"] is None
    assert "pause_approval_nonce" not in result["schedules"][0]
    assert all(isinstance(reason, str) and reason for reason in result["pending_reasons"])
    encoded = repr(result)
    assert "secret-provider" not in encoded and "private-model" not in encoded
    assert "/private/profile" not in encoded and "private\'" not in encoded


def test_channel_status_is_explicitly_unavailable_instead_of_fabricated():
    items, reason = project_channel_status()
    assert items == []
    assert reason == CHANNEL_STATUS_PENDING
    assert "unknown" in reason


def test_routes_use_only_fixed_default_profile_and_reject_query_selectors(tmp_path, monkeypatch):
    async def scenario():
        profile_calls = []
        cron_calls = []

        async def list_profiles(self):
            profile_calls.append(True)
            return [{"name": "default", "display_name": "Jarvis", "is_default": True}]

        async def list_schedules(self):
            cron_calls.append(True)
            return [{"job_id": "secret-id", "name": "Scheduled job", "enabled": False,
                     "schedule": "0 9 * * *", "next_run_at": None, "last_run_at": None,
                     "last_status": "success", "state": "paused", "paused_at": None}]

        monkeypatch.setattr(CoreRpcClient, "list_profiles", list_profiles, raising=False)
        monkeypatch.setattr(CoreRpcClient, "list_schedules", list_schedules, raising=False)
        backend = CoreRpcClient(token_file=Path(tmp_path / "unused-token"))

        def principal(_request):
            now = time.monotonic()
            return ChatPrincipal("owner-subject", now + 30, now + 10, "generation-1")

        service = JarvisChatService(JarvisChatStore(tmp_path / "chat.sqlite3"), backend,
                                    principal_from_request=principal)
        app = web.Application()
        install_jarvis_bots_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/schedules")
            assert response.status == 200
            payload = await response.json()
            assert payload["core_generation"] == "generation-1"
            assert payload["schedules"][0]["enabled"] is False
            assert profile_calls == [True, True]
            assert cron_calls == [True]
            assert (await client.get("/chat/api/schedules?profile=private-profile")).status == 404
            assert profile_calls == [True, True]
        finally:
            await client.close()

    asyncio.run(scenario())


def test_routes_are_fixed_status_reads_and_one_pause_action():
    assert FEATURE_ROUTES == (
        ("GET", "/chat/api/bots"),
        ("GET", "/chat/api/channels"),
        ("GET", "/chat/api/schedules"),
        ("POST", "/chat/api/schedules/{opaque_id}/pause"),
        ("GET", "/chat/api/bot-rooms"),
    )


def test_schedule_action_ledger_binds_owner_generation_revision_and_spends_once(tmp_path):
    ledger = ScheduleActionLedger(tmp_path / "actions.sqlite3")
    rows = [{"job_id": "native-1", "enabled": True, "schedule": "0 * * * *",
             "next_run_at": "2026-10-11T12:00:00Z", "state": "scheduled"}]
    revision = schedule_revision(rows)
    approvals = ledger.issue_snapshot("owner", "generation-1", "default",
                                      time.monotonic() + 60, rows)
    approval = approvals[0]
    assert approval is not None
    assert ledger.resolve_approval(subject="owner", core_generation="generation-1",
                                   profile_identity="default",
                                   jwt_expiry=time.monotonic() + 90, opaque_id=approval.opaque_id,
                                   revision=revision, approval_nonce=approval.approval_nonce) == "native-1"
    key = "k" * 32
    binding = ledger.spend(subject="owner", core_generation="generation-1",
                           profile_identity="default",
                           jwt_expiry=time.monotonic() + 90, opaque_id=approval.opaque_id,
                           revision=revision, approval_nonce=approval.approval_nonce,
                           idempotency_key=key)
    assert binding.job_id == "native-1"
    assert binding.action_state == "pending"
    prior = ledger.lookup_action(subject="owner", core_generation="generation-1",
                                 profile_identity="default",
                                 opaque_id=approval.opaque_id, revision=revision,
                                 approval_nonce=approval.approval_nonce, idempotency_key=key)
    assert prior is not None and prior.action_state == "pending"
    ledger.complete(binding, {"status": "paused"})
    completed = ledger.lookup_action(subject="owner", core_generation="generation-1",
                                    profile_identity="default",
                                    opaque_id=approval.opaque_id, revision=revision,
                                    approval_nonce=approval.approval_nonce, idempotency_key=key)
    assert completed is not None and completed.result == {"status": "paused"}
    with pytest.raises(PermissionError):
        ledger.resolve_approval(subject="another-owner", core_generation="generation-1",
                                profile_identity="default",
                                jwt_expiry=time.monotonic() + 90, opaque_id=approval.opaque_id,
                                revision=revision, approval_nonce=approval.approval_nonce)
    with pytest.raises(PermissionError):
        ledger.lookup_action(subject="owner", core_generation="generation-2",
                             profile_identity="default",
                             opaque_id=approval.opaque_id, revision=revision,
                             approval_nonce=approval.approval_nonce, idempotency_key=key)


def test_schedule_pause_route_calls_fixed_native_pause_and_confirms_state(tmp_path, monkeypatch):
    async def scenario():
        profile_calls = []
        native_calls = []
        schedules = [{"job_id": "native-job-1", "name": "private prompt title", "enabled": True,
                      "schedule": "0 9 * * *", "next_run_at": "2026-10-11T09:00:00Z",
                      "last_run_at": None, "last_status": None, "state": "scheduled", "paused_at": None}]

        async def list_profiles(self):
            profile_calls.append(True)
            return [{"name": "default", "display_name": "Jarvis", "is_default": True}]

        async def list_schedules(self):
            return [dict(row) for row in schedules]

        async def pause_schedule(self, job_id):
            native_calls.append(job_id)
            assert job_id == "native-job-1"
            schedules[0].update(enabled=False, state="paused")

        monkeypatch.setattr(CoreRpcClient, "list_profiles", list_profiles, raising=False)
        monkeypatch.setattr(CoreRpcClient, "list_schedules", list_schedules, raising=False)
        monkeypatch.setattr(CoreRpcClient, "pause_schedule", pause_schedule, raising=False)
        backend = CoreRpcClient(token_file=Path(tmp_path / "unused-token"))

        def principal(_request):
            now = time.monotonic()
            return ChatPrincipal("owner-subject", now + 60, now + 30, "generation-1")

        service = JarvisChatService(JarvisChatStore(tmp_path / "chat.sqlite3"), backend,
                                    principal_from_request=principal)
        app = web.Application()
        install_jarvis_bots_routes(app, service)
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get("/chat/api/schedules")
            payload = await response.json()
            item = payload["schedules"][0]
            assert response.status == 200
            assert item["enabled"] is True
            assert item["pause_approval_nonce"]
            assert "native-job-1" not in repr(payload)
            body = {"revision": item["revision"],
                    "approval_nonce": item["pause_approval_nonce"],
                    "idempotency_key": "z" * 32}
            action = await client.post(
                "/chat/api/schedules/" + item["opaque_id"] + "/pause", json=body)
            assert action.status == 200
            assert await action.json() == {"status": "paused"}
            assert native_calls == ["native-job-1"]
            replay = await client.post(
                "/chat/api/schedules/" + item["opaque_id"] + "/pause", json=body)
            assert replay.status == 200
            assert await replay.json() == {"status": "paused"}
            assert native_calls == ["native-job-1"]
            assert len(profile_calls) == 6
        finally:
            await client.close()

    asyncio.run(scenario())


def test_bots_mount_fences_pause_continuations_across_navigation_refresh_and_unmount(tmp_path):
    """Exercise schedule-action continuation fencing with deferred API responses."""
    from hermes_installer.remote.jarvis_bots_ui import FEATURE_ASSETS

    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the browser lifecycle harness")
    harness = r'''const assert = require('node:assert/strict');
const MOUNT = __MOUNT__;
class Element {
  constructor() { this.children = []; this.dataset = {}; this.attrs = {}; this.handlers = {}; this.textContent = ''; this.hidden = false; this.disabled = false; }
  appendChild(child) { this.children.push(child); return child; }
  replaceChildren(...children) { this.children = children; }
  setAttribute(key, value) { this.attrs[key] = value; }
  removeAttribute(key) { delete this.attrs[key]; }
  closest(selector) {
    if (selector === '[data-bots-section]' && this.dataset.botsSection) return this;
    if (selector === '[data-bots-refresh]' && this.dataset.botsRefresh) return this;
    if (selector === '[data-schedule-pause]' && this.dataset.schedulePause) return this;
    return null;
  }
}
function find(node, predicate) {
  if (predicate(node)) return node;
  for (const child of node.children || []) { const found = find(child, predicate); if (found) return found; }
  return null;
}
function setup() {
  const status = new Element(), rows = new Element(), pending = new Element(), roster = new Element();
  const tabs = ['bots', 'channels', 'schedules'].map(section => { const b = new Element(); b.dataset.botsSection = section; return b; });
  const refresh = new Element(); refresh.dataset.botsRefresh = 'true';
  const nodes = {'[data-bots-status]':status, '[data-bots-rows]':rows,
    '[data-bots-pending]':pending, '[data-bots-roster]':roster};
  const container = {
    children:[...tabs, refresh, status, pending, roster, rows],
    querySelector: selector => nodes[selector],
    querySelectorAll: selector => selector === '[data-bots-section]' ? tabs : [],
    addEventListener(_name, fn) { this.clickHandler = fn; },
    removeEventListener(_name, fn) { if (this.clickHandler === fn) this.clickHandler = null; },
  };
  const calls = [];
  const request = (kind, path, body) => new Promise((resolve, reject) => calls.push({kind, path, body, resolve, reject}));
  const api = {get:path => request('GET', path), post:(path, body) => request('POST', path, body)};
  global.document = {createElement: () => new Element()};
  global.crypto = {getRandomValues(bytes) { bytes.fill(1); return bytes; }};
  const mount = new Function(`return (${MOUNT})`)();
  const cleanup = mount(container, api, {});
  const click = target => container.clickHandler({target});
  return {container, calls, nodes, tabs, refresh, click, cleanup,
    pauseButton:() => find(rows, item => Boolean(item.dataset && item.dataset.schedulePause))};
}
const tick = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
const base = observed_at => ({observed_at, core_generation:'generation-1', pending_reasons:[], profiles:[], channels:[], schedules:[]});
const schedules = (observed_at, revision) => ({...base(observed_at), schedules:[{
  label:'Scheduled job 1', enabled:true, schedule_summary:'0 9 * * *', timezone:'UTC',
  next_run_at:null, last_state:'unknown', opaque_id:'opaque-schedule', revision,
  pause_approval_nonce:'one-use-nonce',
}]});
const get = (app, index, value) => { assert.equal(app.calls[index].kind, 'GET'); app.calls[index].resolve(value); };
const pause = (app, index) => { assert.equal(app.calls[index].kind, 'POST'); app.calls[index].resolve({status:'paused'}); };
const status = app => app.nodes['[data-bots-status]'].textContent;
async function readySchedules(app, timestamp='schedule-current', revision='rev-1') {
  get(app, 0, base('bots-initial')); await tick();
  get(app, 1, {profiles:[]}); await tick();
  await app.click(app.tabs[2]);
  get(app, 2, schedules(timestamp, revision)); await tick();
}
async function run() {
  // Schedules -> Bots: duplicate clicks spend only one exact one-use POST; late success stays off Bots.
  let app = setup(); await readySchedules(app);
  const button = app.pauseButton(); assert.ok(button);
  const continuation = app.click(button); await tick();
  await app.click(button); await tick();
  assert.equal(app.calls.length, 4);
  assert.equal(app.calls[3].path, '/chat/api/schedules/opaque-schedule/pause');
  assert.deepEqual(Object.keys(app.calls[3].body).sort(), ['approval_nonce', 'idempotency_key', 'revision']);
  assert.equal(app.calls[3].body.revision, 'rev-1');
  assert.equal(app.calls[3].body.approval_nonce, 'one-use-nonce');
  assert.match(app.calls[3].body.idempotency_key, /^[0-9a-f]{48}$/);
  await app.click(app.tabs[0]);
  get(app, 4, {...base('bots-current'), profiles:[]}); await tick();
  get(app, 5, {profiles:[]}); await tick();
  pause(app, 3); await continuation; await tick();
  assert.match(status(app), /Observed bots-current/);
  assert.doesNotMatch(status(app), /Pause was confirmed|Pause result is pending/);

  // Schedules -> Channels: late rejection cannot replace the selected Channels status.
  app = setup(); await readySchedules(app, 'schedule-before-channel');
  const failedContinuation = app.click(app.pauseButton()); await tick();
  await app.click(app.tabs[1]);
  get(app, 4, {...base('channels-current'), channels:[]}); await tick();
  app.calls[3].reject(new Error('uncertain')); await failedContinuation; await tick();
  assert.match(status(app), /Observed channels-current/);
  assert.doesNotMatch(status(app), /Pause result|could not be confirmed/);

  // ABA navigation and a newer Schedules refresh make the pending success stale.
  app = setup(); await readySchedules(app, 'schedule-before-aba');
  const abaContinuation = app.click(app.pauseButton()); await tick();
  await app.click(app.tabs[0]);
  get(app, 4, {...base('bots-aba'), profiles:[]}); await tick();
  get(app, 5, {profiles:[]}); await tick();
  await app.click(app.tabs[2]);
  get(app, 6, schedules('schedule-aba-current', 'rev-2')); await tick();
  pause(app, 3); await abaContinuation; await tick();
  assert.match(status(app), /Observed schedule-aba-current/);
  assert.doesNotMatch(status(app), /Pause was confirmed/);

  // A refresh during a POST is authoritative; the old action continuation cannot replace it.
  app = setup(); await readySchedules(app, 'schedule-before-refresh');
  const refreshContinuation = app.click(app.pauseButton()); await tick();
  await app.click(app.refresh);
  get(app, 4, schedules('schedule-refreshed', 'rev-2')); await tick();
  pause(app, 3); await refreshContinuation; await tick();
  assert.match(status(app), /Observed schedule-refreshed/);
  assert.doesNotMatch(status(app), /Pause was confirmed/);
  assert.equal(app.calls.filter(call => call.kind === 'POST').length, 1);

  // Unmount invalidates the continuation and prevents its automatic status reload.
  app = setup(); await readySchedules(app, 'schedule-before-unmount');
  const unmountContinuation = app.click(app.pauseButton()); await tick();
  app.cleanup();
  const priorStatus = status(app);
  pause(app, 3); await unmountContinuation; await tick();
  assert.equal(app.calls.length, 4);
  assert.equal(status(app), priorStatus);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace("__MOUNT__", json.dumps(FEATURE_ASSETS.mount_js))
    path = tmp_path / "bots-pause-lifecycle.cjs"
    path.write_text(harness, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
