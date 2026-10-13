import json
import shutil
import subprocess

import pytest

from hermes_installer.remote.jarvis_calendar import (
    CalendarProjectionError,
    MAX_EVENTS,
    project_calendar_page,
    validate_window,
)
from hermes_installer.remote.jarvis_calendar_assets import FEATURE_ASSETS


def _event(event_id="opaque-event-1", *, title="Planning", start="2026-10-12T09:00:00+01:00",
           end="2026-10-12T10:00:00+01:00"):
    return {"opaque_event_id": event_id, "summary": title,
            "start": {"dateTime": start, "timeZone": "Europe/Lisbon"},
            "end": {"dateTime": end, "timeZone": "Europe/Lisbon"},
            "description": "private detail omitted", "htmlLink": "https://example.invalid"}


def _page(status="connected", events=None):
    return {"status": status, "opaque_account_ref": "opaque-account-1",
            "opaque_calendar_ref": "opaque-calendar-1", "account_label": "Owner calendar",
            "calendar_label": "Primary", "events": [] if events is None else events,
            "next_step": ""}


def test_projects_only_bounded_calendar_fields_and_keeps_source_time():
    projected = project_calendar_page(
        _page(events=[_event(title="Planning <img src=x onerror=alert(1)>")]),
        timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z",
    )
    assert projected["status"] == "connected"
    assert projected["source"] == "Google Calendar"
    assert projected["timezone"] == "Europe/Lisbon"
    assert projected["events"][0]["title"] == "Planning <img src=x onerror=alert(1)>"
    assert set(projected["events"][0]) == {"id", "title", "start", "end", "all_day"}
    assert "description" not in projected["events"][0]
    assert "htmlLink" not in projected["events"][0]


def test_verified_zero_events_is_empty_and_not_unavailable():
    projected = project_calendar_page(
        _page(), timezone_name="UTC", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z",
    )
    assert projected["status"] == "empty"
    assert projected["events"] == []


@pytest.mark.parametrize("window", [
    ("2026-10-12T00:00:00", "2026-10-13T00:00:00Z", "UTC"),
    ("2026-10-12T00:00:00Z", "2026-11-13T00:00:00Z", "UTC"),
    ("2026-10-12T00:00:00Z", "2026-10-13T00:00:00Z", "Not/AZone"),
])
def test_rejects_naive_oversized_or_unknown_timezone_window(window):
    with pytest.raises(CalendarProjectionError):
        validate_window(start=window[0], end=window[1], timezone_name=window[2])


def test_rejects_unavailable_source_with_events_and_oversized_page():
    args = dict(timezone_name="UTC", window_start="2026-10-12T00:00:00Z",
                window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(_page("auth-expired", [_event()]), **args)
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(_page(events=[_event(str(i)) for i in range(MAX_EVENTS + 1)]), **args)


def test_projects_all_day_events_in_requested_zone():
    page = _page(events=[{"opaque_event_id": "day-1", "summary": "Holiday",
                          "start": {"date": "2026-10-12"},
                          "end": {"date": "2026-10-13"}}])
    projected = project_calendar_page(
        page, timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
        window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")
    assert projected["events"][0]["all_day"] is True
    assert projected["events"][0]["start"].startswith("2026-10-12T00:00:00+01:00")


def test_rejects_invalid_event_interval():
    with pytest.raises(CalendarProjectionError):
        project_calendar_page(
            _page(events=[_event(start="2026-10-12T10:00:00+01:00",
                                 end="2026-10-12T09:00:00+01:00")]),
            timezone_name="Europe/Lisbon", window_start="2026-10-12T00:00:00Z",
            window_end="2026-10-13T00:00:00Z", observed_at="2026-10-12T08:00:00Z")


def test_calendar_mount_fences_deferred_responses_and_clears_consent_immediately(tmp_path):
    """Exercise asynchronous UI races with controllable fetch and response-body gates."""
    node = shutil.which("node")
    if not node:
        pytest.skip("Node.js is required for the browser lifecycle harness")
    harness = r'''const assert = require('node:assert/strict');
const MOUNT = __MOUNT__;
class Element {
  constructor() { this.hidden = false; this.disabled = false; this.textContent = ''; this.children = []; this.handlers = {}; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  removeEventListener(name, fn) { if (this.handlers[name] === fn) delete this.handlers[name]; }
  click() { return this.handlers.click && this.handlers.click(); }
}
const names = ['[data-calendar-status]', '[data-calendar-events]', '[data-calendar-empty]',
  '[data-calendar-source]', '[data-calendar-next]', '[data-calendar-refresh]',
  '[data-calendar-select]', '[data-calendar-disable]'];
function setup() {
  const nodes = Object.fromEntries(names.map(name => [name, new Element()]));
  const root = {querySelector: name => nodes[name]};
  const container = {querySelector: () => root};
  const requests = [];
  global.document = {createElement: () => new Element()};
  global.fetch = (...args) => new Promise((resolve, reject) => requests.push({args, resolve, reject}));
  const mount = new Function(`return (${MOUNT})`)();
  const cleanup = mount(container, {}, {});
  return {nodes, requests, cleanup};
}
const tick = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const deferred = () => { let resolve; const promise = new Promise(r => resolve = r); return {promise, resolve}; };
const payload = title => ({schema:1, status:'connected', events:[{title, start:'2026-10-12T09:00:00Z', end:'2026-10-12T10:00:00Z'}]});
const ok = value => ({ok:true, json:async () => value});
const post = (state) => ({ok:true, json:async () => ({schema:1, state})});
const titles = node => node.children.map(li => li.children[0].textContent);
async function run() {
  // A body decode that completes after a newer refresh cannot overwrite the newer view.
  let app = setup();
  const body = deferred();
  app.requests[0].resolve({ok:true, json:() => body.promise}); await tick();
  app.nodes['[data-calendar-refresh]'].click();
  app.requests[1].resolve(ok(payload('Fresh'))); await tick();
  body.resolve(payload('Stale')); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), ['Fresh']);

  // Starting removal clears the projection before either overlapping request settles.
  app.nodes['[data-calendar-source]'].textContent = 'private source';
  app.nodes['[data-calendar-source]'].hidden = false;
  app.nodes['[data-calendar-refresh]'].click();
  app.nodes['[data-calendar-disable]'].click();
  assert.equal(app.nodes['[data-calendar-refresh]'].disabled, true);
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);
  assert.equal(app.nodes['[data-calendar-source]'].textContent, '');
  app.nodes['[data-calendar-refresh]'].click();
  assert.equal(app.requests.length, 4, 'refresh must not start a GET while disable is pending');
  app.requests[2].resolve(ok(payload('Obsolete refresh'))); await tick();
  app.requests[3].resolve(post('disabled')); await tick();
  assert.equal(app.nodes['[data-calendar-refresh]'].disabled, false);
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);
  assert.equal(app.nodes['[data-calendar-status]'].textContent, 'Calendar dashboard consent was removed.');

  // A second selection cannot overlap an enable POST; success starts one fresh GET.
  app.nodes['[data-calendar-select]'].click();
  app.nodes['[data-calendar-disable]'].click();
  assert.equal(app.requests.length, 5, 'selection mutations must be serialized');
  app.requests[4].resolve(post('selected')); await tick();
  app.requests[5].resolve(ok(payload('Selected'))); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), ['Selected']);
  app.nodes['[data-calendar-disable]'].click();
  app.nodes['[data-calendar-refresh]'].click();
  assert.equal(app.requests.length, 7, 'refresh must not start a GET while disable is pending');
  app.requests[6].resolve(post('disabled')); await tick();
  assert.equal(app.nodes['[data-calendar-status]'].textContent, 'Calendar dashboard consent was removed.');
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);

  // Bad payloads and fetch failures settle the current loading state with a safe message.
  app.nodes['[data-calendar-refresh]'].click();
  app.requests[7].resolve(ok({schema:99})); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /unavailable/);
  assert.equal(app.nodes['[data-calendar-refresh]'].disabled, false);
  app.nodes['[data-calendar-refresh]'].click();
  app.requests[8].reject(new Error('offline')); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /unavailable/);
  app.nodes['[data-calendar-select]'].click();
  app.requests[9].resolve({ok:false, json:async () => ({schema:1, error:'authorization-required'})}); await tick();
  assert.equal(app.nodes['[data-calendar-status]'].textContent, 'authorization-required');
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);

  // Unmount invalidates pending JSON and removes any rendered event data.
  app = setup();
  const unmountBody = deferred();
  app.requests[0].resolve({ok:true, json:() => unmountBody.promise}); await tick();
  app.cleanup();
  unmountBody.resolve(payload('After unmount')); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);
}
run().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace("__MOUNT__", json.dumps(FEATURE_ASSETS.mount_js))
    path = tmp_path / "calendar-lifecycle.cjs"
    path.write_text(harness, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr
