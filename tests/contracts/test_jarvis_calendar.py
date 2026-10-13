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


def test_agenda_uses_only_existing_consent_read_routes_and_bounded_assets():
    assert FEATURE_ASSETS.api_routes == (
        ("GET", "/chat/api/calendar"),
        ("POST", "/chat/api/calendar/selection"),
    )
    assert len(FEATURE_ASSETS.view_html.encode("utf-8")) <= 30_000
    assert len(FEATURE_ASSETS.mount_js.encode("utf-8")) <= 30_000
    assert len(FEATURE_ASSETS.css.encode("utf-8")) <= 30_000
    assert len(FEATURE_ASSETS.unmount_js.encode("utf-8")) <= 10_000
    assert "data-calendar-search" in FEATURE_ASSETS.view_html
    assert "data-calendar-days" in FEATURE_ASSETS.view_html
    assert "min-height:52px" in FEATURE_ASSETS.css
    assert "all_day" in FEATURE_ASSETS.mount_js
    assert "window_start" in FEATURE_ASSETS.mount_js and "window_end" in FEATURE_ASSETS.mount_js
    assert "api.post" not in FEATURE_ASSETS.mount_js
    assert "createEvent" not in FEATURE_ASSETS.mount_js
    assert "date-range" not in FEATURE_ASSETS.mount_js


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
  constructor() { this.hidden = false; this.disabled = false; this.textContent = ''; this.children = []; this.handlers = {}; this.dataset = {}; this.attributes = {}; this.value = ''; }
  replaceChildren(...children) { this.children = children; }
  append(...children) { this.children.push(...children); }
  setAttribute(name,value) { this.attributes[name] = String(value); if (name === 'data-day') this.dataset.day = String(value); }
  getAttribute(name) { return this.attributes[name] || null; }
  addEventListener(name, fn) { this.handlers[name] = fn; }
  removeEventListener(name, fn) { if (this.handlers[name] === fn) delete this.handlers[name]; }
  click() { return this.handlers.click && this.handlers.click(); }
  focus() { this.focused = true; }
}
const names = ['[data-calendar-status]', '[data-calendar-events]', '[data-calendar-empty]',
  '[data-calendar-source]', '[data-calendar-next]', '[data-calendar-refresh]',
  '[data-calendar-select]', '[data-calendar-disable]', '[data-calendar-days]', '[data-calendar-search]',
  '[data-calendar-day-heading]', '[data-calendar-all-day]', '[data-calendar-filter-empty]',
  '[data-calendar-detail]', '[data-calendar-detail-title]', '[data-calendar-detail-time]'];
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
const event = (id,title,start='2026-10-12T09:00:00Z',end='2026-10-12T10:00:00Z',all_day=false) => ({id,title,start,end,all_day});
const windowPayload = (events,start='2026-10-12T00:00:00Z',end='2026-10-19T00:00:00Z',timezone='Europe/Lisbon',status='connected',partial=false) => ({schema:1,status,source:'Google Calendar',observed_at:'2026-10-12T08:00:00Z',timezone,window_start:start,window_end:end,account_label:'Owner calendar',calendar_label:'Primary',next_step:'',partial,events});
const payload = title => windowPayload([event(title,title)]);
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
  assert.equal(app.nodes['[data-calendar-days]'].children.length, 8, 'local dates include both partial boundary dates in the exact returned window');
  assert.match(app.nodes['[data-calendar-days]'].children[0].getAttribute('aria-label'), /partial start day/);
  assert.match(app.nodes['[data-calendar-days]'].children[7].getAttribute('aria-label'), /partial final day/);
  assert.match(app.nodes['[data-calendar-source]'].textContent, /Window/);
  const readsBeforeBrowse = app.requests.length;
  app.nodes['[data-calendar-days]'].children[1].click();
  assert.equal(app.requests.length, readsBeforeBrowse, 'day navigation is local');
  const secondDay = app.nodes['[data-calendar-days]'].children[1];
  let prevented = false; secondDay.handlers.keydown({key:'ArrowLeft',preventDefault(){prevented=true;}});
  assert.equal(prevented, true, 'keyboard arrows navigate the local date strip');
  assert.equal(app.nodes['[data-calendar-days]'].children[0].focused, true);
  app.nodes['[data-calendar-days]'].children[0].click();
  app.nodes['[data-calendar-search]'].value = 'fresh'; app.nodes['[data-calendar-search]'].handlers.input();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), ['Fresh'], 'title search filters locally');
  app.nodes['[data-calendar-search]'].value = ''; app.nodes['[data-calendar-search]'].handlers.input();
  app.nodes['[data-calendar-events]'].children[0].children[0].click();
  assert.equal(app.nodes['[data-calendar-detail-title]'].textContent, 'Fresh');

  // Producer title limits count Unicode code points, matching Python and keeping text inert.
  app = setup();
  const title240 = '😀'.repeat(240);
  app.requests[0].resolve(ok(windowPayload([event('unicode-240', title240)]))); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), [title240]);
  assert.equal(app.nodes['[data-calendar-events]'].children[0].children[0].textContent, title240);
  app = setup();
  app.requests[0].resolve(ok(windowPayload([event('unicode-241', '😀'.repeat(241))]))); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), [], '241 code points exceed the producer limit');
  assert.match(app.nodes['[data-calendar-status]'].textContent, /unavailable/);

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
  assert.equal(app.requests.length, 10, 'failed consent does not launch an automatic retry');

  // Returned-zone day grouping spans midnight, DST and multiday ranges; all-day end is exclusive.
  app = setup();
  const dstEvents = [
    event('dst','DST midnight','2026-10-25T00:30:00+01:00','2026-10-25T02:30:00+00:00'),
    event('multi','Multi-day','2026-10-25T23:00:00Z','2026-10-27T01:00:00Z'),
    event('holiday','Holiday','2026-10-25T00:00:00+01:00','2026-10-27T00:00:00+00:00',true)
  ];
  app.requests[0].resolve(ok(windowPayload(dstEvents,'2026-10-24T00:00:00Z','2026-10-31T00:00:00Z'))); await tick();
  const choose = key => app.nodes['[data-calendar-days]'].children.find(button => button.dataset.day === key).click();
  const timedTitles = () => titles(app.nodes['[data-calendar-events]']);
  choose('2026-10-25');
  assert.deepEqual(timedTitles(), ['DST midnight','Multi-day']);
  assert.equal(titles(app.nodes['[data-calendar-all-day]'])[0], 'Holiday');
  app.nodes['[data-calendar-all-day]'].children[0].children[0].click();
  assert.match(app.nodes['[data-calendar-detail-time]'].textContent, /exclusive/);
  choose('2026-10-26'); assert.deepEqual(timedTitles(), ['Multi-day']);
  choose('2026-10-27'); assert.deepEqual(timedTitles(), ['Multi-day'], 'event ending after midnight remains on its final occupied local day');
  assert.equal(app.requests.length, 1, 'all date grouping and selection remain local');

  // The exact returned non-midnight window can span eight local dates; its last partial-day event remains visible.
  app = setup();
  const finalDayEvent = event('window-end','Final partial day','2026-10-31T14:30:00Z','2026-10-31T14:45:00Z');
  app.requests[0].resolve(ok(windowPayload([finalDayEvent], '2026-10-24T15:00:00+01:00',
    '2026-10-31T15:00:00+00:00', 'Europe/Lisbon'))); await tick();
  assert.equal(app.nodes['[data-calendar-days]'].children.length, 8);
  assert.match(app.nodes['[data-calendar-days]'].children[7].getAttribute('aria-label'), /partial final day/);
  app.nodes['[data-calendar-days]'].children[7].click();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), ['Final partial day']);

  // A real Lisbon fallback-offset window is seven wall days but seven days plus one UTC hour.
  app = setup();
  app.requests[0].resolve(ok(windowPayload([event('fallback','Fallback day','2026-10-31T14:30:00Z','2026-10-31T14:45:00Z')],
    '2026-10-24T15:00:00+01:00', '2026-10-31T15:00:00+00:00', 'Europe/Lisbon'))); await tick();
  assert.equal(app.nodes['[data-calendar-days]'].children.length, 8, 'DST fallback offset does not make the returned window invalid');
  app.nodes['[data-calendar-days]'].children[7].click();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), ['Fallback day']);

  // Partial, expired, denied, empty and malformed intervals keep truthful states.
  app = setup();
  app.requests[0].resolve(ok(windowPayload([event('partial','Verified')],'2026-10-12T00:00:00Z','2026-10-19T00:00:00Z','Europe/Lisbon','partial',true))); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /partial/);
  app = setup();
  const expired = windowPayload([]); expired.status='auth-expired'; expired.next_step='Reconnect in Integrations';
  app.requests[0].resolve(ok(expired)); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /expired/);
  assert.equal(app.nodes['[data-calendar-next]'].textContent, 'Reconnect in Integrations');
  app = setup();
  const denied = windowPayload([]); denied.status='permission-denied'; denied.next_step='Read access required';
  app.requests[0].resolve(ok(denied)); await tick(); assert.match(app.nodes['[data-calendar-status]'].textContent, /not granted/);
  app = setup();
  const emptyPage = windowPayload([]); emptyPage.status='empty';
  app.requests[0].resolve(ok(emptyPage)); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /No events were returned/);
  assert.equal(app.nodes['[data-calendar-empty]'].hidden, false);
  app = setup();
  app.requests[0].resolve(ok(windowPayload([event('bad','Backwards','2026-10-13T10:00:00Z','2026-10-13T09:00:00Z')]))); await tick();
  assert.match(app.nodes['[data-calendar-status]'].textContent, /unavailable/);
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), [], 'malformed intervals never render partial payload rows');

  // Unmount invalidates pending JSON and removes any rendered event data.
  app = setup();
  const unmountBody = deferred();
  app.requests[0].resolve({ok:true, json:() => unmountBody.promise}); await tick();
  app.cleanup();
  unmountBody.resolve(payload('After unmount')); await tick();
  assert.deepEqual(titles(app.nodes['[data-calendar-events]']), []);
  console.log('CALENDAR_AGENDA_HARNESS_COMPLETE');
}
run().catch(error => { console.error(error); process.exitCode = 1; });
'''.replace("__MOUNT__", json.dumps(FEATURE_ASSETS.mount_js))
    path = tmp_path / "calendar-lifecycle.cjs"
    path.write_text(harness, encoding="utf-8")
    result = subprocess.run([node, str(path)], capture_output=True, text=True, check=False, timeout=20)
    assert result.returncode == 0, result.stderr
    assert "CALENDAR_AGENDA_HARNESS_COMPLETE" in result.stdout
