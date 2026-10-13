"""Static, read-only Calendar view contribution for the Jarvis feature registry."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

_VIEW = """<section class=\"calendar-page\" aria-labelledby=\"calendar-title\">
  <header class=\"calendar-heading\"><div><p class=\"calendar-eyebrow\">CONNECTED ACCOUNT</p>
    <h1 id=\"calendar-title\">Calendar</h1><p>Read-only events from your selected connected calendar.</p></div>
    <div class=\"calendar-actions\"><button type=\"button\" data-calendar-select>Use selected Calendar · read only</button>\n      <button type=\"button\" data-calendar-disable hidden>Stop showing events</button>\n      <button type=\"button\" data-calendar-refresh>Refresh</button></div></header>
  <p data-calendar-status role=\"status\" aria-live=\"polite\">Checking calendar access…</p>
  <p data-calendar-source class=\"calendar-source\" hidden></p>
  <section class=\"calendar-agenda\" aria-label=\"Returned seven-day calendar agenda\">
    <nav data-calendar-days class=\"calendar-days\" aria-label=\"Days in returned calendar window\"></nav>
    <label class=\"calendar-search-label\">Search event titles<input data-calendar-search type=\"search\" maxlength=\"160\" autocomplete=\"off\" placeholder=\"Search this window\"></label>
    <h2 data-calendar-day-heading></h2>
    <p data-calendar-empty hidden>No events on this day in the verified window.</p>
    <p data-calendar-filter-empty hidden>No event titles match this search.</p>
    <section class=\"calendar-all-day\" aria-label=\"All-day events\"><h3>All day</h3><ol data-calendar-all-day></ol></section>
    <ol data-calendar-events class=\"calendar-events\" aria-label=\"Timed calendar events\"></ol>
  </section>
  <aside data-calendar-detail class=\"calendar-detail\" aria-label=\"Selected event details\" aria-live=\"polite\" hidden>
    <h2 data-calendar-detail-title></h2><p data-calendar-detail-time></p><p data-calendar-detail-description>Read-only event fields only. No location, attendees, or meeting links are available here.</p>
  </aside>
  <p data-calendar-next class=\"calendar-next\" hidden></p>
</section>"""

_CSS = """[data-feature-root=\"calendar\"] .calendar-page{max-width:980px;margin:0 auto;padding:clamp(18px,3vw,36px);color:var(--text,#edf5f6)}
[data-feature-root=\"calendar\"] .calendar-heading{display:flex;align-items:center;justify-content:space-between;gap:16px}\n[data-feature-root=\"calendar\"] .calendar-actions{display:flex;flex-wrap:wrap;gap:8px}
[data-feature-root=\"calendar\"] h1{font-size:clamp(1.8rem,4vw,2.5rem);margin:.2rem 0}
[data-feature-root=\"calendar\"] .calendar-heading p:not(.calendar-eyebrow),[data-feature-root=\"calendar\"] .calendar-source,[data-feature-root=\"calendar\"] .calendar-next{color:var(--muted,#9bafb4);line-height:1.5}
[data-feature-root=\"calendar\"] .calendar-eyebrow{font-size:.72rem;letter-spacing:.14em;color:var(--accent,#83d9ca);margin:0}
[data-feature-root=\"calendar\"] button{font:inherit;padding:.65rem 1rem;border:1px solid var(--border,#38515a);border-radius:9px;background:#0d252b;color:inherit;cursor:pointer}
[data-feature-root=\"calendar\"] button:focus-visible{outline:2px solid #8de7eb;outline-offset:2px}
[data-feature-root=\"calendar\"] .calendar-events{list-style:none;padding:0;margin:1.2rem 0;display:grid;gap:.7rem}
[data-feature-root=\"calendar\"] .calendar-agenda{margin-top:1rem}
[data-feature-root=\"calendar\"] .calendar-days{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:.4rem;overflow-x:auto;padding:.3rem 0}
[data-feature-root=\"calendar\"] .calendar-days button{min-width:72px;min-height:52px}
[data-feature-root=\"calendar\"] .calendar-days button[aria-pressed=\"true\"]{border-color:var(--accent,#83d9ca);background:#17434a}
[data-feature-root=\"calendar\"] .calendar-search-label{display:grid;gap:.35rem;max-width:32rem;margin:.8rem 0;color:var(--muted,#9bafb4)}
[data-feature-root=\"calendar\"] [data-calendar-search]{width:100%;min-height:44px;padding:.65rem .75rem;border:1px solid var(--border,#38515a);border-radius:9px;background:#0d252b;color:inherit;font:inherit}
[data-feature-root=\"calendar\"] .calendar-all-day{padding:.7rem .9rem;margin:.8rem 0;background:rgba(131,217,202,.09);border:1px solid rgba(131,217,202,.24);border-radius:10px}
[data-feature-root=\"calendar\"] .calendar-all-day h3{margin:0;color:var(--accent,#83d9ca);font-size:.82rem}
[data-feature-root=\"calendar\"] .calendar-all-day ol{list-style:none;padding:0;margin:.4rem 0 0}
[data-feature-root=\"calendar\"] .calendar-detail{margin:1rem 0;padding:1rem;border:1px solid rgba(141,231,235,.28);border-radius:10px;background:rgba(18,43,49,.62)}
[data-feature-root=\"calendar\"] .calendar-detail h2{margin:0 0 .45rem;font-size:1.15rem;overflow-wrap:anywhere}
[data-feature-root=\"calendar\"] .calendar-detail p{line-height:1.55;color:var(--muted,#9bafb4);overflow-wrap:anywhere}
[data-feature-root=\"calendar\"] .calendar-event button{display:block;width:100%;min-height:44px;text-align:left;border:0;background:transparent;padding:0;color:inherit}
[data-feature-root=\"calendar\"] .calendar-all-day .calendar-event{margin:.35rem 0;padding:.4rem .55rem;background:rgba(13,37,43,.5)}
[data-feature-root=\"calendar\"] [hidden]{display:none!important}
[data-feature-root=\"calendar\"] .calendar-event{border-left:2px solid var(--accent,#83d9ca);padding:.8rem 1rem;background:rgba(18,43,49,.62);border-radius:0 10px 10px 0}
[data-feature-root=\"calendar\"] .calendar-event time{display:block;color:var(--muted,#9bafb4);font-size:.85rem;margin-top:.35rem}
[data-feature-root=\"calendar\"] [data-calendar-status]{min-height:1.5em;color:var(--muted,#9bafb4)}
@media(max-width:560px){[data-feature-root=\"calendar\"] .calendar-heading{align-items:flex-start;flex-direction:column}[data-feature-root=\"calendar\"] .calendar-actions{width:100%;flex-direction:column}[data-feature-root=\"calendar\"] .calendar-heading button{width:100%;min-height:44px}[data-feature-root=\"calendar\"] .calendar-days{grid-template-columns:repeat(7,minmax(76px,1fr));overflow:auto}}"""

_MOUNT = r'''function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="calendar"]') || container;
  const status = root.querySelector('[data-calendar-status]');
  const events = root.querySelector('[data-calendar-events]');
  const empty = root.querySelector('[data-calendar-empty]');
  const source = root.querySelector('[data-calendar-source]');
  const next = root.querySelector('[data-calendar-next]');
  const dayStrip = root.querySelector('[data-calendar-days]');
  const search = root.querySelector('[data-calendar-search]');
  const dayHeading = root.querySelector('[data-calendar-day-heading]');
  const refresh = root.querySelector('[data-calendar-refresh]');
  const select = root.querySelector('[data-calendar-select]');
  const disable = root.querySelector('[data-calendar-disable]');
  const allDay = root.querySelector('[data-calendar-all-day]');
  const filterEmpty = root.querySelector('[data-calendar-filter-empty]');
  const detail = root.querySelector('[data-calendar-detail]');
  const detailTitle = root.querySelector('[data-calendar-detail-title]');
  const detailTime = root.querySelector('[data-calendar-detail-time]');
  let active = true, serial = 0, displayTimezone, selectionPending = false;
  let windowStart = 0, windowEnd = 0, agendaEvents = [], agendaDays = [], selectedDay = null, selectedEventId = null;
  const isCurrent = token => active && token === serial;
  function clearDisplay() {
    events.replaceChildren(); allDay.replaceChildren(); dayStrip.replaceChildren(); empty.hidden = true; filterEmpty.hidden = true;
    source.textContent = ''; source.hidden = true; detail.hidden = true; detailTitle.textContent = ''; detailTime.textContent = '';
    next.textContent = ''; next.hidden = true; displayTimezone = undefined;
    windowStart = 0; windowEnd = 0; agendaEvents = []; agendaDays = []; selectedDay = null; selectedEventId = null;
  }
  const dateParts = (value, timezone) => Object.fromEntries(new Intl.DateTimeFormat('en-CA', {
    timeZone:timezone, year:'numeric', month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit', hourCycle:'h23'
  }).formatToParts(new Date(value)).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
  const dayKey = (value, timezone) => { const p = dateParts(value, timezone); return `${p.year}-${p.month}-${p.day}`; };
  const localMidnight = (value, timezone) => { const p = dateParts(value, timezone); return p.hour === '00' && p.minute === '00' && p.second === '00' && value % 1000 === 0; };
  const dayCount = (first, last) => (Date.parse(last + 'T00:00:00Z') - Date.parse(first + 'T00:00:00Z')) / 86400000 + 1;
  const shiftDay = (key, amount) => {
    const [year, month, day] = key.split('-').map(Number);
    return new Date(Date.UTC(year, month - 1, day + amount)).toISOString().slice(0, 10);
  };
  const dayText = key => new Intl.DateTimeFormat(undefined, {weekday:'short', month:'short', day:'numeric', timeZone:'UTC'}).format(new Date(key + 'T12:00:00Z'));
  const dateText = value => new Intl.DateTimeFormat(undefined, {dateStyle:'medium', timeStyle:'short', timeZone:displayTimezone}).format(new Date(value));
  const parseInstant = value => typeof value === 'string' && /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) ? Date.parse(value) : NaN;
  function validPayload(payload) {
    if (!payload || payload.schema !== 1 || !['connected','empty','partial','unavailable','auth-expired','permission-denied','rate-limited'].includes(payload.status)
        || typeof payload.timezone !== 'string' || typeof payload.partial !== 'boolean'
        || !Array.isArray(payload.events) || payload.events.length > 100) return false;
    try { new Intl.DateTimeFormat('en', {timeZone:payload.timezone}); } catch (_) { return false; }
    const start = parseInstant(payload.window_start), end = parseInstant(payload.window_end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start || end - start > 31 * 86400000) return false;
    if ((payload.status === 'empty' && payload.events.length) || (payload.status === 'partial' && !payload.partial)) return false;
    if (['unavailable','auth-expired','permission-denied','rate-limited'].includes(payload.status) && payload.events.length) return false;
    const ids = new Set();
    for (const item of payload.events) {
      if (!item || typeof item.id !== 'string' || !item.id || item.id.length > 128 || ids.has(item.id)
          || typeof item.title !== 'string' || item.title.length > 240 || typeof item.all_day !== 'boolean') return false;
      ids.add(item.id);
      const first = parseInstant(item.start), last = parseInstant(item.end);
      if (!Number.isFinite(first) || !Number.isFinite(last) || last <= first || first >= end || last <= start) return false;
      if (item.all_day && dayKey(first, payload.timezone) >= dayKey(last, payload.timezone)) return false;
    }
    if (typeof payload.source !== 'string' || typeof payload.observed_at !== 'string'
        || !Number.isFinite(parseInstant(payload.observed_at))) return false;
    for (const key of ['account_label','calendar_label','next_step']) if (typeof payload[key] !== 'string') return false;
    return true;
  }
  function renderDetail(item) {
    if (!item) { detail.hidden = true; detailTitle.textContent = ''; detailTime.textContent = ''; return; }
    detailTitle.textContent = item.title;
    const first = dayKey(parseInstant(item.start), displayTimezone), last = dayKey(parseInstant(item.end), displayTimezone);
    detailTime.textContent = item.all_day
      ? `All day · ${dayText(first)} through ${dayText(shiftDay(last, -1))} · end date ${dayText(last)} is exclusive`
      : dateText(item.start) + ' – ' + dateText(item.end);
    detail.hidden = false;
  }
  function renderAgenda() {
    const currentDay = selectedDay || agendaDays[0];
    if (!currentDay) return;
    const query = search.value.trim().toLocaleLowerCase();
    dayHeading.textContent = dayText(currentDay) + (currentDay === dayKey(Date.now(), displayTimezone) ? ' · Today' : '');
    dayStrip.replaceChildren();
    agendaDays.forEach(day => {
      const button = document.createElement('button'); button.type = 'button'; button.textContent = dayText(day);
      const boundary = [day === agendaDays[0] && !localMidnight(windowStart, displayTimezone) ? 'partial start day' : '',
        day === agendaDays[agendaDays.length - 1] && !localMidnight(windowEnd, displayTimezone) ? 'partial final day' : ''].filter(Boolean).join(', ');
      button.setAttribute('aria-label', (boundary ? boundary + ' · ' : '') + dayText(day));
      button.setAttribute('aria-pressed', day === currentDay ? 'true' : 'false'); button.dataset.day = day;
      if (boundary) button.textContent += ' · partial';
      button.addEventListener('click', () => { selectedDay = day; renderAgenda(); });
      button.addEventListener('keydown', event => {
        const index = agendaDays.indexOf(day); let nextIndex = index;
        if (event.key === 'ArrowRight') nextIndex = Math.min(agendaDays.length - 1, index + 1);
        else if (event.key === 'ArrowLeft') nextIndex = Math.max(0, index - 1);
        else if (event.key === 'Home') nextIndex = 0;
        else if (event.key === 'End') nextIndex = agendaDays.length - 1;
        else return;
        event.preventDefault(); selectedDay = agendaDays[nextIndex]; renderAgenda();
        const target = [...dayStrip.children][nextIndex]; if (target) target.focus();
      });
      dayStrip.append(button);
    });
    const onDay = agendaEvents.filter(item => {
      if (query && !item.title.toLocaleLowerCase().includes(query)) return false;
      const first = dayKey(parseInstant(item.start), displayTimezone);
      const last = item.all_day ? shiftDay(dayKey(parseInstant(item.end), displayTimezone), -1)
        : dayKey(parseInstant(item.end) - 1, displayTimezone);
      return currentDay >= first && currentDay <= last;
    }).sort((a, b) => parseInstant(a.start) - parseInstant(b.start));
    allDay.replaceChildren(); events.replaceChildren();
    for (const item of onDay) {
      const row = document.createElement('li'); row.className = 'calendar-event';
      const button = document.createElement('button'); button.type = 'button'; button.textContent = item.title;
      button.setAttribute('aria-pressed', item.id === selectedEventId ? 'true' : 'false');
      button.addEventListener('click', () => { selectedEventId = item.id; renderDetail(item); renderAgenda(); });
      const time = document.createElement('time'); time.dateTime = item.start;
      time.textContent = item.all_day ? 'All day · ends ' + dayText(dayKey(parseInstant(item.end), displayTimezone)) + ' (exclusive)'
        : dateText(item.start) + ' – ' + dateText(item.end);
      row.append(button, time); (item.all_day ? allDay : events).append(row);
    }
    const visible = onDay.some(item => item.id === selectedEventId) ? agendaEvents.find(item => item.id === selectedEventId) : null;
    renderDetail(visible);
    empty.hidden = onDay.length > 0 || Boolean(query);
    filterEmpty.hidden = onDay.length > 0 || !query;
  }
  async function load() {
    if (!active || selectionPending) return;
    const current = ++serial;
    refresh.disabled = true; status.textContent = 'Loading verified calendar events…';
    clearDisplay();
    try {
      const response = await fetch('/chat/api/calendar', {credentials:'same-origin', cache:'no-store'});
      if (!isCurrent(current)) return;
      if (!response.ok) throw new Error('unavailable');
      const payload = await response.json();
      if (!isCurrent(current)) return;
      if (!validPayload(payload)) throw new Error('unavailable');
      displayTimezone = payload.timezone; windowStart = parseInstant(payload.window_start); windowEnd = parseInstant(payload.window_end);
      agendaEvents = payload.events.slice();
      const firstDay = dayKey(windowStart, displayTimezone), lastDay = dayKey(windowEnd - 1, displayTimezone);
      agendaDays = Array.from({length:dayCount(firstDay, lastDay)}, (_, index) => shiftDay(firstDay, index));
      selectedDay = firstDay;
      select.hidden = ['connected', 'empty', 'partial'].includes(payload.status);
      disable.hidden = !['connected', 'empty', 'partial'].includes(payload.status);
      if (payload.status === 'unavailable') {
        status.textContent = 'Calendar access is not connected to an enrolled account.';
      } else if (payload.status === 'auth-expired') {
        status.textContent = 'Calendar authorization expired. Reconnect the selected account in Integrations.';
      } else if (payload.status === 'permission-denied') {
        status.textContent = 'The selected account has not granted read access to this calendar.';
      } else if (payload.status === 'rate-limited') {
        status.textContent = 'The calendar provider is temporarily limiting reads. Refresh later.';
      } else if (payload.status === 'partial') {
        status.textContent = 'Showing verified events only; some events could not be verified. The list is partial.';
      } else if (payload.status === 'empty') {
        status.textContent = payload.partial ? 'No events were returned, but this verified date range has partial coverage.'
          : 'No events were returned for this verified date range.'; empty.hidden = false;
      } else if (payload.status === 'connected') {
        status.textContent = payload.partial ? 'Showing current events from the selected calendar; coverage is partial.'
          : 'Showing current events from the selected calendar.';
      } else { throw new Error('unavailable'); }
      if (payload.source || payload.timezone || payload.observed_at) {
        source.textContent = [payload.account_label || 'Account identity unknown', payload.calendar_label || 'Calendar label unavailable',
          payload.source || 'Read source unavailable', 'Event times in ' + payload.timezone,
          'Window ' + dateText(payload.window_start) + ' – ' + dateText(payload.window_end),
          'Checked ' + dateText(payload.observed_at)].filter(Boolean).join(' · ');
        source.hidden = !source.textContent;
      }
      if (typeof payload.next_step === 'string' && payload.next_step) {
        next.textContent = payload.next_step; next.hidden = false;
      }
      renderAgenda();
      if (payload.status === 'connected' && payload.events.length === 0) status.textContent = payload.partial
        ? 'No events were returned, but this verified date range has partial coverage.'
        : 'No events were returned for this verified date range.';
    } catch (_) {
      if (!isCurrent(current)) return;
      clearDisplay();
      status.textContent = 'Calendar events are unavailable. Connect and authorize a selected account in Integrations, then refresh.';
      next.textContent = 'Only read-only access is used here. Calendar changes, invitations, and messages are not available.';
      next.hidden = false;
    } finally { if (isCurrent(current)) refresh.disabled = false; }
  }
  async function setSelection(action) {
    if (!active || selectionPending) return;
    selectionPending = true;
    const current = ++serial;
    // Consent transitions immediately revoke the currently displayed projection. An
    // in-flight read or selection response can no longer repopulate it.
    clearDisplay();
    refresh.disabled = true; select.disabled = true; disable.disabled = true;
    if (action === 'enable') disable.hidden = false;
    else { disable.hidden = true; select.hidden = false; }
    status.textContent = action === 'enable' ? 'Confirming the selected read-only Calendar connection…' : 'Removing Calendar dashboard consent…';
    try {
      const response = await fetch('/chat/api/calendar/selection', {method:'POST', credentials:'same-origin', cache:'no-store',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({schema:1, action, confirmation:'read-only-calendar-events'})});
      if (!isCurrent(current)) return;
      const result = await response.json().catch(() => null);
      if (!isCurrent(current)) return;
      if (!response.ok || !result || result.schema !== 1
          || result.state !== (action === 'enable' ? 'selected' : 'disabled')) {
        const detail = result && typeof result.error === 'string' ? result.error : 'selection-unavailable';
        throw new Error(detail);
      }
      if (action === 'disable') {
        disable.hidden = true; select.hidden = false; status.textContent = 'Calendar dashboard consent was removed.';
      } else {
        selectionPending = false;
        refresh.disabled = false;
        select.disabled = false; disable.disabled = false;
        void load();
      }
    } catch (error) {
      if (!isCurrent(current)) return;
      if (action === 'enable') disable.hidden = true;
      status.textContent = error && error.message && error.message !== 'selection-unavailable'
        ? error.message : 'No current protected Calendar connection is available. Complete the root-managed Google Calendar enrollment, then retry.';
    } finally {
      if (isCurrent(current)) {
        selectionPending = false; refresh.disabled = false;
        select.disabled = false; disable.disabled = false;
      }
    }
  }
  const enableSelection = () => setSelection('enable');
  const disableSelection = () => setSelection('disable');
  const onSearch = () => { if (active && agendaEvents.length) renderAgenda(); };
  refresh.addEventListener('click', load);
  select.addEventListener('click', enableSelection);
  disable.addEventListener('click', disableSelection);
  search.addEventListener('input', onSearch);
  load();
  return () => { active = false; serial++; clearDisplay(); refresh.removeEventListener('click', load);
    select.removeEventListener('click', enableSelection); disable.removeEventListener('click', disableSelection); search.removeEventListener('input', onSearch); };
}'''

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="calendar", nav_label="Calendar", title="Calendar",
    view_html=_VIEW, css=_CSS,
    api_routes=(("GET", "/chat/api/calendar"), ("POST", "/chat/api/calendar/selection")),
    mount_js=_MOUNT, unmount_js="function unmount() {}",
)
