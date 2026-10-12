"""Static, read-only Calendar view contribution for the Jarvis feature registry."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets

_VIEW = """<section class=\"calendar-page\" aria-labelledby=\"calendar-title\">
  <header class=\"calendar-heading\"><div><p class=\"calendar-eyebrow\">CONNECTED ACCOUNT</p>
    <h1 id=\"calendar-title\">Calendar</h1><p>Read-only events from your selected connected calendar.</p></div>
    <div class=\"calendar-actions\"><button type=\"button\" data-calendar-select>Use selected Calendar · read only</button>\n      <button type=\"button\" data-calendar-disable hidden>Stop showing events</button>\n      <button type=\"button\" data-calendar-refresh>Refresh</button></div></header>
  <p data-calendar-status role=\"status\" aria-live=\"polite\">Checking calendar access…</p>
  <p data-calendar-source class=\"calendar-source\" hidden></p>
  <ol data-calendar-events class=\"calendar-events\" aria-label=\"Calendar events\"></ol>
  <p data-calendar-empty hidden>No events in this verified date range.</p>
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
[data-feature-root=\"calendar\"] .calendar-event{border-left:2px solid var(--accent,#83d9ca);padding:.8rem 1rem;background:rgba(18,43,49,.62);border-radius:0 10px 10px 0}
[data-feature-root=\"calendar\"] .calendar-event time{display:block;color:var(--muted,#9bafb4);font-size:.85rem;margin-top:.35rem}
[data-feature-root=\"calendar\"] [data-calendar-status]{min-height:1.5em;color:var(--muted,#9bafb4)}
@media(max-width:560px){[data-feature-root=\"calendar\"] .calendar-heading{align-items:flex-start;flex-direction:column}[data-feature-root=\"calendar\"] .calendar-actions{width:100%;flex-direction:column}[data-feature-root=\"calendar\"] .calendar-heading button{width:100%;min-height:44px}}"""

_MOUNT = r'''function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="calendar"]') || container;
  const status = root.querySelector('[data-calendar-status]');
  const events = root.querySelector('[data-calendar-events]');
  const empty = root.querySelector('[data-calendar-empty]');
  const source = root.querySelector('[data-calendar-source]');
  const next = root.querySelector('[data-calendar-next]');
  const refresh = root.querySelector('[data-calendar-refresh]');
  const select = root.querySelector('[data-calendar-select]');
  const disable = root.querySelector('[data-calendar-disable]');
  let active = true, serial = 0, displayTimezone;
  const dateText = value => {
    const date = new Date(value);
    return Number.isNaN(date.getTime()) ? 'Time unavailable' : new Intl.DateTimeFormat(undefined,
      {dateStyle:'medium', timeStyle:'short', ...(displayTimezone ? {timeZone:displayTimezone} : {})}).format(date);
  };
  async function load() {
    const current = ++serial;
    refresh.disabled = true; status.textContent = 'Loading verified calendar events…';
    events.replaceChildren(); empty.hidden = true; source.hidden = true; next.hidden = true;
    try {
      const response = await fetch('/chat/api/calendar', {credentials:'same-origin', cache:'no-store'});
      if (!active || current !== serial) return;
      const payload = response.ok ? await response.json() : null;
      if (!payload || payload.schema !== 1) throw new Error('unavailable');
      select.hidden = ['connected', 'empty', 'partial'].includes(payload.status);
      disable.hidden = !['connected', 'empty', 'partial'].includes(payload.status);
      displayTimezone = typeof payload.timezone === 'string' ? payload.timezone : undefined;
      if (payload.status === 'unavailable') {
        status.textContent = 'Calendar access is not connected to an enrolled account.';
      } else if (payload.status === 'auth-expired') {
        status.textContent = 'Calendar authorization expired. Reconnect the selected account in Integrations.';
      } else if (payload.status === 'permission-denied') {
        status.textContent = 'The selected account has not granted read access to this calendar.';
      } else if (payload.status === 'rate-limited') {
        status.textContent = 'The calendar provider is temporarily limiting reads. Refresh later.';
      } else if (payload.status === 'partial') {
        status.textContent = 'Some events could not be verified. The list may be incomplete.';
      } else if (payload.status === 'empty') {
        status.textContent = 'No events were returned for this verified date range.'; empty.hidden = false;
      } else if (payload.status === 'connected') {
        status.textContent = 'Showing current events from the selected calendar.';
      } else { throw new Error('unavailable'); }
      if (payload.source || payload.timezone || payload.observed_at) {
        source.textContent = [payload.account_label, payload.calendar_label,
          payload.timezone ? 'Event times in ' + payload.timezone : '',
          payload.observed_at ? 'Checked ' + dateText(payload.observed_at) : ''].filter(Boolean).join(' · ');
        source.hidden = !source.textContent;
      }
      if (typeof payload.next_step === 'string' && payload.next_step) {
        next.textContent = payload.next_step; next.hidden = false;
      }
      if (!Array.isArray(payload.events) || payload.events.length > 100) throw new Error('unavailable');
      for (const item of payload.events) {
        if (!item || typeof item.title !== 'string' || typeof item.start !== 'string' || typeof item.end !== 'string')
          throw new Error('unavailable');
        const li = document.createElement('li'), title = document.createElement('strong'), time = document.createElement('time');
        li.className = 'calendar-event'; title.textContent = item.title;
        time.dateTime = item.start; time.textContent = (item.all_day ? 'All day · ' : '') + dateText(item.start) + ' – ' + dateText(item.end);
        li.append(title, time); events.append(li);
      }
      if (payload.status === 'connected' && payload.events.length === 0) {
        status.textContent = 'No events were returned for this verified date range.'; empty.hidden = false;
      }
    } catch (_) {
      if (!active || current !== serial) return;
      status.textContent = 'Calendar events are unavailable. Connect and authorize a selected account in Integrations, then refresh.';
      next.textContent = 'Only read-only access is used here. Calendar changes, invitations, and messages are not available.';
      next.hidden = false;
    } finally { if (active && current === serial) refresh.disabled = false; }
  }
  async function setSelection(action) {
    select.disabled = true; disable.disabled = true;
    status.textContent = action === 'enable' ? 'Confirming the selected read-only Calendar connection…' : 'Removing Calendar dashboard consent…';
    try {
      const response = await fetch('/chat/api/calendar/selection', {method:'POST', credentials:'same-origin', cache:'no-store',
        headers:{'Content-Type':'application/json'}, body:JSON.stringify({schema:1, action, confirmation:'read-only-calendar-events'})});
      const result = await response.json().catch(() => null);
      if (!response.ok || !result || result.schema !== 1
          || result.state !== (action === 'enable' ? 'selected' : 'disabled')) {
        const detail = result && typeof result.error === 'string' ? result.error : 'selection-unavailable';
        throw new Error(detail);
      }
      if (action === 'disable') {
        events.replaceChildren(); empty.hidden = true; source.hidden = true; next.hidden = true;
        disable.hidden = true; select.hidden = false; status.textContent = 'Calendar dashboard consent was removed.';
      } else { await load(); }
    } catch (error) {
      status.textContent = error && error.message && error.message !== 'selection-unavailable'
        ? error.message : 'No current protected Calendar connection is available. Complete the root-managed Google Calendar enrollment, then retry.';
    } finally { if (active) { select.disabled = false; disable.disabled = false; } }
  }
  const enableSelection = () => setSelection('enable');
  const disableSelection = () => setSelection('disable');
  refresh.addEventListener('click', load);
  select.addEventListener('click', enableSelection);
  disable.addEventListener('click', disableSelection);
  load();
  return () => { active = false; serial++; refresh.removeEventListener('click', load);
    select.removeEventListener('click', enableSelection); disable.removeEventListener('click', disableSelection); };
}'''

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="calendar", nav_label="Calendar", title="Calendar",
    view_html=_VIEW, css=_CSS,
    api_routes=(("GET", "/chat/api/calendar"), ("POST", "/chat/api/calendar/selection")),
    mount_js=_MOUNT, unmount_js="function unmount() {}",
)
