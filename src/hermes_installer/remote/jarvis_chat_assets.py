"""Finite installer-owned assets for the practical Jarvis chat surface.

Only the reviewed `/chat`, `/chat/assets/app.css`, and `/chat/assets/app.js`
paths are exposed. The bundle contains no provider credentials or user data.
"""
from __future__ import annotations

from types import MappingProxyType


_HTML = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
  <meta name="theme-color" content="#071319">
  <title>Jarvis</title>
  <link rel="stylesheet" href="/chat/assets/app.css">
  <script defer src="/chat/assets/app.js"></script>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <button class="icon-button mobile-history-toggle" id="history-toggle" type="button"
        aria-label="Show conversations" aria-controls="conversation-panel" aria-expanded="false">
        <span aria-hidden="true">☰</span>
      </button>
      <a class="brand" href="/chat" aria-label="Jarvis chat home">
        <span class="brand-mark" aria-hidden="true"><span></span></span>
        <span class="brand-copy"><strong>JARVIS</strong><small>PERSONAL ASSISTANT</small></span>
      </a>
      <nav class="primary-nav" aria-label="Jarvis sections">
        <button type="button" class="nav-item" data-view="chat" aria-current="page">Chat</button>
        <button type="button" class="nav-item" data-view="overview">Overview</button>
        <button type="button" class="nav-item" data-view="capabilities">Capabilities</button>
        <button type="button" class="nav-item" data-view="settings">Settings</button>
      </nav>
      <span class="connection" id="connection-state" role="status" aria-live="polite">
        <span class="connection-dot" aria-hidden="true"></span><span>Checking access…</span>
      </span>
    </header>

    <div class="workspace">
      <aside class="conversation-panel" id="conversation-panel" aria-label="Conversations">
        <div class="panel-heading">
          <div><span class="eyebrow">YOUR SPACE</span><h2>Conversations</h2></div>
          <button class="icon-button panel-close" id="history-close" type="button" aria-label="Close conversations">×</button>
        </div>
        <button class="new-chat-button" id="new-chat" type="button"><span aria-hidden="true">＋</span> New conversation</button>
        <p class="list-caption">RECENT</p>
        <nav class="conversation-list" id="conversation-list" aria-label="Recent conversations"></nav>
        <p class="history-empty" id="history-empty">Your conversations will appear here.</p>
        <div class="panel-footer"><span class="privacy-mark" aria-hidden="true">◈</span><span>Private conversations</span></div>
      </aside>

      <main class="chat-main" id="main-content" data-view-panel="chat">
        <div class="chat-heading">
          <div>
            <span class="eyebrow">PERSONAL ASSISTANT</span>
            <h1 id="conversation-title">A clear mind, at your service.</h1>
          </div>
        </div>
        <section class="message-scroll" id="message-scroll" aria-label="Conversation" aria-live="polite" aria-relevant="additions text">
          <div class="welcome" id="welcome-panel">
            <div class="welcome-orbit" aria-hidden="true"><span></span><i></i></div>
            <p class="eyebrow">READY WHEN YOU ARE</p>
            <h2>What can I help you with?</h2>
            <p class="welcome-note">Ask a question or pick up a thought. Your conversation stays in this private space.</p>
          </div>
          <ol class="message-list" id="message-list" aria-label="Messages"></ol>
        </section>
        <div class="compose-wrap">
          <div class="notice" id="chat-notice" role="status" aria-live="polite" hidden></div>
          <form class="composer" id="composer">
            <label class="visually-hidden" for="message-input">Message Jarvis</label>
            <textarea id="message-input" name="message" rows="1" maxlength="8000"
              placeholder="Message Jarvis…" autocomplete="off" autocapitalize="sentences"
              enterkeyhint="send" aria-describedby="composer-hint"></textarea>
            <div class="composer-actions">
              <span class="composer-hint" id="composer-hint">Enter to send · Shift + Enter for a new line</span>
              <button class="send-button" id="send-button" type="submit" aria-label="Send message">
                <span class="send-label">Send</span><span class="send-icon" aria-hidden="true">↑</span>
              </button>
              <button class="stop-button" id="stop-button" type="button" hidden>Stop response</button>
            </div>
          </form>
        </div>
      </main>
      <section class="data-main" id="overview-view" aria-label="Overview" data-view-panel="overview" hidden>
        <div class="page-heading"><span class="eyebrow">SYSTEM STATUS</span><h1>Overview</h1><p>Your assistant activity and service readiness.</p></div>
        <div class="dashboard-grid">
          <section class="data-card status-card"><h2>Core service</h2><p class="large-value" id="core-status">Loading…</p><p id="core-readiness" class="muted">Checking verified status</p><p id="core-observed" class="muted"></p></section>
          <section class="data-card"><h2>Conversations</h2><p class="large-value" id="conversation-count">—</p><p class="muted">Available in your private history</p></section>
          <section class="data-card"><h2>Assistant turns</h2><p class="large-value" id="turn-total">—</p><p class="muted" id="turn-breakdown">Activity totals</p></section>
          <section class="data-card chart-card"><h2>Turns over the last 7 days</h2><p class="muted" id="chart-caption">Loading recorded activity…</p><div id="turn-chart" role="img" aria-label="Assistant turns in the last seven days"></div></section>
        </div>
      </section>
      <section class="data-main" id="capabilities-view" aria-label="Capabilities" data-view-panel="capabilities" hidden>
        <div class="page-heading"><span class="eyebrow">AVAILABLE TO JARVIS</span><h1>Capabilities</h1><p>Verified local inventory and current readiness.</p></div>
        <div id="capability-readiness" class="readiness-banner" role="status">Loading verified capability inventory…</div>
        <div id="capability-list" class="capability-list" aria-live="polite"></div>
      </section>
      <section class="data-main" id="settings-view" aria-label="Settings" data-view-panel="settings" hidden>
        <div class="page-heading"><span class="eyebrow">CONFIGURATION</span><h1>Settings</h1><p>Effective runtime configuration reported by the service.</p></div>
        <section class="data-card settings-card"><h2>Assistant runtime</h2><dl id="settings-list" class="settings-list"><div><dt>Status</dt><dd>Loading verified configuration…</dd></div></dl><p class="muted">These values are read-only here until secure settings changes are available.</p></section>
      </section>
    </div>
  </div>
  <div class="scrim" id="panel-scrim" hidden></div>
</body>
</html>'''.encode("utf-8")


_CSS = '''@charset "UTF-8";
:root{color-scheme:dark;--bg:#071319;--panel:#0b1c24;--panel-2:#0e242d;--line:rgba(123,197,213,.14);--line-strong:rgba(72,221,235,.36);--text:#e8f3f5;--muted:#91a9ae;--soft:#637e85;--cyan:#58e4eb;--cyan-2:#20bcca;--danger:#ff9e9e;--radius:18px;font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;font-synthesis:none;text-rendering:optimizeLegibility}
*{box-sizing:border-box}*[hidden]{display:none!important}html,body{width:100%;min-width:320px;height:100%;margin:0;background:var(--bg);color:var(--text)}body{overflow:hidden;background-image:radial-gradient(ellipse at 74% 5%,rgba(10,116,132,.13),transparent 42%),linear-gradient(145deg,rgba(48,111,121,.045),transparent 60%)}button,textarea{font:inherit}button,a{-webkit-tap-highlight-color:transparent}button{color:inherit}.app-shell{height:100dvh;min-height:100dvh;display:flex;flex-direction:column;padding-top:env(safe-area-inset-top);padding-bottom:env(safe-area-inset-bottom)}.topbar{height:72px;flex:none;display:flex;align-items:center;gap:16px;padding:0 clamp(16px,3vw,36px);border-bottom:1px solid var(--line);background:rgba(5,17,22,.82);backdrop-filter:blur(18px);z-index:4}.brand{display:inline-flex;align-items:center;gap:11px;color:inherit;text-decoration:none}.brand-mark{width:36px;height:36px;border:1px solid rgba(88,228,235,.55);border-radius:50%;display:grid;place-items:center;box-shadow:0 0 22px rgba(32,188,202,.13),inset 0 0 13px rgba(32,188,202,.11);position:relative}.brand-mark:before,.brand-mark:after{content:"";position:absolute;border:1px solid rgba(88,228,235,.25);border-radius:50%;inset:5px}.brand-mark:after{inset:11px;border-color:rgba(88,228,235,.64)}.brand-mark span{width:4px;height:4px;border-radius:50%;background:var(--cyan);box-shadow:0 0 8px var(--cyan)}.brand-copy{display:grid;gap:2px;letter-spacing:.16em}.brand-copy strong{font-size:13px;font-weight:700}.brand-copy small{font-size:8px;color:var(--muted);letter-spacing:.19em}.connection{margin-left:auto;display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}.connection-dot{width:7px;height:7px;border-radius:50%;background:#768a8e;box-shadow:0 0 8px currentColor}.connection[data-state="ready"] .connection-dot{background:var(--cyan);color:var(--cyan)}.connection[data-state="error"] .connection-dot{background:#ed8181;color:#ed8181}.workspace{min-height:0;flex:1;display:grid;grid-template-columns:286px minmax(0,1fr);max-width:1600px;width:100%;margin:0 auto}.conversation-panel{min-height:0;display:flex;flex-direction:column;padding:30px 18px 18px 22px;border-right:1px solid var(--line);background:rgba(7,22,28,.48)}.panel-heading{display:flex;align-items:center;justify-content:space-between;padding:0 8px 21px}.eyebrow{display:block;margin:0 0 8px;color:#7dabb3;font-size:9px;font-weight:700;letter-spacing:.19em}.panel-heading h2{font-size:16px;margin:0;font-weight:550;letter-spacing:.01em}.new-chat-button{width:100%;height:44px;display:flex;align-items:center;justify-content:center;gap:8px;border:1px solid var(--line-strong);border-radius:12px;background:linear-gradient(120deg,rgba(16,113,124,.24),rgba(17,63,73,.16));color:#d5fcff;font-size:12px;font-weight:600;cursor:pointer;transition:background .16s,border-color .16s}.new-chat-button span{font-size:18px;line-height:1}.new-chat-button:hover{background:rgba(23,142,153,.22);border-color:rgba(88,228,235,.62)}.list-caption{margin:28px 9px 10px;color:var(--soft);font-size:9px;font-weight:700;letter-spacing:.16em}.conversation-list{display:grid;gap:5px;overflow:auto}.conversation-item{width:100%;min-height:43px;padding:10px 11px;text-align:left;border:1px solid transparent;border-radius:10px;background:transparent;color:#a8babe;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px;cursor:pointer}.conversation-item:hover{background:rgba(105,169,180,.08);color:var(--text)}.conversation-item[aria-current="page"]{border-color:rgba(88,228,235,.19);background:rgba(25,128,139,.13);color:#dcfbfc}.history-empty{margin:5px 9px;color:#718b91;font-size:11px;line-height:1.55}.history-empty[hidden]{display:none}.panel-footer{margin-top:auto;padding:15px 9px 4px;display:flex;align-items:center;gap:8px;color:#76949a;font-size:10px;border-top:1px solid var(--line)}.privacy-mark{color:var(--cyan);font-size:15px}.chat-main{min-width:0;min-height:0;display:flex;flex-direction:column;padding:32px clamp(20px,5vw,76px) 20px}.chat-heading{width:100%;max-width:880px;margin:0 auto 15px;display:flex;align-items:flex-start;gap:16px}.chat-heading .eyebrow{margin-bottom:9px}.chat-heading h1{max-width:600px;margin:0;font-size:clamp(22px,2.6vw,31px);line-height:1.2;font-weight:530;letter-spacing:-.035em}.message-scroll{position:relative;min-height:0;flex:1;overflow:auto;width:100%;max-width:880px;margin:0 auto;padding:18px 0 28px;scrollbar-color:rgba(87,150,160,.3) transparent;scrollbar-width:thin}.welcome{min-height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:24px 16px 36px}.welcome[hidden]{display:none}.welcome-orbit{width:88px;height:88px;position:relative;margin:0 auto 30px;border:1px solid rgba(88,228,235,.15);border-radius:50%;display:grid;place-items:center;box-shadow:0 0 50px rgba(26,179,194,.07),inset 0 0 28px rgba(31,163,175,.06)}.welcome-orbit:before,.welcome-orbit:after{content:"";position:absolute;border:1px solid rgba(88,228,235,.26);border-radius:50%}.welcome-orbit:before{inset:9px}.welcome-orbit:after{inset:20px;border-color:rgba(88,228,235,.48)}.welcome-orbit span{width:12px;height:12px;border-radius:50%;background:var(--cyan);box-shadow:0 0 19px rgba(88,228,235,.9)}.welcome-orbit i{position:absolute;right:9px;top:13px;width:4px;height:4px;border-radius:50%;background:#c5fcff;box-shadow:0 0 10px var(--cyan)}.welcome .eyebrow{margin-bottom:11px}.welcome h2{margin:0;font-size:clamp(20px,3vw,25px);font-weight:500;letter-spacing:-.025em}.welcome-note{max-width:360px;margin:12px 0 0;color:#92abb0;font-size:13px;line-height:1.65}.message-list{list-style:none;display:grid;gap:22px;margin:0;padding:0 0 20px}.message-row{display:grid;grid-template-columns:30px minmax(0,1fr);gap:12px;align-items:start;animation:appear .18s ease-out}.message-avatar{width:29px;height:29px;display:grid;place-items:center;border:1px solid rgba(88,228,235,.3);border-radius:10px;background:rgba(25,113,124,.14);color:var(--cyan);font-size:9px;font-weight:700}.message-row[data-role="user"] .message-avatar{border-color:var(--line);background:rgba(92,121,126,.14);color:#b7cbd0}.message-content{min-width:0;padding-top:5px;color:#d6e5e7;font-size:14px;line-height:1.7;overflow-wrap:anywhere;white-space:pre-wrap}.message-row[data-role="user"] .message-content{color:#f0f7f8}.message-state{display:inline-block;margin-top:7px;color:#789197;font-size:10px}.message-row[data-state="error"] .message-state{color:var(--danger)}.compose-wrap{flex:none;width:100%;max-width:880px;margin:0 auto;padding-top:12px}.composer{padding:8px 9px 8px 16px;border:1px solid rgba(125,184,193,.26);border-radius:16px;background:rgba(12,31,38,.96);box-shadow:0 8px 32px rgba(0,0,0,.18);transition:border-color .15s,box-shadow .15s}.composer:focus-within{border-color:rgba(88,228,235,.62);box-shadow:0 0 0 3px rgba(88,228,235,.07),0 10px 36px rgba(0,0,0,.2)}.composer textarea{display:block;width:100%;min-height:46px;max-height:180px;resize:none;padding:9px 4px;border:0;outline:0;background:transparent;color:var(--text);font-size:16px;line-height:1.5;caret-color:var(--cyan)}.composer textarea::placeholder{color:#738e94}.composer-actions{min-height:33px;display:flex;align-items:center;gap:9px}.composer-hint{margin-right:auto;color:#718b91;font-size:10px}.send-button,.stop-button{min-height:34px;display:flex;align-items:center;justify-content:center;gap:11px;padding:0 13px;border:1px solid rgba(88,228,235,.33);border-radius:10px;background:rgba(29,139,150,.19);color:#d5fdff;font-size:11px;font-weight:650;cursor:pointer}.send-button:hover,.stop-button:hover{border-color:var(--cyan);background:rgba(29,139,150,.32)}.send-button:disabled,.stop-button:disabled{opacity:.5;cursor:wait}.send-icon{font-size:16px;line-height:1}.stop-button{border-color:rgba(249,153,153,.34);background:rgba(131,56,62,.16);color:#ffd4d4}.notice{margin-bottom:9px;padding:10px 12px;border:1px solid rgba(255,158,158,.28);border-radius:10px;background:rgba(108,34,42,.2);color:#ffd0d0;font-size:12px;line-height:1.45}.notice[hidden]{display:none}.icon-button{width:36px;height:36px;border:1px solid transparent;border-radius:10px;background:transparent;color:#a1b8bc;cursor:pointer}.icon-button:hover{border-color:var(--line);background:rgba(113,169,178,.08);color:var(--text)}.mobile-history-toggle,.panel-close{display:none}.scrim[hidden]{display:none}.visually-hidden{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}:focus-visible{outline:2px solid var(--cyan);outline-offset:3px;border-radius:4px}
@keyframes appear{from{opacity:.45;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
@media(max-width:760px){.workspace{grid-template-columns:minmax(0,1fr)}.conversation-panel{position:fixed;z-index:6;top:calc(72px + env(safe-area-inset-top));bottom:env(safe-area-inset-bottom);left:0;width:min(320px,86vw);padding:24px 18px 16px 20px;background:#091a21;border-right:1px solid var(--line-strong);box-shadow:18px 0 44px rgba(0,0,0,.42);transform:translateX(-105%);transition:transform .2s ease}.conversation-panel[data-open="true"]{transform:translateX(0)}.panel-heading{padding-bottom:19px}.mobile-history-toggle,.panel-close{display:inline-grid;place-items:center}.panel-close{width:30px;height:30px;font-size:22px}.topbar{height:64px;padding-inline:14px;gap:10px}.brand-mark{width:32px;height:32px}.brand-copy{gap:1px}.brand-copy small{font-size:7px}.connection{font-size:10px}.chat-main{padding:22px 17px calc(12px + env(safe-area-inset-bottom))}.chat-heading{margin-bottom:6px;align-items:center}.chat-heading h1{font-size:22px}.message-scroll{padding:10px 0 17px}.welcome{padding-bottom:22px}.welcome-orbit{width:72px;height:72px;margin-bottom:25px}.welcome-orbit:before{inset:7px}.welcome-orbit:after{inset:17px}.welcome-note{font-size:12px}.composer{padding:7px 8px 8px 12px;border-radius:14px}.composer textarea{min-height:43px;max-height:144px;padding:8px 3px;font-size:16px}.composer-hint{font-size:9px}.send-button,.stop-button{min-height:38px}.scrim:not([hidden]){display:block;position:fixed;z-index:5;inset:calc(64px + env(safe-area-inset-top)) 0 0;background:rgba(0,0,0,.48)}}
@media(max-width:390px){.topbar{gap:6px;padding-inline:10px}.brand{gap:7px}.brand-copy strong{font-size:12px}.connection{gap:5px;font-size:9px}.chat-main{padding-inline:13px}.composer-hint{max-width:170px;line-height:1.3}.send-button{gap:7px;padding-inline:10px}.chat-heading h1{font-size:20px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}}
@media(forced-colors:active){.brand-mark,.welcome-orbit,.composer,.new-chat-button,.send-button,.stop-button{border:1px solid CanvasText}.connection-dot{background:Highlight}}
.primary-nav{display:flex;align-items:center;gap:4px;margin-left:24px}.nav-item{min-height:36px;padding:0 12px;border:1px solid transparent;border-radius:9px;background:transparent;color:#9ab1b5;font:inherit;font-size:12px;cursor:pointer}.nav-item:hover,.nav-item[aria-current="page"]{border-color:var(--line);background:rgba(88,228,235,.08);color:#ddfbfd}.workspace>.data-main{grid-column:2;grid-row:1}.data-main{min-width:0;overflow:auto;padding:40px clamp(20px,5vw,76px)}.data-main[hidden],.chat-main[hidden]{display:none}.page-heading{max-width:1080px;margin:0 auto 26px}.page-heading h1{margin:0;font-size:clamp(25px,3vw,34px);font-weight:550;letter-spacing:-.03em}.page-heading p,.muted{color:#8ba5aa;font-size:13px;line-height:1.6}.page-heading p{margin:8px 0}.dashboard-grid{max-width:1080px;margin:0 auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.data-card{min-width:0;padding:21px;border:1px solid var(--line);border-radius:15px;background:rgba(12,31,38,.78)}.data-card h2{margin:0;color:#acc2c6;font-size:13px;font-weight:600}.large-value{margin:14px 0 3px;color:#e6fbfc;font-size:29px;font-weight:550;letter-spacing:-.03em}.data-card .muted{margin:5px 0}.chart-card{grid-column:1/-1}.chart-bars{height:175px;display:grid;grid-template-columns:repeat(7,minmax(24px,1fr));align-items:end;gap:10px;margin:22px 4px 0;border-bottom:1px solid var(--line-strong)}.chart-day{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:7px;color:#88a2a7;font-size:10px}.chart-bar-track{height:124px;width:100%;display:flex;align-items:flex-end;justify-content:center}.chart-bar{width:min(35px,72%);min-height:2px;border-radius:5px 5px 1px 1px;background:linear-gradient(0deg,#137c88,#56dbe2)}.readiness-banner{max-width:1080px;margin:0 auto 16px;padding:14px 17px;border:1px solid rgba(245,194,117,.25);border-radius:12px;background:rgba(106,76,31,.12);color:#e7cca0;font-size:13px;line-height:1.6}.capability-list{max-width:1080px;margin:auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.capability-row{padding:16px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.66)}.capability-row h2{margin:0 0 6px;font-size:14px;font-weight:600}.capability-row p{margin:0;color:#8ba5aa;font-size:12px;line-height:1.6}.state-pill{display:inline-block;margin-top:11px;padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:#abc2c5;font-size:10px;text-transform:capitalize}.settings-card{max-width:720px;margin:0 auto}.settings-list{margin:18px 0;display:grid;gap:0}.settings-list>div{display:flex;justify-content:space-between;gap:20px;padding:14px 0;border-bottom:1px solid var(--line)}.settings-list dt{color:#8ba5aa;font-size:13px}.settings-list dd{margin:0;text-align:right;color:#e1f4f5;font-size:13px;overflow-wrap:anywhere}
@media(max-width:760px){.topbar{height:auto;min-height:64px;flex-wrap:wrap;padding-block:8px}.primary-nav{order:3;width:100%;margin:0;justify-content:space-around}.nav-item{flex:1;padding-inline:6px}.connection{margin-left:auto}.conversation-panel{top:calc(112px + env(safe-area-inset-top))}.scrim:not([hidden]){inset:calc(104px + env(safe-area-inset-top)) 0 0}.workspace{min-height:0}.workspace>.data-main{grid-column:1;grid-row:1}.data-main{padding:26px 16px calc(20px + env(safe-area-inset-bottom))}.dashboard-grid,.capability-list{grid-template-columns:1fr}.chart-card{grid-column:auto}.data-card{padding:17px}.chart-bars{gap:5px}.settings-list>div{gap:12px}}
@media(prefers-reduced-motion:reduce){.nav-item{transition:none}}
'''.encode("utf-8")


_JS = r'''/* Browser client is deliberately a text-only view over the finite Jarvis API. */
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const ui = {
    connection: byId("connection-state"), history: byId("conversation-list"),
    empty: byId("history-empty"), title: byId("conversation-title"),
    messages: byId("message-list"), welcome: byId("welcome-panel"),
    scroll: byId("message-scroll"), form: byId("composer"), input: byId("message-input"),
    send: byId("send-button"), stop: byId("stop-button"), notice: byId("chat-notice"),
    toggle: byId("history-toggle"), close: byId("history-close"), panel: byId("conversation-panel"),
    scrim: byId("panel-scrim"), newChat: byId("new-chat")
  };
  let conversations = [];
  let conversationId = null;
  let activeTurnId = null;
  let eventSource = null;
  let heartbeatTimer = null;
  let heartbeatNonce = null;
  let latestSequence = 0;
  const API = "/chat/api";

  function renderTurnControls(active, stopping = false) {
    ui.input.disabled = active;
    ui.send.hidden = active;
    ui.send.disabled = active;
    ui.stop.hidden = !active;
    ui.stop.disabled = stopping;
  }

  function showError(message) {
    ui.notice.textContent = message;
    ui.notice.hidden = false;
  }
  function clearError() { ui.notice.textContent = ""; ui.notice.hidden = true; }
  function setConnection(state, label) {
    ui.connection.dataset.state = state;
    ui.connection.lastElementChild.textContent = label;
  }
  function appendMessage(role, text, state) {
    if (role !== "user" && role !== "assistant") return null;
    const item = document.createElement("li");
    item.className = "message-row";
    item.dataset.role = role;
    if (state) item.dataset.state = state;
    const avatar = document.createElement("span");
    avatar.className = "message-avatar";
    avatar.setAttribute("aria-hidden", "true");
    avatar.textContent = role === "user" ? "YOU" : "J";
    const body = document.createElement("div");
    body.className = "message-content";
    body.textContent = typeof text === "string" ? text : "";
    item.append(avatar, body);
    ui.messages.append(item);
    ui.welcome.hidden = true;
    ui.scroll.scrollTop = ui.scroll.scrollHeight;
    return body;
  }
  function renderHistory() {
    ui.history.replaceChildren();
    ui.empty.hidden = conversations.length !== 0;
    for (const entry of conversations) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "conversation-item";
      button.textContent = typeof entry.title === "string" && entry.title.trim() ? entry.title : "New conversation";
      if (entry.id === conversationId) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => loadConversation(entry.id));
      ui.history.append(button);
    }
  }
  function setPanel(open) {
    const value = Boolean(open);
    ui.panel.dataset.open = String(value);
    ui.toggle.setAttribute("aria-expanded", String(value));
    ui.scrim.hidden = !value;
  }
  function closeStream() {
    if (eventSource) eventSource.close();
    eventSource = null;
    if (heartbeatTimer !== null) window.clearInterval(heartbeatTimer);
    heartbeatTimer = null;
    activeTurnId = null;
    heartbeatNonce = null;
    renderTurnControls(false);
  }
  async function request(path, options = {}) {
    let response;
    try {
      response = await fetch(path, { credentials: "same-origin", cache: "no-store", ...options,
        headers: { Accept: "application/json", ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } });
    } catch (_) {
      throw new Error("Jarvis is unreachable. Check your connection and try again.");
    }
    if (response.status === 401 || response.status === 403) throw new Error("Your secure session is no longer current. Sign in again to continue.");
    if (response.status === 429) throw new Error("Jarvis is busy right now. Your conversation remains separate.");
    if (response.status === 503) throw new Error("The assistant service is currently unavailable.");
    if (!response.ok) throw new Error("Jarvis could not complete that request. Try again in a moment.");
    try { return await response.json(); }
    catch (_) { throw new Error("Jarvis returned an unreadable response. Please reload this conversation."); }
  }
  async function refreshConversations() {
    const data = await request(`${API}/conversations`);
    if (!data || !Array.isArray(data.conversations)) throw new Error("Conversation history is unavailable.");
    conversations = data.conversations.filter((item) => item && typeof item.id === "string" && typeof item.title === "string");
    renderHistory();
  }
  async function loadConversation(id) {
    if (typeof id !== "string" || !id) return;
    closeStream();
    clearError();
    try {
      const data = await request(`${API}/conversations/${encodeURIComponent(id)}/messages`);
      if (!Array.isArray(data.messages)) throw new Error("This conversation could not be read.");
      conversationId = id;
      ui.messages.replaceChildren();
      for (const message of data.messages) {
        if (!message || (message.role !== "user" && message.role !== "assistant") || typeof message.content !== "string") continue;
        appendMessage(message.role, message.content);
      }
      ui.welcome.hidden = data.messages.length !== 0;
      ui.title.textContent = conversations.find((item) => item.id === id)?.title || "Your conversation";
      renderHistory();
      setPanel(false);
    } catch (error) { showError(error.message); }
  }
  async function createConversation() {
    closeStream();
    clearError();
    try {
      const data = await request(`${API}/conversations`, { method: "POST", body: "{}" });
      if (!data.conversation || typeof data.conversation.id !== "string" || !data.conversation.id) throw new Error("Jarvis could not start a conversation.");
      conversationId = data.conversation.id;
      ui.messages.replaceChildren();
      ui.welcome.hidden = false;
      ui.title.textContent = "A clear mind, at your service.";
      await refreshConversations();
      renderHistory();
      setPanel(false);
      ui.input.focus({ preventScroll: true });
    } catch (error) { showError(error.message); }
  }
  function startHeartbeat() {
    heartbeatTimer = window.setInterval(async () => {
      if (!activeTurnId || !heartbeatNonce) return;
      const turnId = activeTurnId;
      const nonce = heartbeatNonce;
      heartbeatNonce = null;
      try {
        const data = await request(`${API}/heartbeat`, { method: "POST", body: JSON.stringify({ turnId, nonce }) });
        if (activeTurnId !== turnId || data.turnId !== turnId || typeof data.nonce !== "string" || !/^[0-9a-f]{64}$/.test(data.nonce)) throw new Error("Secure connection could not be renewed.");
        heartbeatNonce = data.nonce;
      } catch (error) {
        closeStream(); showError(error.message); setConnection("error", "Access unavailable");
      }
    }, 2000);
  }
  function watchTurn(turnId, initialNonce, assistantBody, waiting) {
    if (typeof turnId !== "string" || !turnId || typeof initialNonce !== "string" || !/^[0-9a-f]{64}$/.test(initialNonce)) throw new Error("Jarvis did not start this response securely.");
    activeTurnId = turnId;
    heartbeatNonce = initialNonce;
    latestSequence = 0;
    // Show Stop as soon as the server accepts the queued turn. Install the
    // controls before opening SSE, whose connection can fail immediately.
    renderTurnControls(true);
    eventSource = new EventSource(`${API}/turns/${encodeURIComponent(turnId)}/events`, { withCredentials: true });
    startHeartbeat();
    eventSource.addEventListener("message.delta", (event) => {
      let payload;
      try { payload = JSON.parse(event.data); } catch (_) { closeStream(); showError("Jarvis sent an unreadable update."); return; }
      if (!payload || !Number.isSafeInteger(payload.sequence) || payload.sequence < 1 || payload.sequence <= latestSequence || typeof payload.text !== "string") return;
      latestSequence = payload.sequence;
      waiting.remove();
      if (payload.text.length > 65536 || assistantBody.textContent.length + payload.text.length > 524288) {
        closeStream();
        showError("This response reached the display limit. Reload the conversation to view its saved state.");
        return;
      }
      assistantBody.append(document.createTextNode(payload.text));
      ui.scroll.scrollTop = ui.scroll.scrollHeight;
    });
    eventSource.addEventListener("turn.completed", () => {
      waiting.remove();
      closeStream();
      refreshConversations().catch((error) => showError(error.message));
    });
    eventSource.addEventListener("message.completed", () => { waiting.remove(); });
    eventSource.addEventListener("turn.cancelled", () => { waiting.remove(); closeStream(); });
    eventSource.addEventListener("turn.failed", () => {
      waiting.remove();
      closeStream();
      showError("Jarvis could not finish that response. You can try again.");
    });
    eventSource.addEventListener("error", (event) => {
      if (!activeTurnId) return;
      waiting.remove();
      let code = "";
      try { code = JSON.parse(event.data).code; } catch (_) {}
      const safeErrors = {
        busy: "Jarvis is busy right now. Your conversation remains separate.",
        authorization: "Your secure session is no longer current. Sign in again to continue.",
        "backend-unavailable": "The assistant service is currently unavailable."
      };
      closeStream();
      if (typeof code === "string" && safeErrors[code]) {
        showError(safeErrors[code]);
        if (code === "authorization") setConnection("error", "Access unavailable");
      } else {
        showError("The response stream ended. Reload the conversation to see its saved state.");
        setConnection("error", "Connection interrupted");
      }
    });
  }
  async function sendMessage(text) {
    clearError();
    if (!conversationId) {
      const data = await request(`${API}/conversations`, { method: "POST", body: "{}" });
      if (!data.conversation || typeof data.conversation.id !== "string" || !data.conversation.id) throw new Error("Jarvis could not start a conversation.");
      conversationId = data.conversation.id;
      ui.title.textContent = data.conversation.title || "Your conversation";
      await refreshConversations();
    }
    appendMessage("user", text);
    const assistantBody = appendMessage("assistant", "");
    const waiting = document.createElement("span");
    waiting.className = "message-state";
    waiting.textContent = "Waiting for Jarvis…";
    assistantBody.append(waiting);
    ui.input.disabled = true;
    ui.send.disabled = true;
    try {
      const data = await request(`${API}/conversations/${encodeURIComponent(conversationId)}/turns`, {
        method: "POST", body: JSON.stringify({ text }),
        headers: { "Idempotency-Key": createIdempotencyKey() }
      });
      if (!data || data.status !== "queued") throw new Error("Jarvis could not safely queue this response.");
      watchTurn(data.turnId, data.heartbeatNonce, assistantBody, waiting);
      refreshConversations().catch((error) => showError(error.message));
    } catch (error) {
      ui.input.disabled = false;
      ui.send.disabled = false;
      assistantBody.textContent = "";
      assistantBody.parentElement.dataset.state = "error";
      const status = document.createElement("span");
      status.className = "message-state";
      status.textContent = error.message;
      assistantBody.append(status);
      showError(error.message);
    }
  }
  function createIdempotencyKey() {
    const bytes = new Uint8Array(24);
    window.crypto.getRandomValues(bytes);
    let binary = "";
    for (const value of bytes) binary += String.fromCharCode(value);
    return window.btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  }
  async function stopTurn() {
    if (!activeTurnId) return;
    const turnId = activeTurnId;
    renderTurnControls(true, true);
    try {
      await request(`${API}/turns/${encodeURIComponent(turnId)}/stop`, { method: "POST", body: "{}" });
      // A terminal event may already have cleared this turn while stop was in
      // flight. Never let an old stop request reset a newer conversation.
      if (activeTurnId === turnId) closeStream();
    } catch (error) {
      showError(error.message);
      if (activeTurnId === turnId) renderTurnControls(true);
    }
  }
  function renderTurnChart(days) {
    const chart = byId("turn-chart");
    chart.replaceChildren();
    if (!Array.isArray(days) || days.length !== 7 || days.some((day) => !day || typeof day.date !== "string" || !Number.isFinite(day.total))) {
      byId("chart-caption").textContent = "Recorded daily activity is not available yet.";
      return;
    }
    byId("chart-caption").textContent = days.reduce((sum, day) => sum + Math.max(0, day.total), 0) === 0 ? "No assistant turns recorded in this period." : "Recorded turns, grouped by day.";
    const max = Math.max(1, ...days.map((day) => Math.max(0, day.total)));
    const bars = document.createElement("div");
    bars.className = "chart-bars";
    for (const day of days) {
      const cell = document.createElement("div");
      cell.className = "chart-day";
      const value = Math.max(0, day.total);
      const track = document.createElement("div");
      track.className = "chart-bar-track";
      const bar = document.createElement("span");
      bar.className = "chart-bar";
      bar.style.height = `${value ? Math.max(4, 100 * value / max) : 1}%`;
      bar.title = `${value} turns`;
      track.append(bar);
      const label = document.createElement("span");
      const parsed = new Date(`${day.date}T00:00:00Z`);
      label.textContent = Number.isNaN(parsed.valueOf()) ? day.date : parsed.toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" });
      cell.append(track, label);
      bars.append(cell);
    }
    chart.append(bars);
  }
  async function loadOverview() {
    const data = await request(`${API}/overview`);
    const core = data.core || {};
    const chat = data.chat || {};
    byId("core-status").textContent = typeof core.status === "string" ? core.status : "Unavailable";
    byId("core-readiness").textContent = typeof core.readiness === "string" ? core.readiness : "Readiness has not been verified.";
    byId("core-observed").textContent = typeof core.observedAt === "string" ? `Observed ${core.observedAt}` : "No verified observation time";
    byId("conversation-count").textContent = Number.isFinite(chat.conversationCount) ? String(chat.conversationCount) : "Unavailable";
    const counts = chat.turnCounts || {};
    byId("turn-total").textContent = Number.isFinite(counts.total) ? String(counts.total) : "Unavailable";
    byId("turn-breakdown").textContent = ["completed", "failed", "cancelled"].map((key) => `${key}: ${Number.isFinite(counts[key]) ? counts[key] : "—"}`).join(" · ");
    renderTurnChart(chat.turnCountsByDay);
  }
  async function loadCapabilities() {
    const data = await request(`${API}/capabilities`);
    const list = byId("capability-list");
    list.replaceChildren();
    byId("capability-readiness").textContent = typeof data.readiness === "string" ? data.readiness : "Some capabilities are still being verified.";
    if (!Array.isArray(data.items) || !data.items.length) {
      const empty = document.createElement("p");
      empty.className = "readiness-banner";
      empty.textContent = "No capability inventory is available yet.";
      list.append(empty);
      return;
    }
    for (const item of data.items) {
      if (!item || typeof item.name !== "string") continue;
      const card = document.createElement("article");
      card.className = "capability-row";
      const name = document.createElement("h2");
      name.textContent = item.name;
      const detail = document.createElement("p");
      detail.textContent = typeof item.summary === "string" ? item.summary : "Details are not available.";
      const state = document.createElement("span");
      state.className = "state-pill";
      const knownState = ["bundled", "pending", "unavailable", "ready"].includes(item.state) ? item.state : "pending";
      state.textContent = knownState === "ready" ? "verified ready" : knownState;
      card.append(name, detail, state);
      list.append(card);
    }
  }
  async function loadSettings() {
    const data = await request(`${API}/settings`);
    const list = byId("settings-list");
    list.replaceChildren();
    for (const [label, setting] of [["Provider", data.provider], ["Model", data.model], ["Core version", data.coreVersion]]) {
      const row = document.createElement("div");
      const term = document.createElement("dt");
      term.textContent = label;
      const definition = document.createElement("dd");
      const value = setting && typeof setting === "object" ? setting.value : setting;
      definition.textContent = typeof value === "string" && value.trim() ? value : "Pending verification";
      row.append(term, definition);
      list.append(row);
    }
  }
  async function showView(view) {
    const selected = ["chat", "overview", "capabilities", "settings"].includes(view) ? view : "chat";
    for (const panel of document.querySelectorAll("[data-view-panel]")) panel.hidden = panel.dataset.viewPanel !== selected;
    for (const button of document.querySelectorAll(".nav-item")) {
      if (button.dataset.view === selected) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    if (selected === "overview") {
      try { await loadOverview(); } catch (error) { byId("chart-caption").textContent = error.message; }
    } else if (selected === "capabilities") {
      try { await loadCapabilities(); } catch (error) { byId("capability-readiness").textContent = error.message; }
    } else if (selected === "settings") {
      try { await loadSettings(); } catch (error) { byId("settings-list").replaceChildren(); const row = document.createElement("div"); const term = document.createElement("dt"); const value = document.createElement("dd"); term.textContent = "Status"; value.textContent = error.message; row.append(term, value); byId("settings-list").append(row); }
    }
  }
  ui.form.addEventListener("submit", (event) => {
    event.preventDefault();
    const text = ui.input.value;
    if (!text.trim() || ui.input.disabled) return;
    ui.input.value = "";
    ui.input.style.height = "auto";
    sendMessage(text).catch((error) => showError(error.message));
  });
  ui.input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault();
      ui.form.requestSubmit();
    }
  });
  ui.input.addEventListener("input", () => {
    ui.input.style.height = "auto";
    ui.input.style.height = `${Math.min(ui.input.scrollHeight, 180)}px`;
  });
  ui.newChat.addEventListener("click", createConversation);
  ui.stop.addEventListener("click", stopTurn);
  ui.toggle.addEventListener("click", () => setPanel(ui.panel.dataset.open !== "true"));
  ui.close.addEventListener("click", () => setPanel(false));
  ui.scrim.addEventListener("click", () => setPanel(false));
  for (const button of document.querySelectorAll(".nav-item")) button.addEventListener("click", () => showView(button.dataset.view));
  window.addEventListener("pagehide", closeStream);
  (async () => {
    try {
      await refreshConversations();
      setConnection("ready", "Secure connection");
      if (conversations.length) await loadConversation(conversations[0].id);
    } catch (error) {
      setConnection("error", "Access unavailable");
      showError(error.message);
    }
  })();
})();
'''.encode("utf-8")


_ASSETS = MappingProxyType({
    "/chat": ("text/html; charset=utf-8", _HTML),
    "/chat/": ("text/html; charset=utf-8", _HTML),
    "/chat/assets/app.css": ("text/css; charset=utf-8", _CSS),
    "/chat/assets/app.js": ("text/javascript; charset=utf-8", _JS),
})


def reviewed_chat_asset(path: str) -> tuple[str, bytes]:
    """Return one exact reviewed Jarvis asset or deny an unknown route."""
    try:
        return _ASSETS[path]
    except (KeyError, TypeError):
        raise ValueError("route is outside the reviewed Jarvis chat asset set") from None
