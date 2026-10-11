"""Finite installer-owned assets for the practical Jarvis chat surface.

Only the reviewed `/chat` document and three fixed static assets are exposed.
The bundle contains no provider credentials or user data.
"""
from __future__ import annotations

from html import escape
import json
from types import MappingProxyType

from .jarvis_feature_contract import validate_feature_assets
from .jarvis_feature_registry import FEATURE_ASSETS
from .jarvis_capability_details_assets import CSS as _CAPABILITY_DETAILS_CSS
from .jarvis_capability_details_assets import MOUNT_JS as _CAPABILITY_DETAILS_MOUNT_JS
from .jarvis_capability_details_assets import VIEW_HTML as _CAPABILITY_DETAILS_HTML


_HTML = '''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover, interactive-widget=resizes-content">
  <meta name="theme-color" content="#071319">
  <title>Jarvis</title>
  <link rel="stylesheet" href="/chat/assets/app.css">
  <script defer src="/chat/assets/features.js"></script>
  <script defer src="/chat/assets/app.js"></script>
</head>
<body>
  <div class="app-shell">
    <header class="topbar">
      <button class="icon-button mobile-history-toggle" id="history-toggle" type="button"
        aria-label="Show conversations" aria-controls="conversation-panel" aria-expanded="false">
        <span aria-hidden="true">☰</span>
      </button>
      <a class="brand" href="/chat" id="jarvis-home" aria-label="Jarvis command centre home">
        <span class="brand-mark" aria-hidden="true"><span></span></span>
        <span class="brand-copy"><strong>JARVIS</strong><small>PERSONAL ASSISTANT</small></span>
      </a>
      <nav class="primary-nav" aria-label="Jarvis sections">
        <details class="nav-group" data-nav-group="command-centre"><summary>Command centre</summary><div class="nav-menu"><button type="button" class="nav-item" data-view="overview">Overview</button></div></details>
        <details class="nav-group" data-nav-group="conversations"><summary>Conversations</summary><div class="nav-menu"><button type="button" class="nav-item" data-view="chat">Chats</button></div></details>
        <details class="nav-group" data-nav-group="work"><summary>Work</summary><div class="nav-menu"><!-- JARVIS_GROUP_WORK --></div></details>
        <details class="nav-group" data-nav-group="resources"><summary>Resources</summary><div class="nav-menu"><button type="button" class="nav-item" data-view="capabilities">Capabilities</button><!-- JARVIS_GROUP_RESOURCES --></div></details>
        <details class="nav-group" data-nav-group="system"><summary>System</summary><div class="nav-menu"><button type="button" class="nav-item" data-view="settings">Settings</button><!-- JARVIS_GROUP_SYSTEM --></div></details>
      </nav>
      <div class="assistant-hud" id="assistant-hud" data-state="checking" aria-label="Jarvis status">
        <span class="assistant-orb" aria-hidden="true"><span class="orb-core"></span><span class="orb-ring"></span><span class="orb-halo"></span></span>
        <span class="assistant-state"><strong id="assistant-state-label">JARVIS · CHECKING</strong><span id="assistant-mode" role="status" aria-live="polite">Checking secure connection</span></span>
      </div>
      <span class="connection" id="connection-state" role="status" aria-live="polite">
        <span class="connection-dot" aria-hidden="true"></span><span>Checking access…</span>
      </span>
    </header>

    <div class="workspace" data-current-view="overview">
      <aside class="conversation-panel" id="conversation-panel" aria-label="Conversations">
        <div class="panel-heading">
          <div><span class="eyebrow">YOUR SPACE</span><h2>Chats</h2></div>
          <button class="icon-button panel-close" id="history-close" type="button" aria-label="Close conversations">×</button>
        </div>
        <button class="new-chat-button" id="new-chat" type="button"><span aria-hidden="true">＋</span> New conversation</button>
        <p class="list-caption">YOUR CONVERSATIONS</p>
        <label class="session-search-label" for="session-search">Find a chat</label>
        <input class="session-search" id="session-search" type="search" autocomplete="off" placeholder="Search chats" aria-describedby="session-count">
        <p class="session-count" id="session-count" role="status" aria-live="polite">Loading chats…</p>
        <nav class="conversation-list" id="conversation-list" aria-label="Owned private chats"></nav>
        <p class="history-empty" id="history-empty">No chats yet. Start a new conversation.</p>
        <p class="history-empty" id="history-filter-empty" hidden>No chats match this search.</p>
        <div class="panel-footer"><span class="privacy-mark" aria-hidden="true">◈</span><span>Private conversations</span></div>
      </aside>

      <main class="chat-main" id="main-content" data-view-panel="chat" hidden>
        <div class="chat-heading">
          <div>
            <span class="eyebrow">PERSONAL ASSISTANT · PRIVATE SESSION</span>
            <h1 id="conversation-title">A clear mind, at your service.</h1>
          </div>
          <details class="chat-preferences" id="chat-preferences">
            <summary aria-label="Open chat controls" aria-controls="chat-preferences-panel">Chat controls</summary>
            <div class="chat-preferences-panel" id="chat-preferences-panel" role="region" aria-labelledby="chat-preferences-title">
              <div class="chat-preferences-heading"><h2 id="chat-preferences-title">Chat controls</h2><span>Model · voice · display</span></div>
              <button type="button" class="chat-model-link" data-view="models-settings">Choose conversation model <span>Session only ↗</span></button>
              <p class="chat-preferences-note">Voice and display choices apply across this browser and are also available in System settings.</p>
              <label class="chat-preference-toggle" id="chat-speech-consent-row"><input id="chat-speech-consent" type="checkbox"><span><strong>Allow browser voice input</strong><small>Push-to-talk or foreground wake phrase · review before sending</small></span></label>
              <label class="chat-preference-toggle" id="chat-speech-output-row"><input id="chat-speech-output" type="checkbox"><span><strong>Read completed replies aloud</strong><small>Uses voices provided by this browser or device</small></span></label>
              <label class="chat-preference-field"><span>Recognition language</span><select id="chat-speech-language" aria-label="Recognition language">
                <option value="en-US">English (United States)</option><option value="en-GB">English (United Kingdom)</option><option value="pt-PT">Português (Portugal)</option><option value="pt-BR">Português (Brasil)</option><option value="es-ES">Español (España)</option><option value="fr-FR">Français</option><option value="de-DE">Deutsch</option><option value="it-IT">Italiano</option>
              </select></label>
              <label class="chat-preference-field"><span>Speech voice</span><select id="chat-speech-voice" aria-label="Speech voice"></select></label>
              <div class="chat-preference-tuning" id="chat-preference-tuning"><label for="chat-speech-rate"><span>Speaking rate</span><output id="chat-speech-rate-value" for="chat-speech-rate">1.0×</output><input id="chat-speech-rate" type="range" min="0.5" max="2" step="0.1" value="1"></label><label for="chat-speech-pitch"><span>Voice pitch</span><output id="chat-speech-pitch-value" for="chat-speech-pitch">1.0</output><input id="chat-speech-pitch" type="range" min="0" max="2" step="0.1" value="1"></label></div>
              <label class="chat-preference-field"><span>Text size</span><select id="chat-text-size" aria-label="Text size"><option value="normal">Default</option><option value="large">Large</option></select></label>
              <label class="chat-preference-field"><span>Layout density</span><select id="chat-density" aria-label="Layout density"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label>
              <label class="chat-preference-field"><span>Motion</span><select id="chat-motion" aria-label="Motion preference"><option value="system">Follow device setting</option><option value="reduce">Reduce motion</option><option value="full">Full motion · override device</option></select></label>
            </div>
          </details>
        </div>
        <section class="message-scroll" id="message-scroll" aria-label="Conversation" aria-live="polite" aria-relevant="additions text">
          <div class="welcome" id="welcome-panel">
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
              inputmode="text" autocorrect="on" spellcheck="true"
              enterkeyhint="send" aria-describedby="composer-hint"></textarea>
            <div class="composer-actions">
              <span class="composer-hint" id="composer-hint">Enter to send · Shift + Enter for a new line</span>
              <button class="send-button" id="send-button" type="submit" aria-label="Send message">
                <span class="send-label">Send</span><span class="send-icon" aria-hidden="true">↑</span>
              </button>
              <button class="stop-button" id="stop-button" type="button" hidden>Stop response</button>
              <button class="voice-button" id="voice-input" type="button" aria-label="Start push to talk" hidden>Speak</button>
              <button class="voice-button" id="voice-stop" type="button" hidden>Stop listening</button>
              <button class="voice-button voice-wake-button" id="voice-wake-toggle" type="button" aria-pressed="false" hidden>Enable foreground wake phrase</button>
              <button class="voice-button" id="speech-stop" type="button" aria-label="Stop reply audio" hidden disabled>Stop audio</button>
            </div>
          </form>
          <div class="voice-wake-controls" id="voice-wake-controls" hidden>
            <label><input id="voice-handsfree-send" type="checkbox"><span>Send a command after “Jarvis” without review</span></label>
            <p>Foreground only. Wake listening uses this browser’s speech service, may send audio outside Jarvis, and stops when this page is hidden or leaves Chat.</p>
          </div>
          <p class="voice-status" id="voice-status" role="status" aria-live="polite" hidden></p>
        </div>
      </main>
      <main class="data-main" id="overview-view" aria-label="Command centre" data-view-panel="overview">
        <div class="command-centre feature-view">
          <div class="page-heading"><h1 id="command-title">Command centre</h1><p>Your assistant, conversations and tools — ready for your direction.</p></div>
          <div class="overview-hud">
            <aside class="telemetry-rail telemetry-rail-left" aria-label="Core and conversation telemetry">
              <section class="telemetry-readout"><h2>Core service</h2><p class="large-value" id="core-status">Loading…</p><p id="core-readiness" class="muted">Checking verified status</p><p id="core-observed" class="muted"></p></section>
              <section class="telemetry-readout"><h2>Conversations</h2><p class="large-value" id="conversation-count">—</p><p class="muted">Available in your private history</p></section>
              <section class="telemetry-readout"><h2>Assistant turns</h2><p class="large-value" id="turn-total">—</p><p class="muted" id="turn-breakdown">Activity totals</p></section>
            </aside>
            <section class="jarvis-presence" id="jarvis-presence" data-state="checking" data-connection="checking" aria-label="Jarvis presence">
              <div class="presence-figure" aria-hidden="true">
                <svg viewBox="0 0 240 240" focusable="false">
                  <circle class="presence-orbit presence-orbit-outer" cx="120" cy="120" r="112"/>
                  <circle class="presence-orbit presence-orbit-inner" cx="120" cy="120" r="94"/>
                  <circle class="presence-orbit presence-orbit-reactor" cx="120" cy="120" r="76"/>
                  <circle class="presence-core" cx="120" cy="120" r="57"/>
                  <path class="presence-axis" d="M120 2v12m0 212v12M2 120h12m212 0h12"/>
                  <circle class="presence-node" cx="120" cy="4" r="2.5"/>
                  <circle class="presence-node" cx="236" cy="120" r="2.5"/>
                  <circle class="presence-node" cx="120" cy="236" r="2.5"/>
                  <circle class="presence-node" cx="4" cy="120" r="2.5"/>
                </svg>
                <span class="presence-core-label">J.A.R.V.I.S.<small>PERSONAL CORE</small></span>
              </div>
              <div class="presence-copy">
                <h2>At your service.</h2>
                <p id="jarvis-presence-state" role="status" aria-live="polite">Checking the secure connection</p>
                <div class="presence-connection"><span class="presence-connection-dot" aria-hidden="true"></span><span>SECURE CHANNEL</span><strong id="jarvis-presence-connection">Checking access…</strong></div>
              </div>
            </section>
            <aside class="telemetry-rail telemetry-rail-right" aria-label="Recorded activity telemetry">
              <section class="telemetry-readout"><h2>Active turns</h2><p class="large-value" id="turn-active">—</p><p class="muted" id="last-turn">Last turn not available</p></section>
              <section class="telemetry-readout activity-readout"><h2>Turns · last 7 days</h2><p class="muted" id="chart-caption">Loading recorded activity…</p><div id="turn-chart" role="list" aria-label="Assistant turns in the last seven days"></div></section>
            </aside>
          </div>
          <section class="command-panel" aria-labelledby="command-title">
            <div class="command-intro"><span class="command-kicker">YOUR COMMAND</span><span>Private owner workspace</span></div>
            <form id="overview-command-form" class="command-form">
              <label class="visually-hidden" for="overview-command-input">Ask Jarvis</label>
              <textarea id="overview-command-input" rows="1" maxlength="8000" placeholder="Ask Jarvis anything…" autocomplete="off" autocapitalize="sentences" enterkeyhint="send" aria-describedby="overview-command-hint"></textarea>
              <button type="submit"><span>Send to Jarvis</span><span aria-hidden="true">↑</span></button>
            </form>
            <p id="overview-command-hint" class="command-hint">Enter to send · Shift + Enter for a new line. Suggestions fill the message and wait for you to send.</p>
            <p id="overview-command-status" class="command-hint" role="status" aria-live="polite" hidden></p>
            <div class="quick-actions" aria-label="Suggested commands">
              <button type="button" id="overview-new-conversation"><span aria-hidden="true">＋</span> New conversation</button>
              <button type="button" data-command-prompt="Review my pending missions and explain what is awaiting execution."><span aria-hidden="true">◇</span> Review pending missions</button>
              <button type="button" data-command-prompt="Summarize my recent Jarvis activity and its available source evidence."><span aria-hidden="true">⌁</span> Summarize recent activity</button>
              <button type="button" data-command-prompt="Help me find the right installed skill or tool for this task: "><span aria-hidden="true">⌘</span> Find a skill or tool</button>
              <button type="button" data-command-prompt="Review the current status of my configured integrations and report anything unavailable. Do not change their configuration."><span aria-hidden="true">↗</span> Check integrations</button>
            </div>
          </section>
        </div>
      </main>
      <section class="data-main" id="capabilities-view" aria-label="Capabilities" data-view-panel="capabilities" hidden>
        <div class="page-heading"><span class="eyebrow">BUNDLED INVENTORY</span><h1>Capabilities</h1><p>Search the fixed offline catalog. Bundled items are declarations, not proof that a resource is enabled or working.</p></div>
        <div id="capability-readiness" class="readiness-banner" role="status">Loading verified capability inventory…</div>
        <p class="capability-state-guide"><strong>Bundled</strong> means declared in the verified catalog. <strong>Discovered</strong> means observed in the source-bound Core inventory. Neither means <strong>ready</strong>; this view does not verify that a capability operates.</p>
        <div class="capability-filters">
          <label for="capability-search">Search inventory</label>
          <input id="capability-search" type="search" autocomplete="off" placeholder="Search names, IDs, and descriptions">
          <label for="capability-kind">Type</label>
          <select id="capability-kind"><option value="">All types</option></select>
          <p id="capability-count" role="status" aria-live="polite">Waiting for inventory…</p>
        </div>
        <section class="catalog-map" aria-labelledby="catalog-map-title">
          <div class="catalog-map-heading"><h2 id="catalog-map-title">Catalog by type</h2><p>Counts come from the verified offline catalog. Select a type to filter the inventory.</p></div>
          <div id="capability-map" class="capability-map" aria-label="Catalog entries grouped by type"></div>
        </section>
        <p id="capability-source" class="muted capability-source"></p>
        <div id="capability-discovery" class="readiness-banner" role="status"></div>
        <div id="capability-list" class="capability-list" aria-live="polite"></div>
        <div id="capability-details-root">__JARVIS_CAPABILITY_DETAILS__</div>
      </section>
      <section class="data-main" id="settings-view" aria-label="Settings" data-view-panel="settings" hidden>
        <div class="page-heading"><span class="eyebrow">CONFIGURATION</span><h1>Settings</h1><p>Verified configuration labels and read-only integration status.</p></div>
        <section class="data-card settings-card"><h2>Assistant runtime</h2><dl id="settings-list" class="settings-list"><div><dt>Status</dt><dd>Loading verified configuration…</dd></div></dl><p class="muted">Configured model labels do not prove account authentication or the route selected for an individual reply. Secure settings changes are not available here.</p></section>
        <section class="data-card voice-settings-card"><h2>Voice preferences</h2>
          <p class="muted">Optional browser features. Text chat remains available on every device.</p>
          <h3 class="voice-group-title">Speech input</h3>
          <label class="voice-choice" id="speech-consent-row" hidden><input id="speech-consent" type="checkbox"><span><strong>Allow browser voice input on this page</strong><small>Push-to-talk or foreground wake listening may process audio through your browser or platform speech service outside Jarvis. Audio is not sent to the Jarvis chat service. Availability and processing depend on your browser.</small></span></label>
          <label class="voice-choice voice-select-row" id="speech-language-row"><span><strong>Recognition language</strong><select id="speech-language" aria-label="Speech recognition language"><option value="en-US">English (United States)</option><option value="en-GB">English (United Kingdom)</option><option value="pt-PT">Português (Portugal)</option><option value="pt-BR">Português (Brasil)</option><option value="es-ES">Español (España)</option><option value="fr-FR">Français</option><option value="de-DE">Deutsch</option><option value="it-IT">Italiano</option></select><small>Applies to the next push-to-talk capture. The browser or operating system chooses the microphone; manage the input device there.</small></span></label>
          <p class="voice-unavailable" id="speech-unavailable" hidden></p>
          <h3 class="voice-group-title">Speech output</h3>
          <label class="voice-choice" id="speech-output-row" hidden><input id="speech-output" type="checkbox"><span><strong>Read completed replies aloud</strong><small>Uses voices available from your browser or operating system; selected voices may use their platform speech service. No separate Jarvis TTS provider is used. Replies are spoken only after Jarvis finishes.</small></span></label>
          <label class="voice-choice voice-select-row" id="speech-voice-row" hidden><span><strong>Speech voice</strong><select id="speech-voice" aria-label="Speech voice"></select></span></label>
          <div class="voice-range-row" id="speech-tuning-row" hidden><label for="speech-rate"><strong>Speaking rate</strong><output id="speech-rate-value" for="speech-rate">1.0×</output><input id="speech-rate" type="range" min="0.5" max="2" step="0.1" value="1"></label><label for="speech-pitch"><strong>Voice pitch</strong><output id="speech-pitch-value" for="speech-pitch">1.0</output><input id="speech-pitch" type="range" min="0" max="2" step="0.1" value="1"></label></div>
          <p class="voice-unavailable" id="speech-voice-status" role="status" aria-live="polite" hidden></p>
          <p class="voice-unavailable" id="speech-output-unavailable" hidden></p>
          <h3 class="voice-group-title">Appearance</h3>
          <div class="voice-range-row appearance-preferences"><label for="ui-density"><strong>Layout density</strong><select id="ui-density"><option value="comfortable">Comfortable</option><option value="compact">Compact</option></select></label><label for="ui-text-size"><strong>Text size</strong><select id="ui-text-size"><option value="normal">Default</option><option value="large">Large</option></select></label><label for="ui-motion"><strong>Motion</strong><select id="ui-motion"><option value="system">Follow device setting</option><option value="reduce">Reduce motion</option><option value="full">Full motion · override device</option></select></label></div>
          <p class="muted">Voice output and appearance choices are stored only in this browser on this device. Microphone permission and voice-input consent are never saved; voice input must be enabled again each time.</p>
          <p class="voice-unavailable" id="preference-storage-status" role="status" aria-live="polite" hidden></p>
          <p class="voice-unavailable" id="voice-settings-status" role="status" aria-live="polite" hidden></p>
        </section>
      </section>
      <!-- JARVIS_FEATURE_PANELS -->
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
.primary-nav{display:flex;align-items:center;gap:4px;margin-left:24px}.nav-item{min-height:36px;padding:0 12px;border:1px solid transparent;border-radius:9px;background:transparent;color:#9ab1b5;font:inherit;font-size:12px;cursor:pointer}.nav-item:hover,.nav-item[aria-current="page"]{border-color:var(--line);background:rgba(88,228,235,.08);color:#ddfbfd}.workspace>.data-main{grid-column:2;grid-row:1}.data-main{min-width:0;overflow:auto;padding:40px clamp(20px,5vw,76px)}.data-main[hidden],.chat-main[hidden]{display:none}.page-heading{max-width:1080px;margin:0 auto 26px}.page-heading h1{margin:0;font-size:clamp(25px,3vw,34px);font-weight:550;letter-spacing:-.03em}.page-heading p,.muted{color:#8ba5aa;font-size:13px;line-height:1.6}.page-heading p{margin:8px 0}.dashboard-grid{max-width:1080px;margin:0 auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.data-card{min-width:0;padding:21px;border:1px solid var(--line);border-radius:15px;background:rgba(12,31,38,.78)}.data-card h2{margin:0;color:#acc2c6;font-size:13px;font-weight:600}.large-value{margin:14px 0 3px;color:#e6fbfc;font-size:29px;font-weight:550;letter-spacing:-.03em}.data-card .muted{margin:5px 0}.chart-card{grid-column:1/-1}.chart-bars{height:175px;display:grid;grid-template-columns:repeat(7,minmax(24px,1fr));align-items:end;gap:10px;margin:22px 4px 0;border-bottom:1px solid var(--line-strong)}.chart-day{height:100%;display:flex;flex-direction:column;align-items:center;justify-content:flex-end;gap:7px;color:#88a2a7;font-size:10px}.chart-bar-track{height:124px;width:100%;display:flex;align-items:flex-end;justify-content:center}.chart-bar{width:min(35px,72%);min-height:2px;border-radius:5px 5px 1px 1px;background:linear-gradient(0deg,#137c88,#56dbe2)}.readiness-banner{max-width:1080px;margin:0 auto 16px;padding:14px 17px;border:1px solid rgba(245,194,117,.25);border-radius:12px;background:rgba(106,76,31,.12);color:#e7cca0;font-size:13px;line-height:1.6}.capability-filters{max-width:1080px;margin:0 auto 12px;display:grid;grid-template-columns:auto minmax(180px,1fr) auto minmax(150px,.35fr);align-items:center;gap:8px 12px}.capability-filters label{color:#9eb5b9;font-size:12px}.capability-filters input,.capability-filters select{min-width:0;min-height:40px;padding:8px 11px;border:1px solid var(--line-strong);border-radius:9px;background:#0c1f26;color:var(--text);font:inherit;font-size:13px}.capability-filters input:focus-visible,.capability-filters select:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}.capability-filters p{grid-column:1/-1;margin:0;color:#8ba5aa;font-size:12px}.capability-source{max-width:1080px;margin:0 auto 12px;overflow-wrap:anywhere}.capability-row summary{cursor:pointer;color:#d7edef;font-weight:600}.capability-meta{margin-top:10px;color:#8ba5aa;font-size:11px;overflow-wrap:anywhere}.feature-view{max-width:1120px;margin:0 auto}.capability-list{max-width:1080px;margin:auto;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.capability-row{padding:16px;border:1px solid var(--line);border-radius:12px;background:rgba(12,31,38,.66)}.capability-row h2{margin:0 0 6px;font-size:14px;font-weight:600}.capability-row p{margin:0;color:#8ba5aa;font-size:12px;line-height:1.6}.state-pill{display:inline-block;margin-top:11px;padding:4px 8px;border:1px solid var(--line);border-radius:999px;color:#abc2c5;font-size:10px;text-transform:capitalize}.settings-card{max-width:720px;margin:0 auto}.voice-settings-card{max-width:720px;margin:16px auto 0}.voice-choice{display:flex;align-items:flex-start;gap:12px;padding:15px 0;border-bottom:1px solid var(--line);cursor:pointer}.voice-choice input{width:18px;height:18px;margin:1px 0 0;accent-color:#42c6d0}.voice-choice span{display:grid;gap:5px}.voice-choice strong{font-size:13px;font-weight:600}.voice-choice small{max-width:560px;color:#8ba5aa;font-size:12px;line-height:1.55}.voice-select-row select{min-height:38px;min-width:min(280px,75vw);padding:7px 10px;border:1px solid var(--line-strong);border-radius:8px;background:#0c1f26;color:var(--text);font:inherit}.voice-unavailable,.voice-status{color:#95b1b5;font-size:11px;line-height:1.5}.voice-status{margin:5px 3px}.voice-button{min-height:34px;padding:0 11px;border:1px solid var(--line-strong);border-radius:9px;background:rgba(105,169,180,.08);color:#c9e5e8;font:inherit;font-size:11px;cursor:pointer}.voice-button:hover{border-color:var(--cyan);background:rgba(29,139,150,.22)}.voice-button:disabled{opacity:.55;cursor:wait}.voice-button[hidden]{display:none}.voice-button[data-listening="true"]{border-color:#83d7bd;color:#b9f5e1}.settings-list{margin:18px 0;display:grid;gap:0}.settings-list>div{display:flex;justify-content:space-between;gap:20px;padding:14px 0;border-bottom:1px solid var(--line)}.settings-list dt{color:#8ba5aa;font-size:13px}.settings-list dd{margin:0;text-align:right;color:#e1f4f5;font-size:13px;overflow-wrap:anywhere}
@media(max-width:760px){.topbar{height:auto;min-height:64px;flex-wrap:wrap;padding-block:8px}.primary-nav{order:3;width:100%;margin:0;justify-content:space-around}.nav-item{flex:1;padding-inline:6px}.connection{margin-left:auto}.conversation-panel{top:calc(112px + env(safe-area-inset-top))}.scrim:not([hidden]){inset:calc(104px + env(safe-area-inset-top)) 0 0}.workspace{min-height:0}.workspace>.data-main{grid-column:1;grid-row:1}.data-main{padding:26px 16px calc(20px + env(safe-area-inset-bottom))}.dashboard-grid,.capability-list{grid-template-columns:1fr}.capability-filters{grid-template-columns:1fr 1fr}.capability-filters label:nth-of-type(2){grid-column:1}.capability-filters select{grid-column:2;grid-row:2}.chart-card{grid-column:auto}.data-card{padding:17px}.chart-bars{gap:5px}.settings-list>div{gap:12px}}
@media(prefers-reduced-motion:reduce){.nav-item{transition:none}}
/* Jarvis HUD: restrained cyan glass with amber reserved for attention states. */
:root{--amber:#e9bd70;--amber-soft:rgba(233,189,112,.16);--ease-out:cubic-bezier(.23,1,.32,1)}
.app-shell{background:radial-gradient(ellipse at 64% 22%,rgba(18,103,118,.11),transparent 48%),var(--bg)}
.topbar{background:rgba(5,17,22,.88);border-bottom-color:rgba(102,188,202,.18)}
.chat-main{background:radial-gradient(ellipse at 75% 22%,rgba(30,119,131,.055),transparent 52%)}
.chat-heading{align-items:center;justify-content:space-between;gap:20px}
.assistant-hud{display:flex;align-items:center;gap:12px;min-width:190px;padding:8px 13px 8px 9px;border:1px solid rgba(97,190,203,.17);border-radius:16px;background:linear-gradient(135deg,rgba(17,49,58,.72),rgba(9,25,32,.74));box-shadow:inset 0 1px rgba(255,255,255,.035)}
.assistant-orb{position:relative;display:grid;place-items:center;flex:none;width:44px;height:44px;border-radius:50%;isolation:isolate}
.orb-core,.orb-ring,.orb-halo{position:absolute;border-radius:50%;pointer-events:none}
.orb-core{inset:12px;background:radial-gradient(circle at 38% 32%,#e8ffff,#66dbe3 38%,#0d8d99 72%,#092830);box-shadow:0 0 15px rgba(73,218,226,.44),inset 0 0 7px rgba(234,255,255,.55)}
.orb-ring{inset:5px;border:1px solid rgba(114,235,239,.56);box-shadow:0 0 10px rgba(53,204,215,.16),inset 0 0 9px rgba(53,204,215,.08)}
.orb-halo{inset:0;border:1px solid rgba(102,196,207,.2)}
.assistant-state{display:grid;gap:4px;min-width:0}
.assistant-state strong{color:#a6c7c8;font:600 9px/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.16em}
.assistant-state span{color:#e5f3f3;font-size:11px;line-height:1.35}
.assistant-hud[data-state="listening"]{border-color:rgba(233,189,112,.48);background:linear-gradient(135deg,rgba(80,61,35,.35),rgba(9,25,32,.82))}
.assistant-hud[data-state="listening"] .orb-core{background:radial-gradient(circle at 38% 32%,#fff7df,#e9bd70 45%,#92703e 78%,#332717);box-shadow:0 0 15px rgba(233,189,112,.36)}
.assistant-hud[data-state="listening"] .orb-ring,.assistant-hud[data-state="error"] .orb-ring{border-color:rgba(233,189,112,.78)}
.assistant-hud[data-state="listening"] .assistant-state strong,.assistant-hud[data-state="error"] .assistant-state strong{color:var(--amber)}
.assistant-hud[data-state="busy"] .orb-halo{animation:jarvis-orb-breathe 1.35s ease-in-out infinite}
.assistant-hud[data-state="speaking"] .orb-core{box-shadow:0 0 20px rgba(73,218,226,.72),inset 0 0 7px rgba(234,255,255,.7)}
.assistant-hud[data-state="error"]{border-color:rgba(233,189,112,.48)}
.welcome-orbit[data-state="listening"]{border-color:rgba(233,189,112,.56);box-shadow:0 0 40px rgba(233,189,112,.11),inset 0 0 24px rgba(233,189,112,.08)}
.welcome-orbit[data-state="listening"]:before,.welcome-orbit[data-state="error"]:before{border-color:rgba(233,189,112,.72)}
.welcome-orbit[data-state="listening"]:after,.welcome-orbit[data-state="error"]:after{border-color:rgba(233,189,112,.9)}
.welcome-orbit[data-state="listening"] span{background:var(--amber);box-shadow:0 0 20px rgba(233,189,112,.82)}
.welcome-orbit[data-state="speaking"] span{box-shadow:0 0 27px rgba(88,228,235,.95)}
.welcome-orbit[data-state="busy"]:after{animation:jarvis-orb-breathe 1.35s ease-in-out infinite}
@media(prefers-reduced-motion:reduce){.welcome-orbit[data-state="busy"]:after{animation:none;opacity:.72}}
@keyframes jarvis-orb-breathe{0%,100%{opacity:.36}50%{opacity:1}}
.data-card{border-color:rgba(102,188,202,.18);background:linear-gradient(145deg,rgba(15,40,48,.84),rgba(8,24,31,.88));box-shadow:inset 0 1px rgba(255,255,255,.035),0 14px 40px rgba(0,0,0,.12)}
.data-card h2{color:#bed3d4;letter-spacing:.015em}
.readiness-banner{border-color:rgba(233,189,112,.25);background:linear-gradient(110deg,rgba(83,64,37,.19),rgba(25,32,30,.18));color:#ead5ad}
.composer{border-color:rgba(99,192,204,.25);background:rgba(9,27,34,.9);box-shadow:0 12px 36px rgba(0,0,0,.15),inset 0 1px rgba(255,255,255,.04)}
.composer:focus-within{border-color:rgba(91,222,230,.62);box-shadow:0 0 0 3px rgba(88,228,235,.08),0 12px 36px rgba(0,0,0,.18)}
.nav-item,.icon-button,.new-chat-button,.send-button,.stop-button,.voice-button{transition:transform 140ms var(--ease-out),color 140ms ease,background-color 140ms ease,border-color 140ms ease}
.icon-button{min-width:42px;min-height:42px}.send-button,.stop-button,.voice-button{min-height:44px}.composer textarea{line-height:1.5}
.nav-item{min-height:44px}.nav-item[aria-current="page"]{border-color:rgba(88,228,235,.42);background:linear-gradient(135deg,rgba(24,129,140,.22),rgba(15,68,77,.2));color:#e4feff;box-shadow:inset 0 0 0 1px rgba(88,228,235,.06)}
.nav-item:active,.icon-button:active,.new-chat-button:active,.send-button:active,.stop-button:active,.voice-button:active{transform:scale(.97)}
:focus-visible{outline:2px solid var(--cyan);outline-offset:3px}
.session-search-label{display:block;margin:18px 8px 7px;color:#91aeb2;font-size:11px;font-weight:600}
.session-search{width:100%;min-height:44px;padding:9px 11px;border:1px solid var(--line-strong);border-radius:10px;background:rgba(6,20,26,.82);color:var(--text);font:inherit;font-size:14px}
.session-search:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.session-count{margin:8px 9px;color:#78969b;font-size:10px;line-height:1.4}
.conversation-list{min-height:0}
.catalog-map{max-width:1080px;margin:0 auto 15px;padding:16px;border:1px solid rgba(102,188,202,.15);border-radius:13px;background:rgba(9,27,34,.58)}
.catalog-map-heading h2{margin:0;color:#bed3d4;font-size:13px;font-weight:600}
.catalog-map-heading p{margin:5px 0 12px;color:#8ba5aa;font-size:11px;line-height:1.5}
.capability-map{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));gap:8px}
.capability-state-guide{max-width:1080px;margin:-5px auto 16px;color:#9ab2b6;font-size:11px;line-height:1.55}
.capability-state-guide strong{color:#d3e7e8;font-weight:650}
.capability-kind{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:8px 12px;align-items:center;min-width:0;min-height:58px;padding:9px 11px;border:1px solid rgba(102,188,202,.16);border-radius:10px;background:rgba(14,41,49,.66);color:#d5edef;text-align:left;cursor:pointer}
.capability-kind:hover,.capability-kind[aria-pressed="true"]{border-color:rgba(88,228,235,.56);background:rgba(25,104,114,.22)}
.capability-kind-name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;font-weight:600}
.capability-kind-count{color:#93b4b8;font-size:10px;font-variant-numeric:tabular-nums}
.capability-kind-track{grid-column:1/-1;display:block;height:4px;overflow:hidden;border-radius:999px;background:rgba(117,166,174,.14)}
.capability-kind-fill{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#137c88,#56dbe2)}
.voice-group-title{margin:18px 0 0;padding-top:12px;border-top:1px solid var(--line);color:#a9c4c7;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}
.voice-group-title:first-of-type{border-top:0;padding-top:0}
@media(hover:hover) and (pointer:fine){.data-card{transition:border-color 160ms ease}.data-card:hover{border-color:rgba(102,188,202,.3)}}
@media(min-width:761px) and (max-width:1120px){.topbar{height:auto;min-height:72px;flex-wrap:wrap;padding-block:9px}.primary-nav{order:3;flex:1 1 100%;width:100%;margin:0;overflow-x:auto;scrollbar-width:thin}.nav-item{flex:0 0 auto}.workspace{min-height:0}}
@media(max-width:760px){
 .chat-heading{gap:10px}.chat-heading h1{max-width:42vw;font-size:clamp(17px,4.5vw,22px)}
 .assistant-hud{min-width:0;padding:6px 9px 6px 6px;gap:8px;border-radius:14px}
 .assistant-orb{width:38px;height:38px}.orb-core{inset:11px}.orb-ring{inset:4px}
 .assistant-state strong{font-size:8px}.assistant-state span{max-width:110px;font-size:10px}
 .workspace{padding-bottom:calc(66px + env(safe-area-inset-bottom))}
 .primary-nav{position:fixed;z-index:12;left:50%;bottom:calc(7px + env(safe-area-inset-bottom));order:0;width:min(calc(100% - 20px),540px);height:58px;margin:0;padding:5px;justify-content:flex-start;gap:3px;overflow-x:auto;overscroll-behavior-inline:contain;scroll-snap-type:x proximity;transform:translateX(-50%);border:1px solid rgba(111,203,214,.2);border-radius:17px;background:rgba(7,23,30,.95);box-shadow:0 12px 32px rgba(0,0,0,.4),inset 0 1px rgba(255,255,255,.05);backdrop-filter:blur(16px) saturate(125%);scrollbar-width:none}
 .primary-nav::-webkit-scrollbar{display:none}
 .nav-item{flex:0 0 auto;min-width:64px;min-height:46px;padding:0 9px;scroll-snap-align:center}
 .conversation-panel{top:calc(64px + env(safe-area-inset-top));bottom:calc(66px + env(safe-area-inset-bottom))}
 .composer-actions{flex-wrap:wrap;gap:7px}.composer-hint{flex:1 1 100%;margin-right:0}
 .scrim:not([hidden]){inset:calc(64px + env(safe-area-inset-top)) 0 calc(66px + env(safe-area-inset-bottom))}
}
@media(max-width:390px){.assistant-hud{padding-right:7px}.assistant-state span{max-width:88px}.nav-item{min-width:60px;padding-inline:7px}}
@media(prefers-reduced-motion:reduce){.assistant-hud[data-state="busy"] .orb-halo{animation:none;opacity:.72}.nav-item,.icon-button,.new-chat-button,.send-button,.stop-button,.voice-button,.data-card{transition:none}}
@media(prefers-reduced-transparency:reduce){.topbar,.primary-nav,.data-card,.assistant-hud,.composer{backdrop-filter:none;background-color:#0a1d25}}
@media(prefers-contrast:more){.assistant-hud,.data-card,.primary-nav,.composer{border-color:currentColor}}
.voice-range-row{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;padding:14px 0;border-bottom:1px solid var(--line)}.voice-range-row label{display:grid;grid-template-columns:1fr auto;align-items:center;gap:9px;color:#c4d8da;font-size:12px}.voice-range-row label strong{font-size:12px;font-weight:600}.voice-range-row output{color:var(--cyan);font-variant-numeric:tabular-nums}.voice-range-row input[type="range"]{grid-column:1/-1;width:100%;accent-color:var(--cyan);min-height:32px}.voice-range-row select{grid-column:1/-1;min-width:0;min-height:42px;padding:8px 10px;border:1px solid var(--line-strong);border-radius:9px;background:#0c1f26;color:var(--text);font:inherit}.voice-select-row small{max-width:600px;color:#8ba5aa;font-size:11px;line-height:1.5}.appearance-preferences label{align-items:start}.appearance-preferences select{grid-row:2}.appearance-preferences label strong{grid-row:1}
html[data-jarvis-density="compact"] .data-card{padding:15px}html[data-jarvis-density="compact"] .message-list{gap:14px}html[data-jarvis-density="compact"] .voice-choice{padding-block:10px}html[data-jarvis-density="compact"] .settings-list>div{padding-block:10px}
html[data-jarvis-text-size="large"] .message-content{font-size:16px}html[data-jarvis-text-size="large"] .data-main{font-size:1.08rem}html[data-jarvis-text-size="large"] .voice-choice strong,html[data-jarvis-text-size="large"] .settings-list dt,html[data-jarvis-text-size="large"] .settings-list dd{font-size:15px}
html[data-jarvis-motion="reduce"] *,html[data-jarvis-motion="reduce"] *::before,html[data-jarvis-motion="reduce"] *::after{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}
@media(max-width:600px){.voice-range-row{grid-template-columns:1fr}.voice-range-row label{min-height:52px}.voice-range-row input[type="range"]{min-height:40px}}
/* Overview is the owner home; the searchable conversation rail remains local to Chat. */
.primary-nav{position:relative;display:flex;align-items:center;justify-content:center;gap:2px;flex:1 1 0;min-width:0;margin-left:8px;overflow:visible}
.nav-group{position:relative;flex:0 0 auto}.nav-group>summary{min-height:44px;display:flex;align-items:center;gap:8px;padding:0 10px;border:1px solid transparent;border-radius:10px;color:#9ab1b5;font-size:11px;white-space:nowrap;list-style:none;cursor:pointer;user-select:none}.nav-group>summary::-webkit-details-marker{display:none}.nav-group>summary:after{content:"";width:6px;height:6px;border-right:1px solid currentColor;border-bottom:1px solid currentColor;transform:rotate(45deg) translateY(-2px);opacity:.7}.nav-group[open]>summary,.nav-group[data-current="true"]>summary{border-color:rgba(88,228,235,.25);background:rgba(88,228,235,.08);color:#ddfbfd}.nav-group>summary:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}
.nav-menu{position:absolute;z-index:30;top:calc(100% + 7px);left:0;width:max-content;min-width:220px;max-width:min(300px,90vw);max-height:min(70dvh,560px);display:grid;gap:3px;overflow:auto;padding:7px;border:1px solid rgba(91,199,211,.3);border-radius:14px;background:rgba(5,22,29,.98);box-shadow:0 18px 48px rgba(0,0,0,.5),inset 0 1px rgba(255,255,255,.04);backdrop-filter:blur(18px)}.nav-group:nth-last-child(-n+2) .nav-menu{left:auto;right:0}.nav-menu .nav-item{width:100%;min-height:44px;display:flex;align-items:center;justify-content:flex-start;padding:0 12px;border-radius:8px;text-align:left;font-size:12px;transition:none}.primary-nav .nav-item{flex:0 0 auto}.nav-item:active{transform:none}
.workspace[data-current-view="chat"]{grid-template-columns:286px minmax(0,1fr)}.workspace[data-current-view]:not([data-current-view="chat"]){display:block}.workspace[data-current-view]:not([data-current-view="chat"])>.conversation-panel{display:none}.workspace[data-current-view]:not([data-current-view="chat"])>.chat-main{display:none}.workspace[data-current-view]:not([data-current-view="chat"])>.data-main{width:100%;height:100%;padding:clamp(20px,4vw,48px)}.assistant-hud{flex:0 0 auto;min-width:168px;padding:6px 10px 6px 6px;gap:8px;border-radius:14px}.assistant-orb{width:42px;height:42px}.orb-core{inset:11px}.orb-ring{inset:4px}.assistant-state strong{font-size:8px}.assistant-state span{max-width:122px;font-size:10px}.assistant-hud[data-state="thinking"] .orb-halo{animation:jarvis-orb-breathe 2.4s linear infinite}.assistant-hud[data-state="idle"] .assistant-state strong{color:#86cfc9}.assistant-hud[data-state="checking"] .orb-halo{opacity:.42}.assistant-hud[data-state="thinking"] .assistant-state strong{color:#91e8ec}.assistant-hud[data-state="error"] .orb-core{background:radial-gradient(circle at 38% 32%,#fff7df,#e9bd70 45%,#92703e 78%,#332717)}
.conversation-model{align-self:center;flex:none;min-height:44px;padding-inline:11px;border-color:rgba(102,188,202,.2);font-size:10px}.command-centre .page-heading{margin-bottom:16px}.command-centre .page-heading h1{font-size:clamp(28px,4vw,42px);font-weight:560;letter-spacing:-.04em}.command-centre .page-heading p{max-width:700px}.command-panel{max-width:1080px;margin:0 auto 20px;padding:clamp(14px,2.5vw,24px);border:1px solid rgba(88,228,235,.28);border-radius:18px;background:radial-gradient(ellipse at 4% 0%,rgba(38,181,193,.15),transparent 55%),linear-gradient(140deg,rgba(13,43,52,.94),rgba(8,23,30,.96));box-shadow:inset 0 1px rgba(255,255,255,.05),0 18px 48px rgba(0,0,0,.17)}.command-intro{display:flex;align-items:center;justify-content:space-between;gap:1rem;color:#8eaaaf;font-size:.72rem}.command-kicker{color:#83d9de;font:600 .65rem/1.2 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.14em}.command-form{display:flex;align-items:flex-end;gap:.6rem;margin-top:.65rem;padding:.55rem;border:1px solid rgba(88,228,235,.34);border-radius:14px;background:rgba(3,17,23,.74)}.command-form textarea{width:100%;min-width:0;min-height:50px;max-height:144px;resize:vertical;padding:.8rem .65rem;border:0;outline:0;background:transparent;color:var(--text);font:inherit;font-size:1rem;line-height:1.5}.command-form textarea::placeholder{color:#708b91}.command-form button{display:flex;align-items:center;justify-content:center;gap:.7rem;min-width:144px;min-height:48px;padding:.65rem .85rem;border:1px solid rgba(93,228,235,.55);border-radius:10px;background:linear-gradient(135deg,#168895,#12626e);color:#efffff;font-size:.82rem;font-weight:650;cursor:pointer}.command-form button:focus-visible,.quick-actions button:focus-visible{outline:2px solid var(--cyan);outline-offset:2px}.command-hint{margin:.6rem .2rem 0;color:#819ca1;font-size:.72rem;line-height:1.55}.quick-actions{display:flex;flex-wrap:wrap;gap:.5rem;margin-top:1rem}.quick-actions button{display:flex;align-items:center;gap:.5rem;min-height:44px;padding:.45rem .8rem;border:1px solid rgba(112,190,199,.2);border-radius:999px;background:rgba(7,29,36,.7);color:#c4dbde;font-size:.76rem;cursor:pointer}.overview-status-strip{max-width:1080px;margin:-5px auto 16px;color:#9ab2b6;font-size:11px;line-height:1.55}.overview-status-strip strong{color:#d3e7e8;font-weight:600}
.chat-preferences{position:relative;align-self:center;margin-left:auto;flex:none}.chat-preferences>summary{min-height:44px;display:flex;align-items:center;gap:9px;padding:0 13px;border:1px solid rgba(102,188,202,.28);border-radius:11px;background:rgba(9,31,38,.84);color:#d7f5f6;font-size:11px;font-weight:600;cursor:pointer;list-style:none}.chat-preferences>summary::-webkit-details-marker{display:none}.chat-preferences>summary:after{content:"";width:6px;height:6px;border-right:1px solid currentColor;border-bottom:1px solid currentColor;transform:rotate(45deg) translateY(-2px);opacity:.75}.chat-preferences>summary:focus-visible,.chat-preferences-panel :focus-visible{outline:2px solid var(--cyan);outline-offset:2px}.chat-preferences-panel{position:fixed;z-index:35;top:88px;right:clamp(12px,4vw,64px);width:min(380px,calc(100vw - 24px));max-height:min(76dvh,680px);overflow:auto;padding:15px 17px 17px;border:1px solid rgba(91,199,211,.38);border-radius:16px;background:#07191f;box-shadow:0 20px 56px rgba(0,0,0,.52),0 8px 22px rgba(8,110,121,.12);overscroll-behavior:contain}.chat-preferences-heading{display:flex;align-items:baseline;justify-content:space-between;gap:10px;padding-bottom:12px;border-bottom:1px solid var(--line)}.chat-preferences-heading h2{margin:0;font-size:15px;font-weight:600}.chat-preferences-heading>span,.chat-preferences-note{color:#a1b9bd;font-size:10px;line-height:1.5}.chat-preferences-note{margin:11px 0 7px}.chat-model-link{width:100%;min-height:44px;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:0 11px;border:1px solid rgba(88,228,235,.27);border-radius:10px;background:rgba(24,102,111,.16);color:#e2fbfc;text-align:left;font:inherit;font-size:12px;cursor:pointer}.chat-model-link span{color:#9ed8dc;font-size:10px}.chat-preference-toggle{min-height:52px;display:flex;align-items:center;gap:11px;border-bottom:1px solid rgba(119,161,167,.13);cursor:pointer}.chat-preference-toggle input{width:18px;height:18px;flex:none;accent-color:#42c6d0}.chat-preference-toggle>span{display:grid;gap:3px}.chat-preference-toggle strong{font-size:12px;font-weight:600}.chat-preference-toggle small{color:#a1b9bd;font-size:10px;line-height:1.4}.chat-preference-field{min-height:47px;display:grid;grid-template-columns:1fr minmax(150px,1.2fr);align-items:center;gap:12px;border-bottom:1px solid rgba(119,161,167,.13);color:#c5dadd;font-size:11px}.chat-preference-field select{width:100%;min-height:44px;padding:7px 9px;border:1px solid var(--line-strong);border-radius:8px;background:#0c1f26;color:var(--text);font:inherit;font-size:11px}
@media(min-width:761px) and (max-width:1120px){.primary-nav{order:4;flex:1 1 100%;width:100%;justify-content:flex-start;margin:0}.assistant-hud{margin-left:auto}}
@media(max-width:760px){.topbar{height:auto;min-height:64px;flex-wrap:wrap;gap:8px 10px;padding:8px 12px}.brand{order:1}.assistant-hud{order:2;margin-left:auto;min-width:0;padding:4px 7px 4px 4px;gap:6px}.assistant-orb{width:36px;height:36px}.orb-core{inset:10px}.orb-ring{inset:3px}.assistant-state strong{font-size:7px;letter-spacing:.11em}.assistant-state span{max-width:96px;font-size:9px}.connection{order:3;margin-left:0;font-size:10px}.primary-nav{position:fixed;z-index:12;left:50%;bottom:calc(7px + env(safe-area-inset-bottom));order:4;width:min(calc(100% - 20px),540px);height:58px;margin:0;padding:5px;justify-content:space-between;gap:2px;overflow-x:auto;overscroll-behavior-inline:contain;transform:translateX(-50%);border:1px solid rgba(111,203,214,.2);border-radius:17px;background:rgba(7,23,30,.96);box-shadow:0 12px 32px rgba(0,0,0,.4),inset 0 1px rgba(255,255,255,.05);backdrop-filter:blur(16px) saturate(125%);scrollbar-width:none}.primary-nav::-webkit-scrollbar{display:none}.nav-group{flex:1 0 auto}.nav-group>summary{min-height:46px;justify-content:center;padding-inline:7px;font-size:9px;gap:5px}.nav-group>summary:after{width:5px;height:5px}.nav-menu,.nav-group:nth-last-child(-n+2) .nav-menu{position:fixed;left:10px;right:10px;top:auto;bottom:calc(76px + env(safe-area-inset-bottom));width:auto;max-width:none;max-height:min(64dvh,520px);padding:9px;border-radius:16px}.workspace{padding-bottom:calc(68px + env(safe-area-inset-bottom))}.workspace[data-current-view="chat"]{grid-template-columns:minmax(0,1fr)}.conversation-panel{top:calc(96px + env(safe-area-inset-top));bottom:calc(66px + env(safe-area-inset-bottom))}.chat-heading{flex-wrap:wrap}.conversation-model{width:100%;justify-content:flex-start;text-align:left}.chat-preferences{margin-left:0}.chat-preferences-panel{top:calc(74px + env(safe-area-inset-top));right:10px;width:min(380px,calc(100vw - 20px));max-height:min(72dvh,620px);padding:13px}.command-form{align-items:stretch;flex-direction:column}.command-form button{width:100%}.quick-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.quick-actions button{justify-content:flex-start;padding-inline:.65rem;font-size:.69rem}.workspace[data-current-view]:not([data-current-view="chat"])>.data-main{padding:20px 16px calc(85px + env(safe-area-inset-bottom))}}
@media(max-width:390px){.brand-copy small{display:none}.assistant-state span{max-width:80px}.nav-group>summary{padding-inline:5px;font-size:8px}.command-centre .page-heading h1{font-size:26px}}
@media(hover:hover) and (pointer:fine){.command-form button,.quick-actions button{transition:filter 140ms ease,border-color 140ms ease,background-color 140ms ease}.command-form button:hover{filter:brightness(1.13);border-color:var(--cyan)}.quick-actions button:hover{border-color:rgba(88,228,235,.48);background:rgba(18,76,85,.68);color:#f2ffff}}
@media(prefers-reduced-motion:reduce){.assistant-hud[data-state="thinking"] .orb-halo{animation:none;opacity:.72}.nav-group>summary,.nav-menu .nav-item,.command-form button,.quick-actions button{transition:none}}
@media(prefers-contrast:more){.nav-group>summary,.nav-menu,.command-panel{border-color:currentColor}}
.jarvis-presence{position:relative;max-width:1080px;min-height:236px;margin:0 auto 18px;display:grid;grid-template-columns:220px minmax(0,1fr);align-items:center;gap:clamp(22px,5vw,58px);overflow:hidden;padding:20px clamp(20px,5vw,52px);border:1px solid rgba(86,210,221,.25);border-radius:20px;background:radial-gradient(ellipse at 15% 52%,rgba(21,139,153,.16),transparent 43%),linear-gradient(112deg,#0a252d,#08191f 68%);box-shadow:inset 0 1px rgba(226,255,255,.045),0 16px 42px rgba(0,0,0,.2)}.jarvis-presence:after{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(112deg,transparent 38%,rgba(102,208,218,.025) 70%,transparent);opacity:.9}.presence-figure{position:relative;z-index:1;width:210px;height:210px;display:grid;place-items:center;filter:drop-shadow(0 14px 24px rgba(0,0,0,.2))}.presence-figure:before{content:"";position:absolute;inset:23px;border-radius:50%;background:radial-gradient(circle,rgba(54,210,222,.17),rgba(34,143,155,.065) 55%,transparent 72%);transition:transform .45s var(--ease-out),opacity .45s var(--ease-out)}.presence-figure svg{position:relative;width:100%;height:100%;overflow:visible}.presence-orbit,.presence-face,.presence-brow,.presence-jaw,.presence-axis{fill:none;stroke:rgba(103,225,232,.62);stroke-width:1.2;vector-effect:non-scaling-stroke}.presence-orbit-outer{stroke-dasharray:2 7;opacity:.66}.presence-orbit-inner{stroke:rgba(81,205,217,.22);stroke-dasharray:48 9 3 10}.presence-face{stroke-width:1.5;stroke:rgba(150,244,246,.84);filter:drop-shadow(0 0 4px rgba(74,219,228,.3))}.presence-brow,.presence-jaw{stroke-width:1.35;stroke:rgba(91,220,230,.75)}.presence-axis{stroke:rgba(82,199,211,.5)}.presence-node{fill:#c3ffff;filter:drop-shadow(0 0 4px rgba(82,229,237,.8))}.presence-copy{position:relative;z-index:1;max-width:540px}.presence-kicker{margin:0 0 12px;color:#83e0e5;font:600 10px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.15em}.presence-kicker span{color:#94adb2;font:500 9px/1.3 Inter,ui-sans-serif,system-ui,sans-serif;letter-spacing:.1em}.presence-copy h2{margin:0;color:#f0fcfc;font-size:clamp(28px,4vw,42px);font-weight:520;letter-spacing:-.04em}.presence-copy>p:not(.presence-kicker){margin:9px 0 19px;color:#b5cccf;font-size:14px;line-height:1.5}.presence-connection{display:grid;grid-template-columns:9px auto 1fr;align-items:center;gap:8px;color:#85a6ab;font-size:9px;letter-spacing:.12em}.presence-connection strong{justify-self:start;margin-left:7px;padding:6px 9px;border:1px solid rgba(93,183,194,.2);border-radius:7px;color:#bcd5d8;font-size:10px;letter-spacing:0;font-weight:550}.presence-connection-dot{width:7px;height:7px;border-radius:50%;background:#83979a}.jarvis-presence[data-state="idle"] .presence-connection-dot,.jarvis-presence[data-state="listening"] .presence-connection-dot,.jarvis-presence[data-state="thinking"] .presence-connection-dot,.jarvis-presence[data-state="speaking"] .presence-connection-dot{background:#66e3e6;box-shadow:0 0 9px rgba(88,228,235,.55)}.jarvis-presence[data-state="error"] .presence-connection-dot{background:var(--amber);box-shadow:0 0 8px rgba(233,189,112,.5)}.jarvis-presence[data-state="thinking"] .presence-figure:before{transform:scale(1.08);opacity:.84}.jarvis-presence[data-state="listening"] .presence-figure:before{transform:scale(1.04);opacity:1}.jarvis-presence[data-state="speaking"] .presence-orbit-outer{stroke-dasharray:12 5;opacity:.95}.jarvis-presence[data-state="error"] .presence-face,.jarvis-presence[data-state="error"] .presence-brow,.jarvis-presence[data-state="error"] .presence-jaw{stroke:rgba(233,189,112,.76)}
@keyframes presence-turn{to{transform:rotate(1turn)}}@keyframes presence-listen{50%{opacity:.32}}.jarvis-presence[data-state="thinking"] .presence-orbit-inner{transform-box:view-box;transform-origin:120px 120px;animation:presence-turn 24s linear infinite}.jarvis-presence[data-state="listening"] .presence-orbit-outer{animation:presence-listen 1.8s ease-in-out infinite}
.chat-preference-tuning{display:grid;grid-template-columns:1fr 1fr;gap:12px;border-bottom:1px solid rgba(119,161,167,.13)}.chat-preference-tuning label{min-width:0;min-height:64px;display:grid;grid-template-columns:1fr auto;align-items:center;gap:3px 6px;color:#c5dadd;font-size:10px}.chat-preference-tuning output{color:#8ce5e9;font-variant-numeric:tabular-nums}.chat-preference-tuning input{grid-column:1/-1;width:100%;min-height:44px;accent-color:var(--cyan)}
@media(max-width:760px){.jarvis-presence{grid-template-columns:112px minmax(0,1fr);min-height:164px;gap:14px;margin-bottom:16px;padding:15px 16px;border-radius:16px}.presence-figure{width:112px;height:112px}.presence-figure:before{inset:12px}.presence-copy h2{font-size:clamp(23px,6vw,30px)}.presence-kicker{font-size:8px;letter-spacing:.1em}.presence-kicker span{display:block;margin-top:4px}.presence-copy>p:not(.presence-kicker){margin:6px 0 11px;font-size:12px}.presence-connection{grid-template-columns:8px 1fr;gap:6px;font-size:8px}.presence-connection strong{grid-column:2;margin:0;padding:4px 7px;font-size:9px}}
@media(max-width:420px){.jarvis-presence{grid-template-columns:84px minmax(0,1fr);gap:11px;padding:13px}.presence-figure{width:84px;height:84px}.presence-copy h2{font-size:22px}.presence-copy>p:not(.presence-kicker){font-size:11px}.presence-kicker span{font-size:8px}}
@media(prefers-reduced-motion:reduce){.presence-figure:before{transition:none}.jarvis-presence .presence-orbit-inner,.jarvis-presence .presence-orbit-outer{animation:none}}
.overview-hud{max-width:1200px;min-height:438px;margin:0 auto 14px;display:grid;grid-template-columns:minmax(150px,.8fr) minmax(340px,1.8fr) minmax(190px,.95fr);align-items:center;gap:clamp(14px,2.3vw,30px)}.telemetry-rail{min-width:0;display:grid;align-content:center;gap:13px}.telemetry-readout{min-width:0;padding:12px 0;border-top:1px solid rgba(91,199,211,.22)}.telemetry-readout:last-child{border-bottom:1px solid rgba(91,199,211,.16)}.telemetry-readout h2{margin:0 0 8px;color:#8cb8be;font:600 9px/1.3 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.13em;text-transform:uppercase}.telemetry-readout .large-value{margin:4px 0 3px;color:#e7fcfd;font-size:21px;line-height:1.2;font-weight:560;letter-spacing:-.025em;font-variant-numeric:tabular-nums}.telemetry-readout .muted{margin:4px 0 0;color:#9bb6bb;font-size:10px;line-height:1.5}.telemetry-readout #core-observed{color:#85a6ab;font-size:9px}.telemetry-readout #turn-breakdown{color:#9bb6bb}.activity-readout{align-self:stretch}.activity-readout #chart-caption{min-height:28px}.activity-readout .chart-bars{height:112px;grid-template-columns:repeat(7,minmax(0,1fr));gap:4px;margin:9px 0 0}.activity-readout .chart-day{min-width:0;gap:5px;color:#9bb6bb;font-size:8px}.activity-readout .chart-bar-track{height:72px}.activity-readout .chart-bar{width:min(13px,70%);border-radius:3px 3px 0 0}.jarvis-presence{min-width:0;min-height:420px;margin:0;display:grid;grid-template-columns:minmax(0,1fr);align-content:center;justify-items:center;gap:0;overflow:visible;padding:12px 0;border:0;border-radius:0;background:transparent;box-shadow:none;text-align:center}.jarvis-presence:after{display:none}.presence-figure{width:min(100%,380px);height:auto;aspect-ratio:1;margin:0 auto;filter:drop-shadow(0 16px 32px rgba(0,0,0,.27))}.presence-figure:before{inset:15%;background:radial-gradient(circle,rgba(59,217,228,.23),rgba(16,104,118,.12) 43%,transparent 72%)}.presence-figure svg{display:block;width:100%;height:100%;overflow:visible}.presence-orbit-outer{stroke:rgba(70,216,228,.72);stroke-width:1.3;stroke-dasharray:2 5}.presence-orbit-inner{stroke:rgba(95,220,231,.52);stroke-width:1.5;stroke-dasharray:35 8 5 9}.presence-orbit-reactor{fill:rgba(6,27,34,.83);stroke:rgba(104,229,236,.79);stroke-width:1.3;stroke-dasharray:98 12 12 9}.presence-core{fill:rgba(42,189,202,.09);stroke:rgba(108,234,239,.78);stroke-width:1.1;filter:drop-shadow(0 0 9px rgba(64,220,231,.22))}.presence-axis{stroke:rgba(88,211,221,.48);stroke-width:1.1}.presence-node{fill:#c8ffff;filter:drop-shadow(0 0 5px rgba(82,229,237,.86))}.presence-core-label{position:absolute;left:50%;top:50%;display:grid;gap:6px;transform:translate(-50%,-50%);color:#ddffff;font:550 clamp(13px,1.35vw,17px)/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.2em;text-shadow:0 0 18px rgba(77,230,237,.54);white-space:nowrap}.presence-core-label small{color:#89dbe0;font-size:8px;letter-spacing:.2em}.presence-copy{max-width:500px;margin-top:-17px;text-align:center}.presence-copy h2{font-size:22px;letter-spacing:-.025em}.presence-copy>p:not(.presence-kicker){margin:7px 0 12px;color:#b5d2d5;font-size:12px}.presence-connection{display:inline-grid;grid-template-columns:8px auto auto;gap:8px;padding:0 10px;color:#8db0b5;font-size:8px}.presence-connection strong{margin-left:3px;padding:5px 7px;font-size:9px}.jarvis-presence[data-state="idle"] .presence-orbit-inner{opacity:.76}.jarvis-presence[data-state="thinking"] .presence-orbit-inner{transform-box:view-box;transform-origin:120px 120px;animation:presence-turn 24s linear infinite}.jarvis-presence[data-state="listening"] .presence-orbit-outer{animation:presence-listen 1.8s ease-in-out infinite}.jarvis-presence[data-state="speaking"] .presence-orbit-reactor{stroke-dasharray:22 7;stroke-width:1.9}.jarvis-presence[data-state="error"] .presence-orbit-reactor,.jarvis-presence[data-state="error"] .presence-core{stroke:rgba(233,189,112,.86)}.command-panel{max-width:1200px;margin:10px auto 8px;padding:14px 18px;border:1px solid rgba(89,190,201,.23);border-radius:13px;background:linear-gradient(110deg,rgba(9,30,37,.88),rgba(7,22,29,.84));box-shadow:inset 0 1px rgba(255,255,255,.025)}.command-intro{font-size:10px}.command-kicker{color:#8ddce0;font-size:9px}.command-form{margin-top:9px}.quick-actions{margin-top:10px}.overview-hud+.command-panel{margin-top:8px}
.jarvis-presence[data-connection="ready"] .presence-connection-dot{background:#66e3e6;box-shadow:0 0 9px rgba(88,228,235,.55)}.jarvis-presence[data-connection="error"] .presence-connection-dot{background:var(--amber);box-shadow:0 0 8px rgba(233,189,112,.5)}.jarvis-presence[data-connection="checking"] .presence-connection-dot{background:#83979a;box-shadow:none}
@media(max-width:980px) and (min-width:761px){.overview-hud{grid-template-columns:minmax(125px,.75fr) minmax(300px,1.7fr) minmax(165px,.95fr);gap:13px}.jarvis-presence{min-height:380px}.presence-figure{width:min(100%,340px)}.telemetry-readout{padding-block:10px}.telemetry-readout .large-value{font-size:19px}}
@media(max-width:760px){.overview-hud{display:flex;flex-direction:column;gap:16px;min-height:0;align-items:stretch}.jarvis-presence{grid-template-columns:minmax(0,1fr);order:-1;min-height:0;padding:2px 0 7px}.presence-figure{width:min(78vw,330px)}.presence-figure:before{inset:15%}.presence-copy{margin-top:-13px}.telemetry-rail{grid-template-columns:repeat(2,minmax(0,1fr));gap:0 18px;padding:0 4px}.telemetry-readout{padding:11px 0}.telemetry-readout .large-value{font-size:19px}.telemetry-readout .muted{font-size:10px}.activity-readout .chart-bars{height:116px}.activity-readout .chart-bar-track{height:74px}.command-panel{padding:12px;border-radius:12px}.command-intro{gap:8px}.command-intro>span:last-child{font-size:9px}.quick-actions{display:flex;flex-wrap:nowrap;overflow-x:auto;padding-bottom:4px;scroll-snap-type:x proximity;overscroll-behavior-inline:contain}.quick-actions button{flex:0 0 auto;scroll-snap-align:start;min-height:44px}.command-hint{font-size:10px}}
@media(max-width:430px){.presence-figure{width:min(82vw,290px)}.presence-copy h2{font-size:20px}.presence-connection{grid-template-columns:7px auto;gap:6px}.presence-connection strong{grid-column:2;justify-self:start;margin-left:0}.telemetry-rail{grid-template-columns:1fr 1fr;gap:0 12px}.telemetry-readout h2{font-size:8px}.activity-readout{grid-column:1/-1}.activity-readout .chart-bars{height:100px}.activity-readout .chart-bar-track{height:62px}}
@media(prefers-reduced-motion:reduce){.jarvis-presence[data-state="thinking"] .presence-orbit-inner,.jarvis-presence[data-state="listening"] .presence-orbit-outer{animation:none;transform:none}}
/* One authored reactor: continuous only while visible, with motion tied to real UI states. */
@keyframes reactor-core-breathe{0%,100%{opacity:.72;transform:scale(.98)}50%{opacity:1;transform:scale(1.035)}}
@keyframes reactor-listening{0%,100%{opacity:.58;stroke-width:1.2}50%{opacity:1;stroke-width:2.1}}
@keyframes jarvis-halo-breathe{0%,100%{opacity:.35;transform:scale(.94)}50%{opacity:.78;transform:scale(1.06)}}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-orbit-inner{transform-box:view-box;transform-origin:120px 120px;animation:presence-turn 58s linear infinite}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-core{transform-box:view-box;transform-origin:120px 120px;animation:reactor-core-breathe 6s ease-in-out infinite}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="thinking"] .presence-orbit-inner{animation-duration:18s}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="thinking"] .presence-orbit-reactor{transform-box:view-box;transform-origin:120px 120px;animation:presence-turn 46s linear infinite reverse}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="listening"] .presence-orbit-outer{animation:reactor-listening 1.7s ease-in-out infinite}
.jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="speaking"] .presence-orbit-reactor{transform-box:view-box;transform-origin:120px 120px;animation:presence-turn 34s linear infinite}
html[data-page-visible="true"] .assistant-hud[data-state="idle"] .orb-halo{animation:jarvis-halo-breathe 7s ease-in-out infinite}
html[data-page-visible="true"] .assistant-hud[data-state="listening"] .orb-halo{animation:jarvis-halo-breathe 1.7s ease-in-out infinite}
html[data-page-visible="true"] .assistant-hud[data-state="speaking"] .orb-ring{animation:presence-turn 16s linear infinite}
.voice-button,.send-button,.stop-button{min-height:44px}
.voice-wake-controls{max-width:880px;margin:8px 3px 0;color:#9bb6bb;font-size:11px;line-height:1.5}
.voice-wake-controls label{min-height:44px;display:flex;align-items:center;gap:10px;color:#cce2e5;cursor:pointer}
.voice-wake-controls input{width:18px;height:18px;flex:none;accent-color:var(--cyan)}
.voice-wake-controls p{margin:0 0 0 28px;max-width:74ch}
.voice-wake-button[aria-pressed="true"]{border-color:#83d7bd;background:rgba(39,137,111,.2);color:#c4f7e5}
@media(max-width:760px){.composer-actions{flex-wrap:wrap}.composer-hint{flex:1 0 100%;padding:2px 0 5px}.voice-wake-controls p{margin-left:0}}
@media(prefers-reduced-motion:reduce){html:not([data-jarvis-motion="full"]) .jarvis-presence .presence-orbit-inner,html:not([data-jarvis-motion="full"]) .jarvis-presence .presence-orbit-reactor,html:not([data-jarvis-motion="full"]) .jarvis-presence .presence-orbit-outer,html:not([data-jarvis-motion="full"]) .jarvis-presence .presence-core,html:not([data-jarvis-motion="full"]) .assistant-hud .orb-halo,html:not([data-jarvis-motion="full"]) .assistant-hud .orb-ring{animation:none!important;transform:none!important}}
@media(prefers-reduced-motion:reduce){html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-orbit-inner{animation:presence-turn 58s linear infinite!important}html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="idle"] .presence-core{animation:reactor-core-breathe 6s ease-in-out infinite!important}html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="thinking"] .presence-orbit-inner{animation:presence-turn 18s linear infinite!important}html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="thinking"] .presence-orbit-reactor{animation:presence-turn 46s linear infinite reverse!important}html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="listening"] .presence-orbit-outer{animation:reactor-listening 1.7s ease-in-out infinite!important}html[data-jarvis-motion="full"] .jarvis-presence[data-in-viewport="true"][data-page-visible="true"][data-state="speaking"] .presence-orbit-reactor{animation:presence-turn 34s linear infinite!important}html[data-jarvis-motion="full"][data-page-visible="true"] .assistant-hud[data-state="idle"] .orb-halo{animation:jarvis-halo-breathe 7s ease-in-out infinite!important}html[data-jarvis-motion="full"][data-page-visible="true"] .assistant-hud[data-state="listening"] .orb-halo{animation:jarvis-halo-breathe 1.7s ease-in-out infinite!important}html[data-jarvis-motion="full"][data-page-visible="true"] .assistant-hud[data-state="speaking"] .orb-ring{animation:presence-turn 16s linear infinite!important}}
'''.encode("utf-8")


_CSS += b'''
/* Target sizes verified by the Pi phone/tablet/desktop render probe. */
#jarvis-home,#history-toggle,#message-input,.conversation-item{min-height:44px}
#history-toggle{min-width:44px}
html[data-jarvis-motion="reduce"] *,html[data-jarvis-motion="reduce"] *::before,html[data-jarvis-motion="reduce"] *::after{transition-duration:0s!important}
@media(prefers-reduced-motion:reduce){html:not([data-jarvis-motion="full"]) *,html:not([data-jarvis-motion="full"]) *::before,html:not([data-jarvis-motion="full"]) *::after{transition-duration:0s!important}}
/* Keep every mobile section reachable without clipping its popup or shrinking its target. */
@media(max-width:760px){
  /* A filtered header traps fixed descendants inside its short box. */
  .topbar{backdrop-filter:none;-webkit-backdrop-filter:none}
  .primary-nav{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));grid-template-rows:1fr;align-items:stretch;justify-content:stretch;overflow:visible;overflow-x:visible;overflow-y:visible;overscroll-behavior-inline:auto;scroll-snap-type:none}
  .nav-group{position:static;min-width:0;flex:none}
  .nav-group>summary{width:100%;min-width:0;height:100%;min-height:46px;justify-content:center;gap:3px;padding-inline:3px;font-size:clamp(8px,2.1vw,8.5px);line-height:1.05;letter-spacing:-.025em;text-align:center;white-space:normal;overflow-wrap:anywhere}
  .nav-group>summary:after{flex:0 0 5px}
  .nav-menu,.nav-group:nth-last-child(-n+2) .nav-menu{position:absolute;inset:auto 0 calc(100% + 12px);width:auto;min-width:0;max-width:none;max-height:min(64dvh,520px)}
  .voice-choice{width:100%;min-height:44px}
}
'''

_JS = r'''/* Browser client is text-first with optional, explicitly enabled browser voice. */
(() => {
  "use strict";
  const byId = (id) => document.getElementById(id);
  const ui = {
    connection: byId("connection-state"), history: byId("conversation-list"),
    empty: byId("history-empty"), historyFilterEmpty: byId("history-filter-empty"),
    sessionSearch: byId("session-search"), sessionCount: byId("session-count"), title: byId("conversation-title"),
    messages: byId("message-list"), welcome: byId("welcome-panel"),
    scroll: byId("message-scroll"), form: byId("composer"), input: byId("message-input"),
    send: byId("send-button"), stop: byId("stop-button"), notice: byId("chat-notice"),
    voiceInput: byId("voice-input"), voiceStop: byId("voice-stop"), voiceWake: byId("voice-wake-toggle"), speechStop: byId("speech-stop"),
    voiceStatus: byId("voice-status"),
    toggle: byId("history-toggle"), close: byId("history-close"), panel: byId("conversation-panel"),
    scrim: byId("panel-scrim"), newChat: byId("new-chat")
  };
  let conversations = [];
  let conversationId = null;
  let conversationHydrated = false;
  let activeTurnId = null;
  let eventSource = null;
  let heartbeatTimer = null;
  let heartbeatNonce = null;
  let latestSequence = 0;
  let recognition = null;
  let recognitionMode = "";
  let wakePhraseHeard = false;
  let presenceObserver = null;
  let speechUtterance = null;
  let voiceSupported = false;
  let synthesisSupported = false;
  const preferenceKey = "jarvis.ui.preferences.v1";
  const preferenceDefaults = Object.freeze({readAloud: false, language: "en-US", voiceURI: "", rate: 1, pitch: 1, density: "comfortable", textSize: "normal", motion: "system"});
  let uiPreferences = {...preferenceDefaults};
  let preferenceStorageAvailable = true;
  const API = "/chat/api";
  const mountCapabilityDetails = (__JARVIS_CAPABILITY_DETAILS_MOUNT__);
  const FEATURE_ASSETS = window.JARVIS_FEATURE_ASSETS;
  const featuresById = new Map(FEATURE_ASSETS.map((feature) => [feature.id, feature]));
  let mountedFeature = null;
  let mountedFeatureCleanup = null;
  let capabilityDetailsCleanup = null;
  let currentView = null;

  function mountCapabilitiesDetails() {
    if (capabilityDetailsCleanup) return;
    const root = byId("capability-details-root");
    if (!root) return;
    const allowed = new Set([
      "/chat/api/capabilities",
      "/chat/api/native-capabilities",
      "/chat/api/resources/learning",
    ]);
    const reader = Object.freeze({get(path) {
      if (!allowed.has(path)) return Promise.reject(new Error("Capability details route is not allowed."));
      return request(path, {method:"GET"});
    }});
    try { capabilityDetailsCleanup = mountCapabilityDetails(root, reader); }
    catch (_) {
      const status = root.querySelector("[data-capability-status]");
      if (status) status.textContent = "Capability details could not be opened.";
    }
  }
  function unmountCapabilitiesDetails() {
    if (typeof capabilityDetailsCleanup === "function") {
      try { capabilityDetailsCleanup(); } catch (_) { /* keep navigation available */ }
    }
    capabilityDetailsCleanup = null;
  }

  function featurePathMatches(template, path) {
    if (typeof path !== "string" || path.includes("?") || path.includes("#")) return false;
    const expected = template.split("/");
    const actual = path.split("/");
    return expected.length === actual.length && expected.every((part, index) =>
      /^\{[a-z][a-z0-9_]*\}$/.test(part)
        ? /^[A-Za-z0-9._~-]+$/.test(actual[index]) && actual[index] !== "." && actual[index] !== ".."
        : part === actual[index]);
  }
  function featureApi(feature) {
    const requestFeature = (method, path, body) => {
      if (!feature.routes.some((route) => route.method === method && featurePathMatches(route.path, path))) {
        return Promise.reject(new Error("This dashboard view is not allowed to call that service route."));
      }
      return request(path, method === "GET" ? {method} : {method, body: JSON.stringify(body)});
    };
    return Object.freeze({get: (path) => requestFeature("GET", path), post: (path, body) => requestFeature("POST", path, body)});
  }
  function unmountFeature() {
    if (!mountedFeature) return;
    try { if (typeof mountedFeature.unmount === "function") mountedFeature.unmount(); } catch (_) { /* keep navigation available */ }
    try { if (typeof mountedFeatureCleanup === "function") mountedFeatureCleanup(); } catch (_) { /* keep navigation available */ }
    mountedFeature = null;
    mountedFeatureCleanup = null;
  }
  function preselectCurrentModelConversation(root) {
    const id = conversationId;
    const select = root.querySelector("[data-models-conversation]");
    if (!id || !select) return null;
    let observer = null;
    const chooseCurrent = () => {
      const option = [...select.options].find((item) => item.value === id);
      if (option) {
        select.value = id;
        select.dispatchEvent(new Event("change", {bubbles: true}));
        observer.disconnect();
      } else if (select.disabled && select.options.length > 1) {
        observer.disconnect();
      }
    };
    observer = new MutationObserver(chooseCurrent);
    observer.observe(select, {childList: true});
    return () => observer.disconnect();
  }
  function mountFeature(feature) {
    if (mountedFeature === feature) return;
    unmountFeature();
    const root = byId(`${feature.id}-view`);
    if (!root || typeof feature.mount !== "function") return;
    mountedFeature = feature;
    let contextualCleanup = null;
    try {
      const cleanup = feature.mount(root, featureApi(feature), Object.freeze({}));
      if (feature.id === "models-settings") contextualCleanup = preselectCurrentModelConversation(root);
      mountedFeatureCleanup = () => {
        try { if (typeof cleanup === "function") cleanup(); } finally { if (contextualCleanup) contextualCleanup(); }
      };
    } catch (_) {
      if (contextualCleanup) contextualCleanup();
      mountedFeature = null;
      const status = root.querySelector('[role="status"]');
      if (status) status.textContent = "This dashboard view could not be loaded.";
    }
  }

  function renderTurnControls(active, stopping = false) {
    ui.input.disabled = active;
    ui.send.hidden = active;
    ui.send.disabled = active;
    ui.stop.hidden = !active;
    ui.stop.disabled = stopping;
    ui.voiceInput.hidden = active || !voiceSupported || !pushToTalkEnabled();
    ui.voiceInput.disabled = active;
    setAssistantState(active ? "busy" : "ready", active ? "Jarvis is responding" : "Ready for your message");
  }

  function setAssistantState(state, label) {
    const hud = byId("assistant-hud");
    if (!hud) return;
    const semanticState = ({ready: "idle", busy: "thinking"})[state] || state;
    hud.dataset.state = ["checking", "idle", "listening", "thinking", "speaking", "error"].includes(semanticState) ? semanticState : "checking";
    hud.setAttribute("aria-label", `Jarvis status: ${semanticState}`);
    byId("assistant-state-label").textContent = `JARVIS · ${hud.dataset.state.toUpperCase()}`;
    byId("assistant-mode").textContent = label;
    const presence = byId("jarvis-presence");
    if (presence) {
      presence.dataset.state = hud.dataset.state;
      byId("jarvis-presence-state").textContent = label;
    }
  }

  function showError(message) {
    ui.notice.textContent = message;
    ui.notice.hidden = false;
    setAssistantState("error", "Needs attention");
  }
  function showVoiceStatus(message) {
    ui.voiceStatus.textContent = message;
    ui.voiceStatus.hidden = !message;
    byId("voice-settings-status").textContent = message;
    byId("voice-settings-status").hidden = !message;
  }
  function boundedPreferenceNumber(value, min, max, fallback) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.round(Math.min(max, Math.max(min, number)) * 10) / 10 : fallback;
  }
  function loadUIPreferences() {
    try {
      const raw = window.localStorage.getItem(preferenceKey);
      if (raw && raw.length <= 2048) {
        const saved = JSON.parse(raw);
        if (saved && typeof saved === "object" && !Array.isArray(saved)) {
          uiPreferences = {
            ...preferenceDefaults,
            readAloud: saved.readAloud === true,
            language: ["en-US", "en-GB", "pt-PT", "pt-BR", "es-ES", "fr-FR", "de-DE", "it-IT"].includes(saved.language) ? saved.language : "en-US",
            voiceURI: typeof saved.voiceURI === "string" ? saved.voiceURI.slice(0, 256) : "",
            rate: boundedPreferenceNumber(saved.rate, 0.5, 2, 1),
            pitch: boundedPreferenceNumber(saved.pitch, 0, 2, 1),
            density: saved.density === "compact" ? "compact" : "comfortable",
            textSize: saved.textSize === "large" ? "large" : "normal",
            motion: ["reduce", "full"].includes(saved.motion) ? saved.motion : "system"
          };
        }
      }
    } catch (_) { preferenceStorageAvailable = false; }
    byId("preference-storage-status").textContent = preferenceStorageAvailable
      ? "Voice and appearance choices are saved on this device. Microphone consent is never saved."
      : "Local preference storage is unavailable. Changes apply only until this page closes.";
    byId("preference-storage-status").hidden = false;
    syncPreferenceControls();
    byId("speech-voice").dataset.preferredVoice = uiPreferences.voiceURI;
    byId("chat-speech-voice").dataset.preferredVoice = uiPreferences.voiceURI;
    applyAppearancePreferences();
    updateSpeechTuningLabels();
  }
  function syncPreferenceControls() {
    for (const id of ["speech-language", "chat-speech-language"]) byId(id).value = uiPreferences.language;
    for (const id of ["speech-output", "chat-speech-output"]) byId(id).checked = uiPreferences.readAloud;
    for (const id of ["speech-rate", "chat-speech-rate"]) byId(id).value = String(uiPreferences.rate);
    for (const id of ["speech-pitch", "chat-speech-pitch"]) byId(id).value = String(uiPreferences.pitch);
    for (const [ids, key] of [[["ui-density", "chat-density"], "density"], [["ui-text-size", "chat-text-size"], "textSize"], [["ui-motion", "chat-motion"], "motion"]]) {
      for (const id of ids) byId(id).value = uiPreferences[key];
    }
    for (const id of ["speech-voice", "chat-speech-voice"]) {
      const select = byId(id);
      if ([...select.options].some((option) => option.value === uiPreferences.voiceURI)) select.value = uiPreferences.voiceURI;
      select.dataset.preferredVoice = uiPreferences.voiceURI;
    }
  }
  function saveUIPreferences(patch) {
    uiPreferences = {...uiPreferences, ...patch};
    syncPreferenceControls();
    if (Object.prototype.hasOwnProperty.call(patch, "rate") || Object.prototype.hasOwnProperty.call(patch, "pitch")) updateSpeechTuningLabels();
    if (!preferenceStorageAvailable) return;
    try {
      const safe = {readAloud: uiPreferences.readAloud, language: uiPreferences.language, voiceURI: uiPreferences.voiceURI, rate: uiPreferences.rate, pitch: uiPreferences.pitch, density: uiPreferences.density, textSize: uiPreferences.textSize, motion: uiPreferences.motion};
      window.localStorage.setItem(preferenceKey, JSON.stringify(safe));
    } catch (_) {
      preferenceStorageAvailable = false;
      byId("preference-storage-status").textContent = "Local preference storage is unavailable. Changes apply only until this page closes.";
    }
  }
  function applyAppearancePreferences() {
    document.documentElement.dataset.jarvisDensity = uiPreferences.density;
    document.documentElement.dataset.jarvisTextSize = uiPreferences.textSize;
    document.documentElement.dataset.jarvisMotion = uiPreferences.motion;
  }
  function updateSpeechTuningLabels() {
    byId("speech-rate-value").textContent = `${Number(uiPreferences.rate).toFixed(1)}×`;
    byId("speech-pitch-value").textContent = Number(uiPreferences.pitch).toFixed(1);
    byId("chat-speech-rate-value").textContent = `${Number(uiPreferences.rate).toFixed(1)}×`;
    byId("chat-speech-pitch-value").textContent = Number(uiPreferences.pitch).toFixed(1);
  }
  function shouldReduceMotion() {
    return uiPreferences.motion === "reduce" || (uiPreferences.motion !== "full" && window.matchMedia("(prefers-reduced-motion: reduce)").matches);
  }
  function pushToTalkEnabled() {
    return byId("speech-consent").checked || byId("chat-speech-consent").checked;
  }
  function updateSpeechVoiceStatus() {
    const status = byId("speech-voice-status");
    if (!synthesisSupported) { status.hidden = true; return; }
    const select = byId("speech-voice");
    const voiceCount = select.options.length;
    const selected = select.selectedOptions[0];
    status.textContent = voiceCount
      ? `${voiceCount} selectable browser voice${voiceCount === 1 ? "" : "s"}. ${selected ? `Selected: ${selected.textContent}.` : "The browser default voice is selected."} Read-aloud is ${uiPreferences.readAloud ? "on" : "off"}.`
      : "Browser speech output is available, but no selectable voices are currently reported. Read-aloud will use the browser default voice.";
    status.hidden = false;
  }
  function stopRecognition(message = "") {
    const current = recognition;
    recognition = null;
    recognitionMode = "";
    wakePhraseHeard = false;
    ui.voiceStop.hidden = true;
    ui.voiceInput.hidden = !voiceSupported || !pushToTalkEnabled();
    ui.voiceInput.dataset.listening = "false";
    ui.voiceWake.setAttribute("aria-pressed", "false");
    ui.voiceWake.textContent = "Enable foreground wake phrase";
    ui.voiceWake.hidden = !voiceSupported || !pushToTalkEnabled();
    if (current) {
      current.onresult = current.onerror = current.onend = null;
      try { current.abort(); } catch (_) {}
    }
    if (message && current) showVoiceStatus(message);
    if (current && !activeTurnId) setAssistantState("ready", "Ready for your message");
  }
  function stopSpeech(message = "") {
    const wasSpeaking = speechUtterance !== null;
    if (synthesisSupported) window.speechSynthesis.cancel();
    speechUtterance = null;
    ui.speechStop.hidden = !synthesisSupported;
    ui.speechStop.disabled = true;
    if (wasSpeaking && !activeTurnId) setAssistantState("ready", "Ready for your message");
    if (message && wasSpeaking) showVoiceStatus(message);
  }
  function speakCompletedReply(text) {
    if (!synthesisSupported || !uiPreferences.readAloud || !text.trim()) return;
    if (text.length > 12000) {
      showVoiceStatus("This reply is too long for browser read-aloud. You can still read it here.");
      return;
    }
    stopSpeech();
    const utterance = new window.SpeechSynthesisUtterance(text);
    utterance.rate = Number(uiPreferences.rate);
    utterance.pitch = Number(uiPreferences.pitch);
    const selectedVoice = uiPreferences.voiceURI;
    const voice = window.speechSynthesis.getVoices().find((candidate) => candidate.voiceURI === selectedVoice);
    if (voice) {
      utterance.voice = voice;
      utterance.lang = voice.lang;
    }
    speechUtterance = utterance;
    setAssistantState("speaking", "Reading the completed reply aloud");
    ui.speechStop.hidden = false;
    ui.speechStop.disabled = false;
    utterance.onend = () => {
      if (speechUtterance === utterance) {
        speechUtterance = null;
        ui.speechStop.disabled = true;
        setAssistantState("ready", "Ready for your message");
        showVoiceStatus("Reply audio finished.");
      }
    };
    utterance.onerror = () => {
      if (speechUtterance === utterance) {
        speechUtterance = null;
        ui.speechStop.disabled = true;
        setAssistantState("error", "Read-aloud unavailable");
        showVoiceStatus("This device could not play the reply. Text chat is still available.");
      }
    };
    try { window.speechSynthesis.speak(utterance); }
    catch (_) {
      speechUtterance = null;
      ui.speechStop.disabled = true;
      setAssistantState("error", "Read-aloud unavailable");
      showVoiceStatus("This device could not play the reply. Text chat is still available.");
    }
  }
  function configureVoice() {
    const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    voiceSupported = Boolean(Recognition && window.isSecureContext);
    synthesisSupported = "speechSynthesis" in window && "SpeechSynthesisUtterance" in window;
    ui.speechStop.hidden = !synthesisSupported;
    ui.speechStop.disabled = true;
    const consentRow = byId("speech-consent-row");
    const unavailable = byId("speech-unavailable");
    consentRow.hidden = !voiceSupported;
    byId("chat-speech-consent-row").hidden = !voiceSupported;
    byId("voice-wake-controls").hidden = !voiceSupported || !pushToTalkEnabled();
    ui.voiceWake.hidden = !voiceSupported || !pushToTalkEnabled();
    if (!Recognition) {
      unavailable.textContent = "Push-to-talk is not supported by this browser. You can still type your message.";
      unavailable.hidden = false;
    } else if (!window.isSecureContext) {
      unavailable.textContent = "Push-to-talk requires a secure browser connection. You can still type your message.";
      unavailable.hidden = false;
    }
    unavailable.hidden = Boolean(voiceSupported);
    byId("speech-output-row").hidden = !synthesisSupported;
    byId("chat-speech-output-row").hidden = !synthesisSupported;
    byId("speech-output-unavailable").hidden = synthesisSupported;
    if (!synthesisSupported) byId("speech-output-unavailable").textContent = "Speech output is not supported by this browser. Replies remain available as text.";
    byId("speech-tuning-row").hidden = !synthesisSupported;
    byId("chat-preference-tuning").hidden = !synthesisSupported;
    if (synthesisSupported) {
      const refreshVoices = () => {
        const options = [];
        for (const voice of window.speechSynthesis.getVoices()) {
          const option = document.createElement("option");
          option.value = voice.voiceURI;
          option.textContent = `${voice.name} (${voice.lang})`;
          options.push(option);
        }
        for (const id of ["speech-voice", "chat-speech-voice"]) byId(id).replaceChildren(...options.map((option) => option.cloneNode(true)));
        const select = byId("speech-voice");
        byId("speech-voice-row").hidden = select.options.length === 0;
        byId("chat-speech-voice").parentElement.hidden = select.options.length === 0;
        syncPreferenceControls();
        updateSpeechVoiceStatus();
      };
      refreshVoices();
      window.speechSynthesis.onvoiceschanged = refreshVoices;
    }
  }
  function startRecognition(mode = "ptt") {
    const Recognition = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!voiceSupported || !pushToTalkEnabled() || !Recognition
        || byId("main-content").hidden || document.visibilityState !== "visible") return;
    if (ui.input.disabled) return;
    if (recognition) stopRecognition();
    stopSpeech();
    let current;
    try { current = new Recognition(); }
    catch (_) {
      showVoiceStatus("Could not access browser speech input. Check microphone access or type your message.");
      setAssistantState("error", "Voice input unavailable");
      return;
    }
    current.continuous = mode === "wake";
    current.interimResults = false;
    current.lang = uiPreferences.language;
    let transcriptReceived = false;
    const captureEligible = () => pushToTalkEnabled()
      && !ui.input.disabled && !byId("main-content").hidden
      && document.visibilityState === "visible";
    current.onresult = (event) => {
      if (recognition !== current) return;
      if (!captureEligible()) { stopRecognition(); return; }
      const transcript = [...event.results].slice(event.resultIndex || 0).filter((result) => result.isFinal)
        .map((result) => result[0] && result[0].transcript || "").join(" ").trim();
      if (!transcript) return;
      transcriptReceived = true;
      if (mode === "wake") {
        let command = transcript;
        if (!wakePhraseHeard) {
          const wake = transcript.match(/(?:^|\b)(?:hey\s+)?jarvis\b[\s,.:;!-]*(.*)$/i);
          if (!wake) return;
          wakePhraseHeard = true;
          command = (wake[1] || "").trim();
          if (!command) {
            showVoiceStatus("Jarvis heard you. Say one command; it will not run until you review or explicitly enable hands-free sending.");
            return;
          }
        }
        if (command) {
          const existingDraft = ui.input.value.trim();
          const autoSend = byId("voice-handsfree-send").checked && !existingDraft;
          stopRecognition();
          const separator = ui.input.value && !/\s$/.test(ui.input.value) ? " " : "";
          const limit = ui.input.maxLength >= 0 ? ui.input.maxLength : ui.input.value.length + command.length + separator.length;
          const accepted = command.slice(0, Math.max(0, limit - ui.input.value.length - separator.length));
          if (!accepted) {
            showVoiceStatus("The message is at its character limit. You can edit it or start a new message.");
            return;
          }
          ui.input.value = `${ui.input.value}${separator}${accepted}`;
          ui.input.dispatchEvent(new Event("input", { bubbles: true }));
          if (autoSend && accepted === command) {
            showVoiceStatus("Hands-free command submitted after the wake phrase.");
            ui.form.requestSubmit();
          } else {
            ui.input.focus({ preventScroll: true });
            showVoiceStatus(existingDraft
              ? "Command added beside your existing draft. Review before sending."
              : "Command added to your message. Review it before sending.");
          }
        }
        return;
      }
      const existing = ui.input.value;
      const separator = existing && !/\s$/.test(existing) ? " " : "";
      const limit = ui.input.maxLength >= 0 ? ui.input.maxLength : existing.length + transcript.length + separator.length;
      const accepted = transcript.slice(0, Math.max(0, limit - existing.length - separator.length));
      if (!accepted) {
        showVoiceStatus("The message is at its character limit. You can edit it or start a new message.");
        return;
      }
      ui.input.value = `${existing}${separator}${accepted}`;
      ui.input.dispatchEvent(new Event("input", { bubbles: true }));
      ui.input.focus({ preventScroll: true });
      showVoiceStatus(accepted.length < transcript.length
        ? "Transcript shortened to fit the message limit. Review it before sending."
        : "Transcript added to your message. Review it before sending.");
    };
    current.onerror = (event) => {
      if (recognition !== current) return;
      if (!captureEligible()) { stopRecognition(); return; }
      const messages = {
        "not-allowed": "Microphone permission was denied. You can continue by typing.",
        "service-not-allowed": "The browser speech service is unavailable. You can continue by typing.",
        "audio-capture": "No microphone is available. You can continue by typing.",
        "no-speech": "No speech was detected. You can continue by typing.",
        "language-not-supported": "This browser speech service does not support the selected language. Choose another language or type your message.",
        network: "The browser speech service could not be reached. You can continue by typing."
      };
      stopRecognition(messages[event.error] || "Speech input stopped. You can continue by typing.");
      setAssistantState("error", "Voice input unavailable");
    };
    current.onend = () => {
      if (recognition !== current) return;
      if (!captureEligible()) { stopRecognition(); return; }
      recognition = null;
      recognitionMode = "";
      ui.voiceInput.hidden = !pushToTalkEnabled();
      ui.voiceInput.dataset.listening = "false";
      ui.voiceStop.hidden = true;
      ui.voiceWake.setAttribute("aria-pressed", "false");
      ui.voiceWake.textContent = "Enable foreground wake phrase";
      setAssistantState("ready", "Ready for your message");
      if (mode === "wake") showVoiceStatus("Foreground wake listening ended. You can enable it again or use push-to-talk.");
      else if (!transcriptReceived) showVoiceStatus("Listening ended without a transcript. You can type your message instead.");
    };
    recognition = current;
    recognitionMode = mode;
    ui.voiceInput.hidden = true;
    ui.voiceInput.dataset.listening = "true";
    ui.voiceStop.hidden = false;
    ui.voiceWake.setAttribute("aria-pressed", String(mode === "wake"));
    ui.voiceWake.textContent = mode === "wake" ? "Stop foreground wake phrase" : "Enable foreground wake phrase";
    if (mode === "wake") {
      byId("voice-wake-controls").hidden = false;
      setAssistantState("listening", "Foreground wake phrase active");
      showVoiceStatus("Listening for “Jarvis” in this visible Chat tab. Browser speech recognition may process audio outside Jarvis.");
    } else {
      setAssistantState("listening", "Listening once · review before sending");
      showVoiceStatus("Listening once. Your speech will not be sent until you review and submit the text.");
    }
    try { current.start(); }
    catch (_) {
      stopRecognition("Could not start speech input. Check microphone access or type your message.");
      setAssistantState("error", "Voice input unavailable");
    }
  }
  function clearError() {
    ui.notice.textContent = "";
    ui.notice.hidden = true;
    setAssistantState(activeTurnId ? "busy" : "ready", activeTurnId ? "Jarvis is responding" : "Ready for your message");
  }
  function setConnection(state, label) {
    ui.connection.dataset.state = state;
    ui.connection.lastElementChild.textContent = label;
    const presenceLink = byId("jarvis-presence-connection");
    if (presenceLink) presenceLink.textContent = label;
    const presence = byId("jarvis-presence");
    if (presence) {
      presence.dataset.connection = state;
      if (state === "error" && !activeTurnId) presence.dataset.state = "error";
    }
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
    const query = ui.sessionSearch.value.trim().toLocaleLowerCase();
    const filtered = conversations.filter((entry) => {
      const text = [entry.title, entry.id].filter((part) => typeof part === "string").join(" ").toLocaleLowerCase();
      return !query || text.includes(query);
    });
    ui.historyFilterEmpty.hidden = conversations.length === 0 || filtered.length !== 0;
    ui.sessionCount.textContent = query
      ? `${filtered.length} matching chats · ${conversations.length} owned in total`
      : `${conversations.length} owned chat${conversations.length === 1 ? "" : "s"}`;
    for (const entry of filtered) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "conversation-item";
      button.textContent = typeof entry.title === "string" && entry.title.trim() ? entry.title : "New conversation";
      if (entry.id === conversationId) button.setAttribute("aria-current", "page");
      button.addEventListener("click", () => {
        loadConversation(entry.id).catch((error) => showError(error.message)).finally(() => setPanel(false));
      });
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
    try {
      const data = await request(`${API}/conversations`);
      if (!data || !Array.isArray(data.conversations)) throw new Error("Conversation history is unavailable.");
      conversations = data.conversations.filter((item) => item && typeof item.id === "string" && typeof item.title === "string");
      renderHistory();
    } catch (error) {
      ui.sessionCount.textContent = "Your chat list is unavailable.";
      throw error;
    }
  }
  function refreshConversationsInBackground() {
    return refreshConversations().catch((error) => {
      // A list refresh is secondary to an accepted/completed turn. Its own
      // session-count message already reports history unavailability; only a
      // real session-expiry response belongs in the global connection notice.
      if (error && error.message === "Your secure session is no longer current. Sign in again to continue.") {
        showError(error.message);
      }
    });
  }
  async function loadConversation(id) {
    if (typeof id !== "string" || !id) return;
    stopRecognition("Push-to-talk stopped when switching conversations.");
    stopSpeech("Reply audio stopped when switching conversations.");
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
    stopRecognition("Push-to-talk stopped for the new conversation.");
    stopSpeech("Reply audio stopped for the new conversation.");
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
  async function renewHeartbeat(turnId, nonce, isCurrentTurn, reconcileCompletedTurn, reportCurrentFailure = () => {}) {
    try {
      const data = await request(`${API}/heartbeat`, { method: "POST", body: JSON.stringify({ turnId, nonce }) });
      if (!isCurrentTurn()) return;
      if (!data || data.turnId !== turnId || typeof data.nonce !== "string" || !/^[0-9a-f]{64}$/.test(data.nonce)) {
        const error = new Error("Secure connection could not be renewed.");
        reportCurrentFailure(error); closeStream(); showError(error.message); setConnection("error", "Access unavailable");
        return;
      }
      heartbeatNonce = data.nonce;
    } catch (error) {
      if (!isCurrentTurn()) return;
      if (error.message === "Your secure session is no longer current. Sign in again to continue.") {
        try { if (await reconcileCompletedTurn()) return; } catch (_) { /* fall through to the truthful connection error */ }
        if (!isCurrentTurn()) return;
      }
      reportCurrentFailure(error); closeStream(); showError(error.message); setConnection("error", "Access unavailable");
    }
  }
  async function reconcileCompletedTurn(turnId, conversationAtStart, prompt, assistantBody, waiting) {
    if (activeTurnId !== turnId || conversationId !== conversationAtStart) return activeTurnId !== turnId;
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const data = await request(`${API}/conversations/${encodeURIComponent(conversationAtStart)}/messages`);
      if (activeTurnId !== turnId || conversationId !== conversationAtStart) return activeTurnId !== turnId;
      if (!data || !Array.isArray(data.messages)) return false;
      let userIndex = -1;
      for (let index = 0; index < data.messages.length; index += 1) {
        const item = data.messages[index];
        if (item && item.role === "user" && item.content === prompt) userIndex = index;
      }
      const reply = userIndex < 0 ? null : data.messages.slice(userIndex + 1)
        .find((item) => item && item.role === "assistant" && typeof item.content === "string");
      if (reply) {
        assistantBody.textContent = reply.content;
        waiting.remove();
        closeStream();
        setConnection("ready", "Secure connection");
        speakCompletedReply(reply.content);
        refreshConversationsInBackground();
        return true;
      }
      if (attempt === 0) await new Promise((resolve) => window.setTimeout(resolve, 150));
    }
    return false;
  }
  async function classifyTurnStreamError(event, readyState, reconcile, onReconnect) {
    let code = "";
    const hasPayload = event && typeof event.data === "string";
    if (hasPayload) { try { code = JSON.parse(event.data).code || ""; } catch (_) {} }
    if (!hasPayload && readyState === 0) {
      onReconnect();
      return {kind: "reconnecting", code: ""};
    }
    if (!hasPayload && readyState === 2) {
      try { if (await reconcile()) return {kind: "recovered", code: ""}; } catch (_) {}
    }
    return {kind: "failed", code: typeof code === "string" ? code : ""};
  }
  function startHeartbeat(turnId, conversationAtStart, prompt, assistantBody, waiting) {
    heartbeatTimer = window.setInterval(async () => {
      if (activeTurnId !== turnId || !heartbeatNonce) return;
      const nonce = heartbeatNonce;
      heartbeatNonce = null;
      await renewHeartbeat(turnId, nonce, () => activeTurnId === turnId,
        () => reconcileCompletedTurn(turnId, conversationAtStart, prompt, assistantBody, waiting),
        () => { waiting.textContent = "The secure connection ended before this reply was confirmed. Reload this conversation to check its saved state."; });
    }, 2000);
  }
  function watchTurn(turnId, initialNonce, assistantBody, waiting, conversationAtStart, prompt) {
    if (typeof turnId !== "string" || !turnId || typeof initialNonce !== "string" || !/^[0-9a-f]{64}$/.test(initialNonce)) throw new Error("Jarvis did not start this response securely.");
    activeTurnId = turnId;
    heartbeatNonce = initialNonce;
    latestSequence = 0;
    // Show Stop as soon as the server accepts the queued turn. Install the
    // controls before opening SSE, whose connection can fail immediately.
    renderTurnControls(true);
    eventSource = new EventSource(`${API}/turns/${encodeURIComponent(turnId)}/events`, { withCredentials: true });
    eventSource.addEventListener("open", () => {
      if (activeTurnId === turnId && ui.connection.dataset.state !== "ready") setConnection("ready", "Secure connection");
    });
    startHeartbeat(turnId, conversationAtStart, prompt, assistantBody, waiting);
    eventSource.addEventListener("message.delta", (event) => {
      if (activeTurnId !== turnId) return;
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
      if (activeTurnId !== turnId) return;
      waiting.remove();
      const finalText = assistantBody.textContent;
      closeStream();
      speakCompletedReply(finalText);
      refreshConversationsInBackground();
    });
    eventSource.addEventListener("message.completed", () => { if (activeTurnId === turnId) waiting.remove(); });
    eventSource.addEventListener("turn.cancelled", () => { if (activeTurnId === turnId) { waiting.remove(); closeStream(); stopSpeech(); } });
    eventSource.addEventListener("turn.failed", () => {
      if (activeTurnId !== turnId) return;
      waiting.remove();
      closeStream();
      stopSpeech();
      showError("Jarvis could not finish that response. You can try again.");
    });
    eventSource.addEventListener("error", async (event) => {
      if (activeTurnId !== turnId) return;
      const source = eventSource;
      const disposition = await classifyTurnStreamError(
        event, source ? source.readyState : 2,
        () => reconcileCompletedTurn(turnId, conversationAtStart, prompt, assistantBody, waiting),
        () => setConnection("checking", "Reconnecting event stream…")
      );
      if (activeTurnId !== turnId) return;
      if (disposition.kind === "reconnecting" || disposition.kind === "recovered") return;
      waiting.remove();
      const safeErrors = {
        busy: "Jarvis is busy right now. Your conversation remains separate.",
        authorization: "Your secure session is no longer current. Sign in again to continue.",
        "backend-unavailable": "The assistant service is currently unavailable."
      };
      closeStream();
      if (typeof disposition.code === "string" && safeErrors[disposition.code]) {
        showError(safeErrors[disposition.code]);
        if (disposition.code === "authorization") setConnection("error", "Access unavailable");
      } else {
        showError("The response stream ended. Reload the conversation to see its saved state.");
        setConnection("error", "Connection interrupted");
      }
    });
  }
  async function sendMessage(text) {
    clearError();
    stopRecognition();
    stopSpeech();
    setAssistantState("busy", "Preparing your response");
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
      watchTurn(data.turnId, data.heartbeatNonce, assistantBody, waiting, conversationId, text);
      refreshConversationsInBackground();
      return true;
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
      return false;
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
    stopRecognition();
    stopSpeech();
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
      cell.setAttribute("role", "listitem");
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
      const weekday = Number.isNaN(parsed.valueOf()) ? day.date : parsed.toLocaleDateString(undefined, { weekday: "short", timeZone: "UTC" });
      label.textContent = `${weekday}: ${value}`;
      cell.setAttribute("aria-label", `${day.date}: ${value} turns`);
      cell.append(track, label);
      bars.append(cell);
    }
    chart.append(bars);
  }
  async function loadOverview() {
    const data = await request(`${API}/overview`);
    const core = data.core || {};
    const chat = data.chat || {};
    const serviceLabels = {"process-observed": "Service process observed", unavailable: "Unavailable"};
    byId("core-status").textContent = serviceLabels[core.status] || "Not verified";
    const readinessLabels = {
      "current-core-witness": "A current process and listener were observed; functional readiness has not been verified.",
      pending: "Functional readiness has not been verified.", stale: "The last observation is stale; refresh verification."
    };
    byId("core-readiness").textContent = readinessLabels[core.readiness] || "Functional readiness has not been verified.";
    const observed = typeof core.observedAt === "string" ? new Date(core.observedAt) : null;
    byId("core-observed").textContent = observed && !Number.isNaN(observed.valueOf())
      ? `Checked ${observed.toLocaleString()}` : "No verified observation time";
    byId("conversation-count").textContent = Number.isFinite(chat.conversationCount) ? String(chat.conversationCount) : "Unavailable";
    const counts = chat.turnCounts || {};
    byId("turn-total").textContent = Number.isFinite(counts.total) ? String(counts.total) : "Unavailable";
    byId("turn-breakdown").textContent = ["completed", "failed", "cancelled"].map((key) => `${key}: ${Number.isFinite(counts[key]) ? counts[key] : "—"}`).join(" · ");
    byId("turn-active").textContent = Number.isFinite(counts.active) ? String(counts.active) : "Unavailable";
    const lastTurn = typeof chat.lastTurnAt === "string" ? new Date(chat.lastTurnAt) : null;
    byId("last-turn").textContent = lastTurn && !Number.isNaN(lastTurn.valueOf()) ? `Last turn ${lastTurn.toLocaleString()}` : "No recorded turns yet";
    renderTurnChart(chat.turnCountsByDay);
  }
  let capabilityItems = [];
  function renderCapabilityMap() {
    const map = byId("capability-map");
    map.replaceChildren();
    const counts = new Map();
    for (const item of capabilityItems) {
      if (typeof item.kind === "string") counts.set(item.kind, (counts.get(item.kind) || 0) + 1);
    }
    const maxCount = Math.max(1, ...counts.values());
    for (const [kind, count] of [...counts.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = "capability-kind";
      button.dataset.kind = kind;
      button.setAttribute("aria-pressed", String(byId("capability-kind").value === kind));
      button.setAttribute("aria-label", `${kind}: ${count} catalog entries. Select to filter.`);
      const label = document.createElement("span");
      label.className = "capability-kind-name";
      label.textContent = kind.split(/[-_]/).map((part) => part ? part[0].toLocaleUpperCase() + part.slice(1) : "").join(" ");
      const total = document.createElement("span");
      total.className = "capability-kind-count";
      total.textContent = `${count} entries`;
      const track = document.createElement("span");
      track.className = "capability-kind-track";
      track.setAttribute("aria-hidden", "true");
      const fill = document.createElement("span");
      fill.className = "capability-kind-fill";
      fill.style.width = `${Math.max(3, Math.round(count / maxCount * 100))}%`;
      track.append(fill);
      button.append(label, total, track);
      button.addEventListener("click", () => {
        const select = byId("capability-kind");
        select.value = select.value === kind ? "" : kind;
        renderCapabilities();
      });
      map.append(button);
    }
  }
  function renderCapabilities() {
    const list = byId("capability-list");
    list.replaceChildren();
    const query = byId("capability-search").value.trim().toLocaleLowerCase();
    const kind = byId("capability-kind").value;
    const filtered = capabilityItems.filter((item) => {
      if (kind && item.kind !== kind) return false;
      const text = [item.id, item.name, item.summary, item.kind].filter((part) => typeof part === "string").join(" ").toLocaleLowerCase();
      return !query || text.includes(query);
    });
    for (const button of byId("capability-map").querySelectorAll(".capability-kind")) {
      button.setAttribute("aria-pressed", String(button.dataset.kind === kind));
    }
    byId("capability-count").textContent = `${filtered.length} of ${capabilityItems.length} catalog entries`;
    if (!filtered.length) {
      const empty = document.createElement("p");
      empty.className = "readiness-banner";
      empty.textContent = capabilityItems.length ? "No catalog entries match these filters." : "No capability inventory is available yet.";
      list.append(empty);
      return;
    }
    for (const item of filtered) {
      const card = document.createElement("article");
      card.className = "capability-row";
      const details = document.createElement("details");
      const summary = document.createElement("summary");
      const isProfile = item.kind === "profiles";
      const canonical = isProfile && item.id === "hermes";
      summary.textContent = canonical ? "Jarvis · primary assistant" : item.name;
      const description = document.createElement("p");
      description.className = "capability-meta";
      description.textContent = typeof item.summary === "string" ? item.summary : "No source description is available.";
      const identity = document.createElement("p");
      identity.className = "capability-meta";
      identity.textContent = isProfile
        ? (canonical ? "Public identity · canonical source ID: hermes" : "Internal profile · catalog only; not selectable")
        : `Catalog ID: ${item.id}`;
      const state = document.createElement("span");
      state.className = "state-pill";
      state.textContent = item.state === "bundled" ? "In offline bundle" : "Catalog status pending";
      const readiness = document.createElement("p");
      readiness.className = "capability-meta";
      readiness.textContent = "Runtime readiness pending; this inventory does not indicate that it is enabled or working.";
      details.append(summary, description, identity, state, readiness);
      card.append(details);
      list.append(card);
    }
  }
  async function loadCapabilities() {
    const data = await request(`${API}/capabilities`);
    capabilityItems = Array.isArray(data.items) ? data.items.filter((item) => item && typeof item.id === "string" && typeof item.name === "string") : [];
    byId("capability-readiness").textContent = data.readiness === "pending"
      ? "Catalog declarations are loaded from the verified offline bundle. Functional readiness remains pending."
      : "Capability readiness has not been verified.";
    const kinds = [...new Set(capabilityItems.map((item) => item.kind).filter((kind) => typeof kind === "string"))].sort();
    const selector = byId("capability-kind");
    selector.replaceChildren(new Option("All types", ""));
    for (const value of kinds) selector.add(new Option(value, value));
    renderCapabilityMap();
    const source = data.source || {};
    byId("capability-source").textContent = source.kind === "offline-bundle"
      ? `Source: verified offline bundle · catalog ${source.catalogVersion || "unknown"} · revision ${source.revision || "unknown"}`
      : "Catalog provenance is unavailable.";
    const discovery = data.nativeDiscovery || {};
    const discoveryLabels = {
      pending: "Runtime discovery is pending; bundled declarations do not mean loaded capabilities.",
      stale: "Runtime discovery is stale; capability activation is unverified.",
      discovered: "A source-bound runtime inventory was observed; capability operation is still unverified."
    };
    const counts = discovery.resourceCounts;
    const resourceSummary = counts && typeof counts === "object"
      ? Object.entries(counts).filter(([, value]) => Number.isFinite(value)).map(([key, value]) => `${key}: ${value}`).join(" · ")
      : "";
    const discoveryObserved = typeof discovery.observedAt === "string" ? new Date(discovery.observedAt) : null;
    const observedLabel = discoveryObserved && !Number.isNaN(discoveryObserved.valueOf()) ? ` Checked ${discoveryObserved.toLocaleString()}.` : "";
    byId("capability-discovery").textContent = `${discoveryLabels[discovery.state] || "Runtime discovery is pending."}${resourceSummary ? ` Inventory: ${resourceSummary}.` : ""}${observedLabel}`;
    byId("capability-search").value = "";
    selector.value = "";
    renderCapabilities();
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
    byId("chat-preferences").open = false;
    const selected = ["chat", "overview", "capabilities", "settings"].includes(view) || featuresById.has(view) ? view : "chat";
    if (selected !== currentView && mountedFeature) unmountFeature();
    if (selected !== currentView && currentView === "capabilities") unmountCapabilitiesDetails();
    currentView = selected;
    const workspace = document.querySelector(".workspace");
    workspace.dataset.currentView = selected;
    ui.toggle.hidden = selected !== "chat";
    if (window.matchMedia("(max-width: 760px)").matches && ui.panel.dataset.open === "true") setPanel(false);
    for (const panel of document.querySelectorAll("[data-view-panel]")) panel.hidden = panel.dataset.viewPanel !== selected;
    for (const button of document.querySelectorAll(".nav-item")) {
      if (button.dataset.view === selected) button.setAttribute("aria-current", "page");
      else button.removeAttribute("aria-current");
    }
    const groupForView = {
      overview: "command-centre", chat: "conversations",
      missions: "work", bots: "work", capabilities: "resources", "resources-learning": "resources",
      "native-inventory": "resources", files: "resources", settings: "system",
      "models-settings": "system", activity: "system", "native-controls": "system"
    };
    const currentGroup = groupForView[selected] || "command-centre";
    for (const group of document.querySelectorAll(".nav-group")) {
      const active = group.dataset.navGroup === currentGroup;
      group.dataset.current = String(active);
      const summary = group.querySelector("summary");
      if (active) summary.setAttribute("aria-current", "location");
      else summary.removeAttribute("aria-current");
    }
    const activeGroup = [...document.querySelectorAll(".nav-group")].find((group) => group.dataset.navGroup === currentGroup);
    const primaryNav = activeGroup && activeGroup.closest(".primary-nav");
    if (activeGroup && primaryNav && primaryNav.scrollWidth > primaryNav.clientWidth) {
      const summary = activeGroup.querySelector("summary");
      const left = summary.offsetLeft - (primaryNav.clientWidth - summary.offsetWidth) / 2;
      const behavior = shouldReduceMotion() ? "auto" : "smooth";
      primaryNav.scrollTo({ left: Math.max(0, left), behavior });
    }
    if (selected !== "chat") {
      stopRecognition("Push-to-talk stopped when leaving chat.");
      stopSpeech("Reply audio stopped when leaving chat.");
    }
    const feature = featuresById.get(selected);
    if (feature) {
      mountFeature(feature);
      return;
    }
    if (selected === "overview") {
      try { await loadOverview(); } catch (_) {
        byId("core-status").textContent = "Unavailable";
        byId("core-readiness").textContent = "The status request failed; functional readiness is not verified.";
        byId("core-observed").textContent = "No current observation is available.";
        byId("conversation-count").textContent = "Unavailable";
        byId("turn-total").textContent = "Unavailable";
        byId("turn-active").textContent = "Unavailable";
        byId("last-turn").textContent = "Last turn is unavailable.";
        byId("turn-breakdown").textContent = "Turn totals are unavailable.";
        byId("chart-caption").textContent = "Recorded daily activity is unavailable.";
        byId("turn-chart").replaceChildren();
      }
    } else if (selected === "capabilities") {
      try { await loadCapabilities(); } catch (_) {
        byId("capability-readiness").textContent = "The catalog request failed. Runtime readiness is not verified.";
        byId("capability-count").textContent = "Catalog entries are unavailable.";
        byId("capability-source").textContent = "Catalog provenance is unavailable.";
        byId("capability-discovery").textContent = "Runtime discovery is unavailable.";
        byId("capability-map").replaceChildren();
        byId("capability-list").replaceChildren();
      }
      if (currentView === "capabilities") mountCapabilitiesDetails();
    } else if (selected === "settings") {
      try { await loadSettings(); } catch (error) { byId("settings-list").replaceChildren(); const row = document.createElement("div"); const term = document.createElement("dt"); const value = document.createElement("dd"); term.textContent = "Status"; value.textContent = error.message; row.append(term, value); byId("settings-list").append(row); }
    }
  }
  byId("capability-search").addEventListener("input", renderCapabilities);
  byId("capability-kind").addEventListener("change", renderCapabilities);
  ui.sessionSearch.addEventListener("input", renderHistory);
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
  ui.voiceInput.addEventListener("click", () => startRecognition("ptt"));
  ui.voiceWake.addEventListener("click", () => {
    if (recognitionMode === "wake") stopRecognition("Foreground wake listening stopped. You can turn it on again any time.");
    else startRecognition("wake");
  });
  ui.voiceStop.addEventListener("click", () => stopRecognition("Speech input stopped. Review the text before sending."));
  ui.speechStop.addEventListener("click", () => stopSpeech("Reply audio stopped."));
  for (const id of ["speech-consent", "chat-speech-consent"]) byId(id).addEventListener("change", (event) => {
    const enabled = Boolean(event.currentTarget.checked);
    byId("speech-consent").checked = enabled;
    byId("chat-speech-consent").checked = enabled;
    if (!enabled) {
      stopRecognition("Voice input is off. You can continue by typing.");
      byId("voice-handsfree-send").checked = false;
      byId("voice-wake-controls").hidden = true;
      ui.voiceWake.hidden = true;
    }
    else {
      byId("voice-wake-controls").hidden = !voiceSupported;
      ui.voiceWake.hidden = !voiceSupported;
      ui.voiceInput.hidden = !voiceSupported || Boolean(activeTurnId);
      showVoiceStatus("Push-to-talk is enabled. Tap Speak when you are ready.");
    }
  });
  for (const id of ["speech-output", "chat-speech-output"]) byId(id).addEventListener("change", (event) => {
    const enabled = Boolean(event.currentTarget.checked);
    if (!enabled) stopSpeech("Read-aloud is off.");
    saveUIPreferences({readAloud: enabled});
    updateSpeechVoiceStatus();
  });
  for (const id of ["speech-voice", "chat-speech-voice"]) byId(id).addEventListener("change", (event) => {
    stopSpeech("Speech voice changed.");
    saveUIPreferences({voiceURI: event.currentTarget.value});
    updateSpeechVoiceStatus();
  });
  for (const id of ["speech-language", "chat-speech-language"]) byId(id).addEventListener("change", (event) => saveUIPreferences({language: event.currentTarget.value}));
  for (const id of ["speech-rate", "chat-speech-rate"]) byId(id).addEventListener("input", (event) => saveUIPreferences({rate: boundedPreferenceNumber(event.currentTarget.value, 0.5, 2, 1)}));
  for (const id of ["speech-pitch", "chat-speech-pitch"]) byId(id).addEventListener("input", (event) => saveUIPreferences({pitch: boundedPreferenceNumber(event.currentTarget.value, 0, 2, 1)}));
  for (const [ids, key, allowed] of [[ ["ui-density", "chat-density"], "density", ["comfortable", "compact"] ], [["ui-text-size", "chat-text-size"], "textSize", ["normal", "large"]], [["ui-motion", "chat-motion"], "motion", ["system", "reduce", "full"]]]) {
    for (const id of ids) byId(id).addEventListener("change", (event) => {
      const value = allowed.includes(event.currentTarget.value) ? event.currentTarget.value : allowed[0];
      saveUIPreferences({[key]: value});
      applyAppearancePreferences();
    });
  }
  const chatPreferences = byId("chat-preferences");
  document.addEventListener("click", (event) => {
    if (chatPreferences.open && !chatPreferences.contains(event.target)) chatPreferences.open = false;
  });
  ui.toggle.addEventListener("click", () => setPanel(ui.panel.dataset.open !== "true"));
  ui.close.addEventListener("click", () => setPanel(false));
  ui.scrim.addEventListener("click", () => setPanel(false));
  for (const group of document.querySelectorAll(".nav-group")) group.querySelector("summary").addEventListener("click", () => {
    for (const other of document.querySelectorAll(".nav-group")) if (other !== group) other.open = false;
  });
  document.addEventListener("click", (event) => {
    if (!event.target.closest(".nav-group")) for (const group of document.querySelectorAll(".nav-group")) group.open = false;
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape") return;
    if (chatPreferences.open) {
      chatPreferences.open = false;
      chatPreferences.querySelector("summary").focus({preventScroll: true});
      return;
    }
    const open = document.querySelector(".nav-group[open]");
    if (!open) return;
    open.open = false;
    open.querySelector("summary").focus({preventScroll: true});
  });
  for (const button of document.querySelectorAll(".nav-item")) button.addEventListener("click", () => {
    for (const group of document.querySelectorAll(".nav-group")) group.open = false;
    showView(button.dataset.view);
  });
  byId("chat-preferences").querySelector(".chat-model-link").addEventListener("click", () => showView("models-settings"));
  byId("jarvis-home").addEventListener("click", (event) => {
    event.preventDefault();
    for (const group of document.querySelectorAll(".nav-group")) group.open = false;
    showView("overview");
  });
  const overviewForm = byId("overview-command-form");
  const overviewInput = byId("overview-command-input");
  const overviewStatus = byId("overview-command-status");
  const overviewSend = overviewForm.querySelector('button[type="submit"]');
  const overviewNewConversation = byId("overview-new-conversation");
  let overviewCommandPending = false;
  let overviewConversationPending = false;
  async function sendOverviewCommand(event) {
    event.preventDefault();
    const text = overviewInput.value.trim();
    if (!text || overviewCommandPending) return;
    if (ui.connection.dataset.state !== "ready" || !conversationHydrated) {
      overviewStatus.textContent = "The secure Jarvis connection is not ready. Your command is still here; try again after it reconnects.";
      overviewStatus.hidden = false;
      return;
    }
    if (activeTurnId || ui.input.disabled || overviewConversationPending) {
      overviewStatus.textContent = "Jarvis is already responding in this conversation. Wait for the response before sending another command.";
      overviewStatus.hidden = false;
      return;
    }
    overviewCommandPending = true;
    overviewInput.disabled = true;
    overviewSend.disabled = true;
    try {
      await showView("chat");
      const accepted = await sendMessage(text);
      if (accepted) {
        overviewInput.value = "";
        overviewStatus.hidden = true;
      } else {
        overviewStatus.textContent = "Jarvis did not accept this command. Your text is preserved here; see the notice in Chat for details.";
        overviewStatus.hidden = false;
      }
    } catch (error) {
      overviewStatus.textContent = "Jarvis could not queue this command. Your text is preserved here; see the notice in Chat for details.";
      overviewStatus.hidden = false;
      showError(error.message);
    } finally {
      overviewCommandPending = false;
      overviewInput.disabled = false;
      overviewSend.disabled = false;
    }
  }
  overviewForm.addEventListener("submit", sendOverviewCommand);
  overviewInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
      event.preventDefault(); overviewForm.requestSubmit();
    }
  });
  overviewInput.addEventListener("input", () => {
    overviewInput.style.height = "auto";
    overviewInput.style.height = `${Math.min(overviewInput.scrollHeight, 144)}px`;
  });
  for (const button of document.querySelectorAll("[data-command-prompt]")) button.addEventListener("click", () => {
    overviewInput.value = button.dataset.commandPrompt;
    overviewInput.dispatchEvent(new Event("input", {bubbles: true}));
    overviewInput.focus({preventScroll: true});
    overviewInput.setSelectionRange(overviewInput.value.length, overviewInput.value.length);
  });
  overviewNewConversation.addEventListener("click", async () => {
    if (overviewCommandPending || overviewConversationPending) return;
    if (ui.connection.dataset.state !== "ready" || !conversationHydrated) {
      overviewStatus.textContent = "Wait for the secure Jarvis connection before starting a conversation.";
      overviewStatus.hidden = false;
      return;
    }
    if (activeTurnId || ui.input.disabled) {
      overviewStatus.textContent = "Wait for Jarvis to finish the current response before starting a new conversation.";
      overviewStatus.hidden = false;
      return;
    }
    overviewConversationPending = true;
    overviewNewConversation.disabled = true;
    overviewStatus.hidden = true;
    try {
      await showView("chat");
      await createConversation();
    } finally {
      overviewConversationPending = false;
      overviewNewConversation.disabled = false;
    }
  });
  window.addEventListener("pagehide", () => { closeStream(); stopRecognition(); stopSpeech(); if (presenceObserver) presenceObserver.disconnect(); unmountFeature(); });
  function syncPageVisibility() {
    const visible = String(document.visibilityState === "visible");
    document.documentElement.dataset.pageVisible = visible;
    const presence = byId("jarvis-presence");
    if (presence) presence.dataset.pageVisible = visible;
  }
  document.addEventListener("visibilitychange", () => {
    syncPageVisibility();
    if (document.visibilityState !== "visible") {
      stopRecognition("Voice listening stopped when this page went into the background.");
      stopSpeech("Reply audio stopped when this page went into the background.");
    }
  });
  const presence = byId("jarvis-presence");
  syncPageVisibility();
  if (presence && "IntersectionObserver" in window) {
    presenceObserver = new IntersectionObserver((entries) => {
      for (const entry of entries) if (entry.target === presence) presence.dataset.inViewport = String(entry.isIntersecting);
    }, {threshold: 0.08});
    presenceObserver.observe(presence);
  } else if (presence) presence.dataset.inViewport = "true";
  loadUIPreferences();
  configureVoice();
  showView("overview");
  (async () => {
    try {
      await refreshConversations();
      setConnection("ready", "Secure connection");
      setAssistantState("ready", "Ready for your message");
      if (conversations.length) await loadConversation(conversations[0].id);
      conversationHydrated = true;
    } catch (error) {
      setConnection("error", "Access unavailable");
      showError(error.message);
    }
  })();
})();
'''.encode("utf-8")


def _compose_feature_assets() -> None:
    """Embed reviewed views in HTML/CSS and serve feature code separately."""
    global _HTML, _CSS, _JS, _FEATURES_JS
    validate_feature_assets(FEATURE_ASSETS)
    grouped_nav: dict[str, list[str]] = {"work": [], "resources": [], "system": []}
    panels: list[str] = []
    css_fragments: list[bytes] = []
    javascript: list[str] = []
    for feature in FEATURE_ASSETS:
        feature_id = escape(feature.feature_id, quote=True)
        nav_label = escape(feature.nav_label)
        title = escape(feature.title, quote=True)
        nav_markup = (
            f'<button type="button" class="nav-item" data-view="{feature_id}">'
            f'{nav_label}</button>'
        )
        group = {
            "missions": "work", "bots": "work",
            "resources-learning": "resources", "native-inventory": "resources", "files": "resources",
            "activity": "system", "native-controls": "system", "models-settings": "system",
        }.get(feature.feature_id)
        if group is None:
            raise ValueError(f"reviewed Jarvis feature has no navigation group: {feature.feature_id}")
        grouped_nav[group].append(nav_markup)
        panels.append(
            f'<section class="data-main" id="{feature_id}-view" '
            f'aria-label="{title}" data-view-panel="{feature_id}" hidden>'
            f'<div class="feature-view" data-feature-root="{feature_id}">'
            f'{feature.view_html}</div></section>'
        )
        if feature.css:
            css_fragments.append(feature.css.encode("utf-8"))
        routes = json.dumps(
            [{"method": method, "path": path} for method, path in feature.api_routes],
            ensure_ascii=True,
            separators=(",", ":"),
        )
        javascript.append(
            "{id:" + json.dumps(feature_id) + ",routes:" + routes
            + ",mount:(" + feature.mount_js + "),unmount:(" + feature.unmount_js + ")}"
        )

    html = _HTML.decode("utf-8")
    html = html.replace("<!-- JARVIS_GROUP_WORK -->", "".join(grouped_nav["work"]))
    html = html.replace("<!-- JARVIS_GROUP_RESOURCES -->", "".join(grouped_nav["resources"]))
    html = html.replace("<!-- JARVIS_GROUP_SYSTEM -->", "".join(grouped_nav["system"]))
    html = html.replace("<!-- JARVIS_FEATURE_PANELS -->", "".join(panels))
    html = html.replace("__JARVIS_CAPABILITY_DETAILS__", _CAPABILITY_DETAILS_HTML)
    if "JARVIS_FEATURE_" in html or "JARVIS_GROUP_" in html:
        raise ValueError("Jarvis feature asset template markers were not fully replaced")
    script = _JS.decode("utf-8")
    feature_script = "window.JARVIS_FEATURE_ASSETS=[" + ",".join(javascript) + "];"
    script = script.replace("__JARVIS_CAPABILITY_DETAILS_MOUNT__", _CAPABILITY_DETAILS_MOUNT_JS)
    if "__JARVIS_CAPABILITY_DETAILS_MOUNT__" in script:
        raise ValueError("Jarvis capability detail marker was not fully replaced")
    if "__JARVIS_CAPABILITY_DETAILS__" in html:
        raise ValueError("Jarvis capability detail markup was not composed")
    _HTML = html.encode("utf-8")
    _CSS += ("\n".encode("utf-8") + b"\n".join(css_fragments)) if css_fragments else b""
    _CSS += ("\n" + _CAPABILITY_DETAILS_CSS).encode("utf-8")
    _JS = script.encode("utf-8")
    _FEATURES_JS = feature_script.encode("utf-8")


_compose_feature_assets()

_ASSETS = MappingProxyType({
    "/chat": ("text/html; charset=utf-8", _HTML),
    "/chat/": ("text/html; charset=utf-8", _HTML),
    "/chat/assets/app.css": ("text/css; charset=utf-8", _CSS),
    "/chat/assets/app.js": ("text/javascript; charset=utf-8", _JS),
    "/chat/assets/features.js": ("text/javascript; charset=utf-8", _FEATURES_JS),
})


def reviewed_chat_asset(path: str) -> tuple[str, bytes]:
    """Return one exact reviewed Jarvis asset or deny an unknown route."""
    try:
        return _ASSETS[path]
    except (KeyError, TypeError):
        raise ValueError("route is outside the reviewed Jarvis chat asset set") from None
