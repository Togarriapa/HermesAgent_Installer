"""Static, offline-free mobile and tablet guidance for the Jarvis dashboard.

This reviewed feature fragment deliberately owns no APIs, microphone prompts,
credentials, or device-specific claims. The root feature registry may include
it after review; this module does not wire itself into the shared shell.
"""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets


_VIEW = """<section class="mobile-page" data-feature-root="mobile" aria-labelledby="mobile-title">
  <header class="mobile-heading">
    <p class="mobile-eyebrow">THIS DEVICE</p>
    <h1 id="mobile-title">Use Jarvis on a small screen</h1>
    <p>Chat and dashboard views adapt to the available screen width. Text chat remains the reliable option on every device.</p>
  </header>
  <p class="mobile-layout-state" data-layout-state role="status" aria-live="polite">Checking the current layout…</p>
  <section class="mobile-card" aria-labelledby="mobile-install-title">
    <h2 id="mobile-install-title">Add a home-screen shortcut</h2>
    <p data-launch-state>Jarvis is open in a browser tab.</p>
    <details>
      <summary>Show browser instructions</summary>
      <p>Open this browser’s menu and choose its Add to Home Screen or install option if one is offered. The wording and launch style depend on the browser.</p>
      <p>Jarvis needs a live connection and normal sign-in. This page does not provide offline chat or cache authentication for offline use.</p>
    </details>
  </section>
  <section class="mobile-card" aria-labelledby="mobile-keyboard-title">
    <h2 id="mobile-keyboard-title">Typing and touch</h2>
    <ul>
      <li>Tap the message box to open your device keyboard. The composer stays text-based and can be used without speech features.</li>
      <li>Use the Chat and Sessions controls to return to a conversation or find an earlier one.</li>
      <li>On a tablet or wider screen, the same views use the available width; rotate or resize the browser to adjust the layout.</li>
    </ul>
  </section>
  <section class="mobile-card" aria-labelledby="mobile-voice-title">
    <h2 id="mobile-voice-title">Browser speech and native assistant features</h2>
    <p>Optional browser push-to-talk and read-aloud settings are in Settings under Voice preferences. Recognition may use a browser or platform speech service outside Jarvis; the available service depends on the browser and device.</p>
    <p>Android assistant-role access and locked-screen wake are separate features and have not been qualified for this installer. A browser shortcut does not enable background listening.</p>
  </section>
</section>"""

_CSS = """
[data-feature-root="mobile"]{max-width:820px;margin:0 auto;padding:clamp(1rem,4vw,2rem);color:var(--text,#edf5f6);padding-bottom:calc(1.5rem + env(safe-area-inset-bottom))}
[data-feature-root="mobile"] .mobile-heading{max-width:680px;margin-bottom:1.25rem}
[data-feature-root="mobile"] .mobile-eyebrow{margin:0;color:var(--accent,#83d9ca);font-size:.72rem;letter-spacing:.13em}
[data-feature-root="mobile"] h1{margin:.4rem 0;font-size:clamp(1.65rem,5vw,2.25rem);line-height:1.15}
[data-feature-root="mobile"] .mobile-heading>p:last-child,[data-feature-root="mobile"] .mobile-card p,[data-feature-root="mobile"] .mobile-card li{color:var(--muted,#9bafb4);font-size:1rem;line-height:1.65}
[data-feature-root="mobile"] .mobile-layout-state{padding:.7rem .85rem;border-left:3px solid var(--accent,#83d9ca);background:rgba(255,255,255,.035);line-height:1.5}
[data-feature-root="mobile"] .mobile-card{margin:1rem 0;padding:clamp(1rem,3vw,1.3rem);border:1px solid var(--border,#294047);border-radius:15px;background:var(--panel,#0d1d23);overflow-wrap:anywhere}
[data-feature-root="mobile"] .mobile-card h2{margin:0 0 .65rem;font-size:1.1rem}
[data-feature-root="mobile"] .mobile-card p{margin:.45rem 0}
[data-feature-root="mobile"] .mobile-card ul{margin:.3rem 0 0;padding-inline-start:1.35rem}
[data-feature-root="mobile"] .mobile-card li{padding:.2rem 0}
[data-feature-root="mobile"] summary{min-height:44px;display:flex;align-items:center;cursor:pointer;font-weight:650;touch-action:manipulation}
[data-feature-root="mobile"] summary:focus-visible{outline:2px solid var(--accent,#83d9ca);outline-offset:3px;border-radius:4px}
@media(max-width:760px){[data-feature-root="mobile"]{padding-inline:1rem}[data-feature-root="mobile"] .mobile-card{border-radius:12px}}
@media(prefers-reduced-motion:reduce){[data-feature-root="mobile"] *{scroll-behavior:auto!important}}
"""

_MOUNT = r"""function mount(container, api) {
  const root = container.querySelector('[data-feature-root="mobile"]');
  if (!root) return function cleanup() {};
  const layout = root.querySelector('[data-layout-state]');
  const launch = root.querySelector('[data-launch-state]');
  const compact = window.matchMedia('(max-width: 760px)');
  const standalone = window.matchMedia('(display-mode: standalone)').matches
    || window.navigator.standalone === true;
  function render() {
    layout.textContent = compact.matches
      ? 'Compact layout is active for this browser width.'
      : 'Wide layout is active for this browser width.';
    launch.textContent = standalone
      ? 'This browser reports that Jarvis is open in a standalone window.'
      : 'Jarvis is open in a browser tab. A home-screen shortcut may be available from the browser menu.';
  }
  compact.addEventListener('change', render);
  render();
  return function cleanup() { compact.removeEventListener('change', render); };
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="mobile",
    nav_label="On this device",
    title="On this device",
    view_html=_VIEW,
    css=_CSS,
    api_routes=(),
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
