"""Static owner-facing fragment for bounded native file attachment staging."""
from __future__ import annotations

from .jarvis_feature_contract import JarvisFeatureAssets
from .jarvis_files import FEATURE_ROUTES

_VIEW = """<section class="files-page" aria-labelledby="files-title">
  <header class="files-heading"><p class="files-eyebrow">PRIVATE CONVERSATION FILES</p><h1 id="files-title">Files</h1>
    <p>Stage a small text file for Jarvis to use in your next message.</p></header>
  <section class="files-card" aria-labelledby="stage-title">
    <h2 id="stage-title">Stage a file</h2>
    <label for="files-conversation">Conversation</label>
    <select id="files-conversation" data-conversation><option value="">Loading conversations…</option></select>
    <label for="files-input">Text file</label>
    <input id="files-input" data-file type="file" accept=".txt,.md,.csv,.json,text/plain,text/markdown,text/csv,application/json">
    <p class="files-hint">TXT, Markdown, CSV, or JSON · up to 128 KiB · UTF-8 text only</p>
    <section class="files-preview" data-preview hidden aria-labelledby="files-preview-title">
      <h3 id="files-preview-title">Selected upload bytes</h3>
      <p data-preview-meta class="files-meta"></p>
      <pre data-preview-bytes tabindex="0" aria-label="UTF-8 preview of the selected upload"></pre>
    </section>
    <button type="button" data-upload disabled>Stage for next message</button>
    <p data-note role="status" aria-live="polite">File contents are sent to the selected private conversation when you next message Jarvis.</p>
  </section>
  <section class="files-card" aria-labelledby="staged-title">
    <div class="files-list-heading"><h2 id="staged-title">Conversation files</h2><button type="button" data-refresh>Refresh</button></div>
    <ul data-files aria-live="polite"></ul>
    <p data-empty class="files-empty" hidden>No files are staged for this conversation.</p>
  </section>
  <p class="files-limitation">The preview reads only the selected upload bytes in this browser. “Staged” means ready for a next message; “Consumed by a turn” means that turn claimed the attachment. Produced artifacts, native file reads, and downloads are unavailable through this interface.</p>
</section>"""

_CSS = """
[data-feature-root="files"] .files-page{max-width:var(--page-max-width,1240px);margin:0 auto;padding:clamp(1rem,3vw,2.4rem);color:var(--text,#e8f3f5)}
[data-feature-root="files"] .files-heading{margin-bottom:1.5rem}
[data-feature-root="files"] .files-heading h1{margin:.35rem 0;font-size:clamp(1.8rem,4vw,2.6rem)}
[data-feature-root="files"] .files-heading p:last-child,[data-feature-root="files"] .files-hint,[data-feature-root="files"] .files-limitation{color:var(--muted,#91a9ae);line-height:1.55}
[data-feature-root="files"] .files-eyebrow{font-size:.72rem;letter-spacing:.14em;color:var(--cyan,#58e4eb);margin:0}
[data-feature-root="files"] .files-card{border:1px solid var(--line,rgba(123,197,213,.14));border-radius:16px;background:var(--panel,#0b1c24);padding:1.15rem;margin:1rem 0}
[data-feature-root="files"] .files-card h2{font-size:1.05rem;margin:.2rem 0 .9rem}
[data-feature-root="files"] label{display:block;margin:.75rem 0 .4rem;color:var(--muted,#91a9ae);font-size:.85rem}
[data-feature-root="files"] select,[data-feature-root="files"] input[type=file]{display:block;width:100%;min-height:44px;border:1px solid var(--line-strong,rgba(72,221,235,.36));border-radius:9px;background:var(--bg,#071319);color:inherit;padding:.6rem}
[data-feature-root="files"] input[type=file]::file-selector-button{min-height:44px;margin-right:.8rem;border:1px solid var(--line,rgba(123,197,213,.14));border-radius:7px;background:var(--panel-2,#0e242d);color:inherit;padding:.35rem .6rem}
[data-feature-root="files"] button{min-height:44px;background:transparent;border:1px solid var(--line-strong,rgba(72,221,235,.36));color:inherit;border-radius:8px;padding:.55rem .85rem;cursor:pointer}
[data-feature-root="files"] button:disabled{opacity:.5;cursor:not-allowed}
[data-feature-root="files"] .files-hint{font-size:.78rem;margin:.45rem 0 .8rem}
[data-feature-root="files"] .files-preview{margin:.9rem 0;padding:.8rem;border:1px solid var(--line,rgba(123,197,213,.14));border-radius:10px;background:var(--panel-2,#0e242d)}
[data-feature-root="files"] .files-preview h3{margin:.1rem 0 .4rem;font-size:.88rem}
[data-feature-root="files"] .files-preview pre{max-height:18rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;margin:.6rem 0 0;padding:.7rem;border-radius:7px;background:rgba(0,0,0,.18);font: .78rem/1.5 ui-monospace,monospace}
[data-feature-root="files"] [data-note]{min-height:1.3em;color:var(--muted,#91a9ae);font-size:.82rem}
[data-feature-root="files"] .files-list-heading{display:flex;align-items:center;justify-content:space-between;gap:1rem}
[data-feature-root="files"] .files-list-heading h2{margin:.2rem 0 .8rem}
[data-feature-root="files"] [data-files]{list-style:none;margin:0;padding:0}
[data-feature-root="files"] [data-files] li{display:flex;align-items:center;justify-content:space-between;gap:1rem;padding:.8rem .2rem;border-top:1px solid var(--line,rgba(123,197,213,.14))}
[data-feature-root="files"] .files-name{font-weight:600;overflow-wrap:anywhere}
[data-feature-root="files"] .files-meta{display:block;margin-top:.2rem;color:var(--muted,#91a9ae);font-size:.77rem}
[data-feature-root="files"] .files-state{flex:none;color:var(--cyan,#58e4eb);font-size:.77rem;text-transform:capitalize}
[data-feature-root="files"] .files-empty{color:var(--muted,#91a9ae)}
[data-feature-root="files"] .files-limitation{font-size:.78rem}
"""

_MOUNT = r"""function mount(container, api, state) {
const root = container.querySelector('[data-feature-root="files"]') || container;
const conversationSelect = root.querySelector('[data-conversation]');
const fileInput = root.querySelector('[data-file]');
const uploadButton = root.querySelector('[data-upload]');
const refreshButton = root.querySelector('[data-refresh]');
const note = root.querySelector('[data-note]');
const preview = root.querySelector('[data-preview]');
const previewMeta = root.querySelector('[data-preview-meta]');
const previewBytes = root.querySelector('[data-preview-bytes]');
const list = root.querySelector('[data-files]');
const empty = root.querySelector('[data-empty]');
let stopped = false, busy = false, pendingAttempt = null, conversationId = '', previewRevision = 0;
let filesReadRevision = 0;
function call(method, path, body) {
if (stopped) return Promise.reject(new Error('View closed'));
return method === 'GET' ? api.get(path) : api.post(path, body);
}
function filesPath(id = conversationId) { return '/chat/api/conversations/' + encodeURIComponent(id) + '/files'; }
function addText(parent, tag, text, className) { const node = document.createElement(tag); if (className) node.className = className; node.textContent = text; parent.append(node); return node; }
function sizeText(value) { return !Number.isSafeInteger(value) || value < 0 ? 'Unknown size' : value < 1024 ? value + ' B' : (value / 1024).toFixed(1) + ' KiB'; }
function renderFiles(items) {
list.replaceChildren();
for (const file of (Array.isArray(items) ? items : [])) {
if (!file || typeof file.name !== 'string' || typeof file.id !== 'string') continue;
const row = document.createElement('li');
const detail = document.createElement('span');
addText(detail, 'span', file.name, 'files-name');
addText(detail, 'span', (typeof file.mime_type === 'string' ? file.mime_type : 'Text file') + ' · ' +
sizeText(file.size_bytes) + (typeof file.sha256 === 'string' && /^[a-f0-9]{64}$/.test(file.sha256) ?
' · SHA-256 ' + file.sha256 : '') + (Number.isFinite(file.created_at) ?
' · ' + new Date(file.created_at * 1000).toLocaleString() : ''), 'files-meta');
row.append(detail);
const stateLabel = ({ready: 'Ready for next message', attached: 'Consumed by turn', pending: 'Staging', unavailable: 'Unavailable'})[file.state] || 'Unknown';
addText(row, 'span', stateLabel, 'files-state');
list.append(row);
}
empty.hidden = list.childElementCount > 0;
}
async function refreshFiles() {
if (stopped || !conversationId) return;
const targetConversation = conversationId, revision = ++filesReadRevision;
const isCurrent = () => !stopped && revision === filesReadRevision && targetConversation === conversationId;
refreshButton.disabled = true;
try { const data = await call('GET', filesPath(targetConversation)); if (isCurrent()) renderFiles(data && data.files); }
catch (_) { if (isCurrent()) note.textContent = 'File status is temporarily unavailable.'; }
finally { if (isCurrent()) refreshButton.disabled = busy; }
}
async function loadConversations() {
try {
const data = await call('GET', '/chat/api/conversations');
if (stopped) return;
conversationSelect.replaceChildren();
for (const conversation of (data && Array.isArray(data.conversations) ? data.conversations : [])) {
if (!conversation || typeof conversation.id !== 'string') continue;
const option = document.createElement('option');
option.value = conversation.id;
option.textContent = typeof conversation.title === 'string' ? conversation.title : 'Conversation'; conversationSelect.append(option);
}
conversationId = conversationSelect.value || '';
if (!conversationId) {
const option = document.createElement('option');
option.value = ''; option.textContent = 'Create a conversation in Chat first'; conversationSelect.append(option);
note.textContent = 'Create a conversation in Chat before staging files.'; uploadButton.disabled = true;
} else {
note.textContent = 'File contents are sent to the selected private conversation when you next message Jarvis.';
uploadButton.disabled = !fileInput.files || fileInput.files.length === 0; await refreshFiles();
}
} catch (_) {
if (!stopped) note.textContent = 'Conversation list is temporarily unavailable.';
}
}
function toBase64(buffer) {
const bytes = new Uint8Array(buffer); let binary = '';
for (let offset = 0; offset < bytes.length; offset += 0x8000) binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
return btoa(binary);
}
async function previewSelectedFile(file, revision) {
preview.hidden = true; previewMeta.textContent = previewBytes.textContent = '';
if (!file) return false;
if (file.size < 1 || file.size > 131072 || !/\.(txt|md|csv|json)$/i.test(file.name) ||
!/^[A-Za-z0-9][A-Za-z0-9._ -]{0,119}$/.test(file.name) || file.name.includes('..')) {
note.textContent = 'Choose supported text up to 128 KiB.'; return false;
}
try {
const decoded = new TextDecoder('utf-8', {fatal:true}).decode(await file.arrayBuffer());
if (stopped || revision !== previewRevision || fileInput.files?.[0] !== file) return false;
previewMeta.textContent = file.name + ' · ' + sizeText(file.size) + ' · UTF-8 bytes';
previewBytes.textContent = decoded; preview.hidden = false;
note.textContent = 'UTF-8 upload preview ready; stage to attach it.'; return true;
} catch (_) {
if (!stopped && revision === previewRevision && fileInput.files?.[0] === file) note.textContent = 'Invalid UTF-8 text.';
return false;
}
}
function previewChoice(file) {
const revision = ++previewRevision, selectedConversation = conversationId;
previewSelectedFile(file, revision).then((valid) => {
if (!stopped && revision === previewRevision && selectedConversation === conversationId && fileInput.files?.[0] === file)
uploadButton.disabled = !selectedConversation || !valid;
});
}
async function stageFile() {
if (stopped || busy || !conversationId) return;
const targetConversation = conversationId;
const file = fileInput.files?.[0];
if (!file) return;
busy = true;
uploadButton.disabled = true;
fileInput.disabled = true;
conversationSelect.disabled = true;
refreshButton.disabled = true;
try {
if (!(await previewSelectedFile(file, ++previewRevision)) || stopped || targetConversation !== conversationId || fileInput.files?.[0] !== file) return;
note.textContent = 'Staging attachment…';
if (!pendingAttempt || pendingAttempt.file !== file || pendingAttempt.conversationId !== targetConversation) {
pendingAttempt = {file, conversationId: targetConversation, body: {
name: file.name, content_base64: toBase64(await file.arrayBuffer()),
idempotency_key: crypto.randomUUID().replaceAll('-', '')
}};
}
await call('POST', filesPath(targetConversation), pendingAttempt.body);
if (stopped) return;
pendingAttempt = null;
fileInput.value = '';
note.textContent = 'Attachment staged for next message.';
try {
renderFiles((await call('GET', filesPath(targetConversation))).files);
} catch (_) {
if (!stopped) note.textContent = 'Staged; refresh status.';
}
} catch (_) {
if (!stopped) note.textContent = 'No receipt; reselect same file to retry.';
} finally {
busy = false;
if (!stopped) {
conversationSelect.disabled = false;
fileInput.disabled = false;
refreshButton.disabled = false;
uploadButton.disabled = !conversationId || !fileInput.files?.length;
}
}
}
function onConversationChange() {
conversationId = conversationSelect.value || '';
filesReadRevision++;
pendingAttempt = null;
renderFiles([]);
uploadButton.disabled = true;
previewChoice(fileInput.files?.[0]);
refreshFiles();
}
function onFileChange() {
pendingAttempt = null;
const file = fileInput.files?.[0];
uploadButton.disabled = true;
previewChoice(file);
}
conversationSelect.addEventListener('change', onConversationChange);
fileInput.addEventListener('change', onFileChange);
uploadButton.addEventListener('click', stageFile);
refreshButton.addEventListener('click', refreshFiles);
loadConversations();
return function cleanup() {
stopped = true;
previewRevision++;
conversationSelect.removeEventListener('change', onConversationChange);
fileInput.removeEventListener('change', onFileChange);
uploadButton.removeEventListener('click', stageFile);
refreshButton.removeEventListener('click', refreshFiles);
preview.hidden = true;
previewMeta.textContent = '';
previewBytes.textContent = '';
};
}"""

_UNMOUNT = "function unmount() {}"

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="files",
    nav_label="Files",
    title="Files",
    view_html=_VIEW,
    css=_CSS,
    api_routes=FEATURE_ROUTES,
    mount_js=_MOUNT,
    unmount_js=_UNMOUNT,
)
