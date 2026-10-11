"""Reviewed static UI fragment for owner-only mission planning."""
from .jarvis_feature_contract import JarvisFeatureAssets

FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="missions",
    nav_label="Missions",
    title="Missions",
    view_html="""
<section class="jm-shell" aria-labelledby="jm-heading">
  <header class="jm-header">
    <div><p class="jm-eyebrow">OWNER WORKSPACE</p><h1 id="jm-heading">Mission planning</h1>
      <p class="jm-intro">Jarvis remains the master for every task. Save a brief and inspect its source-backed plan; experts prepare internal work for Jarvis review.</p></div>
    <button class="jm-refresh" type="button" data-jm-refresh>Refresh</button>
  </header>
  <div class="jm-state" data-jm-state role="status" aria-live="polite">Loading your private mission drafts…</div>
  <div class="jm-grid">
    <section class="jm-panel" aria-labelledby="jm-new-heading">
      <p class="jm-eyebrow">NEW DRAFT</p><h2 id="jm-new-heading">Describe the outcome</h2>
      <form data-jm-form>
        <label for="jm-title">Mission title</label>
        <input id="jm-title" name="title" maxlength="120" required autocomplete="off" placeholder="Prepare the weekly operations brief">
        <label for="jm-brief">Brief and constraints</label>
        <textarea id="jm-brief" name="brief" maxlength="8000" rows="6" required placeholder="Describe the requested outcome, sources that may be used, and constraints."></textarea>
        <fieldset><legend>Source preferences for Jarvis</legend>
          <p class="jm-help">These preferences do not choose the team. Jarvis selects the exact internal profiles in its protected plan; experts prepare drafts for Jarvis review.</p>
          <div class="jm-team-options" data-jm-team-options><span class="jm-muted">Loading verified identities…</span></div>
        </fieldset>
        <button class="jm-primary" type="submit">Save draft</button>
      </form>
    </section>
    <section class="jm-panel" aria-labelledby="jm-list-heading">
      <div class="jm-list-heading"><div><p class="jm-eyebrow">PRIVATE TO YOU</p><h2 id="jm-list-heading">Saved drafts</h2></div><span class="jm-count" data-jm-count>0</span></div>
      <div class="jm-list" data-jm-list><p class="jm-muted">Your saved drafts will appear here.</p></div>
    </section>
  </div>
  <section class="jm-panel jm-preview" data-jm-preview hidden aria-labelledby="jm-preview-heading">
    <div class="jm-list-heading"><div><p class="jm-eyebrow">SOURCE-BOUND PLAN</p><h2 id="jm-preview-heading">Preview</h2></div><span class="jm-pending-badge">Execution pending</span></div>
    <div data-jm-preview-content></div>
    <p class="jm-boundary">Experts can propose internal drafts only. Jarvis review is always required before a final effect. Owner approval is required by default; fully autonomous authorization is explicit, task-scoped, and does not grant experts final-effect authority. Unknown launch outcomes are never retried automatically.</p>
  </section>
</section>
""",
    css="""
[data-feature-root="missions"] .jm-shell{--jm-accent:var(--cyan,#58e4eb);--jm-border:var(--line,rgba(123,197,213,.14));--jm-surface:var(--panel,#0b1c24);--jm-surface-raised:var(--panel-2,#0e242d);--jm-input:var(--bg,#071319);--jm-muted:var(--muted,#91a9ae);max-width:var(--page-max-width,1240px);margin:0 auto;padding:clamp(18px,3vw,38px);color:var(--text,#e8f3f5)}
[data-feature-root="missions"] .jm-header,[data-feature-root="missions"] .jm-list-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:20px}
[data-feature-root="missions"] .jm-header{margin-bottom:22px}
[data-feature-root="missions"] .jm-eyebrow{margin:0 0 8px;color:var(--jm-accent);font-size:.69rem;font-weight:750;letter-spacing:.14em}
[data-feature-root="missions"] h1,[data-feature-root="missions"] h2{margin:0;font-weight:650;letter-spacing:-.025em}
[data-feature-root="missions"] h1{font-size:clamp(1.7rem,3vw,2.5rem)}
[data-feature-root="missions"] h2{font-size:1.08rem}
[data-feature-root="missions"] .jm-intro{max-width:680px;color:var(--jm-muted);line-height:1.55}
[data-feature-root="missions"] .jm-grid{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(280px,.95fr);gap:16px}
[data-feature-root="missions"] .jm-panel{min-width:0;padding:22px;border:1px solid var(--jm-border);border-radius:16px;background:var(--jm-surface)}
[data-feature-root="missions"] form{display:grid;gap:10px;margin-top:18px}
[data-feature-root="missions"] label,[data-feature-root="missions"] legend{font-size:.86rem;font-weight:650}
[data-feature-root="missions"] input:not([type="checkbox"]):not([type="radio"]),[data-feature-root="missions"] textarea,[data-feature-root="missions"] select{box-sizing:border-box;width:100%;min-height:44px;padding:11px 12px;border:1px solid var(--jm-border);border-radius:9px;background:var(--jm-input);color:inherit;font:inherit}
[data-feature-root="missions"] textarea{resize:vertical;line-height:1.5}
[data-feature-root="missions"] fieldset{min-width:0;margin:8px 0 2px;padding:14px;border:1px solid var(--jm-border);border-radius:10px}
[data-feature-root="missions"] .jm-help,[data-feature-root="missions"] .jm-muted{color:var(--jm-muted);font-size:.82rem;line-height:1.5}
[data-feature-root="missions"] .jm-team-options{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;max-height:220px;overflow:auto}
[data-feature-root="missions"] .jm-team-option{display:flex;align-items:center;min-height:44px;gap:9px;padding:9px;border:1px solid var(--jm-border);border-radius:8px;font-size:.8rem;font-weight:500}
[data-feature-root="missions"] .jm-team-option input{width:auto;margin:2px 0 0;accent-color:var(--jm-accent)}
[data-feature-root="missions"] button{min-height:44px;padding:9px 14px;border:1px solid var(--jm-border);border-radius:9px;background:var(--jm-surface-raised);color:inherit;font:inherit;font-size:.84rem;font-weight:650;cursor:pointer}
[data-feature-root="missions"] button:focus-visible,[data-feature-root="missions"] input:focus-visible,[data-feature-root="missions"] textarea:focus-visible{outline:2px solid var(--jm-accent);outline-offset:2px}
[data-feature-root="missions"] button:hover{border-color:var(--jm-accent)}
[data-feature-root="missions"] .jm-primary{justify-self:start;background:var(--jm-accent);border-color:var(--jm-accent);color:#071319}
[data-feature-root="missions"] .jm-approval{margin-top:14px}
[data-feature-root="missions"] .jm-refresh{flex:none}
[data-feature-root="missions"] .jm-count,[data-feature-root="missions"] .jm-pending-badge{padding:5px 9px;border-radius:999px;background:color-mix(in srgb,var(--jm-accent) 14%,transparent);color:var(--jm-accent);font-size:.75rem;font-weight:700}
[data-feature-root="missions"] .jm-list{display:grid;gap:9px;margin-top:18px}
[data-feature-root="missions"] .jm-card{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border:1px solid var(--jm-border);border-radius:10px}
[data-feature-root="missions"] .jm-card-title{margin:0 0 5px;font-weight:650;overflow-wrap:anywhere}
[data-feature-root="missions"] .jm-card-meta{margin:0;color:var(--jm-muted);font-size:.75rem}
[data-feature-root="missions"] .jm-preview{margin-top:16px}
[data-feature-root="missions"] .jm-plan-brief{white-space:pre-wrap;overflow-wrap:anywhere;color:var(--jm-muted);line-height:1.55}
[data-feature-root="missions"] .jm-team-row{display:grid;grid-template-columns:minmax(120px,.6fr) minmax(0,1fr);gap:4px 14px;padding:12px 0;border-top:1px solid var(--jm-border)}
[data-feature-root="missions"] .jm-team-row strong{overflow-wrap:anywhere}
[data-feature-root="missions"] .jm-team-row span{color:var(--jm-muted);font-size:.82rem;line-height:1.45}
[data-feature-root="missions"] .jm-hash{color:var(--jm-muted);font: .74rem ui-monospace,monospace;overflow-wrap:anywhere}
[data-feature-root="missions"] .jm-boundary{margin:18px 0 0;padding:12px;border-left:3px solid var(--jm-accent);background:color-mix(in srgb,var(--jm-accent) 7%,transparent);color:var(--jm-muted);font-size:.8rem;line-height:1.5}
[data-feature-root="missions"] .jm-state{min-height:1.4em;margin:10px 0;color:var(--jm-muted);font-size:.84rem}
[data-feature-root="missions"] .jm-state[data-kind="error"]{color:var(--danger,#ff9e9e)}
[data-feature-root="missions"] [hidden]{display:none!important}
@media(max-width:760px){[data-feature-root="missions"] .jm-grid{grid-template-columns:1fr}[data-feature-root="missions"] .jm-header{align-items:center}}
""",
    api_routes=(
        ("GET", "/chat/api/missions"),
        ("POST", "/chat/api/missions"),
        ("GET", "/chat/api/missions/{mission_id}"),
        ("POST", "/chat/api/missions/{mission_id}/preview"),
        ("POST", "/chat/api/missions/{mission_id}/approve"),
        ("POST", "/chat/api/missions/{mission_id}/launch"),
        ("POST", "/chat/api/missions/{mission_id}/stop"),
        ("POST", "/chat/api/missions/{mission_id}/review"),
    ),
    mount_js=r'''function mount(container, api, state) {
  const root = container.querySelector('[data-feature-root="missions"]') || container;
  const abort = new AbortController();
  let mounted = true;
  let generation = 0;
  let retryPayload = '';
  let retryKey = '';
  let approvalRetryPlan = '';
  let approvalRetryKey = '';
  let approvalRetryAcknowledged = false;
  let activePreview = null;
  let activeApprovalNonce = null;
  let launchAttempted = false;
  const signal = abort.signal;
  const el = (selector) => root.querySelector(selector);
  const stateNode = el('[data-jm-state]');
  const listNode = el('[data-jm-list]');
  const optionsNode = el('[data-jm-team-options]');
  const previewPanel = el('[data-jm-preview]');
  const setMessage = (message, kind = 'info') => {
    if (!mounted) return;
    stateNode.textContent = message;
    stateNode.dataset.kind = kind;
  };
  const addText = (parent, tag, className, value) => {
    const node = document.createElement(tag);
    if (className) node.className = className;
    node.textContent = value == null ? '' : String(value);
    parent.append(node);
    return node;
  };
  const renderOptions = (items) => {
    optionsNode.replaceChildren();
    for (const item of items || []) {
      const label = document.createElement('label');
      label.className = 'jm-team-option';
      const checkbox = document.createElement('input');
      checkbox.type = 'checkbox';
      checkbox.name = 'team_id';
      checkbox.value = item.id;
      checkbox.setAttribute('aria-label', item.label + ' (execution pending)');
      const copy = document.createElement('span');
      copy.textContent = item.label + ' · pending';
      label.append(checkbox, copy);
      optionsNode.append(label);
    }
    if (!items || !items.length) addText(optionsNode, 'span', 'jm-muted', 'No verified profile identities were returned.');
  };
  const renderList = (items) => {
    listNode.replaceChildren();
    el('[data-jm-count]').textContent = String(items.length);
    if (!items.length) {
      addText(listNode, 'p', 'jm-muted', 'No saved drafts yet. Create one to review its source-backed plan.');
      return;
    }
    for (const item of items) {
      const card = document.createElement('article');
      card.className = 'jm-card';
      const copy = document.createElement('div');
      addText(copy, 'p', 'jm-card-title', item.title);
      addText(copy, 'p', 'jm-card-meta', item.status === 'preview_pending' ? 'Preview pending' : 'Draft');
      if (['pending', 'oneshot', 'kanban'].includes(item.execution_mode)) addText(copy, 'p', 'jm-card-meta', item.execution_mode === 'pending' ? 'Jarvis mode decision pending' : (item.execution_mode === 'oneshot' ? 'One-shot' : 'Dedicated Kanban'));
      if (['approval_required', 'fully_autonomous'].includes(item.autonomy_mode)) addText(copy, 'p', 'jm-card-meta', item.autonomy_mode === 'fully_autonomous' ? 'Fully autonomous for this task' : 'Owner approval required');
      if (['not_started', 'awaiting_jarvis_review', 'approved', 'rejected'].includes(item.review_state)) addText(copy, 'p', 'jm-card-meta', item.review_state === 'awaiting_jarvis_review' ? 'Jarvis review pending' : (item.review_state === 'approved' ? 'Jarvis review approved' : item.review_state.replaceAll('_', ' ')));
      const actions = document.createElement('div');
      actions.className = 'jm-card-actions';
      const inspect = document.createElement('button');
      inspect.type = 'button';
      inspect.textContent = 'Open';
      inspect.addEventListener('click', () => openDetail(item.mission_id), { signal });
      const plan = document.createElement('button');
      plan.type = 'button';
      plan.textContent = 'Preview plan';
      plan.addEventListener('click', () => makePreview(item.mission_id, item.revision), { signal });
      actions.append(inspect, plan);
      card.append(copy, actions);
      listNode.append(card);
    }
  };
  const renderPreview = (preview) => {
    activePreview = preview;
    activeApprovalNonce = preview.approval && preview.approval.intent_nonce || null;
    launchAttempted = Boolean(preview.run);
    previewPanel.hidden = false;
    const box = el('[data-jm-preview-content]');
    box.replaceChildren();
    addText(box, 'h3', '', preview.title);
    addText(box, 'p', 'jm-plan-brief', preview.brief);
    addText(box, 'p', 'jm-card-meta', 'Revision ' + preview.revision + ' · ' + preview.status);
    if (['pending', 'oneshot', 'kanban'].includes(preview.execution_mode)) addText(box, 'p', 'jm-card-meta', 'Mode · ' + (preview.execution_mode === 'pending' ? 'Jarvis mode decision pending' : (preview.execution_mode === 'oneshot' ? 'One-shot' : 'Dedicated Kanban')));
    if (['approval_required', 'fully_autonomous'].includes(preview.autonomy_mode)) addText(box, 'p', 'jm-card-meta', 'Final-effect owner gate · ' + (preview.autonomy_mode === 'fully_autonomous' ? 'Fully autonomous for this task' : 'Owner approval required'));
    if (['not_started', 'awaiting_jarvis_review', 'approved', 'rejected'].includes(preview.review_state)) addText(box, 'p', 'jm-card-meta', 'Jarvis review · ' + (preview.review_state === 'awaiting_jarvis_review' ? 'Jarvis review pending' : (preview.review_state === 'approved' ? 'Jarvis review approved' : preview.review_state.replaceAll('_', ' '))));
    for (const member of preview.team || []) {
      const row = document.createElement('div');
      row.className = 'jm-team-row';
      addText(row, 'strong', '', member.label + ' (' + member.id + ')');
      addText(row, 'span', '', member.readiness + ' — ' + member.reason);
      box.append(row);
    }
    addText(box, 'p', 'jm-hash', 'Plan SHA-256 · ' + preview.plan_sha256);
    const reasons = document.createElement('ul');
    for (const reason of preview.pending_reasons || []) addText(reasons, 'li', '', reason);
    box.append(reasons);
    const approval = document.createElement('div');
    approval.className = 'jm-approval';
    const planningReady = preview.execution_mode === 'oneshot'
      && Array.isArray(preview.selected_source_ids)
      && preview.selected_source_ids.length > 0;
    if (!planningReady) addText(approval, 'p', 'jm-card-meta', 'Task start remains unavailable until Jarvis selects an enrolled expert One-shot route.');
    const autonomyLabel = document.createElement('label');
    autonomyLabel.textContent = 'Task authorization';
    const autonomyMode = document.createElement('select');
    autonomyMode.name = 'autonomy_mode';
    const approvalRequired = document.createElement('option');
    approvalRequired.value = 'approval_required'; approvalRequired.textContent = 'Owner approval required';
    const autonomous = document.createElement('option');
    autonomous.value = 'fully_autonomous'; autonomous.textContent = 'Fully autonomous for this task';
    autonomyMode.append(approvalRequired, autonomous);
    autonomyMode.value = preview.autonomy_mode === 'fully_autonomous' ? 'fully_autonomous' : 'approval_required';
    const autonomyHelp = addText(approval, 'p', 'jm-card-meta', 'Fully autonomous applies only to this exact task scope. Jarvis still reviews expert results; experts never receive final-effect authority.');
    autonomyLabel.append(autonomyMode);
    if (planningReady) {
      approval.append(autonomyLabel, autonomyHelp);
      const approve = document.createElement('button');
      approve.type = 'button';
      approve.className = 'jm-primary';
      approve.textContent = 'Approve task scope';
      approve.addEventListener('click', (event) => recordApproval(preview, autonomyMode.value, event.currentTarget), { signal });
      approval.append(approve);
    }
    box.append(approval);
    if (preview.approval && ['approved-pending-execution', 'approved'].includes(preview.approval.status)) {
      addText(box, 'p', 'jm-card-meta', 'Owner approval recorded until ' + preview.approval.expires_at + '. Launch remains a separate action.');
      activeApprovalNonce = preview.approval.intent_nonce;
      if (activeApprovalNonce && Array.isArray(preview.selected_source_ids)
          && preview.selected_source_ids.length > 0) {
        if (preview.execution_mode === 'oneshot') {
          const launch = document.createElement('button');
          launch.type = 'button'; launch.className = 'jm-primary'; launch.textContent = 'Start approved Jarvis task';
          launch.addEventListener('click', (event) => launchMission(preview, event.currentTarget), { signal });
          approval.append(launch);
        } else addText(approval, 'p', 'jm-card-meta', 'This plan has no enrolled native task runner.');
      }
    }
    if (preview.run) renderRun(box, preview, preview.run);
    setMessage('Preview saved for revision ' + preview.revision + '. No Hermes task or model spend has started.');
  };
  const recordApproval = async (preview, autonomyMode, button) => {
    const requestGeneration = ++generation;
    const planKey = preview.mission_id + ':' + preview.revision + ':' + preview.plan_sha256;
    if (planKey !== approvalRetryPlan || approvalRetryAcknowledged) {
      approvalRetryPlan = planKey;
      approvalRetryAcknowledged = false;
      approvalRetryKey = typeof crypto.randomUUID === 'function'
        ? crypto.randomUUID().replaceAll('-', '')
        : Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, '0')).join('');
    }
    button.disabled = true;
    setMessage('Recording owner approval for this exact plan…');
    try {
      const result = await api.post('/chat/api/missions/' + encodeURIComponent(preview.mission_id) + '/approve', {
        revision: preview.revision,
        plan_sha256: preview.plan_sha256,
        autonomy_mode: autonomyMode,
        idempotency_key: approvalRetryKey
      });
      if (!mounted || requestGeneration !== generation) return;
      approvalRetryAcknowledged = true;
      activeApprovalNonce = result.intent_nonce;
      await openDetail(preview.mission_id);
      setMessage('Task-scope authorization recorded. Task start is a separate action.');
    } catch (_) {
      if (mounted && requestGeneration === generation) setMessage('Approval could not be recorded. Refresh the source-bound preview and try again.', 'error');
    } finally {
      if (mounted) button.disabled = false;
    }
  };
  const renderRun = (box, preview, run) => {
    const section = document.createElement('section');
    section.className = 'jm-run';
    addText(section, 'h3', '', 'Owned run · ' + run.status.replaceAll('_', ' '));
    addText(section, 'p', 'jm-card-meta', run.turn_id ? 'Server turn ' + run.turn_id : 'No server turn was accepted.');
    if (run.native_child_started) addText(section, 'p', 'jm-card-meta', 'Native child activity observed.');
    if (run.status === 'review_pending' && typeof run.result === 'string') {
      const output = document.createElement('pre'); output.className = 'jm-result'; output.textContent = run.result; section.append(output);
      if (run.review_state === 'awaiting_jarvis_review') {
        addText(section, 'p', 'jm-card-meta', 'Jarvis review pending. The owner decision control stays unavailable until Jarvis reviews this exact result.');
      } else if (run.review_state === 'approved') {
        addText(section, 'p', 'jm-card-meta', 'Jarvis reviewed this exact draft. Owner approval is a separate step; no final effect is performed here.');
        for (const [decision, label] of [['accept', 'Approve reviewed draft'], ['reject', 'Reject reviewed draft']]) {
          const button = document.createElement('button'); button.type = 'button'; button.textContent = label;
          button.addEventListener('click', () => reviewMission(preview, decision, button), { signal }); section.append(button);
        }
      } else if (run.review_state === 'rejected') {
        addText(section, 'p', 'jm-card-meta', 'Jarvis rejected this draft. It cannot be approved for final effects.');
      }
    }
    if (['queued', 'running'].includes(run.status)) {
      const button = document.createElement('button'); button.type = 'button'; button.textContent = 'Stop owned run';
      button.addEventListener('click', () => stopMission(preview, button), { signal }); section.append(button);
    }
    box.append(section);
  };
  const actionKey = () => typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID().replaceAll('-', '')
    : Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, '0')).join('');
  const launchMission = async (preview, button) => {
    if (launchAttempted || !activeApprovalNonce) return;
    launchAttempted = true;
    button.disabled = true;
    setMessage('Reserving the approved mission and starting its owned server turn…');
    try {
      await api.post('/chat/api/missions/' + encodeURIComponent(preview.mission_id) + '/launch', {
        revision: preview.revision, plan_sha256: preview.plan_sha256,
        approval_nonce: activeApprovalNonce, idempotency_key: actionKey()
      });
      await openDetail(preview.mission_id);
      setMessage('Mission turn accepted. Refresh the mission to see owner-scoped native activity.');
    } catch (_) {
      setMessage('Launch outcome is unknown or unavailable. It was not retried; refresh the mission before taking another action.', 'error');
    } finally { button.disabled = true; }
  };
  const stopMission = async (preview, button) => {
    button.disabled = true;
    try {
      await api.post('/chat/api/missions/' + encodeURIComponent(preview.mission_id) + '/stop', {
        revision: preview.revision, idempotency_key: actionKey()
      });
      await openDetail(preview.mission_id);
      setMessage('Stop requested for the mission-owned turn.');
    } catch (_) { setMessage('The owned turn could not be stopped.', 'error'); button.disabled = false; }
  };
  const reviewMission = async (preview, decision, button) => {
    button.disabled = true;
    try {
      await api.post('/chat/api/missions/' + encodeURIComponent(preview.mission_id) + '/review', {
        revision: preview.revision, decision, idempotency_key: actionKey()
      });
      await openDetail(preview.mission_id);
      setMessage('Owner decision recorded for the Jarvis-reviewed draft. No final effect was performed.');
    } catch (_) { setMessage('The observed result could not be reviewed.', 'error'); button.disabled = false; }
  };
  const load = async () => {
    const requestGeneration = ++generation;
    setMessage('Loading your private mission drafts…');
    try {
      const result = await api.get('/chat/api/missions');
      if (!mounted || requestGeneration !== generation) return;
      renderOptions(result.team_options || []);
      renderList(result.missions || []);
      setMessage('Your drafts are stored privately under the current owner identity.');
    } catch (_) {
      if (mounted && requestGeneration === generation) setMessage('Mission planning is unavailable right now. Your existing chat and drafts are unchanged.', 'error');
    }
  };
  const openDetail = async (missionId) => {
    const requestGeneration = ++generation;
    setMessage('Opening saved mission…');
    try {
      const result = await api.get('/chat/api/missions/' + encodeURIComponent(missionId));
      if (!mounted || requestGeneration !== generation) return;
      if (result.preview) renderPreview({ ...result.preview, approval: result.approval, run: result.run });
      else setMessage('Draft loaded. Preview it to calculate a current-source plan digest.');
    } catch (_) {
      if (mounted && requestGeneration === generation) setMessage('The saved mission could not be opened.', 'error');
    }
  };
  const makePreview = async (missionId, revision) => {
    const requestGeneration = ++generation;
    previewPanel.hidden = true;
    setMessage('Checking verified bundled identities and current source binding…');
    try {
      const preview = await api.post('/chat/api/missions/' + encodeURIComponent(missionId) + '/preview', { revision });
      if (!mounted || requestGeneration !== generation) return;
      renderPreview(preview);
      await load();
      if (mounted) setMessage('Preview saved for revision ' + preview.revision + '. No run was started.');
    } catch (_) {
      if (mounted && requestGeneration === generation) setMessage('Preview unavailable. Refresh and try again; no execution was started.', 'error');
    }
  };
  el('[data-jm-refresh]').addEventListener('click', load, { signal });
  el('[data-jm-form]').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const selected = [...form.querySelectorAll('input[name="team_id"]:checked')].map((node) => node.value);
    if (!selected.length) { setMessage('Select at least one verified profile identity for this planning draft.', 'error'); return; }
    const payload = {
      title: form.elements.namedItem('title').value,
      brief: form.elements.namedItem('brief').value,
      team_ids: selected
    };
    const serialized = JSON.stringify(payload);
    if (serialized !== retryPayload) {
      retryPayload = serialized;
      retryKey = typeof crypto.randomUUID === 'function' ? crypto.randomUUID().replaceAll('-', '') : Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => n.toString(16).padStart(2, '0')).join('');
    }
    const requestGeneration = ++generation;
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    setMessage('Saving private draft…');
    try {
      const result = await api.post('/chat/api/missions', {
        ...payload,
        idempotency_key: retryKey
      });
      if (!mounted || requestGeneration !== generation) return;
      retryPayload = '';
      retryKey = '';
      form.reset();
      setMessage('Draft saved. Review its preview before any future execution capability is considered.');
      await load();
      await openDetail(result.mission.mission_id);
    } catch (_) {
      if (mounted && requestGeneration === generation) setMessage('Draft could not be saved. Check the fields and current protected connection.', 'error');
    } finally {
      submit.disabled = false;
    }
  }, { signal });
  void load();
  return () => { mounted = false; generation += 1; abort.abort(); };
}''',
    unmount_js="function unmount() {}",
)
