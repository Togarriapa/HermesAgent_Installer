"""Static, read-only Jarvis feature for reviewing native skill proposals."""

from .jarvis_feature_contract import JarvisFeatureAssets


FEATURE_ASSETS = JarvisFeatureAssets(
    feature_id="resources-learning",
    nav_label="Learning",
    title="Skill proposals",
    view_html=(
        '<section class="learning" aria-live="polite">'
        '<p class="learning-status" data-status>Loading native review queue…</p>'
        '<ol class="learning-list" data-candidates></ol>'
        '<p class="learning-next" data-next></p>'
        '</section>'
    ),
    css=(
        '[data-feature-root="resources"] .learning{max-width:58rem;margin:auto}'
        '[data-feature-root="resources"] .learning-status{color:var(--muted,#aab8c8)}'
        '[data-feature-root="resources"] .learning-list{display:grid;gap:.8rem;padding:0;list-style:none}'
        '[data-feature-root="resources"] .learning-card{border:1px solid var(--line,#344252);border-radius:.7rem;padding:1rem;background:var(--panel,#121b25)}'
        '[data-feature-root="resources"] .learning-meta{color:var(--muted,#aab8c8);font-size:.9rem}'
        '[data-feature-root="resources"] .learning-diff{max-height:24rem;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere}'
        '[data-feature-root="resources"] .learning-next{margin-top:1rem;color:var(--muted,#aab8c8)}'
    ),
    api_routes=(("GET", "/chat/api/resources/learning"),),
    mount_js=(
        "async function mount(container, api, state){"
        "const root=container.querySelector('.learning');if(!root)return;"
        "const status=root.querySelector('[data-status]'),list=root.querySelector('[data-candidates]'),next=root.querySelector('[data-next]');"
        "let stopped=false;"
        "try{const result=await api.get('/chat/api/resources/learning');"
        "if(stopped)return;if(!result||result.schema!==1||result.state!=='read-only-native-review'||!Array.isArray(result.candidates))throw new Error('invalid');"
        "status.textContent=result.candidates.length?`${result.candidates.length} native proposal(s) awaiting review.`:'No native skill proposals are waiting for review.';"
        "for(const item of result.candidates){if(!item||typeof item.id!=='string'||typeof item.diff!=='string')continue;"
        "const li=document.createElement('li');li.className='learning-card';const h=document.createElement('h3');h.textContent=item.summary||item.action||'Skill proposal';"
        "const meta=document.createElement('p');meta.className='learning-meta';meta.textContent=`${item.action} · ${item.reviewState} · ${item.createdAt}`;"
        "const details=document.createElement('details');const summary=document.createElement('summary');summary.textContent='Review candidate diff';"
        "const pre=document.createElement('pre');pre.className='learning-diff';pre.textContent=item.diff;details.append(summary,pre);li.append(h,meta,details);list.append(li)}"
        "next.textContent=typeof result.nextStep==='string'?result.nextStep:'';"
        "}catch{if(!stopped)status.textContent='Native proposal review is unavailable. Existing skills were not changed.';}"
        "return ()=>{stopped=true;};}"
    ),
    unmount_js="function unmount(){}",
)
