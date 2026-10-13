from hermes_installer.remote.jarvis_context import (
    decode_context_breakdown,
    decode_session_status,
)


def test_context_projection_keeps_only_bounded_category_and_usage_fields():
    projected = decode_context_breakdown({
        "categories": [
            {"id": "conversation", "label": "localized untrusted label", "tokens": 12},
            {"id": "system_prompt", "label": "also ignored", "tokens": 8},
        ],
        "context_max": 100,
        "context_percent": 20,
        "context_used": 20,
        "estimated_total": 20,
        "context_estimated": False,
        "context_source": "provider_usage",
        "model": "zai/glm-5.2",
    })

    assert projected == {
        "state": "observed", "contextMax": 100, "contextUsed": 20,
        "contextPercent": 20, "estimatedTotal": 20, "estimated": False,
        "source": "provider_usage", "model": "zai/glm-5.2",
        "categories": [
            {"id": "conversation", "label": "Conversation", "tokens": 12},
            {"id": "system_prompt", "label": "System prompt", "tokens": 8},
        ],
    }
    assert "localized" not in repr(projected)


def test_context_projection_fails_closed_on_paths_or_unreviewed_categories():
    base = {
        "categories": [{"id": "../../private", "label": "secret", "tokens": 1}],
        "context_max": 100, "context_percent": 1, "context_used": 1,
        "estimated_total": 1, "context_estimated": True,
        "context_source": "local_estimate", "model": "zai/glm-5.2",
    }
    assert decode_context_breakdown(base) == {"state": "unknown"}
    base["categories"] = [{"id": "conversation", "label": "x", "tokens": 1}]
    base["model"] = "/home/admin/.hermes/private-model"
    assert decode_context_breakdown(base) == {"state": "unknown"}


def test_status_parser_never_returns_session_id_or_path():
    result = decode_session_status({"output": (
        "Hermes TUI Status\n\nSession ID: native-session-secret\n"
        "Path: /home/admin/.hermes/profiles/internal\n"
        "Created: 2026-10-11 09:30\nLast Activity: 2026-10-11 09:45\n"
        "Tokens: 12,345\nAgent Running: Yes\n")})

    assert result == {
        "state": "observed", "running": True, "created": "2026-10-11 09:30",
        "lastActivity": "2026-10-11 09:45", "tokens": 12345,
    }
    assert "native-session-secret" not in repr(result)
    assert "/home/admin" not in repr(result)


def test_status_parser_fails_closed_on_malformed_or_duplicate_allowed_fields():
    malformed = decode_session_status({"output": "Path: /private\nAgent Running: yes\n"})
    duplicate = decode_session_status({"output": "Agent Running: Yes\nAgent Running: No\n"})
    assert malformed["state"] == duplicate["state"] == "unknown"
    assert malformed["running"] is duplicate["running"] is None


def test_context_feature_assets_are_static_and_avoid_native_rpc_or_markup_interpolation():
    from hermes_installer.remote.jarvis_context_assets import FEATURE_ASSETS
    from hermes_installer.remote.jarvis_feature_contract import validate_feature_assets

    validate_feature_assets((FEATURE_ASSETS,))
    assert FEATURE_ASSETS.feature_id == "context"
    assert FEATURE_ASSETS.api_routes == (
        ("GET", "/chat/api/conversations"),
        ("GET", "/chat/api/conversations/{conversation_id}/context"),
    )
    assert "innerHTML" not in FEATURE_ASSETS.mount_js
    assert ".textContent =" in FEATURE_ASSETS.mount_js
    assert "text(selector, value)" in FEATURE_ASSETS.mount_js
    assert ".append(" in FEATURE_ASSETS.mount_js
    assert "session_id" not in FEATURE_ASSETS.mount_js
    assert "profiles.describe" not in FEATURE_ASSETS.mount_js


def test_context_view_binds_deferred_responses_to_the_current_selection_and_mount():
    import subprocess
    import tempfile
    from pathlib import Path

    from hermes_installer.remote.jarvis_context_assets import FEATURE_ASSETS

    harness = r'''
const assert = require('node:assert/strict');
global.document = {createElement:element};
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}
function element() {
  return {textContent:'', value:'', disabled:false, children:[], attrs:{}, listeners:{},
    setAttribute(key, value) { this.attrs[key] = value; },
    replaceChildren(...children) { this.children = children; },
    append(...children) { this.children.push(...children); },
    addEventListener(name, callback) { this.listeners[name] = callback; },
    removeEventListener(name, callback) { if (this.listeners[name] === callback) delete this.listeners[name]; }};
}
function makeView() {
  const selectors = ['[data-conversation]', '[data-refresh]', '[data-status]', '[data-usage]',
    '[data-categories]', '[data-running]', '[data-created]', '[data-activity]', '[data-tokens]',
    '[data-persona]', '[data-workspace]'];
  const nodes = Object.fromEntries(selectors.map(key => [key, element()]));
  const root = {attrs:{}, querySelector:key => nodes[key],
    setAttribute(key, value) { this.attrs[key] = value; }};
  const container = {querySelector:() => root};
  const calls = [];
  const api = {get(path) { const pending = deferred(); calls.push({path, ...pending}); return pending.promise; }};
  const cleanup = mount(container, api);
  const selector = nodes['[data-conversation]'];
  const change = id => { selector.value = id; selector.listeners.change(); };
  return {nodes, root, calls, selector, change, cleanup};
}
function observed(used, model) {
  return {state:'observed', context:{state:'observed', contextUsed:used, contextMax:100,
    contextPercent:used, estimated:false, model, categories:[]},
    status:{state:'observed', running:false, created:model, lastActivity:model, tokens:used},
    primaryPersona:{state:'pending'}, workspace:{state:'pending'}};
}
async function flush() { await Promise.resolve(); await Promise.resolve(); }
async function startView() {
  const view = makeView();
  view.calls[0].resolve({conversations:[{id:'A'.repeat(24),title:'A'}, {id:'B'.repeat(24),title:'B'}]});
  await flush();
  return view;
}
(async() => {
  // A→B: A must not overwrite B after B has completed.
  let view = await startView();
  view.change('A'.repeat(24)); const firstA = view.calls[1];
  view.change('B'.repeat(24)); const b = view.calls[2];
  b.resolve(observed(20, 'B')); await flush();
  firstA.resolve(observed(10, 'A')); await flush();
  assert.match(view.nodes['[data-status]'].textContent, /observed/);
  assert.match(view.nodes['[data-usage]'].textContent, /^20 of 100/);
  assert.equal(view.nodes['[data-created]'].textContent, 'B');

  // A→B→A: the first A response is stale even though A is selected again.
  view = await startView();
  view.change('A'.repeat(24)); const oldA = view.calls[1];
  view.change('B'.repeat(24)); const oldB = view.calls[2];
  view.change('A'.repeat(24)); const newA = view.calls[3];
  oldA.resolve(observed(11, 'old-A')); oldB.resolve(observed(22, 'old-B')); await flush();
  assert.equal(view.nodes['[data-status]'].textContent, 'Loading owned session context…');
  assert.equal(view.nodes['[data-created]'].textContent, 'Unknown');
  newA.resolve(observed(12, 'new-A')); await flush();
  assert.match(view.nodes['[data-usage]'].textContent, /^12 of 100/);
  assert.equal(view.nodes['[data-created]'].textContent, 'new-A');

  // Clearing immediately removes prior data and makes a late completion inert.
  view = await startView();
  view.change('A'.repeat(24)); const clearedA = view.calls[1];
  view.change('');
  assert.equal(view.nodes['[data-usage]'].textContent, 'Unknown');
  assert.equal(view.nodes['[data-created]'].textContent, 'Unknown');
  assert.equal(view.nodes['[data-categories]'].children.length, 0);
  assert.equal(view.nodes['[data-status]'].textContent, 'Choose a conversation to inspect its context.');
  clearedA.resolve(observed(99, 'cleared')); await flush();
  assert.equal(view.nodes['[data-usage]'].textContent, 'Unknown');
  assert.equal(view.nodes['[data-status]'].textContent, 'Choose a conversation to inspect its context.');

  // A stale rejection/finally cannot replace B's loading state or enable its refresh.
  view = await startView();
  view.change('A'.repeat(24)); const failedA = view.calls[1];
  view.change('B'.repeat(24)); const pendingB = view.calls[2];
  failedA.reject(new Error('late A failure')); await flush();
  assert.equal(view.nodes['[data-status]'].textContent, 'Loading owned session context…');
  assert.equal(view.nodes['[data-refresh]'].disabled, true);
  pendingB.resolve(observed(21, 'current-B')); await flush();
  assert.match(view.nodes['[data-usage]'].textContent, /^21 of 100/);
  assert.equal(view.nodes['[data-refresh]'].disabled, false);
  assert.equal(view.root.attrs['aria-busy'], 'false');

  // List results and errors both stop at unmount.
  view = makeView(); const lateList = view.calls[0];
  view.cleanup();
  lateList.resolve({conversations:[{id:'A'.repeat(24),title:'late'}]}); await flush();
  assert.equal(view.selector.children.length, 0);
  assert.equal(view.nodes['[data-status]'].textContent, 'Choose a conversation to inspect its context.');
  view = makeView(); const failedList = view.calls[0];
  view.cleanup(); failedList.reject(new Error('late list failure')); await flush();
  assert.equal(view.nodes['[data-status]'].textContent, 'Choose a conversation to inspect its context.');
})().catch(error => { console.error(error); process.exitCode = 1; });
'''

    with tempfile.TemporaryDirectory() as temporary:
        path = Path(temporary) / "jarvis-context-selection-harness.js"
        path.write_text(FEATURE_ASSETS.mount_js + "\n" + harness, encoding="utf-8")
        result = subprocess.run(["node", str(path)], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def test_context_route_resolves_private_session_only_after_owner_lookup():
    import asyncio
    import time

    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from hermes_installer.remote.jarvis_chat import (
        ChatPrincipal,
        JarvisChatDenied,
        JarvisChatService,
    )
    from hermes_installer.remote.jarvis_context import install_jarvis_context_routes

    conversation_id = "A" * 24
    native_session_id = "native-session-secret"

    class Store:
        def get_conversation(self, subject, requested_id):
            if subject != "owner-subject" or requested_id != conversation_id:
                raise JarvisChatDenied("conversation is unavailable")
            return {"id": conversation_id, "backend_id": native_session_id,
                    "core_generation": "generation-1"}

    class Backend:
        def __init__(self):
            self.ids = []

        async def session_context_breakdown(self, session_id):
            self.ids.append(session_id)
            return {
                "categories": [{"id": "conversation", "label": "Conversation", "tokens": 3}],
                "context_max": 100, "context_percent": 3, "context_used": 3,
                "estimated_total": 3, "context_estimated": False,
                "context_source": "provider_usage", "model": "zai/glm-5.2",
            }

        async def session_status(self, session_id):
            self.ids.append(session_id)
            return {"output": (
                f"Session ID: {session_id}\nPath: /home/admin/.hermes/private\n"
                "Created: 2026-10-11 09:30\nLast Activity: 2026-10-11 09:45\n"
                "Tokens: 3\nAgent Running: No\n")}

    class Service(JarvisChatService):
        def __init__(self, backend):
            self.backend = backend
            self.store = Store()
            self.current_calls = 0

        def _current(self, _request):
            self.current_calls += 1
            now = time.monotonic()
            return ChatPrincipal("owner-subject", now + 30, now + 20, "generation-1")

    async def scenario():
        backend = Backend()
        app = web.Application()
        install_jarvis_context_routes(app, Service(backend))
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get(f"/chat/api/conversations/{conversation_id}/context")
            assert response.status == 200
            assert response.headers["Cache-Control"] == "no-store"
            payload = await response.json()
            body = await response.text()
            assert payload["conversationId"] == conversation_id
            assert payload["context"]["state"] == "observed"
            assert payload["status"]["running"] is False
            assert payload["primaryPersona"]["state"] == "pending"
            assert payload["workspace"]["state"] == "pending"
            assert native_session_id not in body
            assert "/home/admin" not in body
            assert backend.ids == [native_session_id, native_session_id]
            assert (await client.get(f"/chat/api/conversations/{'B' * 24}/context?profile=other")).status == 404
            assert backend.ids == [native_session_id, native_session_id]
        finally:
            await client.close()


def test_context_route_denies_expired_ingress_before_native_reads():
    import asyncio

    from aiohttp import web
    from aiohttp.test_utils import TestClient, TestServer

    from hermes_installer.remote.jarvis_chat import JarvisChatDenied, JarvisChatService
    from hermes_installer.remote.jarvis_context import install_jarvis_context_routes

    class Service(JarvisChatService):
        def __init__(self):
            self.backend = object()
            self.store = object()

        def _current(self, _request):
            raise JarvisChatDenied("private ingress detail")

    async def scenario():
        app = web.Application()
        install_jarvis_context_routes(app, Service())
        client = TestClient(TestServer(app))
        await client.start_server()
        try:
            response = await client.get(f"/chat/api/conversations/{'A' * 24}/context")
            assert response.status == 403
            assert "private ingress detail" not in await response.text()
        finally:
            await client.close()

    asyncio.run(scenario())
