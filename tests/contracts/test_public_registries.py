"""Effects and denials for fixed public registry adapters (RB-T02/RB-T03)."""
import hashlib
import json
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.components.native_plugins import (
    NATIVE_PLUGIN_ADAPTERS,
    RESOURCE_OVERLAY_STORE_IMPLEMENTATION,
    create_native_plugin_handler,
    resolve_native_plugin_implementation,
)
from hermes_installer.components.public_registries import (
    PublicRegistryDenied,
    build_registry_handlers,
    canonical_registry_payload,
    invoke_public_registry_read,
)
import hermes_installer.components.public_registries as public_registry_module
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext,
    ResourceIdentity,
    ReviewedPluginAdapterRegistry,
)


class _Network:
    calls = []
    responses = []
    status = 200
    headers = {"Content-Type": "application/json"}
    body = b"{}"

    def __init__(self, **bounds):
        self.bounds = bounds

    def request(self, url, *, method, headers, body, cancelled):
        self.calls.append((url, method, headers, body, self.bounds))
        if cancelled():
            raise TimeoutError("cancelled")
        response_body = self.responses.pop(0) if self.responses else self.body
        return SimpleNamespace(status=self.status, headers=self.headers, body=response_body)


class _Authority:
    """Broker-shaped fixture; production still needs protected root enrollment."""

    def __init__(self):
        self.handlers = build_registry_handlers()
        self.calls = []

    def context(self, *, purpose, intent, source_receipt_handles=(), **_kwargs):
        if purpose != "native-hermes-chat" or not source_receipt_handles:
            raise PermissionError("trusted invocation lineage required")
        self._context = _context(sensitivity="public")
        return self._context

    def authorize_effect(self, context, *, capability, target, recipient, request_digest, retry_index=0, **_kwargs):
        self.calls.append(("authorize", capability, target, recipient, retry_index))
        return SimpleNamespace(
            purpose=context.purpose, principal_id=context.principal_id,
            profile_id=context.profile_id, namespace_id=context.namespace_id,
            uid=context.uid, intent_id=context.intent_id, trace_id=context.trace_id,
            policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
            target=target, recipient=recipient, capability=capability,
            request_digest=request_digest, retry_index=retry_index,
            monotonic_expires_at=time.monotonic() + 20,
        )

    def verify_effect(self, authorization, context, **kwargs):
        self.calls.append(("verify", kwargs["target"], kwargs["retry_index"]))

    def perform_effect(self, authorization, *, operation, payload, timeout, cancelled=None):
        self.calls.append(("perform", operation, timeout))
        target = authorization.target
        response = self.handlers[(operation, target)](
            context=self._context, authorization=authorization, payload=payload,
            timeout=timeout, peer_pid=42, cancelled=cancelled or (lambda: False),
        )
        return SimpleNamespace(**response)


def _context(*, capabilities=frozenset({"registry-read", "registry-agent37-read"}),
             sensitivity="public"):
    now = time.monotonic()
    return SimpleNamespace(
        purpose="native-hermes-chat", sensitivity=sensitivity,
        capabilities=capabilities, principal_id="principal", profile_id="profile",
        namespace_id="namespace", uid=1001, intent_id="intent", trace_id="trace",
        policy_revision="policy-1", lineage_hash="lineage", monotonic_expires_at=now + 25,
    )


def _lineage(**kwargs):
    return SimpleNamespace(
        schema=1, invocation_handle="i" * 32,
        source_receipt_handles=("r" * 32,),
        parent_closure_digest="c" * 64,
        arguments_sha256=kwargs["arguments_sha256"],
        expires_monotonic=time.monotonic() + 10,
    )


def _grant(context, *, target, recipient, capability, payload, retry_index=0):
    return SimpleNamespace(
        purpose=context.purpose, principal_id=context.principal_id,
        profile_id=context.profile_id, namespace_id=context.namespace_id, uid=context.uid,
        intent_id=context.intent_id, trace_id=context.trace_id,
        policy_revision=context.policy_revision, lineage_hash=context.lineage_hash,
        target=target, recipient=recipient, capability=capability,
        request_digest=hashlib.sha256(payload).hexdigest(), retry_index=retry_index,
        monotonic_expires_at=time.monotonic() + 20,
    )


class PublicRegistryHandlerTests(unittest.TestCase):
    def setUp(self):
        _Network.calls = []
        _Network.responses = []
        _Network.status = 200
        _Network.headers = {"Content-Type": "application/json"}
        network_patch = patch.object(public_registry_module, "BoundedNetwork", _Network)
        network_patch.start()
        self.addCleanup(network_patch.stop)

    def test_mcp_registry_search_and_version_path_are_fixed_and_bounded(self):
        handlers = build_registry_handlers()
        handler = handlers[("registry.read", "registry:modelcontextprotocol")]
        query = {"schema": 1, "query": {"search": "filesystem", "version": "latest"}, "limit": 10, "cursor": "next-1"}
        payload = canonical_registry_payload(query)
        ctx = _context()
        grant = _grant(ctx, target="registry:modelcontextprotocol",
                       recipient="https://registry.modelcontextprotocol.io",
                       capability="registry-read", payload=payload)
        _Network.body = b'{"servers":[],"metadata":{"nextCursor":null}}'
        result = handler(context=ctx, authorization=grant, payload=payload,
                         timeout=8, peer_pid=10, cancelled=lambda: False)
        url, method, headers, body, bounds = _Network.calls[0]
        self.assertEqual(method, "GET")
        self.assertEqual(body, None)
        self.assertEqual(headers, {"Accept": "application/json"})
        self.assertTrue(url.startswith("https://registry.modelcontextprotocol.io/v0.1/servers?"))
        self.assertIn("search=filesystem", url)
        self.assertIn("version=latest", url)
        self.assertIn("cursor=next-1", url)
        self.assertLessEqual(bounds["deadline_seconds"], 8)
        self.assertEqual(json.loads(result["body"]), {
            "servers": [], "metadata": {"nextCursor": None}, "pageCount": 1,
        })

    def test_mcp_version_routes_encode_name_and_use_only_documented_parameters(self):
        handlers = build_registry_handlers()
        handler = handlers[("registry.read", "registry:modelcontextprotocol")]
        payload = canonical_registry_payload({"schema": 1, "query": {"name": "io.github.owner/repo"}, "limit": 5, "cursor": None})
        ctx = _context()
        grant = _grant(ctx, target="registry:modelcontextprotocol",
                       recipient="https://registry.modelcontextprotocol.io",
                       capability="registry-read", payload=payload)
        _Network.body = json.dumps({
            "servers": [{"server": {"name": "io.github.owner/repo",
                                     "description": "fixture", "version": "1.2.3"}}],
            "metadata": {"nextCursor": None},
        }).encode()
        handler(context=ctx, authorization=grant, payload=payload,
                timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls[-1][0], "https://registry.modelcontextprotocol.io/v0.1/servers/io.github.owner%2Frepo/versions")

        payload = canonical_registry_payload({"schema": 1, "query": {"name": "io.github.owner/repo", "version": "1.2.3"}, "limit": 5, "cursor": None})
        grant = _grant(ctx, target="registry:modelcontextprotocol",
                       recipient="https://registry.modelcontextprotocol.io",
                       capability="registry-read", payload=payload)
        _Network.body = json.dumps({"server": {
            "name": "io.github.owner/repo", "description": "fixture", "version": "1.2.3",
            "packages": [{"runtimeArguments": ["untrusted"]}],
        }}).encode()
        handler(context=ctx, authorization=grant, payload=payload,
                timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls[-1][0], "https://registry.modelcontextprotocol.io/v0.1/servers/io.github.owner%2Frepo/versions/1.2.3")

    def test_agent37_search_strips_skill_instructions_and_uses_fixed_api(self):
        handler = build_registry_handlers()[("registry.read", "registry:agent37")]
        response = {"hits": [{"id": "a" * 32, "name": "fixture", "description": "public summary",
                              "content": "untrusted instructions", "githubRepoFullName": "org/repo"}],
                    "totalHits": 31, "limit": 1, "offset": 30}
        _Network.body = json.dumps(response).encode()
        payload = canonical_registry_payload({"schema": 1, "query": {"search": "hermes", "min_stars": 10, "recent": True}, "limit": 1, "cursor": "30"})
        ctx = _context()
        grant = _grant(ctx, target="registry:agent37", recipient="https://www.agent37.com",
                       capability="registry-agent37-read", payload=payload)
        result = handler(context=ctx, authorization=grant, payload=payload,
                         timeout=8, peer_pid=10, cancelled=lambda: False)
        url = _Network.calls[-1][0]
        self.assertTrue(url.startswith("https://www.agent37.com/api/skills/search?"))
        self.assertIn("query=hermes", url)
        self.assertIn("limit=1", url)
        self.assertIn("offset=30", url)
        self.assertIn("minStars=10", url)
        self.assertIn("recentlyUpdated=30", url)
        result_body = json.loads(result["body"])
        self.assertNotIn("content", result_body["hits"][0])
        self.assertEqual(result_body["hits"][0]["name"], "fixture")

    def test_agent37_inspect_only_accepts_returned_opaque_id(self):
        handler = build_registry_handlers()[("registry.read", "registry:agent37")]
        payload = canonical_registry_payload({"schema": 1, "query": {"id": "b" * 32}, "limit": 1, "cursor": None})
        ctx = _context()
        grant = _grant(ctx, target="registry:agent37", recipient="https://www.agent37.com",
                       capability="registry-agent37-read", payload=payload)
        _Network.body = json.dumps({"id": "b" * 32, "name": "fixture", "content": "do not fetch or expose"}).encode()
        result = handler(context=ctx, authorization=grant, payload=payload,
                         timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls[-1][0], f"https://www.agent37.com/api/skills/{'b' * 32}")
        self.assertNotIn("content", json.loads(result["body"]))

    def test_agent37_does_not_return_nested_source_payloads_or_mismatched_ids(self):
        handler = build_registry_handlers()[("registry.read", "registry:agent37")]
        payload = canonical_registry_payload({"schema": 1, "query": {"id": "c" * 32}, "limit": 1, "cursor": None})
        ctx = _context()
        grant = _grant(ctx, target="registry:agent37", recipient="https://www.agent37.com",
                       capability="registry-agent37-read", payload=payload)
        for body in (
            {"id": "d" * 32, "name": "other"},
            {"id": "c" * 32, "name": {"nested": "payload"}},
            {"id": "c" * 32, "content": "instructions"},
        ):
            _Network.body = json.dumps(body).encode()
            if body.get("id") != "c" * 32 or isinstance(body.get("name"), dict):
                with self.subTest(body=body), self.assertRaises(PublicRegistryDenied):
                    handler(context=ctx, authorization=grant, payload=payload,
                            timeout=8, peer_pid=10, cancelled=lambda: False)
            else:
                result = handler(context=ctx, authorization=grant, payload=payload,
                                 timeout=8, peer_pid=10, cancelled=lambda: False)
                self.assertEqual(json.loads(result["body"]), {
                    "id": "c" * 32,
                    "sourceContentTrust": "untrusted-public-metadata",
                })

    def test_search_pagination_stops_at_three_pages_and_ninety_entries(self):
        handler = build_registry_handlers()[("registry.read", "registry:agent37")]
        _Network.responses = [json.dumps({
            "hits": [{"id": f"{page:032x}", "name": f"item-{page}"} for page in range(start, start + 30)],
            "totalHits": 120, "limit": 30, "offset": start,
        }).encode() for start in (0, 30, 60)]
        payload = canonical_registry_payload({"schema": 1, "query": {"search": "x"}, "limit": 30, "cursor": "0"})
        ctx = _context()
        grant = _grant(ctx, target="registry:agent37", recipient="https://www.agent37.com",
                       capability="registry-agent37-read", payload=payload)
        result = handler(context=ctx, authorization=grant, payload=payload,
                         timeout=9, peer_pid=10, cancelled=lambda: False)
        parsed = json.loads(result["body"])
        self.assertEqual(len(_Network.calls), 3)
        self.assertEqual(len(parsed["hits"]), 90)
        self.assertEqual(parsed["pageCount"], 3)
        self.assertIn("offset=60", _Network.calls[-1][0])

    def test_query_source_and_page_limits_fail_before_network(self):
        handler = build_registry_handlers()[("registry.read", "registry:modelcontextprotocol")]
        ctx = _context()
        for query, limit in (({"search": "x" * 300}, 1), ({"search": "test"}, 31)):
            payload = canonical_registry_payload({"schema": 1, "query": query,
                                                  "limit": limit, "cursor": None})
            grant = _grant(ctx, target="registry:modelcontextprotocol",
                           recipient="https://registry.modelcontextprotocol.io",
                           capability="registry-read", payload=payload)
            with self.subTest(query_length=len(str(query)), limit=limit), self.assertRaises(PublicRegistryDenied):
                handler(context=ctx, authorization=grant, payload=payload,
                        timeout=9, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls, [])

    def test_plugin_rejects_oversized_query_before_consuming_authority(self):
        authority = _Authority()
        source = _context()
        runtime = NativePluginRuntimeContext(
            identity=ResourceIdentity(
                resource_id="mcp-registry", kind="plugins", version="1.0.0",
                source_path="plugins/mcp-registry.yaml", source_revision="pinned",
                content_digest="a" * 64,
            ),
            declared_capabilities=("registry-read",), authority=authority,
            invocation_contexts=_lineage,
            selected_adapters=ReviewedPluginAdapterRegistry(),
        )
        tools = {}

        class PluginContext:
            def register_tool(self, name, **kwargs):
                tools[name] = kwargs["handler"]

        create_native_plugin_handler("mcp-registry", runtime)(PluginContext())
        with self.assertRaises(PublicRegistryDenied):
            tools["mcp_registry_discover"]({"search": "x" * 300})
        self.assertEqual(authority.calls, [])
        self.assertEqual(_Network.calls, [])

    def test_wrong_capability_digest_target_private_context_and_redirect_fail_before_network(self):
        handler = build_registry_handlers()[("registry.read", "registry:modelcontextprotocol")]
        payload = canonical_registry_payload({"schema": 1, "query": {"search": "test"}, "limit": 1, "cursor": None})
        good = _context()
        recipient = "https://registry.modelcontextprotocol.io"
        target = "registry:modelcontextprotocol"
        good_grant = _grant(good, target=target, recipient=recipient, capability="registry-read", payload=payload)
        for ctx, grant in (
            (good, _grant(good, target=target, recipient=recipient, capability="provider-inference", payload=payload)),
            (good, _grant(good, target=target, recipient=recipient, capability="registry-read", payload=b"different")),
            (good, _grant(good, target="registry:agent37", recipient=recipient, capability="registry-read", payload=payload)),
            (_context(sensitivity="private"), good_grant),
        ):
            with self.subTest(grant=grant):
                with self.assertRaises(PublicRegistryDenied):
                    handler(context=ctx, authorization=grant, payload=payload,
                            timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls, [])
        _Network.status = 302
        with self.assertRaisesRegex(PublicRegistryDenied, "invalid or oversized"):
            handler(context=good, authorization=good_grant, payload=payload,
                    timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(len(_Network.calls), 1)

    def test_query_schema_rejects_caller_url_method_and_unsafe_pagination(self):
        handler = build_registry_handlers()[("registry.read", "registry:modelcontextprotocol")]
        ctx = _context()
        target = "registry:modelcontextprotocol"
        recipient = "https://registry.modelcontextprotocol.io"
        for query in ({"url": "https://attacker.invalid"}, {"method": "POST"}, {"name": "safe", "version": "../admin"}):
            payload = canonical_registry_payload({"schema": 1, "query": query, "limit": 1, "cursor": None})
            grant = _grant(ctx, target=target, recipient=recipient, capability="registry-read", payload=payload)
            with self.subTest(query=query), self.assertRaises(PublicRegistryDenied):
                handler(context=ctx, authorization=grant, payload=payload,
                        timeout=8, peer_pid=10, cancelled=lambda: False)
        self.assertEqual(_Network.calls, [])

    def test_plugin_registry_contains_concrete_adapters_but_no_unrelated_aliases(self):
        adapters = {row.resource_id: row for row in NATIVE_PLUGIN_ADAPTERS}
        for resource_id in ("mcp-registry", "agent37-discovery", "resource-overlay-store"):
            self.assertTrue(adapters[resource_id].handler_available)
            self.assertIsNotNone(resolve_native_plugin_implementation(resource_id))
        self.assertTrue(all(row.blocker for row in adapters.values()))
        self.assertIn("root `registry-read` enrollment", adapters["mcp-registry"].blocker)
        self.assertIn("one-shot explicit-order confirmation", adapters["agent-live-wallet"].blocker)
        self.assertNotEqual(adapters["agent-live-wallet"].blocker,
                            adapters["financial-execution-gateway"].blocker)
        self.assertIs(RESOURCE_OVERLAY_STORE_IMPLEMENTATION,
                      resolve_native_plugin_implementation("resource-overlay-store"))
        self.assertIsNotNone(resolve_native_plugin_implementation("github"))

    def test_registered_mcp_plugin_tool_uses_fresh_root_effect_and_marks_data_untrusted(self):
        authority = _Authority()
        source = _context()
        identity = ResourceIdentity(
            resource_id="mcp-registry", kind="plugins", version="1.0.0",
            source_path="plugins/mcp-registry.yaml", source_revision="pinned",
            content_digest="a" * 64,
        )
        runtime = NativePluginRuntimeContext(
            identity=identity, declared_capabilities=("registry-read",),
            authority=authority,
            invocation_contexts=_lineage,
            selected_adapters=ReviewedPluginAdapterRegistry(),
        )
        tools = {}

        class PluginContext:
            def register_tool(self, name, **kwargs):
                tools[name] = kwargs["handler"]

        create_native_plugin_handler("mcp-registry", runtime)(PluginContext())
        _Network.body = b'{"servers":[{"name":"io.example/test"}],"metadata":{"nextCursor":null}}'
        result = tools["mcp_registry_discover"]({"search": "test", "latest_only": True})
        self.assertEqual(result["trust"], "untrusted-public-source")
        self.assertEqual(result["service_id"], "registry:modelcontextprotocol")
        self.assertEqual([call[0] for call in authority.calls], ["authorize", "verify", "perform"])
        self.assertEqual(authority.calls[-1][1], "registry.read")
        self.assertEqual(len(_Network.calls), 1)


if __name__ == "__main__":
    unittest.main()
