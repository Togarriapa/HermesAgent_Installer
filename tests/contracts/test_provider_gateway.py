from __future__ import annotations

import json
import socket
import tempfile
import threading
import time
import urllib.error
import urllib.request
import unittest
from pathlib import Path

from hermes_installer.policy import BudgetLedger, DispatchAuthorization, DispatchContext, DispatchPolicy, Dispatcher, ProviderResponse, Sensitivity, default_public_route
from hermes_installer.provider_gateway import (GatewayError, LOCAL_KEY_ENV, LOCAL_PROVIDER_NAME, LocalProviderGateway, materialize_hermes_provider_plugin, materialize_hermes_profile_config)
from hermes_installer.state import OwnedRoot


MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"
TOKEN="local-fixture-token-value-0123456789abcdef"


def fixture_context(*, purpose, intent, source_contexts=(), source_receipts=(),
                    trace_id, lease_seconds, final_payload_digest=None,
                    operation=None, retry_index=0, cancelled=None,
                    sensitivity=Sensitivity.PUBLIC):
    return DispatchContext(
        profile_id="fixture-profile", purpose=purpose, sensitivity=sensitivity, trace_id=trace_id,
        principal_id="fixture-principal", namespace="fixture-namespace",
        provenance="sha256:" + "f" * 64, capabilities=frozenset({"inference", "tool-call"}),
        policy_revision="fixture-revision", grant_id="fixture-context-grant",
        lease_expires_at=time.monotonic() + min(60, lease_seconds),
    )


def synthetic_authorizer(context, capability, intent_id, now, timeout, cancelled):
    import uuid
    return DispatchAuthorization(context.principal_id, context.profile_id, context.namespace,
        context.trace_id, context.capabilities, context.effective_sensitivity,
        context.policy_revision, context.purpose, capability, intent_id,
        context.provenance[7:], str(uuid.uuid4()), min(context.lease_expires_at, now + min(60, timeout)))


class RecordingTransport:
    def __init__(self):
        self.calls=[]
    def __call__(self,route,model,payload,*,output_token_limit,timeout,trace_id,cancelled=lambda:False):
        self.calls.append((route.name,model,payload,output_token_limit,timeout,trace_id))
        return ProviderResponse(200,b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":3}}',{"Content-Type":"application/json"},2,3)


class ProviderGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=OwnedRoot(Path(self.temp.name)/"owned");root.ensure()
        self.transport=RecordingTransport()
        self.dispatcher=Dispatcher(DispatchPolicy({"public":default_public_route()},"public"),BudgetLedger(root),self.transport,context_authorizer=synthetic_authorizer)
        self.gateway=LocalProviderGateway(self.dispatcher,token=TOKEN,profile_id="public-demo",sensitivity=Sensitivity.PUBLIC,model=MODEL,max_output_tokens=32,context_factory=fixture_context)
        self.port=self.gateway.start()
        self.addCleanup(self.gateway.close)
        self.addCleanup(self.temp.cleanup)

    def request(self,path="/v1/chat/completions",*,method="POST",body=None,token=TOKEN,headers=None):
        url=f"http://127.0.0.1:{self.port}{path}"
        request=urllib.request.Request(url,data=body,method=method,headers={"Authorization":"Bearer "+token,"Content-Type":"application/json",**(headers or {})})
        try:
            response=urllib.request.urlopen(request,timeout=2)
        except urllib.error.HTTPError as exc:
            return exc.code,exc.read(),exc.headers
        return response.status,response.read(),response.headers

    def test_host_context_factory_is_required(self):
        with self.assertRaisesRegex(GatewayError, "host-issued context factory"):
            LocalProviderGateway(
                self.dispatcher, token=TOKEN, profile_id="public-demo",
                sensitivity=Sensitivity.PUBLIC, model=MODEL,
            )

    def test_plugin_port_is_stable_across_restarts_and_conflicts_are_preserved(self):
        root = OwnedRoot(Path(self.temp.name) / "stable")
        root.ensure()
        first = materialize_hermes_provider_plugin(root, profile_relative="hermes", port=None, model=MODEL)
        selected = int(first["port"])
        self.assertTrue(1024 <= selected <= 65535)
        second = materialize_hermes_provider_plugin(root, profile_relative="hermes", port=None, model=MODEL)
        self.assertEqual(second["port"], first["port"])
        self.assertEqual(Path(first["entrypoint"]).read_text().count(f"127.0.0.1:{selected}/v1"), 1)
        with self.assertRaisesRegex(GatewayError, "different gateway port"):
            materialize_hermes_provider_plugin(root, profile_relative="hermes", port=selected + 1, model=MODEL)
        # A listener that acquires the persisted endpoint causes startup to
        # fail closed; the service never silently moves away from the plugin URL.
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", selected))
        blocker.listen()
        self.addCleanup(blocker.close)
        gateway = LocalProviderGateway(self.dispatcher, token=TOKEN, profile_id="public-demo",
            sensitivity=Sensitivity.PUBLIC, model=MODEL, port=selected, context_factory=fixture_context)
        with self.assertRaises(OSError):
            gateway.start()
        self.assertIsNone(gateway._server)

    def test_managed_home_config_selects_local_primary_and_aux_profile(self):
        root = OwnedRoot(Path(self.temp.name) / "managed-config")
        root.ensure()
        profile = materialize_hermes_provider_plugin(root, profile_relative="home", port=None, model=MODEL)
        config_path = materialize_hermes_profile_config(root, home_relative="home", port=int(profile["port"]), model=MODEL)
        text = config_path.read_text()
        self.assertIn("provider: hermes-installer-dispatch", text)
        self.assertIn("api_key_env: " + LOCAL_KEY_ENV, text)
        self.assertIn("127.0.0.1:" + profile["port"] + "/v1", text)
        self.assertNotIn(TOKEN, text)
        self.assertEqual(materialize_hermes_profile_config(root, home_relative="home", port=int(profile["port"]), model=MODEL), config_path)
        with self.assertRaises(Exception):
            materialize_hermes_profile_config(root, home_relative="home", port=int(profile["port"]) + 1, model=MODEL)

    def test_materializer_refuses_to_adopt_existing_unowned_home(self):
        root = OwnedRoot(Path(self.temp.name) / "unowned-home")
        root.ensure()
        home = root.path("home")
        home.mkdir(mode=0o700)
        (home / "config.yaml").write_text("model: user-owned\\n")
        with self.assertRaisesRegex(Exception, "explicit adoption"):
            materialize_hermes_provider_plugin(root, profile_relative="home", port=None, model=MODEL)
        self.assertEqual((home / "config.yaml").read_text(), "model: user-owned\\n")

    def test_gateway_authenticates_and_routes_native_chat_to_dispatcher(self):
        payload=json.dumps({"model":MODEL,"messages":[{"role":"user","content":"hello"}],"max_tokens":999}).encode()
        status,body,headers=self.request(body=payload)
        self.assertEqual(status,200)
        self.assertEqual(json.loads(body)["choices"][0]["message"]["content"],"ok")
        self.assertEqual(headers["Content-Type"],"application/json")
        self.assertEqual(len(self.transport.calls),1)
        route,model,canonical,outcap,timeout,_trace=self.transport.calls[0]
        self.assertEqual((route,model,outcap),("openrouter-nemotron-free",MODEL,32))
        normalized=json.loads(canonical)
        self.assertEqual(normalized["model"],MODEL)
        self.assertEqual(normalized["max_tokens"],32)

    def test_auth_origin_route_and_size_fail_before_dispatch(self):
        payload=json.dumps({"model":MODEL,"messages":[{"role":"user","content":"hello"}]}).encode()
        status,_,_=self.request(body=payload,token="wrong")
        self.assertEqual(status,401)
        status,_,_=self.request(path="/v1/responses",body=payload)
        self.assertEqual(status,404)
        # Send headers with an oversized Content-Length but no body. The
        # gateway must reject before reading an attacker-controlled body; a
        # full-body urllib client would correctly see a reset/BrokenPipe here.
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as sock:
            sock.sendall((
                "POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 1048577\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii"))
            response = sock.recv(4096)
        self.assertIn(b"HTTP/1.1 413", response)
        self.assertEqual(self.transport.calls,[])

    def test_http_cannot_downgrade_trusted_private_profile_or_choose_public_model(self):
        private=LocalProviderGateway(self.dispatcher,token=TOKEN,profile_id="private-session",sensitivity=Sensitivity.PRIVATE,model=MODEL,context_factory=fixture_context)
        private.context_factory=lambda **claims: fixture_context(**claims, sensitivity=Sensitivity.PRIVATE)
        private_port=private.start()
        self.addCleanup(private.close)
        req=urllib.request.Request(f"http://127.0.0.1:{private_port}/v1/chat/completions",
            data=json.dumps({"model":MODEL,"messages":[{"role":"user","content":"sensitive"}]}).encode(),
            headers={"Authorization":"Bearer "+TOKEN,"X-Classification":"PUBLIC","Content-Type":"application/json"})
        try:
            urllib.request.urlopen(req,timeout=2)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code,403)
        else:
            self.fail("private trusted profile reached the public provider")
        self.assertEqual(self.transport.calls,[])

    def test_public_server_tools_multimodal_and_fallback_payloads_are_denied(self):
        invalid=[
            {"models":["paid/model"]},
            {"fallbacks":["paid/model"]},
            {"tools":[{"type":"openrouter:web_search","openrouter":{"search_context_size":"high"}}]},
            {"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://image.invalid/x"}}]}]},
            {"messages":[{"role":"user","content":"hello"}],"response_format":{"type":"json_object"}},
        ]
        for addition in invalid:
            with self.subTest(addition=addition):
                base={"model":MODEL,"messages":[{"role":"user","content":"hello"}]}
                base.update(addition)
                status,_,_=self.request(body=json.dumps(base).encode())
                self.assertIn(status,(400,403))
        self.assertEqual(self.transport.calls,[])

    def test_materialized_plugin_uses_local_only_endpoint_and_contains_no_api_secret(self):
        root=OwnedRoot(Path(self.temp.name)/"owned"); root.ensure()
        paths=materialize_hermes_provider_plugin(root,profile_relative="profiles/test",port=18081,model=MODEL)
        source=Path(paths["entrypoint"]).read_text()
        self.assertIn(LOCAL_PROVIDER_NAME,source)
        self.assertIn(LOCAL_KEY_ENV,source)
        self.assertIn("http://127.0.0.1:18081/v1",source)
        self.assertNotIn(TOKEN,source)
        compile(source,paths["entrypoint"],"exec")
        self.assertEqual(Path(paths["entrypoint"]).stat().st_mode & 0o777,0o600)
        repeated=materialize_hermes_provider_plugin(root,profile_relative="profiles/test",port=18081,model=MODEL)
        self.assertEqual(Path(repeated["entrypoint"]).read_bytes(),Path(paths["entrypoint"]).read_bytes())

    def test_materializer_refuses_existing_unowned_plugin_tree(self):
        from hermes_installer.state import OwnershipError

        root=OwnedRoot(Path(self.temp.name)/"unowned"); root.ensure()
        plugin=root.path("profiles/test/plugins/model-providers/"+LOCAL_PROVIDER_NAME)
        plugin.parent.mkdir(parents=True,mode=0o700)
        current=plugin.parent
        while current != root.root:
            current.chmod(0o700)
            if current == root.path("profiles"):
                break
            current=current.parent
        plugin.mkdir(mode=0o700)
        entry=plugin/"__init__.py"
        entry.write_text("# user plugin")
        with self.assertRaisesRegex(OwnershipError,"installer-owned|ownership"):
            materialize_hermes_provider_plugin(root,profile_relative="profiles/test",port=18081,model=MODEL)
        self.assertEqual(entry.read_text(),"# user plugin")

    def test_gateway_strict_host_origin_and_duplicate_framing(self):
        payload=json.dumps({"model":MODEL,"messages":[{"role":"user","content":"hello"}]}).encode()
        status,_,_=self.request(body=payload,headers={"Origin":"https://evil.example"})
        self.assertEqual(status,403)
        status,_,_=self.request(body=payload,headers={"Host":"attacker.invalid"})
        self.assertEqual(status,403)
        with socket.create_connection(("127.0.0.1",self.port),timeout=2) as sock:
            sock.sendall((
                f"POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{self.port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 2\r\n"
                "Content-Length: 2\r\n"
                "Connection: close\r\n\r\n"
            ).encode("ascii"))
            reply=sock.recv(4096)
        self.assertIn(b"HTTP/1.1 400",reply)
        self.assertEqual(self.transport.calls,[])

    def test_gateway_body_read_has_deadline(self):
        root=OwnedRoot(Path(self.temp.name)/"slow"); root.ensure()
        transport=RecordingTransport()
        dispatcher=Dispatcher(DispatchPolicy({"public":default_public_route()},"public"),BudgetLedger(root),transport,context_authorizer=synthetic_authorizer)
        gateway=LocalProviderGateway(dispatcher,token=TOKEN,profile_id="slow",sensitivity=Sensitivity.PUBLIC,
                                     model=MODEL,read_timeout_seconds=0.15,max_connections=1,context_factory=fixture_context)
        port=gateway.start()
        self.addCleanup(gateway.close)
        with socket.create_connection(("127.0.0.1",port),timeout=2) as sock:
            sock.sendall((
                f"POST /v1/chat/completions HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Authorization: Bearer {TOKEN}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 10\r\n"
                "Connection: close\r\n\r\n"
                "x"
            ).encode("ascii"))
            response=sock.recv(4096)
        self.assertIn(b"HTTP/1.1 408",response)
        self.assertEqual(transport.calls,[])

    def test_connection_limit_closes_excess_slow_clients(self):
        root=OwnedRoot(Path(self.temp.name)/"limited"); root.ensure()
        dispatcher=Dispatcher(DispatchPolicy({"public":default_public_route()},"public"),BudgetLedger(root),RecordingTransport(),context_authorizer=synthetic_authorizer)
        gateway=LocalProviderGateway(dispatcher,token=TOKEN,profile_id="limited",sensitivity=Sensitivity.PUBLIC,
                                     model=MODEL,read_timeout_seconds=1,max_connections=1,context_factory=fixture_context)
        port=gateway.start()
        self.addCleanup(gateway.close)
        first=socket.create_connection(("127.0.0.1",port),timeout=2)
        self.addCleanup(first.close)
        first.sendall(b"POST /v1/chat/completions HTTP/1.1\r\n")
        second=socket.create_connection(("127.0.0.1",port),timeout=2)
        second.settimeout(1)
        self.addCleanup(second.close)
        self.assertEqual(second.recv(1),b"")

    def test_gateway_close_cancels_inflight_dispatch(self):
        import threading
        import time

        class CancellableTransport:
            def __init__(self):
                self.started=threading.Event()
                self.cancel_seen=threading.Event()
            def __call__(self,route,model,payload,*,output_token_limit,timeout,trace_id,cancelled=lambda:False):
                self.started.set()
                limit=time.monotonic()+2
                while time.monotonic()<limit:
                    if cancelled():
                        self.cancel_seen.set()
                        return ProviderResponse(200,b'{"choices":[]}')
                    time.sleep(0.01)
                return ProviderResponse(200,b'{"choices":[]}')

        root=OwnedRoot(Path(self.temp.name)/"cancel"); root.ensure()
        downstream=CancellableTransport()
        dispatcher=Dispatcher(DispatchPolicy({"public":default_public_route()},"public"),BudgetLedger(root),downstream,context_authorizer=synthetic_authorizer)
        gateway=LocalProviderGateway(dispatcher,token=TOKEN,profile_id="cancel",sensitivity=Sensitivity.PUBLIC,model=MODEL,context_factory=fixture_context)
        port=gateway.start()
        self.addCleanup(gateway.close)
        outcome=[]
        def request():
            req=urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions",
                data=json.dumps({"model":MODEL,"messages":[{"role":"user","content":"hello"}]}).encode(),
                headers={"Authorization":"Bearer "+TOKEN,"Content-Type":"application/json"})
            try:
                urllib.request.urlopen(req,timeout=3)
            except urllib.error.HTTPError as exc:
                outcome.append(exc.code)
            except OSError:
                outcome.append("closed")
        client=threading.Thread(target=request)
        client.start()
        self.assertTrue(downstream.started.wait(1))
        gateway.close()
        client.join(2)
        self.assertFalse(client.is_alive())
        self.assertTrue(downstream.cancel_seen.is_set())
        self.assertIn(outcome,[[],[503],["closed"]])


if __name__=="__main__": unittest.main()
