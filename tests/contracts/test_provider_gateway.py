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

from hermes_installer.policy import BudgetLedger, DispatchPolicy, Dispatcher, ProviderResponse, Sensitivity, default_public_route
from hermes_installer.provider_gateway import LOCAL_KEY_ENV, LOCAL_PROVIDER_NAME, LocalProviderGateway, materialize_hermes_provider_plugin
from hermes_installer.state import OwnedRoot


MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"
TOKEN="local-fixture-token-value-0123456789abcdef"


class RecordingTransport:
    def __init__(self):
        self.calls=[]
    def __call__(self,route,model,payload,*,output_token_limit,timeout,trace_id):
        self.calls.append((route.name,model,payload,output_token_limit,timeout,trace_id))
        return ProviderResponse(200,b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":2,"completion_tokens":3}}',{"Content-Type":"application/json"},2,3)


class ProviderGatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        root=OwnedRoot(Path(self.temp.name)/"owned");root.ensure()
        self.transport=RecordingTransport()
        self.dispatcher=Dispatcher(DispatchPolicy({"public":default_public_route()},"public"),BudgetLedger(root),self.transport)
        self.gateway=LocalProviderGateway(self.dispatcher,token=TOKEN,profile_id="public-demo",sensitivity=Sensitivity.PUBLIC,model=MODEL,max_output_tokens=32)
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
        private=LocalProviderGateway(self.dispatcher,token=TOKEN,profile_id="private-session",sensitivity=Sensitivity.PRIVATE,model=MODEL)
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

if __name__=="__main__": unittest.main()
