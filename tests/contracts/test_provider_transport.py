from __future__ import annotations

import json
import unittest

from hermes_installer.network import HTTPResult
from hermes_installer.policy import PolicyDenied, Route, Sensitivity, default_public_route
from hermes_installer.provider_transport import OPENROUTER_ENDPOINT, OpenRouterTransport

MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"


class RecordingNetwork:
    def __init__(self, *, deadline_seconds, socket_timeout, max_response_bytes):
        self.deadline_seconds=deadline_seconds
        self.socket_timeout=socket_timeout
        self.max_response_bytes=max_response_bytes
        self.calls=[]
    def request(self,url,*,method,headers,body):
        self.calls.append((url,method,headers,body))
        return HTTPResult(200,{"x-secret-echo":"must not propagate","Retry-After":"1"},b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}')


class ProviderTransportTests(unittest.TestCase):
    def make(self):
        networks=[]
        def factory(**kwargs):
            network=RecordingNetwork(**kwargs)
            networks.append(network)
            return network
        transport=OpenRouterTransport("file:///secure/provider-token",secret_reader=lambda ref:"fixture-secret-r",network_factory=factory)
        return transport,networks

    def test_fixed_endpoint_secret_and_response_usage(self):
        transport,networks=self.make()
        route=default_public_route()
        payload=b'{"model":"attacker/model","max_tokens":999999,"messages":[{"role":"user","content":"hello"}]}'
        response=transport(route,MODEL,payload,output_token_limit=77,timeout=3,trace_id="trace-1")
        self.assertEqual(response.status,200)
        self.assertEqual((response.input_tokens,response.output_tokens),(3,4))
        self.assertEqual(response.headers,{"Retry-After":"1"})
        url,method,headers,body=networks[0].calls[0]
        self.assertEqual(url,OPENROUTER_ENDPOINT+"/chat/completions")
        self.assertEqual(method,"POST")
        self.assertEqual(headers["Authorization"],"Bearer fixture-secret-r")
        self.assertNotIn("x-secret-echo",headers)
        sent=json.loads(body)
        self.assertEqual(sent["model"],MODEL)
        self.assertEqual(sent["max_tokens"],77)
        self.assertEqual(sent["provider"],{"allow_fallbacks":False,"require_parameters":True,"data_collection":"deny"})
        self.assertTrue(all(plugin["enabled"] is False for plugin in sent["plugins"]))
        self.assertNotIn("max_completion_tokens",sent)
        self.assertNotIn("fixture-secret-r",repr(transport))

    def test_route_host_and_nonpublic_sensitivity_are_denied(self):
        transport,_=self.make()
        payload=b'{"messages":[]}'
        evil=Route("openrouter-nemotron-free","https://attacker.invalid/api/v1",frozenset({MODEL}),Sensitivity.PUBLIC,True,True,0,0)
        with self.assertRaisesRegex(PolicyDenied,"pinned public"):
            transport(evil,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")
        private=Route("openrouter-nemotron-free",OPENROUTER_ENDPOINT,frozenset({MODEL}),Sensitivity.PRIVATE,True,True,0,0)
        with self.assertRaisesRegex(PolicyDenied,"non-public"):
            transport(private,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")

    def test_conflicting_model_and_invalid_request_are_rejected_or_normalized(self):
        transport,networks=self.make()
        route=default_public_route()
        payload=b'{"model":"private/hidden","max_completion_tokens":1,"messages":[]}'
        response=transport(route,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")
        self.assertEqual(response.status,200)
        self.assertEqual(json.loads(networks[0].calls[0][3])["model"],MODEL)
        for bad in (b"[]",b"not-json",b'{"messages":"not-an-array"}', b'{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://image.invalid/a"}}]}]}', b'{"messages":[],"response_format":{"type":"json_object"}}', b'{"messages":[],"models":["paid/model"]}', b'{"messages":[],"fallbacks":["paid/model"]}', b'{"messages":[],"tools":[{"type":"openrouter:web_search"}]}', b'{"messages":[],"plugins":[{"id":"web"}]}'):
            with self.assertRaises(PolicyDenied):
                transport(route,MODEL,bad,output_token_limit=8,timeout=2,trace_id="trace")

    def test_unapproved_model_and_unbounded_timeout_are_denied(self):
        transport,_=self.make()
        with self.assertRaisesRegex(PolicyDenied,"not approved"):
            transport(default_public_route(),"attacker/model",b'{"messages":[]}',output_token_limit=8,timeout=2,trace_id="trace")
        with self.assertRaisesRegex(PolicyDenied,"hard bound"):
            transport(default_public_route(),MODEL,b'{"messages":[]}',output_token_limit=8,timeout=31,trace_id="trace")

    def test_oversized_request_is_rejected_before_secret_resolution(self):
        resolved=[]
        transport=OpenRouterTransport("file:///secure/provider-token",secret_reader=lambda ref:resolved.append(ref) or "fixture",network_factory=lambda **kwargs:None)
        route=default_public_route()
        with self.assertRaisesRegex(PolicyDenied,"byte limit"):
            transport(route,MODEL,b'{"messages":[]}' + b"x"*1_048_577,output_token_limit=8,timeout=2,trace_id="trace")
        self.assertEqual(resolved,[])

    def test_secret_reference_cannot_use_environment(self):
        with self.assertRaisesRegex(Exception,"private file or secure store"):
            OpenRouterTransport("env://PROVIDER_KEY",secret_reader=lambda ref:"token")
