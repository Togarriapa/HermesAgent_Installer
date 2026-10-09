from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path

from hermes_installer.network import HTTPResult
from hermes_installer.policy import (BudgetLedger, DispatchAuthorization, DispatchContext, DispatchPolicy, Dispatcher,
    PolicyDenied, Route, Sensitivity, default_public_route)
from hermes_installer.provider_transport import OPENROUTER_ENDPOINT, OpenRouterTransport
from hermes_installer.eligibility import AccountEligibilityGate, EligibilityEvidence
from hermes_installer.state import OwnedRoot

MODEL="nvidia/nemotron-3-ultra-550b-a55b:free"


def fixture_context(profile_id, purpose, sensitivity, **kwargs):
    return DispatchContext(profile_id, purpose, sensitivity,
        principal_id="fixture-principal", namespace="fixture-namespace",
        provenance="sha256:" + "f" * 64,
        capabilities=frozenset({"inference", "tool-call"}),
        policy_revision="fixture-revision", grant_id="fixture-context-grant",
        lease_expires_at=time.monotonic() + 3600, **kwargs)


def synthetic_authorizer(context, capability, intent_id, now, timeout, cancelled):
    import uuid
    return DispatchAuthorization(context.principal_id, context.profile_id, context.namespace,
        context.trace_id, context.capabilities, context.effective_sensitivity,
        context.policy_revision, context.purpose, capability, intent_id,
        context.provenance[7:], str(uuid.uuid4()),
        min(now + min(60, timeout), context.lease_expires_at))


class RecordingNetwork:
    def __init__(self, *, deadline_seconds, socket_timeout, max_response_bytes):
        self.deadline_seconds=deadline_seconds
        self.socket_timeout=socket_timeout
        self.max_response_bytes=max_response_bytes
        self.calls=[]
    def request(self,url,*,method,headers,body,cancelled=lambda:False):
        self.calls.append((url,method,headers,body))
        return HTTPResult(200,{"x-secret-echo":"must not propagate","Retry-After":"1"},b'{"choices":[{"message":{"content":"ok"}}],"usage":{"prompt_tokens":3,"completion_tokens":4}}')


class ProviderTransportTests(unittest.TestCase):
    def make(self):
        networks=[]
        def factory(**kwargs):
            network=RecordingNetwork(**kwargs)
            networks.append(network)
            return network
        evidence = EligibilityEvidence.create(account_id="fixture", checked_at=1000, lifetime_seconds=60,
            free_account=True, effective_plugins_disabled=True, approved_model=MODEL,
            evidence_source="synthetic-test-only", credential_ref="file:///secure/provider-token",
            credential="fixture-secret-r", policy_snapshot_sha256="a" * 64)
        gate = AccountEligibilityGate(model=MODEL, credential_ref="file:///secure/provider-token",
            evidence=evidence, clock=lambda: 1001, allow_test_evidence=True)
        transport=OpenRouterTransport("file:///secure/provider-token",secret_reader=lambda ref:"fixture-secret-r",network_factory=factory,eligibility=gate,allow_direct_fixture_transport=True)
        return transport,networks

    def test_absent_or_expired_account_policy_denies_before_secret_or_network(self):
        resolved = []
        network_calls = []
        transport = OpenRouterTransport(
            "file:///secure/provider-token",
            secret_reader=lambda ref: resolved.append(ref) or "fixture",
            network_factory=lambda **kwargs: network_calls.append(kwargs),
        )
        with self.assertRaisesRegex(PolicyDenied, "zero-charge account policy"):
            transport(default_public_route(), MODEL, b'{"messages":[]}',
                      output_token_limit=8, timeout=2, trace_id="trace")
        self.assertEqual(resolved, [])
        self.assertEqual(network_calls, [])

        expired = EligibilityEvidence.create(account_id="fixture", checked_at=1000,
            lifetime_seconds=10, free_account=True, effective_plugins_disabled=True,
            approved_model=MODEL, evidence_source="synthetic-test-only",
            credential_ref="file:///secure/provider-token", credential="fixture",
            policy_snapshot_sha256="b" * 64)
        expired_gate = AccountEligibilityGate(model=MODEL,
            credential_ref="file:///secure/provider-token", evidence=expired,
            clock=lambda: 1011, allow_test_evidence=True)
        transport = OpenRouterTransport("file:///secure/provider-token",
            secret_reader=lambda ref: resolved.append(ref) or "fixture",
            network_factory=lambda **kwargs: network_calls.append(kwargs),
            eligibility=expired_gate)
        with self.assertRaisesRegex(PolicyDenied, "missing or expired"):
            transport(default_public_route(), MODEL, b'{"messages":[]}',
                      output_token_limit=8, timeout=2, trace_id="trace")
        self.assertEqual(resolved, [])
        self.assertEqual(network_calls, [])


    def test_synthetic_evidence_is_test_only_and_bound_to_key_reference_model_and_credential(self):
        ref = "file:///secure/provider-token"
        evidence = EligibilityEvidence.create(account_id="fixture", checked_at=1000,
            lifetime_seconds=60, free_account=True, effective_plugins_disabled=True,
            approved_model=MODEL, evidence_source="synthetic-test-only",
            credential_ref=ref, credential="bound-secret",
            policy_snapshot_sha256="d" * 64)
        production_gate = AccountEligibilityGate(model=MODEL, credential_ref=ref,
            evidence=evidence, clock=lambda: 1001)
        with self.assertRaisesRegex(PolicyDenied, "authoritative"):
            production_gate.require_eligible(model=MODEL, credential_ref=ref)

        fixture_gate = AccountEligibilityGate(model=MODEL, credential_ref=ref,
            evidence=evidence, clock=lambda: 1001, allow_test_evidence=True)
        with self.assertRaisesRegex(PolicyDenied, "does not match"):
            fixture_gate.require_eligible(model=MODEL, credential_ref="file:///other/key")
        with self.assertRaisesRegex(PolicyDenied, "does not match"):
            fixture_gate.require_eligible(model="other/model", credential_ref=ref)
        fixture_gate.require_eligible(model=MODEL, credential_ref=ref)
        with self.assertRaisesRegex(PolicyDenied, "credential"):
            fixture_gate.verify_credential("rotated-secret")

        resolved, network_factories = [], []
        def network_factory(**kwargs):
            network_factories.append(kwargs)
            return RecordingNetwork(**kwargs)
        transport = OpenRouterTransport(ref, secret_reader=lambda value: resolved.append(value) or "rotated-secret",
            network_factory=network_factory, eligibility=fixture_gate)
        with self.assertRaisesRegex(PolicyDenied, "credential"):
            transport(default_public_route(), MODEL, b'{"messages":[{"role":"user","content":"hi"}]}',
                output_token_limit=8, timeout=2, trace_id="bound-key")
        self.assertEqual(resolved, [ref])
        self.assertEqual(network_factories, [])


    def test_credential_rotation_after_success_denies_before_second_network_factory(self):
        ref = "file:///secure/provider-token"
        values = iter(["fixture-secret-r", "rotated-secret"])
        resolved, networks = [], []
        def secret_reader(value):
            resolved.append(value)
            return next(values)
        def factory(**kwargs):
            network = RecordingNetwork(**kwargs)
            networks.append(network)
            return network
        evidence = EligibilityEvidence.create(account_id="fixture", checked_at=1000,
            lifetime_seconds=60, free_account=True, effective_plugins_disabled=True,
            approved_model=MODEL, evidence_source="synthetic-test-only",
            credential_ref=ref, credential="fixture-secret-r",
            policy_snapshot_sha256="e" * 64)
        gate = AccountEligibilityGate(model=MODEL, credential_ref=ref,
            evidence=evidence, clock=lambda: 1001, allow_test_evidence=True)
        transport = OpenRouterTransport(ref, secret_reader=secret_reader,
            network_factory=factory, eligibility=gate, allow_direct_fixture_transport=True)
        payload = b'{"messages":[{"role":"user","content":"hi"}]}'
        transport(default_public_route(), MODEL, payload, output_token_limit=8,
            timeout=2, trace_id="rotation-first")
        with self.assertRaisesRegex(PolicyDenied, "credential"):
            transport(default_public_route(), MODEL, payload, output_token_limit=8,
                timeout=2, trace_id="rotation-second")
        self.assertEqual(resolved, [ref, ref])
        self.assertEqual(len(networks), 1)
        self.assertEqual(len(networks[0].calls), 1)

    def test_fixed_endpoint_secret_and_response_usage(self):
        transport,networks=self.make()
        route=default_public_route()
        payload=b'{"model":"attacker/model","max_tokens":999999,"messages":[{"role":"user","content":"hello"}]}'
        response=transport(route,MODEL,payload,output_token_limit=77,timeout=3,trace_id="trace-1")
        self.assertEqual(response.status,200)
        self.assertEqual((response.input_tokens,response.output_tokens),(3,4))
        self.assertEqual(response.headers,{"Content-Type":"application/json","Retry-After":"1"})
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
        payload=b'{"messages":[{"role":"user","content":"hi"}]}'
        evil=Route("openrouter-nemotron-free","https://attacker.invalid/api/v1",frozenset({MODEL}),Sensitivity.PUBLIC,True,True,0,0)
        with self.assertRaisesRegex(PolicyDenied,"pinned public"):
            transport(evil,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")
        private=Route("openrouter-nemotron-free",OPENROUTER_ENDPOINT,frozenset({MODEL}),Sensitivity.PRIVATE,True,True,0,0)
        with self.assertRaisesRegex(PolicyDenied,"non-public"):
            transport(private,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")

    def test_conflicting_model_and_invalid_request_are_rejected_or_normalized(self):
        transport,networks=self.make()
        route=default_public_route()
        payload=b'{"model":"private/hidden","max_completion_tokens":1,"messages":[{"role":"user","content":"hi"}]}'
        response=transport(route,MODEL,payload,output_token_limit=8,timeout=2,trace_id="trace")
        self.assertEqual(response.status,200)
        self.assertEqual(json.loads(networks[0].calls[0][3])["model"],MODEL)
        for bad in (b"[]",b"not-json",b'{"messages":"not-an-array"}', b'{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"https://image.invalid/a"}}]}]}', b'{"messages":[],"response_format":{"type":"json_object"}}', b'{"messages":[],"models":["paid/model"]}', b'{"messages":[],"fallbacks":["paid/model"]}', b'{"messages":[],"tools":[{"type":"openrouter:web_search"}]}', b'{"messages":[],"plugins":[{"id":"web"}]}'):
            with self.assertRaises(PolicyDenied):
                transport(route,MODEL,bad,output_token_limit=8,timeout=2,trace_id="trace")

    def test_unapproved_model_and_unbounded_timeout_are_denied(self):
        transport,_=self.make()
        with self.assertRaisesRegex(PolicyDenied,"does not match"):
            transport(default_public_route(),"attacker/model",b'{"messages":[]}',output_token_limit=8,timeout=2,trace_id="trace")
        with self.assertRaisesRegex(PolicyDenied,"hard bound"):
            transport(default_public_route(),MODEL,b'{"messages":[]}',output_token_limit=8,timeout=31,trace_id="trace")

    def test_oversized_request_is_rejected_before_secret_resolution(self):
        resolved=[]
        evidence = EligibilityEvidence.create(account_id="fixture", checked_at=1000, lifetime_seconds=60,
            free_account=True, effective_plugins_disabled=True, approved_model=MODEL,
            evidence_source="synthetic-test-only", credential_ref="file:///secure/provider-token",
            credential="fixture", policy_snapshot_sha256="c" * 64)
        gate = AccountEligibilityGate(model=MODEL, credential_ref="file:///secure/provider-token",
            evidence=evidence, clock=lambda: 1001, allow_test_evidence=True)
        transport=OpenRouterTransport("file:///secure/provider-token",secret_reader=lambda ref:resolved.append(ref) or "fixture",network_factory=lambda **kwargs:None,eligibility=gate)
        route=default_public_route()
        with self.assertRaisesRegex(PolicyDenied,"byte limit"):
            transport(route,MODEL,b'{"messages":[]}' + b"x"*1_048_577,output_token_limit=8,timeout=2,trace_id="trace")
        self.assertEqual(resolved,[])

    def test_dispatcher_to_real_transport_is_idempotent_and_posts_once(self):
        with tempfile.TemporaryDirectory() as td:
            transport, networks = self.make()
            root = OwnedRoot(Path(td) / "owned")
            root.ensure()
            dispatcher = Dispatcher(
                DispatchPolicy({"public": default_public_route()}, "public"),
                BudgetLedger(root), transport, context_authorizer=synthetic_authorizer,
            )
            response = dispatcher.dispatch(
                fixture_context("hermes", "chat", Sensitivity.PUBLIC),
                MODEL,
                b'{"messages":[{"role":"user","content":"hello"}]}',
                input_tokens=8,
                output_token_limit=32,
            )
            self.assertEqual(response.status, 200)
            self.assertEqual(len(networks), 1)
            self.assertEqual(len(networks[0].calls), 1)
            body = json.loads(networks[0].calls[0][3])
            self.assertEqual(body["model"], MODEL)
            self.assertEqual(body["max_tokens"], 32)
            self.assertEqual(body["provider"], {
                "allow_fallbacks": False, "require_parameters": True, "data_collection": "deny"
            })
            self.assertTrue(body["plugins"])
            self.assertTrue(all(plugin["enabled"] is False for plugin in body["plugins"]))

    def test_secret_reference_cannot_use_environment(self):
        with self.assertRaisesRegex(Exception,"private file or secure store"):
            OpenRouterTransport("env://PROVIDER_KEY",secret_reader=lambda ref:"token")
