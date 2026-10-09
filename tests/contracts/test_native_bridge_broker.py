"""Failure-effect proofs for the HI11 root-owned producer/gateway bridge."""
from __future__ import annotations

import base64
import hashlib
import os
import unittest
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.authority.native_bridge import NativeBridgeBroker
from hermes_installer.authority.service import AuthorityService, EffectRule, PrincipalBinding
from hermes_installer.authority.types import AuthorityDenied, Sensitivity, canonical_digest


class _Policy:
    revision = "native-bridge-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        return Sensitivity.UNKNOWN, canonical_digest({"fixture": "unknown"})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        return True


class NativeBridgeBrokerContracts(unittest.TestCase):
    def test_worker_submitted_request_is_not_promoted_to_observed_source(self):
        producer = PrincipalBinding(1201, "principal:producer", "profile:producer",
                                    "namespace:producer", frozenset({"provider-inference"}))
        gateway = PrincipalBinding(1202, "principal:gateway", "profile:gateway",
                                   "namespace:gateway", frozenset({"provider-inference"}))
        rule = EffectRule("provider-inference", "provider.dispatch", "fixed-provider-target", "fixed-recipient")
        outbound = []

        def handler(*, context, authorization, payload, timeout, peer_pid, peer_pidfd, cancelled):
            outbound.append(payload)
            return {"status": 200, "body": b"should-not-send", "headers": {}, "receipt_id": "fixture"}

        service = AuthorityService(
            signing_key=b"N" * 32, key_id="native-bridge-fixture",
            bindings_by_uid={producer.uid: producer, gateway.uid: gateway},
            rules={(rule.capability, rule.operation, rule.target): rule},
            handlers={(rule.operation, rule.target): handler}, policy=_Policy(),
            profile_generations={producer.profile_id: "producer-v1", gateway.profile_id: "gateway-v1"},
        )
        identity = lambda pid, uid: f"linux-proc:{canonical_digest({'pid': pid, 'uid': uid})}"
        service._native_process_identity = identity

        class Resolver:
            def __call__(self, pid, pidfd, *, profile_id, generation):
                uid = producer.uid if profile_id == producer.profile_id else gateway.uid
                sha = "a" * 64 if profile_id == producer.profile_id else "b" * 64
                return SimpleNamespace(profile_id=profile_id, generation=generation,
                                       kernel_uid=uid, executable_sha256=sha,
                                       cgroup_identity=f"cgroup:{profile_id}", namespace_identity="mnt:1;net:1")

        def canonicalizer(root_enrollments, payload, *, normalization_policy):
            self.assertEqual(set(root_enrollments), {("fixed-provider-target", "fixed-recipient")})
            self.assertEqual(normalization_policy["id"], "provider-output-reject-4096-v1")
            return payload, "fixed-provider-target", "fixed-recipient", "provider-inference", "model:fixed"

        source_digest = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        bridge = SimpleNamespace(
            bridge_id="bridge:fixture", producer_profile_id=producer.profile_id,
            producer_uid=producer.uid, producer_generation="producer-v1",
            producer_executable_sha256="a" * 64, gateway_profile_id=gateway.profile_id,
            gateway_uid=gateway.uid, gateway_generation="gateway-v1",
            gateway_executable_sha256="b" * 64, canonicalizer_artifact_id="provider-canonicalizer-v1",
            canonicalizer_sha256=source_digest, approved_operation="provider.dispatch",
            normalization_policy_id="provider-output-reject-4096-v1",
            normalization_policy_sha256="c" * 64, normalization_policy_revision=1,
            route_schema_id="provider-chat-compatible-v1", output_limit_mode="reject-over-ceiling",
            output_limit_ceiling=4096,
            target="fixed-provider-target", recipient="fixed-recipient",
        )
        broker = NativeBridgeBroker(
            service=service, bridges={bridge.bridge_id: bridge}, process_resolver=Resolver(),
            canonicalizer=canonicalizer,
            root_selected_enrollments={bridge.bridge_id: {("fixed-provider-target", "fixed-recipient"): object()}},
            canonicalizer_sha256=source_digest,
        )
        service.native_bridge_broker = broker
        producer_read, producer_write = os.pipe()
        gateway_read, gateway_write = os.pipe()
        try:
            raw = b'{"messages":[{"role":"user","content":"private"}]}'
            with self.assertRaises(AuthorityDenied) as denied:
                service._dispatch(producer.uid, 41001, producer_read,
                    "prepare_native_event", {
                "schema": 1, "payload": base64.b64encode(raw).decode("ascii"),
                "parent_receipt_handles": [], "purpose": "native-hermes-chat",
                    "intent_id": "intent:fixture", "trace_id": "trace:fixture", "retry_index": 0,
                    }, cancelled=lambda: False)
            self.assertEqual(denied.exception.code, "native.observer_unavailable")
            self.assertEqual(outbound, [])
            self.assertEqual(service._source_receipt_handles, {})
        finally:
            for fd in (producer_read, producer_write, gateway_read, gateway_write):
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
