from __future__ import annotations

import base64
import hashlib
import os
import unittest
from types import SimpleNamespace

from hermes_installer.authority.native_runtime_observer import (
    NativeActionSelection,
    NativeInvocationRegistry,
)
from hermes_installer.authority.service import (
    AuthorityService,
    EffectRule,
    PrincipalBinding,
)
from hermes_installer.authority.source_observers import SourceObserverRegistry
from hermes_installer.authority.types import (
    AuthorityDenied,
    Sensitivity,
    canonical_digest,
)
from hermes_installer.provider_response_observer import parse_successful_provider_tool_calls
from tests.contracts.test_source_observers import (
    _Identity,
    _LoadedProof,
    _Package,
    _TargetPeer,
    _enrollment,
)


class _Policy:
    revision = "native-registry-fixture"

    def classify(self, *, purpose, intent, source_contexts, binding):
        del purpose, intent, source_contexts, binding
        return Sensitivity.PRIVATE, canonical_digest({"fixture": "private"})

    def allow_effect(self, *, context, rule, request_digest, retry_index):
        del context, rule, request_digest, retry_index
        return True


class NativeInvocationServiceRegistryIntegration(unittest.TestCase):
    """Exercise root effect -> observer -> service RPC -> invocation ancestry."""

    def test_successful_response_is_root_bound_private_and_one_use(self):
        producer_uid, gateway_uid = 2001, 2002
        producer_pid, gateway_pid = 733, 844
        producer_profile, gateway_profile = "producer-profile", "gateway-profile"
        generation, gateway_generation = "gen-4", "gen-8"
        target, recipient = "provider.fixed", "public-provider"
        capability, operation = "provider-inference", "provider.dispatch"
        producer_binding = PrincipalBinding(
            producer_uid, "producer-principal", producer_profile,
            "producer-namespace", frozenset({capability}),
        )
        gateway_binding = PrincipalBinding(
            gateway_uid, "gateway-principal", gateway_profile,
            "gateway-namespace", frozenset({capability}),
        )
        rule = EffectRule(capability, operation, target, recipient)
        request_bytes = b'{"model":"fixture","messages":[]}'
        request_digest = hashlib.sha256(request_bytes).hexdigest()
        response_bytes = (
            b'{"choices":[{"message":{"tool_calls":[{"id":"call-1",'
            b'"type":"function","function":{"name":"selected_tool",'
            b'"arguments":"{\\"x\\":1}"}}]},"finish_reason":"tool_calls"}]}'
        )
        response_digest = hashlib.sha256(response_bytes).hexdigest()

        def handler(*, context, authorization, payload, timeout,
                    peer_pid, peer_pidfd, cancelled):
            del context, authorization, timeout, peer_pid, peer_pidfd
            self.assertEqual(payload, request_bytes)
            self.assertFalse(cancelled())
            return {
                "status": 200,
                "body": response_bytes,
                "headers": {"Content-Type": "application/json"},
                "receipt_id": "fixture-provider-result",
            }

        service = AuthorityService(
            signing_key=b"N" * 32,
            key_id="native-invocation-fixture",
            bindings_by_uid={producer_uid: producer_binding, gateway_uid: gateway_binding},
            rules={(capability, operation, target): rule},
            handlers={(operation, target): handler},
            policy=_Policy(),
            profile_generations={producer_profile: generation, gateway_profile: gateway_generation},
            service_generation_digest="2" * 64,
        )
        service._native_process_identity = lambda pid, uid: f"{pid}:{uid}"
        producer_enrollment_id = canonical_digest({
            "uid": producer_uid,
            "principal_id": producer_binding.principal_id,
            "profile_id": producer_profile,
            "namespace_id": producer_binding.namespace_id,
            "generation": generation,
            "authority_epoch": service.authority_epoch,
        })
        producer_identity = _Identity(
            producer_profile, generation, producer_uid, 811, "b" * 64,
        )
        gateway_identity = _Identity(
            gateway_profile, gateway_generation, gateway_uid, 992, "f" * 64,
        )

        def process_resolver(pid, _pidfd, *, profile_id, generation):
            identities = {
                (producer_pid, producer_profile, generation): producer_identity,
                (gateway_pid, gateway_profile, generation): gateway_identity,
            }
            identity = identities.get((pid, profile_id, generation))
            return identity

        service.process_effect_handler = SimpleNamespace(resolve_live_peer=process_resolver)

        package = _Package()
        loaded_proof_fixture = _LoadedProof(
            proof_id="loaded-proof-fixture",
            package_id=package.package_id,
            profile_id=producer_profile,
            generation=generation,
            compiled_closure_sha256=package.compiled_closure_sha256,
            entrypoint_sha256=package.entrypoint_sha256,
            resolver_sha256=package.resolver_sha256,
            mount_namespace_inode=123,
            mount_id="mount-fixture",
            mount_target_digest="1" * 64,
            mount_flags=frozenset({"ro", "nosuid", "nodev"}),
            source_root_device=8,
            source_root_inode=99,
            target_peer_identity=producer_identity,
            loader_role_artifact_id="hermes-main",
            loader_role_sha256="b" * 64,
            loader_ready_event_id="loader-ready-fixture",
            observed_entrypoint_action_ids=("chat.complete",),
            issued_monotonic=service.monotonic() - 1,
            expires_monotonic=service.monotonic() + 60,
            service_generation_digest="2" * 64,
        )
        source_enrollment = _enrollment(
            observer_enrollment_id="observer.provider.result",
            source_kind="provider-result",
            origin_id="hermes.provider.result",
            enrollment_id=producer_enrollment_id,
            source_action_id="chat.complete",
            target_id=target,
            recipient=recipient,
            allowed_parent_source_kinds=frozenset(),
        )

        def loaded_proof(identity, observer, *, peer_pid, peer_pidfd):
            del identity, observer, peer_pid, peer_pidfd
            return loaded_proof_fixture

        source_observers = SourceObserverRegistry(
            service=service,
            observers={source_enrollment.observer_enrollment_id: source_enrollment},
            process_resolver=process_resolver,
            package_resolver=lambda _package_id, _generation: package,
            # The observer resolver transfers an owned descriptor which
            # record_observed_event closes after pinning its own duplicate.
            target_peer_resolver=lambda _observer, _context: _TargetPeer(
                producer_pid, os.dup(producer_fd), producer_uid,
                producer_profile, generation, producer_identity,
            ),
            loaded_package_proof_resolver=loaded_proof,
        )
        service.attach_source_observer_registry(source_observers)
        bridge = SimpleNamespace(
            bridge_id="bridge.fixture",
            provider_enrollment_id="openrouter",
            producer_uid=producer_uid,
            producer_profile_id=producer_profile,
            producer_generation=generation,
            producer_executable_sha256="b" * 64,
            gateway_uid=gateway_uid,
            gateway_profile_id=gateway_profile,
            gateway_generation=gateway_generation,
            gateway_executable_sha256="f" * 64,
            approved_operation=operation,
            target=target,
            recipient=recipient,
        )

        def select_action(_bridge, identity, tool_name):
            if identity != producer_identity or tool_name != "selected_tool":
                raise AuthorityDenied("fixture.action", "unselected native tool")
            return NativeActionSelection(
                package_id=package.package_id,
                profile_id=producer_profile,
                generation=generation,
                adapter_id="hermes-main",
                action_id="chat.complete",
                validate_arguments=lambda args: args == b'{"x":1}',
            )

        registry = NativeInvocationRegistry(
            service=service,
            source_observers=source_observers,
            bridges={bridge.bridge_id: bridge},
            provider_result_observer_ids={
                (bridge.provider_enrollment_id, target, recipient): source_enrollment.observer_enrollment_id,
            },
            provider_tool_call_parser=parse_successful_provider_tool_calls,
            process_resolver=process_resolver,
            action_resolver=select_action,
        )
        service.attach_native_invocation_registry(registry)

        producer_fd = os.open(os.devnull, os.O_RDONLY)
        gateway_fd = os.open(os.devnull, os.O_RDONLY)
        try:
            context_wire = service._issue_context(
                producer_uid,
                {
                    "purpose": "native-hermes-chat",
                    "intent": "fixture-provider-call",
                    "trace_id": "trace-native-fixture",
                    "lease_seconds": 30,
                    "source_contexts": [],
                    "source_receipts": [],
                    "final_payload_digest": request_digest,
                    "operation": operation,
                },
                inherited_process_identity=f"{producer_pid}:{producer_uid}",
            )
            from hermes_installer.authority.types import HostContext, EffectAuthorization
            context = HostContext.from_wire(context_wire)
            grant_wire = service._authorize_effect(
                producer_uid,
                {
                    "context": context_wire,
                    "capability": capability,
                    "target": target,
                    "recipient": recipient,
                    "request_digest": request_digest,
                    "retry_index": 0,
                },
                peer_pid=producer_pid,
            )
            grant = EffectAuthorization.from_wire(grant_wire)
            result = service._perform_effect(
                producer_uid,
                gateway_pid,
                {
                    "authorization": grant_wire,
                    "operation": operation,
                    "payload": base64.b64encode(request_bytes).decode("ascii"),
                    "timeout": 10,
                },
                cancelled=lambda: False,
                peer_pidfd=gateway_fd,
                enforce_peer_identity=False,
            )
            observed_response = base64.b64decode(result["body"], validate=True)
            self.assertEqual(hashlib.sha256(observed_response).hexdigest(), response_digest)
            delivery = registry.register_provider_response(
                bridge=bridge,
                producer_identity=producer_identity,
                producer_pid=producer_pid,
                producer_pidfd=producer_fd,
                gateway_identity=gateway_identity,
                gateway_pid=gateway_pid,
                gateway_pidfd=gateway_fd,
                request_context=context,
                request_source_receipts=(),
                authorization=grant,
                target=target,
                recipient=recipient,
                request_digest=request_digest,
                response_status=result["status"],
                response_headers=result["headers"],
                response_bytes=observed_response,
                response_digest=response_digest,
                native_request_handle="r" * 43,
                expires_monotonic=grant.monotonic_expires_at,
                cancelled=lambda: False,
            )
            self.assertFalse(hasattr(delivery, "producer_context_handle"))
            lookup_payload = {
                "schema": 1,
                "delivery_handle": delivery.response_delivery_handle,
                "response_body_sha256": response_digest,
                "native_request_handle": "r" * 43,
            }
            metadata_wire = service._dispatch(
                producer_uid, producer_pid, producer_fd,
                "native.response.take", lookup_payload, cancelled=lambda: False,
            )
            self.assertEqual(set(metadata_wire), {
                "producer_context_handle", "tool_call_bindings", "turn_handle",
                "final_response_delivery_handle",
            })
            # Provider tool dispatch does not establish a completed native
            # conversation turn or its final-response delivery.
            self.assertIsNone(metadata_wire["turn_handle"])
            self.assertIsNone(metadata_wire["final_response_delivery_handle"])
            self.assertEqual(len(metadata_wire["tool_call_bindings"]), 1)
            call_binding = metadata_wire["tool_call_bindings"][0]

            arguments = b'{"x":1}'
            begin_wire = service._dispatch(
                producer_uid, producer_pid, producer_fd,
                "native.invocation.begin",
                {
                    "schema": 1,
                    "producer_context_handle": metadata_wire["producer_context_handle"],
                    "observed_call_handle": call_binding["observed_call_handle"],
                    "canonical_arguments_b64": base64.b64encode(arguments).decode("ascii"),
                },
                cancelled=lambda: False,
            )
            contexts_wire = service._dispatch(
                producer_uid, producer_pid, producer_fd,
                "native.invocation.contexts",
                {"schema": 1, "invocation_handle": begin_wire["invocation_handle"]},
                cancelled=lambda: False,
            )
            self.assertEqual(contexts_wire["arguments_sha256"], hashlib.sha256(arguments).hexdigest())
            self.assertEqual(len(contexts_wire["source_receipt_handles"]), 1)
            self.assertIn(contexts_wire["source_receipt_handles"][0], service._source_receipt_handles)

            handle = contexts_wire["source_receipt_handles"][0]
            capsule = source_observers._payload_capsules[handle][2]
            self.assertEqual(bytes(capsule), response_bytes)
            self.assertEqual(source_observers.cancel_invocation_payload_capsules(context.grant_id), 1)
            self.assertEqual(bytes(capsule), b"\x00" * len(response_bytes))
            self.assertNotIn(handle, service._source_receipt_handles)
            with self.assertRaises(AuthorityDenied):
                service._dispatch(
                    producer_uid, producer_pid, producer_fd,
                    "native.response.take", lookup_payload, cancelled=lambda: False,
                )
        finally:
            source_observers.close()
            registry.close()
            os.close(producer_fd)
            os.close(gateway_fd)


if __name__ == "__main__":
    unittest.main()
