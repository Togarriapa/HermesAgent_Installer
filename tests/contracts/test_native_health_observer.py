from __future__ import annotations

import os
import secrets
import unittest
from types import SimpleNamespace

from hermes_installer.authority.native_health_observer import (
    RootNativeHealthEvent,
    RootNativeHealthObserver,
    RootNativeHealthStartAuthority,
    RootNativeHealthStartMaterial,
    RootSelectedNativeHealthRun,
    RootValidatedNativeHealthResult,
)
from hermes_installer.authority.types import AuthorityDenied


class NativeHealthObserverContracts(unittest.TestCase):
    def _observer(self, *, result_validator=None):
        now = [100.0]
        fd = os.open(os.devnull, os.O_RDONLY)
        identity = SimpleNamespace(kernel_uid=2001)
        proof = SimpleNamespace(
            proof_id="proof:loaded", package_id="package:selected",
            compiled_closure_sha256="a" * 64, profile_id="profile:native",
            generation="generation:1", service_generation_digest="b" * 64,
        )
        run = RootSelectedNativeHealthRun(
            operation_id="hermes-agent-health-v1", enrollment_id="enrollment:1",
            profile_id="profile:native", process_generation="generation:1",
            service_generation_digest="b" * 64,
            bootstrap_transaction_handle="transaction:1",
            committed_enrollment_receipt_id="receipt:committed",
            process_id="process:health", process_pid=411, process_pidfd=fd,
            process_uid=2001, process_identity=identity, package_id="package:selected",
            compiled_closure_sha256="a" * 64, loaded_package_proof=proof,
            fixture_artifact_id="artifact:fixture", fixture_sha256="c" * 64,
            health_action_id="health:local-tool", result_schema_id="schema:health-result",
            provider_required=True, parent_closure_digest="d" * 64,
            expires_monotonic=190.0,
        )
        refs = {kind: secrets.token_urlsafe(32) for kind in (
            "loader-ready", "native-request", "provider-result",
            "tool-invocation", "tool-result", "terminal",
        )}
        events = {}

        def event(kind, **extra):
            record = RootNativeHealthEvent(
                event_id=refs[kind], event_kind=kind,
                operation_id=run.operation_id, enrollment_id=run.enrollment_id,
                profile_id=run.profile_id, process_generation=run.process_generation,
                service_generation_digest=run.service_generation_digest,
                process_id=run.process_id, process_pid=run.process_pid,
                process_uid=run.process_uid, package_id=run.package_id,
                compiled_closure_sha256=run.compiled_closure_sha256,
                parent_closure_digest=run.parent_closure_digest,
                observed_monotonic=now[0] - 1, expires_monotonic=now[0] + 30,
                **extra,
            )
            events[record.event_id] = record

        event("loader-ready", loader_ready_event_id=refs["loader-ready"],
              loaded_proof_id=proof.proof_id)
        event("native-request", native_request_event_id=refs["native-request"],
              provider_result_event_id=refs["provider-result"])
        event("provider-result", provider_result_event_id=refs["provider-result"],
              native_request_event_id=refs["native-request"])
        event("tool-invocation", tool_invocation_event_id=refs["tool-invocation"],
              native_request_event_id=refs["native-request"],
              provider_result_reference=refs["provider-result"],
              action_id=run.health_action_id, invocation_handle=secrets.token_urlsafe(32))
        invocation_handle = events[refs["tool-invocation"]].invocation_handle
        event("tool-result", tool_result_event_id=refs["tool-result"],
              tool_invocation_event_id=refs["tool-invocation"],
              invocation_handle=invocation_handle,
              result_schema_id=run.result_schema_id, result_bytes=b'{"healthy":true}')
        event("terminal", terminal_receipt_handle=secrets.token_urlsafe(32),
              terminal_status="succeeded", cleanup_verified=True)

        def validate(schema, body):
            if result_validator is not None:
                return result_validator(schema, body)
            import hashlib
            return RootValidatedNativeHealthResult(schema, hashlib.sha256(body).hexdigest(), "passed")

        observer = RootNativeHealthObserver(
            selected_health_resolver=lambda _control: run,
            event_resolver=lambda _handle, event_id: events[event_id],
            process_resolver=lambda _pid, _pidfd, **_kwargs: identity,
            loaded_package_proof_resolver=lambda _run: proof,
            result_validator=validate,
            selected_run_canceller=lambda _run: None,
            monotonic=lambda: now[0],
        )
        return observer, run, events, refs, now, fd

    def test_root_joined_events_issue_health_receipt_once(self):
        observer, _run, _events, refs, _now, fd = self._observer()
        try:
            handle = observer.begin_selected_health(secrets.token_urlsafe(32))
            for kind in ("loader-ready", "native-request", "provider-result",
                         "tool-invocation", "tool-result", "terminal"):
                observer.observe_health_event(handle, refs[kind])
            receipt = observer.finish_selected_health(handle)
            self.assertEqual(receipt.status, "passed")
            self.assertEqual(receipt.provider_result_event_id, refs["provider-result"])
            self.assertEqual(receipt.tool_result_event_id, refs["tool-result"])
            self.assertIs(observer.consume_selected_health_receipt(
                receipt.health_receipt_handle, receipt.committed_enrollment_receipt_id), receipt)
            with self.assertRaises(AuthorityDenied):
                observer.consume_selected_health_receipt(
                    receipt.health_receipt_handle, receipt.committed_enrollment_receipt_id)
        finally:
            os.close(fd)

        observer, _run, events, refs, _now, fd = self._observer()
        try:
            handle = observer.begin_selected_health(secrets.token_urlsafe(32))
            event = events[refs["tool-result"]]
            events[refs["tool-result"]] = RootNativeHealthEvent(
                **{**{name: getattr(event, name) for name in event.__dataclass_fields__},
                   "profile_id": "profile:sibling"},
            )
            with self.assertRaises(AuthorityDenied):
                observer.observe_health_event(handle, refs["tool-result"])
        finally:
            os.close(fd)

    def test_plain_boolean_result_and_unrelated_event_are_rejected(self):
        observer, _run, events, refs, _now, fd = self._observer(
            result_validator=lambda _schema, _body: True)
        try:
            handle = observer.begin_selected_health(secrets.token_urlsafe(32))
            for kind in ("loader-ready", "native-request", "provider-result",
                         "tool-invocation", "tool-result", "terminal"):
                observer.observe_health_event(handle, refs[kind])
            with self.assertRaises(AuthorityDenied):
                observer.finish_selected_health(handle)
        finally:
            os.close(fd)

    def test_start_authority_rejects_untyped_committed_source_material(self):
        class Resolver:
            def resolve_current_health_material(self, *_args):
                return SimpleNamespace(health_fixture_artifact_id="caller-controlled")

            def is_current(self, _value):
                return True

        class Store:
            def verify_committed_receipt(self, *_args):
                raise AssertionError("must reject untyped source before setup-store lookup")

        class AuthorityService:
            issue_root_selected_service_effect = lambda *_args: None
            consume_root_selected_service_effect = lambda *_args: None

        authority = RootNativeHealthStartAuthority(
            active_bindings=object(), committed_enrollment_registry=Resolver(),
            verified_installer_release=SimpleNamespace(verify_current=lambda: None),
            current_installed_actor_verifier=SimpleNamespace(verify_current=lambda _plan: {}),
            authority_service=AuthorityService(),
            managed_process_custody=SimpleNamespace(start_selected_health_operation=lambda *_: None),
            health_observer=SimpleNamespace(begin_selected_health=lambda *_: None),
            root_journal=object(),
        )
        with self.assertRaises(AuthorityDenied):
            authority.admit_selected_health(secrets.token_urlsafe(32))

    def test_health_start_material_rejects_fixture_bytes_not_matching_catalog_digest(self):
        with self.assertRaises(ValueError):
            RootNativeHealthStartMaterial(
                verified_commit=object(), enrollment_id="enrollment:1",
                profile_id="profile:health", principal_id="principal:root-selected",
                process_generation="generation:1", service_generation_digest="a" * 64,
                parameter_schema_sha256="b" * 64, recipe_sha256="c" * 64,
                health_fixture_artifact_id="fixture:health",
                health_fixture_sha256="d" * 64,
                health_fixture_receipt_handle=secrets.token_urlsafe(32),
                health_result_schema_id="schema:health-result",
                health_result_schema_sha256="e" * 64,
                native_package_id="package:hermes", native_package_generation="generation:pkg1",
                native_closure_sha256="f" * 64,
                controller_binding_handle=secrets.token_urlsafe(32),
                service_profile=object(), process_operation=object(),
                controller_lease=object(), fixture_bytes=b"reviewed bytes",
                source_binding=object(), setup_plan=object(), namespace_identity="namespace:root",
            )

if __name__ == "__main__":
    unittest.main()
