from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.authority import setup_capabilities as capabilities
from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending
from hermes_installer.authority.setup_principal import (
    AuthentikIdentityReceipt, PrincipalBindingFactory, ReviewedPrincipalCapabilities,
    _PrincipalSetupContext, _validate_capability_selection,
)


ROOT = Path(__file__).resolve().parents[2]
MAP = ROOT / "plans/amendments/2026-10-10-reviewed-native-capability-selection-v91/reviewed-native-capability-map-v1.json"


class ReviewedNativeCapabilitySelectionTests(unittest.TestCase):
    def setUp(self):
        self.identity = SimpleNamespace(
            authentik_subject_id="auth-subject-7", username="operator",
            email="operator@example.test", system_member=False,
        )
        self.principal_id = "authentik:" + hashlib.sha256(b"auth-subject-7").hexdigest()
        self.namespace = capabilities._namespace_id(
            self.identity, capabilities._expected_map_document())

    def _enrollment(self, *, system_cap="host-write", system_row_profile=None):
        binding = SimpleNamespace(
            principal_id=self.principal_id, profile_id="hermes-agent-native-v1",
            namespace_id=self.namespace,
            capabilities=frozenset({"memory-retrieval", system_cap}),
        )
        identity = SimpleNamespace(
            subject_id="auth-subject-7", username="operator",
            email="operator@example.test",
        )
        rows = () if system_row_profile is None else ({
            "profile_id": system_row_profile, "capability": system_cap,
            "operation": "host.update", "target": "selected-resource",
        },)
        return SimpleNamespace(
            bindings_by_uid={1201: binding},
            policy=SimpleNamespace(enrollment=SimpleNamespace(
                principal_identities={self.principal_id: identity})),
            rules={
                ("memory-retrieval", "memory.read", "owner-data"): SimpleNamespace(
                    capability="memory-retrieval", target="owner-data"),
                (system_cap, "host.update", "selected-resource"): SimpleNamespace(
                    capability=system_cap, target="selected-resource"),
            },
            process_profiles={}, service_records=(),
            resource_job_records=rows, native_mcp_tool_binding_records=(),
            selected_native_adapter_records=(), protected_enrollment_digest="a" * 64,
        )

    def test_installed_map_is_exact_pinned_closed_document(self):
        raw = MAP.read_bytes()
        self.assertEqual(len(raw), capabilities.MAP_SIZE)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), capabilities.MAP_SHA256)
        document = json.loads(raw)
        self.assertEqual(document, capabilities._expected_map_document())
        self.assertEqual(document["prepared_capabilities"], [])
        self.assertEqual(document["ordinary_member_capability_candidates"], [
            "provider-dispatch", "memory-retrieval", "memory-capture",
            "memory-extraction", "memory-embedding", "memory-export",
            "memory-backup", "memory-restore", "memory-delete",
        ])

    def test_namespace_is_bound_to_subject_and_fixed_profile(self):
        expected = "hermes-native-" + hashlib.sha256(
            (self.principal_id + "\0hermes-agent-native-v1").encode()).hexdigest()[:32]
        self.assertEqual(self.namespace, expected)
        other = SimpleNamespace(authentik_subject_id="other")
        self.assertNotEqual(self.namespace, capabilities._namespace_id(
            other, capabilities._expected_map_document()))

    def test_current_non_system_identity_gets_only_exact_ordinary_intersection(self):
        current = self._enrollment(system_row_profile="hermes-agent-native-v1")
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selected, digest = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection
            )._project_current_enrollment(
                self.identity, None, capabilities._expected_map_document())
        self.assertEqual(selected, ("memory-retrieval",))
        self.assertEqual(digest, "a" * 64)

    def test_system_membership_only_projects_exact_selected_row_intersection(self):
        self.identity.system_member = True
        current = self._enrollment(system_row_profile="hermes-agent-native-v1")
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selected, _ = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection
            )._project_current_enrollment(
                self.identity, None, capabilities._expected_map_document())
        self.assertEqual(selected, ("host-write", "memory-retrieval"))

    def test_system_capability_is_omitted_for_mismatched_selected_row(self):
        self.identity.system_member = True
        current = self._enrollment(system_row_profile="some-other-profile")
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selected, _ = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection
            )._project_current_enrollment(
                self.identity, None, capabilities._expected_map_document())
        self.assertEqual(selected, ("memory-retrieval",))

    def test_system_capability_requires_exact_selected_action_target_rule(self):
        self.identity.system_member = True
        current = self._enrollment(system_row_profile="hermes-agent-native-v1")
        current.resource_job_records = ({
            "profile_id": "hermes-agent-native-v1", "capability": "host-write",
            "operation": "host.update", "target": "different-target",
        },)
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selected, _ = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection
            )._project_current_enrollment(
                self.identity, None, capabilities._expected_map_document())
        self.assertEqual(selected, ("memory-retrieval",))

    def test_stale_or_mismatched_current_identity_fails_closed(self):
        current = self._enrollment(system_row_profile=None)
        current.policy.enrollment.principal_identities[self.principal_id].email = "changed@example.test"
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selector = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection)
            with self.assertRaises(BootstrapEnrollmentPending):
                selector._project_current_enrollment(
                    self.identity, None, capabilities._expected_map_document())

    def test_prepared_empty_capabilities_are_phase_explicit_and_bind_still_denies_empty(self):
        prepared = ReviewedPrincipalCapabilities(
            "hermes-agent-native-v1", self.namespace, ())
        _validate_capability_selection(prepared, allow_empty=True)
        with self.assertRaises(BootstrapEnrollmentPending):
            _validate_capability_selection(prepared)
        with self.assertRaises(ValueError):
            PrincipalBindingFactory(
                "authentik:" + "1" * 64, "hermes-agent-native-v1",
                self.namespace, frozenset(),
            ).bind(1201)

    def test_unknown_or_infrastructure_capabilities_never_enter_projection(self):
        binding = SimpleNamespace(
            principal_id=self.principal_id, profile_id="hermes-agent-native-v1",
            namespace_id=self.namespace,
            capabilities=frozenset({"memory-retrieval", "arbitrary-shell", "installer-bootstrap"}),
        )
        current = self._enrollment(system_row_profile=None)
        current.bindings_by_uid[1201] = binding
        current.rules[("arbitrary-shell", "shell.exec", "host")] = SimpleNamespace(
            capability="arbitrary-shell", target="host")
        current.rules[("installer-bootstrap", "install", "service")] = SimpleNamespace(
            capability="installer-bootstrap", target="service")
        with patch("hermes_installer.authority.enrollment.load_protected_enrollment",
                   return_value=current):
            selected, _ = capabilities.ReviewedNativeCapabilitySelection.__new__(
                capabilities.ReviewedNativeCapabilitySelection
            )._project_current_enrollment(
                self.identity, None, capabilities._expected_map_document())
        self.assertEqual(selected, ("memory-retrieval",))

    def _selector(self):
        selector = capabilities.ReviewedNativeCapabilitySelection.__new__(
            capabilities.ReviewedNativeCapabilitySelection)
        selector._clock = __import__("time").monotonic
        selector._seal = "selector-seal"
        selector._issued = {}
        selector._policy_digests = {}
        selector._identity_receipts = {}
        selector._map_documents = {}
        return selector

    def _identity_receipt(self, session_id="setup-1"):
        now = __import__("time").monotonic()
        return AuthentikIdentityReceipt(
            1, "i" * 64, session_id, "transaction-1", "a" * 64, "b" * 64,
            "operator", "operator@example.test", "auth-subject-7", "actor-ref",
            ("member",), ("member",), False, "authentik-policy-v1", now, now + 30,
        )

    def test_normal_selection_returns_sealed_current_projection_and_detects_policy_change(self):
        selector = self._selector()
        identity = self._identity_receipt()
        proof = _PrincipalSetupContext(
            "setup-1", "transaction-1", "a" * 64,
            identity.expires_monotonic, "root-setup")
        expected = capabilities._expected_map_document()
        with patch.object(selector, "_resolve_map", return_value=expected), \
             patch.object(selector, "_project_current_enrollment",
                          return_value=(("memory-retrieval",), "c" * 64)):
            selection = selector.select_for_identity(identity, proof)
            self.assertEqual(selection.service_profile_id, "hermes-agent-native-v1")
            self.assertEqual(selection.namespace_id, self.namespace)
            self.assertEqual(selection.capabilities, ("memory-retrieval",))
            resolved = selector.resolve_reviewed_capability_selection(
                identity.receipt_id, selection.effect_policy_receipt_handle)
            self.assertIs(resolved, selection)
        with patch.object(selector, "_project_current_enrollment",
                          return_value=(("memory-retrieval",), "d" * 64)):
            with self.assertRaises(BootstrapEnrollmentPending):
                selector.resolve_reviewed_capability_selection(
                    identity.receipt_id, selection.effect_policy_receipt_handle)

    def test_stage_zero_emits_empty_prepared_selection_only(self):
        from hermes_installer.authority.bootstrap_runtime_factory import RootInitialCompilationSession
        session = object.__new__(RootInitialCompilationSession)
        object.__setattr__(session, "compilation_session_handle", "setup-1")
        selector = self._selector()
        identity = self._identity_receipt()
        proof = _PrincipalSetupContext(
            "setup-1", "transaction-1", "a" * 64,
            identity.expires_monotonic, "initial-compilation", resolver_handle=session)
        with patch.object(selector, "_resolve_map",
                          return_value=capabilities._expected_map_document()):
            selection = selector.select_for_identity(identity, proof)
        self.assertEqual(selection.capabilities, ())
        _validate_capability_selection(selection, allow_empty=True)
        with self.assertRaises(BootstrapEnrollmentPending):
            _validate_capability_selection(selection)


if __name__ == "__main__":
    unittest.main()
