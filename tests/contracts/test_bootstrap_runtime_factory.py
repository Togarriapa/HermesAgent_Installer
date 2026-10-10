from __future__ import annotations

import unittest
import os
import json
from types import MappingProxyType, SimpleNamespace
from pathlib import Path

from hermes_installer.authority.bootstrap_enrollment import (
    BootstrapEnrollmentPending, EnrollmentPolicy, EnrollmentReceipt, ServiceIdentity,
    VerifiedRootSetupAuthorization, _generation,
)
from hermes_installer.authority.bootstrap_runtime_factory import (
    InstalledBootstrapPolicyResolver,
    RootComposioSetupSelectionAuthority,
    RootBootstrapRuntimeFactory,
    RootSetupPolicyFactory,
    RootRuntimeArtifactReceipt,
    RootReleaseModuleReceipt,
    RootPreparedReleaseMemberReceipt,
    RootInitialCompilationRegistry,
    RootBootstrapSession,
    RootRunnableRoleReceiptProjection,
    RootRunnableRoleRow,
    _runnable_role_matches_compiled_rule,
    _service_requires_package_runtime,
    VerifiedReviewedNativeCapabilityMap,
    VerifiedRootBootstrapPolicy,
)


class RootBootstrapRuntimeFactoryContracts(unittest.TestCase):
    def test_runnable_role_projection_exposes_only_literal_v72_fields_as_detached_values(self):
        child_refs = {"native-compiled-closure:test": "a" * 64,
                      "native-entrypoint-manifest:test": "b" * 64}
        projection = RootRunnableRoleReceiptProjection(
            schema=1, closure_handle="closure-fixture", closure_sha256="c" * 64,
            role_rows=(RootRunnableRoleRow(
                "native-compiled-closure", "native-output-cas", "receipt-fixture",
                "native-compiled-closure:test", "a" * 64, 16, "compiled-closure", ()),),
            _field_values=(("native-compiled-closure", "child_artifact_refs",
                            MappingProxyType(dict(child_refs))),),
            _issuer=object(), _registry_seal=object(),
        )
        resolved = projection.resolve_field("native-compiled-closure", "child_artifact_refs")
        self.assertEqual(resolved, child_refs)
        resolved["native-compiled-closure:test"] = "d" * 64
        self.assertEqual(
            projection.resolve_field("native-compiled-closure", "child_artifact_refs"), child_refs)
        with self.assertRaises(BootstrapEnrollmentPending):
            projection.resolve_field("native-compiled-closure", "catalog_executable_path")

    def test_package_runtime_guard_reads_operation_key_and_package_set_target_shapes(self):
        self.assertTrue(_service_requires_package_runtime({
            "package.install": "coral-cp39-runtime-v1",
        }))
        self.assertTrue(_service_requires_package_runtime({
            "process.start": "package-set:coral-cp39-runtime-v1:" + "a" * 64,
        }))
        self.assertFalse(_service_requires_package_runtime({
            "process.start": "hermes-agent-health:start",
        }))
        self.assertTrue(_service_requires_package_runtime(None))

    def test_observed_pm_executable_requires_exact_compiled_v189_artifact_id(self):
        observed = RootRunnableRoleRow(
            "official-pm-runtime", "pm-runtime", "h" * 40,
            "observed:pm-committed-venv-python", "a" * 64, 100, "pm-runtime", (),
        )
        rule = {
            "required_phase": "runnable",
            "allowed_artifact_ids": ["observed:pm-committed-venv-python"],
            "allowed_output_kinds": ["pm-runtime"],
        }
        self.assertTrue(_runnable_role_matches_compiled_rule(observed, rule))
        rule["allowed_artifact_ids"] = ["observed:arbitrary-python"]
        self.assertFalse(_runnable_role_matches_compiled_rule(observed, rule))

    def test_policy_identity_tags_reject_cross_domain_principal_substitution(self):
        from hermes_installer.authority.bootstrap_runtime_factory import (
            HERMES_SOURCE_ARTIFACT_ID, _POLICY_ID,
        )
        resolver = object.__new__(InstalledBootstrapPolicyResolver)
        plan = {"bootstrap_policy_artifact_id": _POLICY_ID,
                "allowed_artifact_ids": [HERMES_SOURCE_ARTIFACT_ID]}
        selection = SimpleNamespace()
        common = {"service_profile_id": "hermes-agent-native-v1",
                  "service_account_name": "hermes-agent",
                  "exclusive_group_name": "hermes-agent",
                  "uid_allocation": "root-dedicated-account"}
        cases = (
            {**common, "identity_kind": "authentik-subject-v1",
             "principal_id": "linux-local-owner:" + "a" * 64},
            {**common, "identity_kind": "linux-local-owner-v1",
             "principal_id": "authentik:" + "a" * 64,
             "owner_binding_sha256": "b" * 64},
        )
        for identity in cases:
            with self.subTest(identity_kind=identity["identity_kind"]), self.assertRaises(
                    BootstrapEnrollmentPending):
                resolver._parse_policy(
                    {"schema": 1, "id": _POLICY_ID,
                     "source_artifact_id": HERMES_SOURCE_ARTIFACT_ID,
                     "identity_policy": identity}, "c" * 64, plan, selection)

    def test_active_enrollment_accessor_rejects_prepared_and_returns_only_current_commit(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._authorization = SimpleNamespace(transaction_handle="a" * 64)
        prepared = EnrollmentReceipt(
            1, "a" * 64, "b" * 64, "prepared-generation", "c" * 64,
            None, "prepared", (), 1.0, 100.0)
        session._last_receipt = prepared
        with self.assertRaises(BootstrapEnrollmentPending):
            session._resolve_current_active_enrollment()

        committed = EnrollmentReceipt(
            1, "a" * 64, "d" * 64, "active-generation", "e" * 64,
            "c" * 64, "committed", ("selected-enrollment",), 2.0, 100.0)
        session._last_receipt = committed
        self.assertIs(session._resolve_current_active_enrollment(), committed)

    def test_prepared_enrollment_accessor_rechecks_the_durable_current_receipt(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._authorization = SimpleNamespace(transaction_handle="a" * 64)
        prepared = EnrollmentReceipt(
            1, "a" * 64, "b" * 48, "prepared-generation", "c" * 64,
            None, "prepared", (), 1.0, 1e20)
        session._last_receipt = prepared
        session._read_current_prepared_checkpoint_receipt = lambda: prepared
        self.assertIs(session._resolve_current_prepared_enrollment(), prepared)

        changed = EnrollmentReceipt(
            1, "a" * 64, "d" * 48, "replacement-generation", "e" * 64,
            None, "prepared", (), 2.0, 1e20)
        session._read_current_prepared_checkpoint_receipt = lambda: changed
        with self.assertRaises(BootstrapEnrollmentPending):
            session._resolve_current_prepared_enrollment()

    def test_resume_reissues_only_a_fresh_prepared_receipt(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._authorization = SimpleNamespace(mode="resume")
        prepared = EnrollmentReceipt(
            1, "a" * 64, "b" * 48, "prepared-generation", "c" * 64,
            None, "prepared", (), 1.0, 1e20)
        session._read_current_prepared_checkpoint_receipt = lambda: prepared
        self.assertIs(session._restore_current_prepared_checkpoint(), prepared)
        self.assertIs(session._last_receipt, prepared)

        session._authorization = SimpleNamespace(mode="install")
        with self.assertRaises(BootstrapEnrollmentPending):
            session._restore_current_prepared_checkpoint()

    def test_active_compiler_composition_requires_adopted_principal_before_dependencies(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        prepared = SimpleNamespace(state="prepared", enrollment_ids=())
        session._resolve_current_prepared_enrollment = lambda: prepared
        session._adopted_principal_registry = None
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "adopted normal-session principal"):
            session._resolve_current_active_policy_compilation_registry()

    def test_active_compiler_binding_checks_session_seal(self):
        from hermes_installer.authority.bootstrap_runtime_factory import RootSelectedInstallationBinding

        session = SimpleNamespace(_seal="right")
        binding = RootSelectedInstallationBinding(session, "wrong")
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "active policy compiler"):
            binding.resolve_current_active_policy_compilation_registry()

    def test_runnable_role_projection_binding_checks_session_seal(self):
        from hermes_installer.authority.bootstrap_runtime_factory import RootSelectedInstallationBinding

        session = SimpleNamespace(_seal="right")
        binding = RootSelectedInstallationBinding(session, "wrong")
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "runnable role projection"):
            binding.resolve_current_runnable_role_projection_registry()

    def test_prepared_native_policy_records_are_reopened_by_exact_selection_and_identity(self):
        session = object.__new__(RootBootstrapSession)
        selection = SimpleNamespace(selection_handle="selection", selection_sha256="a" * 64)
        records = SimpleNamespace(records_handle="records", native_policy_selection_handle="selection",
                                  selection_sha256="a" * 64)
        registry = SimpleNamespace(
            resolve_selection_current=lambda handle: selection,
            resolve_prepared_policy=lambda handle, binding: records,
        )
        session._resolve_current_native_policy_registry = lambda: registry
        session._native_policy_records_by_selection = {"selection": records}
        session._selected_installation = object()
        self.assertIs(session.resolve_current_prepared_native_policy_records("selection"), records)

        registry.resolve_prepared_policy = lambda *_args: SimpleNamespace()
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "records are unavailable"):
            session.resolve_current_prepared_native_policy_records("selection")

    def test_runtime_receipt_generation_is_derived_from_current_prepared_authorization(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._authorization = SimpleNamespace(transaction_handle="tx-current")
        session._resolve_current_prepared_enrollment = lambda: SimpleNamespace(
            state="prepared", enrollment_ids=(), transaction_handle="tx-current")
        receipt = SimpleNamespace(generation="tx-current")
        calls = []
        session.resolve_runtime_receipt = lambda role, handle, generation: (
            calls.append((role, handle, generation)) or receipt)
        session._policy = SimpleNamespace(receipt_binding_rules=[
            {"receipt_role": "official-pm-runtime", "required_phase": "runnable"}])
        session._factory = SimpleNamespace(
            _actor=SimpleNamespace(verify_current=lambda _release: None),
            _release=SimpleNamespace(verify_current=lambda: None))
        assert session._resolve_current_runtime_receipt("official-pm-runtime", "opaque-cas-handle") is receipt
        assert calls == [("official-pm-runtime", "opaque-cas-handle", "tx-current")]

        session._policy.receipt_binding_rules[0]["required_phase"] = "prepared-source"
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "current runnable role"):
            session._resolve_current_runtime_receipt("official-pm-runtime", "opaque-cas-handle")

    def test_capture_profile_members_remain_pending_when_release_lacks_exact_amendments(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._last_receipt = SimpleNamespace(
            state="prepared", enrollment_ids=(), provision_receipt_handle="prepared-receipt",
            generation_id="generation")
        session._authorization = SimpleNamespace(plan_artifact_id="plan")
        session._factory = SimpleNamespace(
            _release=SimpleNamespace(files=()),
            _actor=SimpleNamespace(verify_current=lambda _release: None),
            resolver=SimpleNamespace(resolve=lambda _plan: SimpleNamespace(allowed_artifact_ids=())))
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "not uniquely pinned"):
            session._resolve_prepared_native_capture_profile_receipts()

    def test_prepared_release_member_rechecks_its_exact_role(self):
        import hashlib
        import tempfile
        from hermes_installer.authority.bootstrap_runtime_factory import _PREPARED_RELEASE_MEMBER_SEAL

        with tempfile.NamedTemporaryFile() as file:
            raw = b"reviewed amendment bytes"
            file.write(raw)
            file.flush()
            digest = hashlib.sha256(raw).hexdigest()
            release = SimpleNamespace(
                files=[SimpleNamespace(artifact_id="capture-profile", roles=("amendment",),
                                       relative_path="plans/capture.json", sha256=digest,
                                       size_bytes=len(raw))],
                release_commit="commit", deployment_receipt_sha256="d" * 64,
                open_file=lambda _artifact_id: os.open(file.name, os.O_RDONLY))
            session = object.__new__(RootBootstrapSession)
            session._check_live = lambda: None
            session._last_receipt = SimpleNamespace(state="prepared", enrollment_ids=(), generation_id="g")
            session._authorization = SimpleNamespace(plan_artifact_id="plan")
            session._factory = SimpleNamespace(
                _release=release,
                _actor=SimpleNamespace(verify_current=lambda _release: None),
                resolver=SimpleNamespace(resolve=lambda _plan: SimpleNamespace(
                    allowed_artifact_ids=("capture-profile",))))
            session._handle = SimpleNamespace(session_id="session")
            session._seal = "session-seal"
            session._prepared_release_file_receipts = {}
            receipt = RootPreparedReleaseMemberReceipt(
                "capture-profile", "plans/capture.json", digest, len(raw), "commit",
                "d" * 64, "receipt-handle", "session", "g",
                _PREPARED_RELEASE_MEMBER_SEAL, "session-seal", session)
            session._prepared_release_file_receipts[receipt.source_receipt_handle] = receipt
            self.assertEqual(receipt.read_current(), raw)

            release.files[0].roles = ("module",)
            with self.assertRaisesRegex(BootstrapEnrollmentPending, "differs from its fixed receipt"):
                receipt.read_current()

    def test_action_schema_modules_require_exact_release_and_import_closure(self):
        import hashlib

        paths = (
            "src/hermes_installer/components/plugin_accounts_schemas.py",
            "src/hermes_installer/components/plugin_document_schemas.py",
            "src/hermes_installer/components/plugin_finance_schemas.py",
            "src/hermes_installer/components/plugin_homelab_schemas.py",
            "src/hermes_installer/components/plugin_local_voice_web_schemas.py",
        )
        descriptors = []
        artifact_files = {}
        origins = []
        for index, relative_path in enumerate(paths):
            raw = Path(relative_path).read_bytes()
            artifact_id = f"release-artifact-{index}"
            digest = hashlib.sha256(raw).hexdigest()
            descriptors.append(SimpleNamespace(
                artifact_id=artifact_id, relative_path=relative_path, sha256=digest,
                size_bytes=len(raw), roles=("module",)))
            artifact_files[artifact_id] = Path(relative_path)
            origins.append(("module", f"/release/{relative_path}", "origin", "loader", digest))
        release = SimpleNamespace(
            files=descriptors, release_root=Path("/release"), release_commit="commit",
            deployment_receipt_sha256="d" * 64,
            open_file=lambda artifact_id: os.open(artifact_files[artifact_id], os.O_RDONLY))
        actor = SimpleNamespace(module_origins=origins, verify_current=lambda _release: None)
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session._authorization = SimpleNamespace(plan_artifact_id="plan")
        session._last_receipt = SimpleNamespace(
            state="prepared", enrollment_ids=(), provision_receipt_handle="prepared",
            generation_id="generation")
        session._handle = SimpleNamespace(session_id="session")
        session._seal = "session-seal"
        session._release_member_receipts = {}
        session._prepared_release_member_receipts = {}
        session._factory = SimpleNamespace(
            _release=release, _actor=actor,
            resolver=SimpleNamespace(resolve=lambda _plan: SimpleNamespace(
                allowed_artifact_ids=tuple(artifact_files))))

        receipts = session._resolve_prepared_native_action_schema_module_receipts()
        self.assertEqual(len(receipts), 5)
        self.assertTrue(all(type(item) is RootReleaseModuleReceipt for item in receipts))
        self.assertEqual(tuple(item.relative_path for item in receipts), paths)
        self.assertEqual(tuple(item.read_current() for item in receipts),
                         tuple(Path(path).read_bytes() for path in paths))
        self.assertIs(receipts[0], session._resolve_prepared_native_action_schema_module_receipts()[0])

        actor.module_origins = origins[:-1]
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "outside the current root actor"):
            session._resolve_prepared_native_action_schema_module_receipts()

    def test_native_assembly_requires_retained_root_tty_policy_selection(self):
        session = object.__new__(RootBootstrapSession)
        session._check_live = lambda: None
        session._refresh_authorization = lambda: None
        session.resolve_prepared_receipt = lambda _handle: object()
        session.prepare_selected_native_bundle = lambda: object()
        session._resolve_current_prepared_native_bundle = lambda _bundle: None
        session._current_native_policy_selection_handle = None
        with self.assertRaisesRegex(BootstrapEnrollmentPending, "root-TTY native policy configuration"):
            session._resolve_native_bootstrap_assembly("prepared-handle", "materialization-handle")

    def test_reviewed_capability_map_resolves_only_exact_release_pin(self):
        import hermes_installer.authority.bootstrap_runtime_factory as factory_module

        raw = Path("plans/amendments/2026-10-10-reviewed-native-capability-selection-v91/"
                   "reviewed-native-capability-map-v1.json").read_bytes()
        session = SimpleNamespace(compilation_session_handle="a" * 64)
        registry = object.__new__(RootInitialCompilationRegistry)
        registry._seal = "test-registry-seal"
        registry.resolve_initial_session = lambda handle: session
        registry.verify_initial_session = lambda value: self.assertIs(value, session)
        descriptor = SimpleNamespace(
            relative_path=factory_module._CAPABILITY_MAP_TEMPLATE_PATH,
            sha256=factory_module._CAPABILITY_MAP_TEMPLATE_SHA256,
            size_bytes=factory_module._CAPABILITY_MAP_TEMPLATE_SIZE,
            roles=("template",))
        registry._release_file = lambda artifact_id: (descriptor, raw)

        result = registry.resolve_reviewed_capability_map("a" * 64)
        self.assertIsInstance(result, VerifiedReviewedNativeCapabilityMap)
        self.assertEqual(result.artifact_id, "installer-reviewed-native-capability-map-v1")
        self.assertEqual(result._session_handle, session.compilation_session_handle)
        self.assertEqual(result.document["prepared_capabilities"], [])
        self.assertEqual(json.dumps(dict(result.document), sort_keys=True, separators=(",", ":"),
                                    ensure_ascii=False).encode() + b"\n", raw)

        registry._release_file = lambda artifact_id: (descriptor, raw + b" ")
        with self.assertRaises(BootstrapEnrollmentPending):
            registry.resolve_reviewed_capability_map("a" * 64)

    def test_adopted_capability_map_rechecks_live_handoff_and_session(self):
        import hermes_installer.authority.bootstrap_runtime_factory as factory_module
        from hermes_installer.authority.bootstrap_enrollment import RootSetupSessionHandle

        raw = Path("plans/amendments/2026-10-10-reviewed-native-capability-selection-v91/"
                   "reviewed-native-capability-map-v1.json").read_bytes()
        handle = RootSetupSessionHandle("c" * 64, "fixture-session-seal")
        authorization = SimpleNamespace(transaction_handle="d" * 64, plan_digest="e" * 64)
        live = object()
        actor = SimpleNamespace(verify_current=lambda release: None)
        descriptor = SimpleNamespace(
            relative_path=factory_module._CAPABILITY_MAP_TEMPLATE_PATH,
            sha256=factory_module._CAPABILITY_MAP_TEMPLATE_SHA256,
            size_bytes=factory_module._CAPABILITY_MAP_TEMPLATE_SIZE,
            roles=("template",))
        handoff = factory_module.RootInitialPublicationHandoff(
            1, "f" * 64, "a" * 64, "b" * 64, "g" * 64, "h" * 64,
            "e" * 64, "i" * 64, "j" * 64, (), 1.0, 1e20,
            handle.session_id, authorization.transaction_handle)
        registry = object.__new__(RootInitialCompilationRegistry)
        registry._session_store = SimpleNamespace(
            _live=lambda actual: live,
            _proof=lambda actual: authorization)
        registry._adopted_handoffs = {handle.session_id: handoff}
        registry.actor, registry.release = actor, object()
        registry._validate_release_closure = lambda: None
        registry._release_file = lambda artifact_id: (descriptor, raw)
        registry._seal = "fixture-registry-seal"

        result = registry.resolve_adopted_reviewed_capability_map(handle)
        self.assertIsInstance(result, VerifiedReviewedNativeCapabilityMap)
        self.assertEqual(result._session_handle, handle.session_id)
        self.assertEqual(result._registry_seal, registry._seal)
        self.assertEqual(result.document["prepared_capabilities"], [])

        registry._session_store._proof = lambda actual: SimpleNamespace(
            transaction_handle="x" * 64, plan_digest="e" * 64)
        with self.assertRaises(BootstrapEnrollmentPending):
            registry.resolve_adopted_reviewed_capability_map(handle)

    def test_prepared_authority_base_accepts_only_exact_empty_root_snapshot(self):
        root = {"root_id": "installer-authority-journal-v1",
                "absolute_path": "/var/lib/hermes-installer/authority-journal",
                "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"}
        generation = _generation(EnrollmentPolicy(
            service_profile_id="profile", principal_id="principal", generation_id="prepared-fixture",
            source_artifact_id="source", records=(), resource_controller_roles=(),
            native_mcp_tool_bindings=(), remote_observation_enrollments=(),
            root_journal_roots=(root,), activation_state="prepared"))
        base = {"schema": 1, "key_id": "authority-key-fixture", "principals": {}, "rules": {},
                "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                "service_generations": generation}
        InstalledBootstrapPolicyResolver._validate_authority_base_template(base)
        empty_template = dict(base)
        empty_template["key_id"] = {"root_binding": "authority_key.key_id"}
        empty_template["service_generations"] = {
            "root_binding": "prepared_service_generation.exact_empty_snapshot"}
        InstalledBootstrapPolicyResolver._validate_authority_base_template(empty_template)
        for mutate in (
                lambda value: value.update(service_generations={}),
                lambda value: value["service_generations"].update(service_records=[{"enabled": True}]),
                lambda value: value["service_generations"].update(root_journal_roots=[]),
                lambda value: value.update(authentik={"token": "must-not-exist"})):
            invalid = {**base, "service_generations": dict(generation), "authentik": {}}
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_authority_base_template(invalid)

    def test_active_catalog_rows_must_match_digest_bound_generation(self):
        root = {"root_id": "installer-authority-journal-v1",
                "absolute_path": "/var/lib/hermes-installer/authority-journal",
                "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"}
        generation = _generation(EnrollmentPolicy(
            service_profile_id="profile", principal_id="principal", generation_id="active-fixture",
            source_artifact_id="source", records=(), resource_controller_roles=(),
            native_mcp_tool_bindings=(), remote_observation_enrollments=(),
            root_journal_roots=(root,), activation_state="active"))
        base = {"service_generations": generation}
        catalogs = {name: tuple(generation[name]) for name in (
            "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
                "memory_service_enablement_projections",
            "operation_parameter_schemas", "source_issuers", "resource_jobs",
            "remote_session_enrollments", "resource_backend_enrollments", "resource_body_recipes",
            "resource_scope_bindings", "resource_validators", "root_journal_roots",
            "resource_controller_roles", "native_mcp_tool_bindings", "remote_observation_enrollments",
            "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings",
            "selected_resource_executions", "selected_application_runtimes")}
        InstalledBootstrapPolicyResolver._validate_active_catalog_selections(catalogs, base)
        catalogs["composio_channel_enrollments"] = ({"unverified": True},)
        with self.assertRaises(BootstrapEnrollmentPending):
            InstalledBootstrapPolicyResolver._validate_active_catalog_selections(catalogs, base)

    def test_composio_catalog_projection_is_pinned_version_and_strictly_bounded(self):
        authority = object.__new__(RootComposioSetupSelectionAuthority)
        authority._SLUG = RootComposioSetupSelectionAuthority._SLUG
        row = {"slug": "WHATSAPP_MESSAGE", "name": "Send message", "description": "Send",
               "type": "trigger", "toolkit": {"slug": "whatsapp", "name": "WhatsApp"},
               "version": "20260721_00", "config": {}, "payload": {}}
        projected = authority._trigger_projection(row, "20260721_00")
        self.assertEqual(projected["toolkit"], {"slug": "whatsapp", "version": "20260721_00"})
        self.assertNotIn("instructions", projected)
        with self.assertRaises(BootstrapEnrollmentPending):
            authority._trigger_projection({**row, "version": "other"}, "20260721_00")
        with self.assertRaises(BootstrapEnrollmentPending):
            authority._trigger_projection({**row, "unreviewed": "field"}, "20260721_00")

    def test_installed_factory_has_no_caller_selected_trust_paths(self):
        with self.assertRaises(TypeError):
            RootBootstrapRuntimeFactory(selection_path="/tmp/caller-selection.json")

    def test_session_id_lookup_only_resolves_an_existing_root_issued_session(self):
        factory = object.__new__(RootBootstrapRuntimeFactory)
        factory._sessions = {}
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.resolve_live_session_id("not-a-session")
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.resolve_live_session_id("a" * 64)

    def test_factory_refuses_non_linux_or_uninstalled_root_trust(self):
        if os.geteuid() == 0 and Path("/proc/sys/kernel/ostype").exists() \
                and Path("/etc/hermes-installer/root-setup-selection.json").exists():
            self.skipTest("real installed root selection is outside this source-checkout fixture")
        with self.assertRaises(BootstrapEnrollmentPending):
            RootBootstrapRuntimeFactory.from_installed()

    def test_prepared_policy_is_concrete_empty_and_journal_bound(self):
        policy = VerifiedRootBootstrapPolicy(
            artifact_id="installer-bootstrap-policy-v1", sha256="a" * 64,
            plan_artifact_id="installer-root-setup-plan-v1", source_artifact_id="hermes-source-v1",
            identity_policy={"service_profile_id": "hermes-profile", "principal_id": "hermes-service",
                             "service_account_name": "hermes-service", "exclusive_group_name": "hermes-service",
                             "uid_allocation": "root-dedicated-account"},
            root_policy={"journal_root_id": "installer-authority-journal-v1",
                         "service_home_root_id": "hermes-home-v1", "service_work_root_id": "hermes-work-v1",
                         "service_data_root_id": "hermes-data-v1",
                         "service_parent_root": "/var/lib/hermes-installer/services/hermes-agent-native-v1"},
            authority_base_template={"schema": 1, "key_id": "root-key", "principals": {}, "rules": {},
                                     "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                                     "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                                     "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                                     "service_generations": {}},
            service_record_templates=(),
            catalog_selections={name: () for name in (
                "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
                "memory_service_enablement_projections",
                "operation_parameter_schemas", "source_issuers", "resource_jobs", "remote_session_enrollments",
                "resource_backend_enrollments", "resource_body_recipes", "resource_scope_bindings",
                "resource_validators", "root_journal_roots", "resource_controller_roles",
                "native_mcp_tool_bindings", "remote_observation_enrollments",
                "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings")},
            receipt_binding_rules=(),
        )

        class Resolver:
            @staticmethod
            def resolve_policy(_plan_id, **_kwargs):
                return policy

        authorization = VerifiedRootSetupAuthorization(
            target_id="local-target-fixture", setup_session_id="setup-fixture", plan_digest="b" * 64,
            operator_uid=501, transaction_handle="transaction-fixture",
            plan_artifact_id="installer-root-setup-plan-v1",
            root_journal_root={"root_id": "installer-authority-journal-v1",
                               "absolute_path": "/var/lib/hermes-installer/authority-journal",
                               "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                               "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"},
        )
        prepared = RootSetupPolicyFactory(Resolver()).prepare(authorization)
        self.assertEqual(prepared.activation_state, "prepared")
        self.assertEqual(prepared.records, ())
        self.assertEqual(prepared.root_journal_roots, (dict(authorization.root_journal_root),))
        self.assertEqual(prepared.home_root.as_posix(), "/var/lib/hermes-installer/services/hermes-agent-native-v1/home")
        self.assertEqual(prepared.data_root.as_posix(), "/var/lib/hermes-installer/services/hermes-agent-native-v1/data")

    def test_prepared_policy_can_activate_only_after_a_root_runtime_receipt(self):
        record = {"generation": "template-generation", "service_uid": 0, "service_gid": 0,
                  "runtime_artifact_id": None}
        policy = VerifiedRootBootstrapPolicy(
            artifact_id="installer-bootstrap-policy-v1", sha256="a" * 64,
            plan_artifact_id="installer-root-setup-plan-v1", source_artifact_id="hermes-source-v1",
            identity_policy={"service_profile_id": "hermes-profile", "principal_id": "selected-principal",
                             "service_account_name": "hermes-service", "exclusive_group_name": "hermes-service",
                             "uid_allocation": "root-dedicated-account"},
            root_policy={"journal_root_id": "installer-authority-journal-v1",
                         "service_home_root_id": "hermes-home-v1", "service_work_root_id": "hermes-work-v1",
                         "service_data_root_id": "hermes-data-v1",
                         "service_parent_root": "/var/lib/hermes-installer/services/hermes-agent-native-v1"},
            authority_base_template={"schema": 1, "key_id": "root-key", "principals": {}, "rules": {},
                                     "authentik": {}, "process_profiles": {}, "provider_enrollments": {},
                                     "mcp_services": {}, "mcp_http_bindings": {}, "memory_providers": {},
                                     "native_bridges": {}, "normalization_policies": {}, "delegations": {},
                                     "service_generations": {}},
            service_record_templates=({"id": "selected-template", "record": record,
                                      "receipt_bindings": ({"field_path": ["runtime_artifact_id"],
                                                            "receipt_role": "official-pm-runtime",
                                                            "receipt_field": "artifact_id"},)},),
            catalog_selections={name: () for name in (
                "protected_devices", "protected_build_records", "native_packages", "memory_enrollments",
                "memory_service_enablement_projections",
                "operation_parameter_schemas", "source_issuers", "resource_jobs", "remote_session_enrollments",
                "resource_backend_enrollments", "resource_body_recipes", "resource_scope_bindings",
                "resource_validators", "root_journal_roots", "resource_controller_roles",
                "native_mcp_tool_bindings", "remote_observation_enrollments",
                "native_schema_artifacts", "composio_channel_enrollments", "channel_delivery_bindings")},
            receipt_binding_rules=({"receipt_role": "official-pm-runtime",
                                    "allowed_artifact_ids": ["pm-runtime-fixture"],
                                    "allowed_output_kinds": ["source-archive"],
                                    "required_phase": "runnable",
                                    "field_bindings": [{"field_path": ["runtime_artifact_id"],
                                                        "receipt_role": "official-pm-runtime",
                                                        "receipt_field": "artifact_id"}]},),
        )

        class Resolver:
            @staticmethod
            def resolve_policy(_plan_id, **_kwargs):
                return policy

        authorization = VerifiedRootSetupAuthorization(
            target_id="local-target-fixture", setup_session_id="setup-fixture", plan_digest="b" * 64,
            operator_uid=501, transaction_handle="transaction-fixture",
            plan_artifact_id="installer-root-setup-plan-v1",
            root_journal_root={"root_id": "installer-authority-journal-v1",
                               "absolute_path": "/var/lib/hermes-installer/authority-journal",
                               "owner_uid": 0, "owner_gid": 0, "mode": 0o700, "device": 1,
                               "inode": 2, "generation": "journal-fixture", "purpose": "authority-journal"},
        )
        factory = RootSetupPolicyFactory(Resolver())
        prepared = factory.prepare(authorization)
        self.assertEqual((prepared.activation_state, prepared.records), ("prepared", ()))
        identity = ServiceIdentity("hermes-service", 1001, 1001)
        receipt = RootRuntimeArtifactReceipt(
            "official-pm-runtime", "pm-runtime-fixture", "c" * 64,
            authorization.transaction_handle, "d" * 64, 10, "test-seal")
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.activate_runnable(authorization, identity, {}, seal="test-seal")
        # A selected worker can enter the sealed-role path without generic CAS
        # handles; it still fails unless every exact producer/selection proof is
        # present. The source provider appends its independent held source handle.
        with self.assertRaisesRegex(BootstrapEnrollmentPending,
                                    "selected native worker requires the exact signed selection"):
            factory.activate_runnable(
                authorization, identity, {}, seal="test-seal",
                native_worker_recipe_handles=("selected-recipe",),
                native_policy_selection=object(),
                native_worker_generation_producer=object(),
                runnable_role_receipts=object(),
            )
        unsealed = RootRuntimeArtifactReceipt(
            "official-pm-runtime", "pm-runtime-fixture", "c" * 64,
            authorization.transaction_handle, "d" * 64, 10, "other-session-seal")
        with self.assertRaises(BootstrapEnrollmentPending):
            factory.activate_runnable(authorization, identity,
                                      {"official-pm-runtime": unsealed}, seal="test-seal")
        active = factory.activate_runnable(
            authorization, identity, {"official-pm-runtime": receipt}, seal="test-seal")
        self.assertEqual(active.activation_state, "active")
        self.assertEqual(len(active.records), 1)
        self.assertEqual(active.records[0]["service_uid"], 1001)
        self.assertEqual(active.records[0]["runtime_artifact_id"], "pm-runtime-fixture")
        self.assertEqual(active.root_journal_roots, (dict(authorization.root_journal_root),))
        malformed = dict(authorization.root_journal_root)
        malformed["unreviewed_path"] = "/tmp/journal"
        with self.assertRaises(BootstrapEnrollmentPending):
            RootSetupPolicyFactory._root_journal_join(
                VerifiedRootSetupAuthorization(
                    target_id="local-target-fixture", setup_session_id="setup-fixture",
                    plan_digest="b" * 64, operator_uid=501, transaction_handle="transaction-fixture",
                    plan_artifact_id="installer-root-setup-plan-v1", root_journal_root=malformed))

    def test_receipt_rules_bind_one_exact_role_artifact_phase_and_output_kind(self):
        row = {"receipt_role": "official-pm-runtime",
               "allowed_artifact_ids": ["pm-runtime-314"],
               "allowed_output_kinds": ["pm-runtime"],
               "required_phase": "runnable", "field_bindings": []}
        parsed = InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
            [row], ["pm-runtime-314"])
        self.assertEqual(parsed, [row])
        for mutate in (
                lambda value: value.update(allowed_artifact_ids=["unselected-runtime"]),
                lambda value: value.update(required_phase="functional-health"),
                lambda value: value.update(allowed_output_kinds=["native-health"]),
                lambda value: value.update(receipt_role=["official-pm-runtime"]),
                lambda value: value.update(allowed_artifact_ids=[{}]),
                lambda value: value.update(allowed_output_kinds=[{}]),
                lambda value: value.update(unreviewed=True)):
            invalid = dict(row)
            mutate(invalid)
            with self.subTest(invalid=invalid), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                    [invalid], ["pm-runtime-314"])

    def test_receipt_rules_reject_cross_role_field_binding(self):
        row = {"receipt_role": "official-pm-runtime",
               "allowed_artifact_ids": ["pm-runtime-314"],
               "allowed_output_kinds": ["source-archive"],
               "required_phase": "runnable",
               "field_bindings": [{"field_path": ["executable_sha256"],
                                    "receipt_role": "official-agent-source",
                                    "receipt_field": "sha256"}]}
        with self.assertRaises(BootstrapEnrollmentPending):
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], ["pm-runtime-314"])

    def test_receipt_rules_require_role_specific_output_kind(self):
        for role, output in (("official-pm-runtime", "pm-runtime"),
                             ("native-compiled-closure", "compiled-closure"),
                             ("native-entrypoint-manifest", "entrypoint-json"),
                             ("native-action-resolver", "resolver-json"),
                             ("native-boundary-overlay", "boundary-overlay"),
                             ("native-candidate-index", "candidate-index-json"),
                             ("native-health", "native-health")):
            row = {"receipt_role": role, "allowed_artifact_ids": ["selected-output"],
                   "allowed_output_kinds": [output],
                   "required_phase": "functional-health" if role == "native-health" else "runnable",
                   "field_bindings": []}
            parsed = InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], ["selected-output"])
            self.assertEqual(parsed, [row])
            invalid = {**row, "allowed_output_kinds": ["source-archive"]}
            with self.subTest(role=role), self.assertRaises(BootstrapEnrollmentPending):
                InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                    [invalid], ["selected-output"])

    def test_empty_runtime_receipt_ids_only_allowed_for_prepared_dormant_roles(self):
        row = {"receipt_role": "native-compiled-closure", "allowed_artifact_ids": [],
               "allowed_output_kinds": ["compiled-closure"], "required_phase": "runnable",
               "field_bindings": []}
        self.assertEqual(
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules(
                [row], [], dormant_prepared=True), [row])
        with self.assertRaises(BootstrapEnrollmentPending):
            InstalledBootstrapPolicyResolver._validate_receipt_binding_rules([row], [])


if __name__ == "__main__":
    unittest.main()
