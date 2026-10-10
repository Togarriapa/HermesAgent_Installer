import hashlib
import time
import unittest

from hermes_installer.authority.bootstrap_runtime_factory import (
    RootPreparedReleaseMemberReceipt, RootReleaseModuleReceipt,
    RootSelectedInstallationBinding,
)
from hermes_installer.authority.native_source_definitions import (
    NativeSourceDefinitionUnavailable,
    RootNativeSourceDefinitionRegistry,
)


class _Session:
    def __init__(self, receipts=()):
        self._seal = "session-seal"
        self._closed = False
        self.receipts = tuple(receipts)
        self.bytes_by_path = {}

    def _check_live(self):
        return None

    def _resolve_prepared_worker_role_module_receipts(self):
        return self.receipts

    def _read_prepared_release_member(self, receipt):
        return self.bytes_by_path[receipt.relative_path]

    def _read_release_member_receipt(self, receipt):
        return self.bytes_by_path[receipt.relative_path]

    def _resolve_prepared_native_source_definition_module_receipt(self):
        raw = b"root imported source definition adapter"
        path = "hermes_installer/authority/native_source_definitions.py"
        self.bytes_by_path[path] = raw
        receipt = object.__new__(RootReleaseModuleReceipt)
        values = {
            "artifact_id": "root-release:" + path,
            "relative_path": path,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
            "release_commit": "release-commit",
            "deployment_receipt_sha256": "b" * 64,
            "source_receipt_handle": "d" * 32,
            "_session_id": "session-id",
            "_session_seal": self._seal,
            "_session": self,
            "_prepared_generation_id": "generation",
        }
        for key, value in values.items():
            object.__setattr__(receipt, key, value)
        return receipt


class _Selection:
    selection_handle = "selection-current"
    selection_sha256 = "a" * 64
    package_id = "hermes-profile"

    @property
    def expires_monotonic(self):
        return time.monotonic() + 60


def _receipt(session, path, raw, artifact_id=None):
    session.bytes_by_path[path] = raw
    receipt = object.__new__(RootPreparedReleaseMemberReceipt)
    values = {
        "artifact_id": artifact_id or "root-release:" + path,
        "relative_path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "release_commit": "release-commit",
        "deployment_receipt_sha256": "b" * 64,
        "source_receipt_handle": "c" * 32,
        "setup_session_id": "session-id",
        "prepared_generation_id": "generation",
        "_receipt_seal": __import__(
            "hermes_installer.authority.bootstrap_runtime_factory",
            fromlist=["_PREPARED_RELEASE_MEMBER_SEAL"],
        )._PREPARED_RELEASE_MEMBER_SEAL,
        "_session_seal": session._seal,
        "_session": session,
    }
    for key, value in values.items():
        object.__setattr__(receipt, key, value)
    return receipt


class NativeSourceDefinitionContracts(unittest.TestCase):
    def test_preparation_is_pending_until_actual_definition_and_role_receipts_exist(self):
        session = _Session()
        binding = RootSelectedInstallationBinding(session, session._seal)
        module = __import__(
            "hermes_installer.authority.native_source_definitions",
            fromlist=["_REGISTRY_SEAL"],
        )
        registry = RootNativeSourceDefinitionRegistry(
            binding, session._resolve_prepared_worker_role_module_receipts,
            session._resolve_prepared_native_source_definition_module_receipt,
            _seal=module._REGISTRY_SEAL,
        )

        bundle = registry.prepare_for_policy(_Selection())

        self.assertIs(registry.resolve_current(bundle), bundle)
        self.assertIsNotNone(bundle.definition_source_receipt)
        self.assertEqual(bundle.role_module_receipts, ())
        self.assertIn("hermes_installer.native_invocations", bundle.missing_prerequisite_ids)
        self.assertIn("hermes_installer.native_boundary", bundle.missing_prerequisite_ids)
        self.assertIn("installer-native-input-capture-profile-v1", bundle.missing_prerequisite_ids)
        self.assertIn("installer-native-tool-result-capture-profile-v1", bundle.missing_prerequisite_ids)
        self.assertIn("installer-native-provider-result-capture-profile-v1", bundle.missing_prerequisite_ids)
        self.assertIn("installer-native-mcp-discovery-capture-profile-v171", bundle.missing_prerequisite_ids)
        self.assertEqual(
            tuple(row.module_name for row in bundle.declarations),
            ("hermes_installer.native_invocations", "hermes_installer.native_boundary"),
        )

    def test_role_receipt_must_match_held_path_bytes_and_pin(self):
        session = _Session()
        declaration = __import__(
            "hermes_installer.authority.native_source_definitions",
            fromlist=["_ROLE_DECLARATIONS"],
        )._ROLE_DECLARATIONS[0]
        wrong = _receipt(session, declaration.release_member_path, b"different installed module")
        session.receipts = (wrong,)
        binding = RootSelectedInstallationBinding(session, session._seal)
        module = __import__(
            "hermes_installer.authority.native_source_definitions",
            fromlist=["_REGISTRY_SEAL"],
        )
        registry = RootNativeSourceDefinitionRegistry(
            binding, session._resolve_prepared_worker_role_module_receipts,
            session._resolve_prepared_native_source_definition_module_receipt,
            _seal=module._REGISTRY_SEAL,
        )

        with self.assertRaises(NativeSourceDefinitionUnavailable):
            registry.prepare_for_policy(_Selection())

    def test_constructor_rejects_unsealed_resolver_injection(self):
        with self.assertRaises(TypeError):
            RootNativeSourceDefinitionRegistry(object(), lambda: (), lambda: None)

    def test_setup_binding_requires_dedicated_source_receipt_resolver(self):
        session = _Session()
        binding = RootSelectedInstallationBinding(session, session._seal)
        registry = RootNativeSourceDefinitionRegistry.from_selected_installation(binding)
        self.assertIsInstance(registry, RootNativeSourceDefinitionRegistry)

    def test_capture_profiles_require_exact_held_bytes_and_keep_dynamic_tool_actions_empty(self):
        import json
        from pathlib import Path
        from hermes_installer.authority.native_source_definitions import _CAPTURE_PROFILES, _REGISTRY_SEAL

        session = _Session()
        binding = RootSelectedInstallationBinding(session, session._seal)
        receipts = []
        for profile in _CAPTURE_PROFILES:
            raw = (Path(__file__).parents[2] / profile.relative_path).read_bytes()
            document = json.loads(raw)
            declaration = (document["profile"] if profile.artifact_id.endswith("v171") else document)
            self.assertEqual(declaration["capture_schema_id"], profile.capture_schema_id)
            receipts.append(_receipt(session, profile.relative_path, raw, profile.artifact_id))
        session._resolve_prepared_native_capture_profile_receipts = lambda: tuple(receipts)
        registry = RootNativeSourceDefinitionRegistry(
            binding, session._resolve_prepared_worker_role_module_receipts,
            session._resolve_prepared_native_source_definition_module_receipt,
            capture_profile_receipt_provider=session._resolve_prepared_native_capture_profile_receipts,
            _seal=_REGISTRY_SEAL,
        )

        bundle = registry.prepare_for_policy(_Selection())

        self.assertEqual(bundle.capture_profiles, _CAPTURE_PROFILES)
        self.assertEqual(len(bundle.capture_profile_receipts), 4)
        self.assertNotIn("installer-native-input-capture-profile-v1", bundle.missing_prerequisite_ids)
        tool = next(row for row in bundle.capture_profiles if row.capture_schema_id == "native-registered-tool-result-v1")
        self.assertEqual(tool.source_action_ids, ())
        self.assertIn("selected-tool-result-schema-action-join", bundle.missing_prerequisite_ids)
        discovery = next(row for row in bundle.capture_profiles
                         if row.artifact_id == "installer-native-mcp-discovery-capture-profile-v171")
        self.assertEqual(discovery.source_action_ids, ("root-mcp-tools-list-discovery-v1",))
        self.assertEqual(discovery.call_site, "dispatch_native_mcp_tool_call")

    def test_capture_profile_changed_bytes_are_rejected_even_with_a_held_receipt(self):
        from hermes_installer.authority.native_source_definitions import _CAPTURE_PROFILES, _REGISTRY_SEAL

        session = _Session()
        binding = RootSelectedInstallationBinding(session, session._seal)
        profile = _CAPTURE_PROFILES[0]
        bad = _receipt(session, profile.relative_path, b'{"schema":1}', profile.artifact_id)
        session._resolve_prepared_native_capture_profile_receipts = lambda: (bad,)
        registry = RootNativeSourceDefinitionRegistry(
            binding, session._resolve_prepared_worker_role_module_receipts,
            session._resolve_prepared_native_source_definition_module_receipt,
            capture_profile_receipt_provider=session._resolve_prepared_native_capture_profile_receipts,
            _seal=_REGISTRY_SEAL,
        )
        with self.assertRaises(NativeSourceDefinitionUnavailable):
            registry.prepare_for_policy(_Selection())


if __name__ == "__main__":
    unittest.main()
