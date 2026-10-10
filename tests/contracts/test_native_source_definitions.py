import hashlib
import time
import unittest

from hermes_installer.authority.bootstrap_runtime_factory import (
    RootReleaseModuleReceipt, RootSelectedInstallationBinding,
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

    def _check_live(self):
        return None

    def _resolve_prepared_release_module_receipts(self):
        return self.receipts

    def _read_release_member_receipt(self, receipt):
        return self.bytes_by_path[receipt.relative_path]


class _Selection:
    selection_handle = "selection-current"
    selection_sha256 = "a" * 64
    package_id = "hermes-profile"
    expires_monotonic = time.monotonic() + 60


def _receipt(session, path, raw):
    session.bytes_by_path = {path: raw}
    receipt = object.__new__(RootReleaseModuleReceipt)
    values = {
        "artifact_id": "root-release:" + path,
        "relative_path": path,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "release_commit": "release-commit",
        "deployment_receipt_sha256": "b" * 64,
        "source_receipt_handle": "c" * 32,
        "_session_id": "session-id",
        "_session_seal": session._seal,
        "_session": session,
        "_prepared_generation_id": "generation",
    }
    for key, value in values.items():
        object.__setattr__(receipt, key, value)
    return receipt


class NativeSourceDefinitionContracts(unittest.TestCase):
    def test_preparation_is_pending_until_actual_definition_and_role_receipts_exist(self):
        session = _Session()
        binding = RootSelectedInstallationBinding(session, session._seal)
        registry = RootNativeSourceDefinitionRegistry.from_selected_installation(binding)

        bundle = registry.prepare_for_policy(_Selection())

        self.assertIs(registry.resolve_current(bundle), bundle)
        self.assertIsNone(bundle.definition_source_receipt)
        self.assertEqual(bundle.role_module_receipts, ())
        self.assertIn("hermes_installer.native_invocations", bundle.missing_prerequisite_ids)
        self.assertIn("hermes_installer.native_boundary", bundle.missing_prerequisite_ids)
        self.assertIn("selected-source-capture-schema", bundle.missing_prerequisite_ids)
        self.assertIn("selected-source-action-binding", bundle.missing_prerequisite_ids)
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
        wrong = _receipt(session, declaration.closure_member_path, b"different installed module")
        session.receipts = (wrong,)
        binding = RootSelectedInstallationBinding(session, session._seal)
        registry = RootNativeSourceDefinitionRegistry.from_selected_installation(binding)

        with self.assertRaises(NativeSourceDefinitionUnavailable):
            registry.prepare_for_policy(_Selection())

    def test_constructor_rejects_unsealed_resolver_injection(self):
        with self.assertRaises(TypeError):
            RootNativeSourceDefinitionRegistry(object(), lambda: ())


if __name__ == "__main__":
    unittest.main()
