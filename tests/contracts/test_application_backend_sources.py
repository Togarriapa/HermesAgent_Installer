from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from hermes_installer.authority.application_backend_sources import (
    BackendSourceDenied,
    RootSelectedApplicationBackendSourceObserver,
    _BACKEND_POLICY_SHA256,
    _POLICY_BYTES,
    urllib_parse,
)


class BackendPolicyContractTests(unittest.TestCase):
    def test_held_policy_source_table_has_exact_digest_and_finite_app_closures(self):
        path = Path(
            "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/"
            "application-pep517-backend-source-table-v1.json")
        payload = path.read_bytes()
        self.assertEqual(len(payload), _POLICY_BYTES)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), _BACKEND_POLICY_SHA256)
        table = json.loads(payload)
        RootSelectedApplicationBackendSourceObserver._validate_table(table)
        rows = {(row["name"], row["version"]) for row in table["packages"]}
        self.assertEqual(len(rows), 8)
        self.assertIn(("setuptools", "84.0.0"), rows)
        self.assertIn(("hatchling", "1.32.0"), rows)
        self.assertIn(("hatchling", "1.26.3"), rows)

    def test_policy_row_tampering_and_unpinned_wheel_origin_are_rejected(self):
        path = Path(
            "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/"
            "application-pep517-backend-source-table-v1.json")
        table = json.loads(path.read_bytes())
        table["packages"][0]["url"] = "https://evil.example/packages/wheel.whl"
        with self.assertRaises(BackendSourceDenied):
            RootSelectedApplicationBackendSourceObserver._validate_table(table)
        self.assertTrue(urllib_parse(
            "https://files.pythonhosted.org/packages/aa/bb/example.whl"))
        for url in (
            "http://files.pythonhosted.org/packages/example.whl",
            "https://evil.example/packages/example.whl",
            "https://user@files.pythonhosted.org/packages/example.whl",
            "https://files.pythonhosted.org/packages/example.whl?token=x",
            "https://files.pythonhosted.org/elsewhere/example.whl",
        ):
            self.assertFalse(urllib_parse(url), url)

    def test_caller_cannot_construct_a_source_observation(self):
        from hermes_installer.authority.application_backend_sources import (
            VerifiedApplicationBackendSourceObservation,
        )
        values = dict(
            schema=1, source_observation_handle="a" * 40,
            policy_artifact_id="installer-application-pep517-backend-sources-v1",
            policy_sha256="0" * 64, policy_member_receipt_handle="b" * 40,
            preparation_input_selection_handle="c" * 40,
            source_preparation_receipt_handle="d" * 40,
            pyproject_receipt_handle="d" * 40,
            qualification_choice_handle="e" * 40, package_name="hatchling",
            package_version="1.32.0", filename="hatchling.whl",
            source_url_sha256="0" * 64, sha256="0" * 64, size_bytes=1,
            device=1, inode=1, mode=0o444, metadata_sha256="0" * 64,
            license_observation_handle="f" * 40, issued_monotonic=1.0,
            expires_monotonic=2.0)
        with self.assertRaises(TypeError):
            VerifiedApplicationBackendSourceObservation(**values)


if __name__ == "__main__":
    unittest.main()
