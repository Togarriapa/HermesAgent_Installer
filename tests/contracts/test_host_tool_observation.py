from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path

from hermes_installer.authority import host_tool_observation as observation


class HostToolCatalogTests(unittest.TestCase):
    def test_closed_v2_catalog_is_the_pinned_release_artifact(self):
        body = observation.CATALOG_PATH.read_bytes()
        self.assertEqual(len(body), observation.CATALOG_SIZE)
        self.assertEqual(hashlib.sha256(body).hexdigest(), observation.CATALOG_SHA256)
        catalog = json.loads(body)
        self.assertEqual(catalog["artifact_id"], observation.CATALOG_ID)
        self.assertEqual(catalog["schema"], 1)
        self.assertEqual({(row["distribution"], row["release"], row["architecture"])
                          for row in catalog["variants"]}, {
            ("ubuntu", "24.04", "amd64"), ("ubuntu", "24.04", "arm64"),
            ("debian", "13", "arm64"),
        })
        self.assertTrue(all(row["executable_sha256"] and row["package_sha256"]
                            and row["package_size_bytes"] > 0 for row in catalog["variants"]))

    def test_archive_signer_allowlist_is_finite_and_distribution_specific(self):
        self.assertEqual(observation._SIGNERS["ubuntu"], {"F6ECB3762474EDA9D21B7022871920D1991BC93C"})
        self.assertEqual(len(observation._SIGNERS["debian"]), 3)
        self.assertFalse(observation._SIGNERS["ubuntu"] & observation._SIGNERS["debian"])


if __name__ == "__main__":
    unittest.main()
