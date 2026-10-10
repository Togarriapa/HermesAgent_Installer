from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest
from email.message import Message
from urllib import error, request

from hermes_installer.authority.application_toolchain_sources import (
    SOURCE_POLICY_ARTIFACT_ID,
    SOURCE_POLICY_BYTES,
    SOURCE_POLICY_PATH,
    SOURCE_POLICY_SHA256,
    _PINNED,
)


class SelectedToolchainSourcePinTests(unittest.TestCase):
    def test_installed_policy_member_is_the_exact_reviewed_source(self):
        repo = Path(__file__).parents[2]
        body = (repo / SOURCE_POLICY_PATH).read_bytes()
        self.assertEqual((len(body), hashlib.sha256(body).hexdigest()),
                         (SOURCE_POLICY_BYTES, SOURCE_POLICY_SHA256))
        policy = json.loads(body.decode("utf-8", "strict"))
        self.assertEqual(policy["schema"], 1)
        rows = {row["tool_id"]: row for row in policy["toolchain_sources"]}
        self.assertEqual(set(rows), set(_PINNED))
        for artifact_id, (version, url, size, digest, kind, _hosts) in _PINNED.items():
            row = rows[artifact_id]
            self.assertEqual((row["version"], row["url"], row["size_bytes"],
                              row["sha256"], row["archive_kind"]),
                             (version, url, size, digest, kind))
        self.assertEqual(SOURCE_POLICY_ARTIFACT_ID,
                         "installer-application-toolchain-source-policy-v144")

    def test_source_catalog_rows_are_exact_and_large_observer_is_narrow(self):
        repo = Path(__file__).parents[2]
        catalog = json.loads((repo / "src/hermes_installer/authority/artifact-catalog.json").read_text())
        rows = {row["artifact_id"]: row for row in catalog["artifacts"]}
        self.assertEqual(set(_PINNED), set(_PINNED) & set(rows))
        for artifact_id, (version, url, size, digest, _kind, hosts) in _PINNED.items():
            row = rows[artifact_id]
            self.assertEqual((row["version"], row["source_url"], row["size_bytes"],
                              row["max_bytes"], row["sha256"], tuple(row["redirect_hosts"])),
                             (version, url, size, size, digest, hosts))
        self.assertTrue(all(row["max_bytes"] <= 64 * 1024 * 1024
                            for row in (rows[item] for item in _PINNED)))
        self.assertEqual(catalog["packages"], [])

    def test_observation_surface_has_only_opaque_handle_and_held_fd(self):
        from hermes_installer.authority.application_toolchain_sources import (
            RootSelectedApplicationToolchainSourceObserver,
            VerifiedApplicationToolchainSourceObservation,
            _TwoHopAllowlistedRedirect,
        )
        self.assertTrue(callable(RootSelectedApplicationToolchainSourceObserver.observe_selected_toolchain_source))
        self.assertTrue(callable(RootSelectedApplicationToolchainSourceObserver.verify_current))
        self.assertTrue(callable(RootSelectedApplicationToolchainSourceObserver.open_blob))
        self.assertNotIn("source_url", VerifiedApplicationToolchainSourceObservation.__dataclass_fields__)
        self.assertNotIn("path", VerifiedApplicationToolchainSourceObservation.__dataclass_fields__)
        self.assertIn("_fd", VerifiedApplicationToolchainSourceObservation.__dataclass_fields__)
        self.assertEqual((_TwoHopAllowlistedRedirect.max_redirections,
                          _TwoHopAllowlistedRedirect.max_repeats), (2, 2))

    def test_redirect_handler_accepts_only_the_pinned_bun_asset_host(self):
        from hermes_installer.authority.application_toolchain_sources import _TwoHopAllowlistedRedirect
        handler = _TwoHopAllowlistedRedirect(frozenset({"release-assets.githubusercontent.com"}))
        req = request.Request("https://github.com/oven-sh/bun/archive.zip")
        headers = Message()
        redirected = handler.redirect_request(req, None, 302, "Found", headers,
                                               "https://release-assets.githubusercontent.com/a.zip")
        self.assertEqual(redirected.full_url, "https://release-assets.githubusercontent.com/a.zip")
        for url in ("http://release-assets.githubusercontent.com/a.zip",
                    "https://evil.example/a.zip",
                    "https://user@release-assets.githubusercontent.com/a.zip"):
            with self.assertRaises(error.HTTPError):
                handler.redirect_request(req, None, 302, "Found", headers, url)


if __name__ == "__main__":
    unittest.main()
