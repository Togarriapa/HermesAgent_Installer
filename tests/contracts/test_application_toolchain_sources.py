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
    _BUN_LICENSE_ID,
    _BUN_LICENSE_PIN,
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
        bun = rows["application-bun-1.4.3-linux-arm64"]
        self.assertEqual((bun["license_url"], bun["license_sha256"], bun["license_size_bytes"]),
                         (_BUN_LICENSE_PIN[1], _BUN_LICENSE_PIN[3], _BUN_LICENSE_PIN[2]))
        self.assertEqual(_BUN_LICENSE_ID, "application-bun-1.4.3-license")
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
        license_row = rows[_BUN_LICENSE_ID]
        self.assertEqual((license_row["version"], license_row["source_url"],
                          license_row["size_bytes"], license_row["max_bytes"],
                          license_row["sha256"], tuple(license_row["redirect_hosts"])),
                         (_BUN_LICENSE_PIN[0], _BUN_LICENSE_PIN[1], _BUN_LICENSE_PIN[2],
                          _BUN_LICENSE_PIN[2], _BUN_LICENSE_PIN[3], _BUN_LICENSE_PIN[4]))
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
        self.assertIn("source_kind", VerifiedApplicationToolchainSourceObservation.__dataclass_fields__)
        self.assertEqual(VerifiedApplicationToolchainSourceObservation.__dataclass_fields__["source_kind"].type, "str")
        self.assertEqual((_TwoHopAllowlistedRedirect.max_redirections,
                          _TwoHopAllowlistedRedirect.max_repeats), (2, 2))

    def test_observer_release_closes_only_its_exact_held_record_and_prunes_expired(self):
        import os
        import tempfile
        from hermes_installer.authority.application_toolchain_sources import (
            ApplicationToolchainSourceDenied,
            RootSelectedApplicationToolchainSourceObserver,
            VerifiedApplicationToolchainSourceObservation,
            _RECORD_SEAL,
        )

        def record(handle, observer_id, fd, expiry, *, artifact_id=_BUN_LICENSE_ID,
                   prep_handle="4" * 32):
            return VerifiedApplicationToolchainSourceObservation(
                1, handle, artifact_id, artifact_id,
                SOURCE_POLICY_ARTIFACT_ID, SOURCE_POLICY_SHA256, "1" * 64,
                "license", "", "2" * 64, 5_807, 1, 2, 0, 0, 0o444,
                "session", "transaction", "3" * 64, prep_handle, "5" * 32,
                "6" * 32, 1, 10.0, expiry, fd, observer_id, _RECORD_SEAL)

        with tempfile.TemporaryFile() as file:
            first_fd = os.dup(file.fileno())
            expired_fd = os.dup(file.fileno())
            replacement_fd = os.dup(file.fileno())
            different_fd = os.dup(file.fileno())
            observer = object.__new__(RootSelectedApplicationToolchainSourceObserver)
            observer._observer_id = "observer-one"
            observer._held = {}
            observer.monotonic = lambda: 20.0
            live = record("live-handle-" + "a" * 32, observer._observer_id, first_fd, 30.0)
            expired = record("expired-handle-" + "b" * 32, observer._observer_id, expired_fd, 19.0)
            replacement = record("replacement-handle-" + "c" * 32, observer._observer_id,
                                 replacement_fd, 30.0)
            different = record("different-handle-" + "d" * 32, observer._observer_id,
                              different_fd, 30.0, artifact_id="application-bun-1.4.3-linux-arm64")
            observer._held[live.observation_handle] = live
            observer._held[expired.observation_handle] = expired
            observer._held[replacement.observation_handle] = replacement
            observer._held[different.observation_handle] = different

            observer._prune_expired_observations("4" * 32, _BUN_LICENSE_ID)
            self.assertEqual(tuple(observer._held), (different.observation_handle,))
            with self.assertRaises(OSError):
                os.fstat(expired_fd)
            with self.assertRaises(OSError):
                os.fstat(first_fd)
            with self.assertRaises(OSError):
                os.fstat(replacement_fd)
            observer.release(different)
            self.assertEqual(observer._held, {})
            with self.assertRaises(ApplicationToolchainSourceDenied):
                observer.release(different)

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
