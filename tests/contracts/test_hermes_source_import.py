from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from hermes_installer.artifacts import ArtifactCatalog, _artifact_from_record
from hermes_installer.authority.types import AuthorityDenied
from hermes_installer.hermes_source import (
    HERMES_SOURCE_ARTIFACT_ID,
    HERMES_SOURCE_BYTES,
    HERMES_SOURCE_COMMIT,
    HERMES_SOURCE_NORMALIZATION_SHA256,
    HERMES_SOURCE_SHA256,
    HERMES_SOURCE_TREE_MANIFEST_SHA256,
    HERMES_SOURCE_TREE_SHA1,
    HermesSourceReceiptHandoff,
    PinnedHermesSourceProvisioner,
    _git_tree_sha1,
    _git_blob_sha1,
    _load_normalization_manifest,
    materialize_pinned_hermes_source,
    register_pinned_hermes_source_receipt,
    VerifiedHermesSource,
)


ROOT = Path(__file__).resolve().parents[2]


class HermesSourceImportTests(unittest.TestCase):
    def test_protected_catalog_contains_exact_complete_source_pin(self):
        raw = json.loads((ROOT / "src/hermes_installer/authority/artifact-catalog.json").read_text())
        record = next(item for item in raw["artifacts"] if item["artifact_id"] == HERMES_SOURCE_ARTIFACT_ID)
        spec = _artifact_from_record(record)
        self.assertEqual(spec.sha256, HERMES_SOURCE_SHA256)
        self.assertEqual(spec.size_bytes, HERMES_SOURCE_BYTES)
        self.assertEqual(len(spec.tree_files), 17_973)
        self.assertEqual(spec.tree_manifest_sha256, HERMES_SOURCE_TREE_MANIFEST_SHA256)
        self.assertEqual(spec.archive_root, "hermes-agent-7085fbf7753266fc4943c55ac04926186bc90005/")

    def test_store_reference_must_be_exact_before_accessing_catalog(self):
        with self.assertRaises(AuthorityDenied):
            materialize_pinned_hermes_source(ArtifactCatalog.from_records(()),
                "artifact:caller-selected:00000000", "/nonexistent", expected_uid=os.getuid())

    def test_cancellation_prevents_source_resolution_before_any_import(self):
        store_id = f"artifact:{HERMES_SOURCE_ARTIFACT_ID}:{HERMES_SOURCE_SHA256}"
        with self.assertRaises(AuthorityDenied) as caught:
            materialize_pinned_hermes_source(ArtifactCatalog.from_records(()), store_id,
                "/nonexistent", expected_uid=os.getuid(), cancelled=lambda: True)
        self.assertEqual(caught.exception.code, "source.cancelled")

    def test_pinned_line_ending_manifest_is_hashed_and_complete(self):
        rows = _load_normalization_manifest()
        self.assertEqual(len(rows), 37)
        self.assertEqual(HERMES_SOURCE_NORMALIZATION_SHA256,
                         hashlib.sha256((ROOT / "src/hermes_installer/authority/hermes-source-normalization.json").read_bytes()).hexdigest())

    def test_git_tree_identity_reconstructs_known_upstream_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "dir").mkdir()
            (root / "a.txt").write_bytes(b"hello\n")
            script = root / "dir/run.sh"
            script.write_bytes(b"#!/bin/sh\necho ok\n")
            script.chmod(0o755)
            self.assertEqual(_git_tree_sha1(root, {}), "73c9649eac820b650904a7b7f8d6a3a706e9475c")
            self.assertNotEqual(_git_tree_sha1(root, {}), HERMES_SOURCE_TREE_SHA1)

    def test_only_a_pinned_crlf_file_is_normalized_for_git_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = b"line\r\n"
            normalized = b"line\n"
            path = root / "a.ps1"
            path.write_bytes(raw)
            row = {
                "archive_git_blob_sha1": _git_blob_sha1(raw),
                "archive_sha256": hashlib.sha256(raw).hexdigest(),
                "archive_size_bytes": len(raw),
                "normalized_git_blob_sha1": _git_blob_sha1(normalized),
                "normalized_size_bytes": len(normalized),
                "path": "a.ps1", "source_git_blob_sha1": _git_blob_sha1(normalized),
                "source_size_bytes": len(normalized),
            }
            tree = _git_tree_sha1(root, {"a.ps1": row})
            self.assertEqual(tree, "feb019423a130722da842e8e01b46056cd41623a")
            with self.assertRaises(AuthorityDenied):
                _git_tree_sha1(root, {"other.ps1": row})

    def test_registry_receives_only_verified_pinned_store_identity(self):
        source = VerifiedHermesSource(HERMES_SOURCE_ARTIFACT_ID, HERMES_SOURCE_SHA256,
            HERMES_SOURCE_BYTES, HERMES_SOURCE_COMMIT, HERMES_SOURCE_TREE_SHA1,
            HERMES_SOURCE_TREE_MANIFEST_SHA256, HERMES_SOURCE_NORMALIZATION_SHA256,
            Path("/root-private/archive"), Path("/root-private/tree"))

        class Registry:
            called = None

            def mint(self, **kwargs):
                self.called = kwargs
                return "opaque-setup-handle"

        registry = Registry()
        store_id = f"artifact:{HERMES_SOURCE_ARTIFACT_ID}:{HERMES_SOURCE_SHA256}"
        setup_authorization = object()
        with patch("hermes_installer.hermes_source.materialize_pinned_hermes_source", return_value=source):
            handoff = register_pinned_hermes_source_receipt(
                object(), store_id, "effect-receipt-123", "/root-private/cas", registry,
                setup_authorization, expected_uid=os.getuid())
        self.assertEqual(handoff.receipt_handle, "opaque-setup-handle")
        self.assertEqual(registry.called, {
            "store_id": store_id, "receipt_id": "effect-receipt-123",
            "setup_authorization": setup_authorization,
        })
        self.assertEqual(handoff.source.git_tree_sha1, HERMES_SOURCE_TREE_SHA1)

    def test_root_provisioner_uses_fixed_broker_identity_then_mints_handle(self):
        source = VerifiedHermesSource(HERMES_SOURCE_ARTIFACT_ID, HERMES_SOURCE_SHA256,
            HERMES_SOURCE_BYTES, HERMES_SOURCE_COMMIT, HERMES_SOURCE_TREE_SHA1,
            HERMES_SOURCE_TREE_MANIFEST_SHA256, HERMES_SOURCE_NORMALIZATION_SHA256,
            Path("/root-private/archive"), Path("/root-private/tree"))

        class Fetcher:
            calls = []

            def fetch_artifact(self, **kwargs):
                self.calls.append(kwargs)
                return (f"artifact:{HERMES_SOURCE_ARTIFACT_ID}:{HERMES_SOURCE_SHA256}",
                        "root-effect-receipt")

        class Registry:
            calls = []

            def mint(self, **kwargs):
                self.calls.append(kwargs)
                return "opaque-setup-receipt-handle"

        fetcher, registry = Fetcher(), Registry()
        catalog = object()
        artifact_root = Path("/root-private/cas")
        provisioner = PinnedHermesSourceProvisioner(
            fetcher=fetcher, catalog=catalog, artifact_root=artifact_root,
            receipt_registry=registry, expected_uid=os.getuid())
        proof = object()
        with patch("hermes_installer.hermes_source.register_pinned_hermes_source_receipt",
                   return_value=HermesSourceReceiptHandoff("opaque-setup-receipt-handle", source)) as register:
            result = provisioner.provision(proof)
        self.assertEqual(result.receipt_handle, "opaque-setup-receipt-handle")
        self.assertEqual(len(fetcher.calls), 1)
        self.assertEqual({key: value for key, value in fetcher.calls[0].items()
                          if key not in {"timeout", "cancelled"}}, {
            "artifact_id": HERMES_SOURCE_ARTIFACT_ID, "sha256": HERMES_SOURCE_SHA256,
            "max_bytes": 100_663_296,
        })
        self.assertGreater(fetcher.calls[0]["timeout"], 119.0)
        self.assertLessEqual(fetcher.calls[0]["timeout"], 120.0)
        self.assertTrue(callable(fetcher.calls[0]["cancelled"]))
        register.assert_called_once_with(
            catalog, f"artifact:{HERMES_SOURCE_ARTIFACT_ID}:{HERMES_SOURCE_SHA256}",
            "root-effect-receipt", artifact_root, registry, proof,
            expected_uid=os.getuid(), cancelled=unittest.mock.ANY,
            deadline_monotonic=unittest.mock.ANY)

    def test_root_provisioner_rejects_unpinned_receipt_before_registry(self):
        class Fetcher:
            def fetch_artifact(self, **kwargs):
                return ("artifact:caller-selected:" + "0" * 64, "receipt")

        class Registry:
            def mint(self, **kwargs):
                raise AssertionError("unverified receipt must not be minted")

        provisioner = PinnedHermesSourceProvisioner(
            fetcher=Fetcher(), catalog=object(), artifact_root=Path("/root-private/cas"),
            receipt_registry=Registry(), expected_uid=os.getuid())
        with self.assertRaises(AuthorityDenied) as caught:
            provisioner.provision(object())
        self.assertEqual(caught.exception.code, "source.receipt")

    def test_cancelled_root_provisioner_never_starts_artifact_fetch(self):
        class Fetcher:
            def fetch_artifact(self, **_kwargs):
                raise AssertionError("cancelled provision must not make a broker request")

        class Registry:
            def mint(self, **_kwargs):
                raise AssertionError("cancelled provision must not mint a receipt")

        provisioner = PinnedHermesSourceProvisioner(
            fetcher=Fetcher(), catalog=object(), artifact_root=Path("/root-private/cas"),
            receipt_registry=Registry(), expected_uid=os.getuid())
        with self.assertRaises(AuthorityDenied) as caught:
            provisioner.provision(object(), cancelled=lambda: True)
        self.assertEqual(caught.exception.code, "source.cancelled")


if __name__ == "__main__":
    unittest.main()
