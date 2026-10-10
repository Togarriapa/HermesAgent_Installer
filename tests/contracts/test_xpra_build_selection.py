from __future__ import annotations

import json
import hashlib
import unittest
from types import SimpleNamespace
from pathlib import Path

from hermes_installer.authority.xpra_build_selection import (
    SOURCE_MANIFEST_SHA256,
    _full_manifest_sha256,
    RootXpraSourceReceipt,
    RootXpraBuildSelectionProducer,
    BUILD_TARGET,
    BUILD_OPERATION_ID,
    TRANSFORM_MODULE_ID,
    TRANSFORM_MODULE_SHA256,
)
from hermes_installer.artifacts import TreeFile


class XpraBuildSelectionContracts(unittest.TestCase):
    def test_full_source_manifest_commits_kind_and_link_target_bytes(self) -> None:
        row = TreeFile(
            "fs/etc/default", "ed85312a196268e2240f401f7d8711c4edaad4d43bcfd76ec5f4e19ec8916ee0",
            9, False, "symlink", "sysconfig",
        )
        changed = TreeFile(
            "fs/etc/default", hashlib.sha256(b"sysconfig2").hexdigest(),
            10, False, "symlink", "sysconfig2",
        )
        regular = TreeFile("docs/README", "a" * 64, 1)
        self.assertNotEqual(_full_manifest_sha256((row, regular)),
                            _full_manifest_sha256((changed, regular)))
        self.assertNotEqual(_full_manifest_sha256((row, regular)),
                            _full_manifest_sha256((TreeFile("docs/README", "b" * 64, 1), row)))

    def test_source_receipt_cannot_be_constructed_without_root_seal(self) -> None:
        with self.assertRaises(TypeError):
            RootXpraSourceReceipt(
                "opaque", "session", "transaction", "prepared", "a" * 64,
                "xpra-source-521b0d2e762c770b2641d258b93d23575fa9cbea",
                "b" * 64, 1, SOURCE_MANIFEST_SHA256, object(), object(), object(),
            )

    def test_setup_profile_binds_only_fixed_recipe_to_actual_selected_subject(self) -> None:
        subject = SimpleNamespace(
            profile_id="hermes-installer-build-v1",
            template_artifact_id="installer-prepared-build-service-template-v1",
            template_sha256="0d98bdabf27185d769f55de12e9242d5286e07d11e5d62369c2eeedf1fa4b967",
            allowed_operation_ids=(BUILD_OPERATION_ID,), allowed_targets=(BUILD_TARGET,),
            service_uid=41002, service_gid=41002,
            id="setup-build:txn:hermes-installer-build-v1", generation="a" * 64,
            transaction_handle="txn", prepared_generation_id="prepared",
            prepared_generation_digest="b" * 64,
        )
        pm = SimpleNamespace(receipt_handle="opaque-pm-receipt", device=1, inode=2,
                             runtime_sha256="c" * 64)
        prepared = SimpleNamespace(generation_digest="b" * 64)
        profile = RootXpraBuildSelectionProducer._fixed_build_profile(
            subject, pm, prepared, "d" * 64, Path("/root/private/output"))
        self.assertEqual(profile.target_id, BUILD_TARGET)
        self.assertEqual(profile.output_owner_uid, subject.service_uid)
        self.assertEqual(profile.build_service_enrollment_id, subject.id)
        self.assertEqual(profile.build_service_generation, subject.generation)
        self.assertEqual(profile.builder_sha256, pm.runtime_sha256)
        self.assertEqual(profile.toolchain_artifact_id, TRANSFORM_MODULE_ID)
        self.assertEqual(profile.toolchain_sha256, TRANSFORM_MODULE_SHA256)
        self.assertEqual(profile.argv_recipe[1], {"literal": "-I"})
        self.assertEqual(profile.output_specs["xpra-overlay.tar"].maximum_bytes, 134_217_728)
        self.assertEqual(profile.service_generation_digest, prepared.generation_digest)

    def test_static_catalog_tree_manifest_still_uses_separate_regular_projection(self) -> None:
        repo = Path(__file__).parents[2]
        catalog = json.loads((repo / "src/hermes_installer/authority/artifact-catalog.json").read_text())
        rows = catalog["artifacts"] if isinstance(catalog, dict) else catalog
        source = next(row for row in rows
                     if row.get("artifact_id") == "xpra-source-521b0d2e762c770b2641d258b93d23575fa9cbea")
        tree_files = tuple(TreeFile(
            row["path"], row["sha256"], row["size_bytes"], row["executable"],
            row["kind"], row["link_target"],
        ) for row in source["tree_files"])
        self.assertEqual(_full_manifest_sha256(tree_files), SOURCE_MANIFEST_SHA256)
        self.assertEqual(sum(row.kind == "file" for row in tree_files), 2469)
        self.assertEqual(sum(row.kind == "symlink" for row in tree_files), 5)


if __name__ == "__main__":
    unittest.main()
