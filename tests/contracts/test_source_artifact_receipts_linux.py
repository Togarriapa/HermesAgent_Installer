"""Root-owned package schema derivation fixture; live setup is not implied."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec, TreeFile, load_protected_catalog
from hermes_installer.authority import artifacts as derivation
from hermes_installer.authority.artifacts import RootSchemaDerivationReceiptRegistry
from hermes_installer.authority.bootstrap_enrollment import RootArtifactReceiptRegistry
from hermes_installer.authority.runtime_bindings import RootRuntimeBindings
from hermes_installer.authority.setup_policy_publication import (
    PolicyPublicationReceiptResolver, RootSetupPublicationReceipt,
)
from hermes_installer.authority.source_artifact_receipts import (
    RootCatalogArtifactObserver, SourceArtifactReceiptDenied,
    build_root_schema_receipt_runtime,
)
from hermes_installer.protected_enrollment import ProtectedRootJournalCatalog, RootJournalSelection


class RootSchemaDerivationLinuxTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0,
                         "requires isolated Linux root-owned catalog fixture")
    def test_pinned_xpra_source_catalog_has_exact_full_tree_and_link_rows(self):
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-catalog-", dir="/var/lib") as temporary:
            root = Path(temporary)
            os.chmod(root, 0o700)
            catalog_path = root / "artifact-catalog.json"
            shutil.copyfile(
                Path(__file__).parents[2] / "src/hermes_installer/authority/artifact-catalog.json",
                catalog_path,
            )
            os.chmod(catalog_path, 0o600)
            catalog = load_protected_catalog(catalog_path, expected_uid=0)
            spec = catalog._artifact(
                "xpra-source-521b0d2e762c770b2641d258b93d23575fa9cbea",
                "20b55586457df5aed8453b0d1b446e4dd954f2027d814f1eb7c0a96227ef1c80",
            )
            self.assertEqual(spec.version, "521b0d2e762c770b2641d258b93d23575fa9cbea")
            self.assertEqual(spec.source_url,
                             "https://codeload.github.com/Xpra-org/xpra/tar.gz/"
                             "521b0d2e762c770b2641d258b93d23575fa9cbea")
            self.assertEqual((spec.size_bytes, spec.max_bytes, spec.max_tree_bytes),
                             (13962693, 16777216, 67108864))
            self.assertEqual((len(spec.tree_files), sum(row.kind == "file" for row in spec.tree_files),
                              sum(row.kind == "symlink" for row in spec.tree_files)), (2474, 2469, 5))
            self.assertEqual(spec.tree_manifest_sha256,
                             "f52b4ce760b86c24a4d6d930f47e58357442a984d9ff2478d7abf338ff48e467")
            self.assertEqual({(row.path, row.link_target, row.sha256, row.size_bytes)
                              for row in spec.tree_files if row.kind == "symlink"}, {
                ("debian", "packaging/debian/xpra",
                 "a1aef4be57bc54eefaab320b3728f3c0e0f463bc3c7307b1ac4528e2b3f00d4b", 21),
                ("fs/etc/default", "sysconfig",
                 "ed85312a196268e2240f401f7d8711c4edaad4d43bcfd76ec5f4e19ec8916ee0", 9),
                ("fs/libexec/xpra/gnome-open", "xdg-open",
                 "cdb8bb17173e1db8bf5dad2247fbe8be8d8c82e076cb465a471482387f521a29", 8),
                ("fs/libexec/xpra/gvfs-open", "xdg-open",
                 "cdb8bb17173e1db8bf5dad2247fbe8be8d8c82e076cb465a471482387f521a29", 8),
                ("fs/share/doc/xpra", "../../../docs",
                 "bdc7f46fbdfe68781df25dec18962c3ac2aa93d35c3e04185ecc9ac201c73b35", 13),
            })

    @unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0,
                         "requires isolated Linux root-owned fixture")
    def test_glm_source_blobs_are_observed_only_from_exact_root_catalog_cas(self):
        repo = Path(__file__).parents[2]
        with tempfile.TemporaryDirectory(prefix="hermes-glm-source-", dir="/var/lib") as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
            catalog_path = base / "artifact-catalog.json"
            catalog_path.write_bytes((repo / "src/hermes_installer/authority/artifact-catalog.json").read_bytes())
            os.chmod(catalog_path, 0o600)
            catalog = load_protected_catalog(catalog_path, expected_uid=0)
            staging = base / "staging"
            staging.mkdir(mode=0o700)
            expected = {
                "glm52-artifact-metadata-v1": (
                    "b42e3fa6fd5c287b95fcda4d370697bd4c0ef226767ddc08fae4e5bebcfecd1a",
                    "planning/glm52-artifact-metadata.json"),
                "glm52-upstream-mit-license-cf457fa": (
                    "f4a18c6ae40b0a8e7d2b7667f52f6e1994e54a46430d2e172b73cb8c9b5eb0d7",
                    "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-upstream-MIT-LICENSE.txt"),
                "glm52-quantized-readme-6bbb01e": (
                    "85fc4cf947276c376f09ad1226926ebc03eefbb99d184cd05f34412d32d8406b",
                    "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-quantized-README.md"),
            }
            for artifact_id, (digest, relative_path) in expected.items():
                body = (repo / relative_path).read_bytes()
                spec = catalog._artifact(artifact_id, digest)
                self.assertEqual((spec.size_bytes, spec.max_bytes, spec.archive_format, spec.tree_files),
                                 (len(body), len(body), None, ()))
                target = staging / "objects" / artifact_id / digest / spec.filename
                target.parent.mkdir(mode=0o700, parents=True)
                target.write_bytes(body)
                os.chmod(target, 0o444)
            bindings = RootRuntimeBindings(
                enrollment_catalog=SimpleNamespace(digest="a" * 64), build_catalog=None,
                device_catalog=None, process_manager=None, effect_handlers={}, native_bridges={},
                artifact_catalog=catalog, build_store=None, service_connector=None,
            )
            enrollment = SimpleNamespace(protected_enrollment_digest="a" * 64,
                                         artifact_staging_directory=staging)
            observer = RootCatalogArtifactObserver.from_root_runtime(bindings, enrollment)
            observations = []
            try:
                for artifact_id, (digest, relative_path) in expected.items():
                    observation = observer.observe(artifact_id, digest)
                    observations.append(observation)
                    self.assertTrue(observer.verify_current(observation))
                    source = (repo / relative_path).read_bytes()
                    fd = observation.open_blob()
                    try:
                        actual = os.read(fd, len(source) + 1)
                    finally:
                        os.close(fd)
                    self.assertEqual(actual, source)
                    self.assertEqual((observation.artifact_id, observation.sha256,
                                      observation.size_bytes), (artifact_id, digest, len(source)))
                first = observations[0]
                staged = staging / "objects" / first.artifact_id / first.sha256 / catalog.artifacts[first.artifact_id].filename
                with staged.open("r+b") as output:
                    output.write(b"X")
                with self.assertRaises(SourceArtifactReceiptDenied):
                    observer.verify_current(first)
            finally:
                for observation in observations:
                    observation.close()

    @unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0,
                         "requires isolated Linux root-owned fixture")
    def test_package_member_derivation_requires_current_active_receipt_closure(self):
        # /tmp is intentionally rejected by the root journal reader because
        # its writable sticky parent is not part of the trusted journal chain.
        with tempfile.TemporaryDirectory(prefix="hermes-schema-derivation-",
                                         dir="/var/lib") as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
            journal_dir = Path("/var/lib/hermes-installer/authority-journal")
            if journal_dir.exists():
                self.skipTest("fixed production journal path already exists; refusing to alter it")
            journal_parent = journal_dir.parent
            parent_created = not journal_parent.exists()
            journal_parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            journal_dir.mkdir(mode=0o700)
            self.addCleanup(shutil.rmtree, journal_dir)
            if parent_created:
                self.addCleanup(self._remove_empty_parent, journal_parent)
            cas = base / "cas"
            cas.mkdir(mode=0o700)
            schema = b'{"additionalProperties":false,"type":"object"}'
            schema_hash = hashlib.sha256(schema).hexdigest()
            archive_bytes = self._zip("schemas/arguments.json", schema)
            archive_hash = hashlib.sha256(archive_bytes).hexdigest()
            source_tree = (TreeFile("schemas/arguments.json", schema_hash, len(schema)),)
            source = ArtifactSpec("pkg-source", "1.2.3", archive_hash,
                                  "https://example.invalid/pkg.zip", len(archive_bytes),
                                  len(archive_bytes), filename="source.zip", tree_files=source_tree,
                                  archive_format="zip", max_tree_bytes=1024)
            child = ArtifactSpec("action-schema", "1.0.0", schema_hash,
                                 "https://example.invalid/schema.json", len(schema), len(schema),
                                 filename="schema.json")
            catalog = ArtifactCatalog.from_records((source, child))
            self._put_cas(cas, source.artifact_id, source.sha256, source.filename, archive_bytes)
            self._put_cas(cas, child.artifact_id, child.sha256, child.filename, schema)

            journal_info = journal_dir.stat()
            generation = "b" * 64
            root_catalog = ProtectedRootJournalCatalog.from_protected_records([{
                "root_id": "installer-authority-journal-v1",
                "absolute_path": str(journal_dir), "owner_uid": 0, "owner_gid": 0,
                "mode": 0o700, "device": journal_info.st_dev, "inode": journal_info.st_ino,
                "generation": "generation-1", "purpose": "authority-journal",
            }], generation_digest=generation)
            receipt_root = journal_dir / "bootstrap-receipts"
            receipt_root.mkdir(mode=0o700)
            parent = "parentreceipt0000000000000000000000000000000000000000000"
            parent_record = {
                "schema": 1, "handle": parent, "receipt_id": "fetch-1",
                "setup_session_id": "setup-1", "transaction_handle": "txn-1",
                "target_id": "target-1", "operation_target_id": "target-1",
                "plan_digest": "a" * 64, "operator_uid": 0,
                "artifact_role": source.artifact_id, "artifact_id": source.artifact_id,
                "sha256": source.sha256, "size_bytes": len(archive_bytes),
            }
            self._write_json(receipt_root / f"{parent}.json", parent_record)
            parent_registry = RootArtifactReceiptRegistry(
                receipt_root, catalog=catalog, artifact_root=cas,
            )

            schema_row = {
                "id": "schema-demo-arguments-v1", "artifact_id": child.artifact_id,
                "sha256": child.sha256, "schema_kind": "arguments",
                "native_package_id": "package-demo", "native_package_generation": "generation-1",
                "adapter_id": "adapter-demo", "action_id": "action-demo",
                "source_receipt_handle": parent, "size_bytes": len(schema),
                "derivation_receipt_handle": None,
            }
            package = SimpleNamespace(
                generation="generation-1", profile_id="profile-demo",
                source_tree_sha256=source.tree_manifest_sha256, source_revision=source.version,
            )

            class SelectedRuntime:
                native_schema_artifact_records = (schema_row,)

                def resolve_native_package(self, package_id, generation):
                    if (package_id, generation) != ("package-demo", "generation-1"):
                        raise LookupError
                    return package

                def resolve_native_schema_record(self, *identity):
                    expected = (schema_row["id"], schema_row["native_package_id"],
                                schema_row["native_package_generation"], schema_row["adapter_id"],
                                schema_row["action_id"], schema_row["schema_kind"])
                    if identity != expected:
                        raise LookupError
                    return schema_row

            class RuntimeBindings(RootRuntimeBindings):
                def resolve_native_package(self, package_id, package_generation):
                    if (package_id, package_generation) != ("package-demo", "generation-1"):
                        raise LookupError
                    return package

                def resolve_native_schema_record(self, *identity):
                    expected = (schema_row["id"], schema_row["native_package_id"],
                                schema_row["native_package_generation"], schema_row["adapter_id"],
                                schema_row["action_id"], schema_row["schema_kind"])
                    if identity != expected:
                        raise LookupError
                    return schema_row

            bindings = RuntimeBindings(
                enrollment_catalog=SimpleNamespace(digest=generation), build_catalog=None,
                device_catalog=None, process_manager=None, effect_handlers={}, native_bridges={},
                artifact_catalog=catalog, build_store=None, service_connector=None,
                root_journal_catalog=root_catalog, native_schema_artifact_records=(schema_row,),
            )
            enrollment = SimpleNamespace(
                protected_enrollment_digest=generation, artifact_staging_directory=cas,
            )
            source_runtime = build_root_schema_receipt_runtime(bindings, enrollment)
            registry = source_runtime.derivations
            self.assertIs(source_runtime.artifact_receipts.catalog, catalog)
            self.assertEqual(source_runtime.artifact_receipts.root, receipt_root)
            dynamic_schema = b'{"additionalProperties":false,"type":"object"}'
            dynamic_sha = hashlib.sha256(dynamic_schema).hexdigest()
            dynamic_id = f"native-mcp-schema:{dynamic_sha}"
            registry._write_derived_schema(dynamic_id, dynamic_sha, dynamic_schema)
            self.assertEqual(
                registry._read_derived_schema(dynamic_id, dynamic_sha, len(dynamic_schema)),
                dynamic_schema,
            )
            with self.assertRaises(derivation.SchemaDerivationDenied):
                registry._write_derived_schema("native-mcp-schema:" + "0" * 64,
                                                "0" * 64, dynamic_schema)
            external_schema = b'{"$ref":"https://invalid.example/schema.json"}'
            external_sha = hashlib.sha256(external_schema).hexdigest()
            with self.assertRaises(derivation.SchemaDerivationDenied):
                registry._write_derived_schema(
                    f"native-mcp-schema:{external_sha}", external_sha, external_schema,
                )
            dynamic_path = journal_dir / "derived-schemas" / f"{dynamic_sha}.json"
            os.chmod(dynamic_path, 0o644)
            with self.assertRaises(derivation.SchemaDerivationDenied):
                registry._read_derived_schema(dynamic_id, dynamic_sha, len(dynamic_schema))
            os.chmod(dynamic_path, 0o444)
            observer = RootCatalogArtifactObserver.from_root_runtime(bindings, enrollment)
            held_tree = observer.observe(source.artifact_id, source.sha256, materialize_tree=True)
            try:
                self.assertTrue(observer.verify_current(held_tree))
                self.assertEqual(held_tree.tree_files, source_tree)
                self.assertEqual(held_tree.tree_manifest_sha256, source.tree_manifest_sha256)
                member_fd = held_tree.open_member("schemas/arguments.json", observer=observer)
                try:
                    self.assertEqual(os.read(member_fd, len(schema)), schema)
                    os.fchmod(member_fd, 0o644)
                    with self.assertRaises(SourceArtifactReceiptDenied):
                        observer.verify_current(held_tree)
                    os.fchmod(member_fd, 0o444)
                finally:
                    os.close(member_fd)
                self.assertTrue(observer.verify_current(held_tree))
                os.fchmod(held_tree._fd, 0o755)
                unexpected_fd = os.open(
                    "unexpected.bin", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
                    0o600, dir_fd=held_tree._fd,
                )
                try:
                    os.write(unexpected_fd, b"unlisted")
                finally:
                    os.close(unexpected_fd)
                os.fchmod(held_tree._fd, 0o555)
                with self.assertRaises(SourceArtifactReceiptDenied):
                    observer.verify_current(held_tree)
                os.fchmod(held_tree._fd, 0o755)
                os.unlink("unexpected.bin", dir_fd=held_tree._fd)
                os.fchmod(held_tree._fd, 0o555)
                self.assertTrue(observer.verify_current(held_tree))
            finally:
                held_tree.close()
            with mock.patch.object(derivation, "_active_publication_with_parent", lambda _handle: object()):
                observation = registry.observe_packaged_schema(
                    schema_record=schema_row, parent_receipt_handle=parent,
                )
                handle = registry.mint_schema_artifact(observation)

            schema_row["derivation_receipt_handle"] = handle
            active = self._publication(journal_dir, generation, (parent, handle))
            unlisted_parent = self._publication(journal_dir, generation, (handle,))
            with mock.patch.object(PolicyPublicationReceiptResolver, "resolve_current",
                                   return_value=unlisted_parent):
                with self.assertRaises(derivation.SchemaDerivationDenied):
                    registry.resolve_schema_derivation(
                        handle, artifact_id=child.artifact_id, artifact_sha256=child.sha256,
                        size_bytes=len(schema), service_generation_digest=generation,
                    )
            prepared = self._publication(journal_dir, generation, (parent, handle), state="prepared")
            with mock.patch.object(PolicyPublicationReceiptResolver, "resolve_current",
                                   return_value=prepared):
                with self.assertRaises(derivation.SchemaDerivationPending):
                    registry.resolve_schema_derivation(
                        handle, artifact_id=child.artifact_id, artifact_sha256=child.sha256,
                        size_bytes=len(schema), service_generation_digest=generation,
                    )
            with mock.patch.object(PolicyPublicationReceiptResolver, "resolve_current",
                                   return_value=active):
                receipt = registry.resolve_schema_derivation(
                    handle, artifact_id=child.artifact_id, artifact_sha256=child.sha256,
                    size_bytes=len(schema), service_generation_digest=generation,
                )
                from hermes_installer.authority.source_artifact_receipts import (
                    RootSourceArtifactReceiptVerifier,
                )
                verifier = RootSourceArtifactReceiptVerifier.from_root_runtime(
                    bindings, registry, expected_uid=0,
                )
                identity = {
                    "schema_id": schema_row["id"], "sha256": child.sha256,
                    "schema_kind": "arguments", "native_package_id": "package-demo",
                    "native_package_generation": "generation-1", "adapter_id": "adapter-demo",
                    "action_id": "action-demo",
                }
                self.assertTrue(verifier.verify_source_receipt(parent, identity))
                with self.assertRaises(SourceArtifactReceiptDenied):
                    verifier.verify_source_receipt(handle, identity)
                from hermes_installer.mcp.native_dispatch import NativeMCPToolBinding
                selected_binding = NativeMCPToolBinding(
                    id="action-demo", profile_id="profile-demo", process_generation="generation-1",
                    native_package_id="package-demo", native_package_generation="generation-1",
                    native_server_name="fixture", native_tool_name="fixture.schema",
                    native_schema_sha256="a" * 64, mcp_enrollment_id="fixture",
                    mcp_generation="generation-1", mcp_tool_name="fixture.schema",
                    request_schema_id=schema_row["id"], result_schema_id="schema-result",
                    effect_operation="mcp.request", effect_target="mcp:fixture:http",
                    capability="mcp:fixture:read", recipient=None, scope_bindings=(),
                    handler_artifact_id="adapter-demo", handler_artifact_sha256="a" * 64,
                )
                derived = registry.resolve_schema_artifact(
                    handle, selected_binding=selected_binding, schema_role="arguments",
                )
                self.assertEqual(derived.canonical_schema_bytes, schema)
                self.assertEqual(derived.source_receipt_handle, parent)
                self.assertEqual(derived.derivation_receipt_handle, handle)
                self.assertEqual(receipt.source_kind, "packaged-schema")
                self.assertEqual(receipt.source_member_path, "schemas/arguments.json")
                self.assertEqual(receipt.parent_receipt_handles, (parent,))
                with self.assertRaises(derivation.SchemaDerivationDenied):
                    registry.resolve_schema_derivation(
                        handle, artifact_id=child.artifact_id, artifact_sha256="c" * 64,
                        size_bytes=len(schema), service_generation_digest=generation,
                    )

    @staticmethod
    def _zip(path: str, content: bytes) -> bytes:
        import io
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
            archive.writestr(path, content)
        return stream.getvalue()

    @staticmethod
    def _put_cas(root: Path, artifact_id: str, digest: str, filename: str, content: bytes) -> None:
        path = root / "objects" / artifact_id / digest
        path.mkdir(parents=True, mode=0o700)
        output = path / filename
        output.write_bytes(content)
        os.chmod(output, 0o400)

    @staticmethod
    def _write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.chmod(path, 0o600)

    @staticmethod
    def _publication(root: Path, generation: str, handles: tuple[str, ...], *, state: str = "active"):
        from hermes_installer.authority.setup_policy_publication import _SEAL
        info = root.stat()
        return RootSetupPublicationReceipt(
            1, "receipt-handle", "transaction-handle", "generation-id", "d" * 64,
            root, info.st_dev, info.st_ino, "e" * 64, "f" * 64, "a" * 64,
            "b" * 64, None, "c" * 64, handles, state, _SEAL,
        )

    @staticmethod
    def _remove_empty_parent(path: Path) -> None:
        try:
            path.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
