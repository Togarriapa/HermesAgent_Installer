"""Root-owned package schema derivation fixture; live setup is not implied."""
from __future__ import annotations

import hashlib
import json
import os
import platform
import tempfile
import unittest
from unittest import mock
import zipfile
from pathlib import Path
from types import SimpleNamespace

from hermes_installer.artifacts import ArtifactCatalog, ArtifactSpec, TreeFile
from hermes_installer.authority import artifacts as derivation
from hermes_installer.authority.artifacts import RootSchemaDerivationReceiptRegistry
from hermes_installer.authority.bootstrap_enrollment import RootArtifactReceiptRegistry
from hermes_installer.authority.setup_policy_publication import RootSetupPublicationReceipt
from hermes_installer.protected_enrollment import RootJournalSelection


class RootSchemaDerivationLinuxTests(unittest.TestCase):
    @unittest.skipUnless(platform.system() == "Linux" and os.geteuid() == 0,
                         "requires isolated Linux root-owned fixture")
    def test_package_member_derivation_requires_current_active_receipt_closure(self):
        # /tmp is intentionally rejected by the root journal reader because
        # its writable sticky parent is not part of the trusted journal chain.
        with tempfile.TemporaryDirectory(prefix="hermes-schema-derivation-",
                                         dir="/var/lib") as temporary:
            base = Path(temporary)
            os.chmod(base, 0o700)
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

            receipt_root = base / "bootstrap-receipts"
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
                "source_receipt_handle": "pending-schema-receipt-handle-000000000000000000000000000000000000",
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

            journal_dir = base / "selected-journal"
            journal_dir.mkdir(mode=0o700)
            journal_info = journal_dir.stat()
            generation = "b" * 64
            journal = RootJournalSelection("journal-demo", journal_dir, journal_info.st_dev,
                                           journal_info.st_ino, "generation-1", generation)
            registry = RootSchemaDerivationReceiptRegistry.from_root_runtime(
                catalog, parent_registry, SelectedRuntime(), None, journal,
            )
            with mock.patch.object(derivation, "_active_publication_with_parent", lambda _handle: object()):
                observation = registry.observe_packaged_schema(
                    schema_record=schema_row, parent_receipt_handle=parent,
                )
                handle = registry.mint_schema_artifact(observation)

            schema_row["source_receipt_handle"] = handle
            active = self._publication(journal_dir, generation, (parent, handle))
            with mock.patch.object(derivation, "_active_publication", lambda: active):
                receipt = registry.resolve_schema_derivation(
                    handle, artifact_id=child.artifact_id, artifact_sha256=child.sha256,
                    size_bytes=len(schema), service_generation_digest=generation,
                )
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
    def _publication(root: Path, generation: str, handles: tuple[str, ...]):
        from hermes_installer.authority.setup_policy_publication import _SEAL
        info = root.stat()
        return RootSetupPublicationReceipt(
            1, "receipt-handle", "transaction-handle", "generation-id", "d" * 64,
            root, info.st_dev, info.st_ino, "e" * 64, "f" * 64, "a" * 64,
            "b" * 64, None, "c" * 64, handles, "active", _SEAL,
        )


if __name__ == "__main__":
    unittest.main()
