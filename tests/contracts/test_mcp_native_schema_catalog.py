"""Protected source and action joins for native MCP JSON-schema bodies."""
import hashlib
import unittest
from types import MappingProxyType

from hermes_installer.authority.types import canonical_bytes
from hermes_installer.mcp.native_schema_catalog import (
    NativeCandidateIndex,
    NativeMCPProtectedSchemaCatalog,
    NativeSchemaCatalogError,
)


def _thaw(value):
    if hasattr(value, "items"):
        return {key: _thaw(child) for key, child in value.items()}
    if isinstance(value, (tuple, list)):
        return [_thaw(child) for child in value]
    return value


class NativeMCPProtectedSchemaCatalogTests(unittest.TestCase):
    def setUp(self):
        self.schema = {
            "type": "object",
            "properties": {"file_key": {"type": "string", "minLength": 1, "maxLength": 128}},
            "required": ["file_key"],
            "additionalProperties": False,
        }
        self.body = canonical_bytes(self.schema)
        self.digest = hashlib.sha256(self.body).hexdigest()
        self.row = {
            "id": "schema-figma-arguments-v1",
            "artifact_id": "artifact-figma-arguments-v1",
            "sha256": self.digest,
            "schema_kind": "arguments",
            "native_package_id": "native-package-1",
            "native_package_generation": "native-generation-1",
            "adapter_id": "hermes-installer.native-mcp-dispatch.v1",
            "action_id": "mcp-binding-figma-file",
            "source_receipt_handle": "source-receipt-handle-1",
            "size_bytes": len(canonical_bytes(self.schema)),
            "derivation_receipt_handle": None,
        }

    def catalog(self, rows=None, *, body=None, source_ok=True):
        artifacts = {self.row["artifact_id"]: self.body if body is None else body}
        seen = []
        selected_rows = [self.row] if rows is None else rows
        if rows is None and body is not None:
            selected_rows = [dict(self.row, size_bytes=len(body))]

        def read_artifact(artifact_id, expected_digest):
            return artifacts[artifact_id]

        def verify_source(handle, identity):
            seen.append((handle, dict(identity)))
            return source_ok

        catalog = NativeMCPProtectedSchemaCatalog.from_protected_records(
            selected_rows,
            read_artifact=read_artifact,
            verify_source_receipt=verify_source,
        )
        return catalog, seen

    def test_resolves_only_exact_package_action_schema_kind(self):
        catalog, seen = self.catalog()
        schema = catalog.resolve(
            self.row["id"], native_package_id="native-package-1",
            native_package_generation="native-generation-1",
            adapter_id="hermes-installer.native-mcp-dispatch.v1",
            action_id="mcp-binding-figma-file", schema_kind="arguments",
        )
        self.assertEqual(_thaw(schema), self.schema)
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][0], "source-receipt-handle-1")
        with self.assertRaises(NativeSchemaCatalogError):
            catalog.resolve(
                self.row["id"], native_package_id="other-package",
                native_package_generation="native-generation-1",
                adapter_id="hermes-installer.native-mcp-dispatch.v1",
                action_id="mcp-binding-figma-file", schema_kind="arguments",
            )

    def test_requires_current_source_receipt_and_artifact_digest(self):
        with self.assertRaisesRegex(NativeSchemaCatalogError, "source receipt"):
            self.catalog(source_ok=False)
        with self.assertRaisesRegex(NativeSchemaCatalogError, "digest"):
            self.catalog(body=b'{"type":"string"}')

    def test_dynamic_schema_requires_root_derived_resolver_before_any_artifact_read(self):
        row = dict(self.row)
        row.update({
            "artifact_id": f"native-mcp-schema:{self.digest}",
            "derivation_receipt_handle": "derived-receipt-handle-1",
        })
        reads = []
        with self.assertRaisesRegex(NativeSchemaCatalogError, "derived schema resolver"):
            NativeMCPProtectedSchemaCatalog.from_protected_records(
                [row],
                read_artifact=lambda artifact_id, digest: reads.append((artifact_id, digest)) or self.body,
                verify_source_receipt=lambda _handle, _identity: True,
            )
        self.assertEqual(reads, [])

    def test_rejects_noncanonical_duplicate_and_external_reference_schema(self):
        for body in (
            b'{ "type":"string" }',
            b'{"type":"string","type":"object"}',
            canonical_bytes({"$ref": "https://schemas.example/schema.json"}),
        ):
            row = dict(self.row)
            row["sha256"] = hashlib.sha256(body).hexdigest()
            with self.subTest(body=body), self.assertRaises(NativeSchemaCatalogError):
                self.catalog([row], body=body)

    def test_rejects_unsupported_bounds_and_malformed_protected_row(self):
        for schema in (
            {"type": "object", "required": ["absent"], "properties": {}},
            {"type": "string", "pattern": ".*"},
            {"type": "array", "items": {"type": "string"}, "maxItems": -1},
        ):
            body = canonical_bytes(schema)
            row = dict(self.row)
            row["sha256"] = hashlib.sha256(body).hexdigest()
            with self.subTest(schema=schema), self.assertRaises(NativeSchemaCatalogError):
                self.catalog([row], body=body)
        malformed = dict(self.row, extra="untrusted")
        with self.assertRaisesRegex(NativeSchemaCatalogError, "shape"):
            self.catalog([malformed])

    def test_candidate_index_uses_v41_names_and_utf8_argument_digest(self):
        from hermes_installer.mcp.native_dispatch import canonical_json

        argument_schema = {"type": "object", "properties": {"title": {"type": "string", "enum": ["café"]}}}
        digest = hashlib.sha256(canonical_json(argument_schema)).hexdigest()
        result_schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}}
        index = NativeCandidateIndex(
            "native-package-1", "profile-1", "native-generation-1", "a" * 64,
            (MappingProxyType({
                "native_tool_name": "mcp_figma_get_file", "native_server_name": "figma_native",
                "description": "Protected installer action", "adapter_id": "hermes-installer.native-mcp-dispatch.v1",
                "action_id": "mcp-binding-figma-file", "argument_schema": argument_schema,
                "result_schema": result_schema, "native_schema_sha256": digest,
                "observer_enrollment_ids": ("observer-1",),
            }),),
        )
        payload = index.to_bytes()
        self.assertIn('"native_server_name":"figma_native"'.encode(), payload)
        self.assertIn('"café"'.encode("utf-8"), payload)
        self.assertEqual(hashlib.sha256(canonical_json(argument_schema)).hexdigest(), digest)


if __name__ == "__main__":
    unittest.main()
