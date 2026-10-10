"""Root-selected, IDs-only Hermes profile MCP metadata writer."""
import hashlib
import os
import tempfile
import unittest
from pathlib import Path

import yaml

from hermes_installer.mcp.broker import ProtectedMCPService
from hermes_installer.mcp.enrolled_transport import ProtectedMCPHTTPBinding
from hermes_installer.mcp.native_config import (
    RootSelectedMCPConfigInputs,
    RootSelectedNativeMCPConfigWriter,
    _SelectedProfileTarget,
)
from hermes_installer.mcp.native_dispatch import (
    HANDLER_ARTIFACT_ID, NativeMCPRegistrationIndex, schema_sha256,
)


class _Credential:
    def headers_for(self, *_args, **_kwargs):
        return {}


class NativeMCPConfigWriterTests(unittest.TestCase):
    def setUp(self):
        schema = {"type": "object", "properties": {"file_key": {"type": "string"}},
                  "required": ["file_key"]}
        self.handler_digest = hashlib.sha256(b"pinned handler").hexdigest()
        row = {
            "id": "binding-figma-file", "profile_id": "selected",
            "process_generation": "worker-gen-1", "native_package_id": "pkg-1",
            "native_package_generation": "pkg-gen-1", "native_server_name": "figma_native",
            "native_tool_name": "mcp_figma_get_file", "native_schema_sha256": schema_sha256(schema),
            "mcp_enrollment_id": "figma", "mcp_generation": "mcp-gen-1",
            "mcp_tool_name": "get_file", "request_schema_id": "request-schema-1",
            "result_schema_id": "result-schema-1", "effect_operation": "mcp.request",
            "effect_target": "mcp:figma:http", "capability": "mcp:figma:read",
            "recipient": None,
            "scope_bindings": [{"argument_field": "file_key", "selected_resource_id": "file-selection-1"}],
            "handler_artifact_id": HANDLER_ARTIFACT_ID,
            "handler_artifact_sha256": self.handler_digest,
        }
        service = ProtectedMCPService(
            service_id="figma", channel="http", allowed_tools=frozenset({"get_file"}),
            transport_binding_id="transport-figma", reviewed_revision="a" * 64,
            selection_arguments={"get_file": ("file_key",)},
        )
        self.index = NativeMCPRegistrationIndex.from_protected_records(
            [row], services={"figma": service},
            mcp_generation_by_enrollment={"figma": "mcp-gen-1"},
            profile_id="selected", process_generation="worker-gen-1",
            native_package_id="pkg-1", native_package_generation="pkg-gen-1",
            handler_artifact_sha256=self.handler_digest,
        )
        self.http = ProtectedMCPHTTPBinding(
            binding_id="transport-figma", service_id="figma", endpoint="https://mcp.figma.com/mcp",
            endpoint_source_id="https://developers.figma.com/docs/figma-mcp-server/remote-server-installation/",
            reviewed_revision="a" * 64, credential_handle=_Credential(),
        )

    def test_ids_only_operation_preserves_foreign_entries_and_keeps_raw_transport_disabled(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            profile = home / "profiles" / "selected"
            profile.mkdir(mode=0o700, parents=True)
            os.chmod(home, 0o700)
            os.chmod(home / "profiles", 0o700)
            os.chmod(profile, 0o700)
            config = profile / "config.yaml"
            config.write_text("model: GLM-5.2\nmcp_servers:\n  personal:\n    url: https://private.example/mcp\n",
                              encoding="utf-8")
            os.chmod(config, 0o600)
            root_selection = RootSelectedMCPConfigInputs(
                enrollment_id="install-1", service_generation_digest="b" * 64,
                profile_id="selected", registration_index=self.index,
                services={"figma": {"id": "figma", "channel": "http",
                    "transport_binding_id": "transport-figma", "reviewed_revision": "a" * 64,
                    "allowed_tools": ("get_file",)}},
                current_mcp_generations={"figma": "mcp-gen-1"},
                http_bindings={"transport-figma": self.http},
            )
            ownership = {}
            writer = RootSelectedNativeMCPConfigWriter._from_root_factory(
                target_for_ids=lambda *_: _SelectedProfileTarget("selected", home, os.geteuid()),
                selection_for_ids=lambda *_: root_selection,
                owners_for_ids=lambda *_: dict(ownership),
                commit_owners=lambda _e, _g, _p, rows, _d: ownership.update(rows),
                expected_owner_uid=os.geteuid(),
            )
            receipt = writer.write_selected_mcp_config("install-1", "b" * 64, "selected")
            self.assertEqual(receipt.status, "materialized_disabled_pending_native_dispatch")
            document = yaml.safe_load(config.read_text(encoding="utf-8"))
            self.assertEqual(document["model"], "GLM-5.2")
            self.assertEqual(document["mcp_servers"]["personal"]["url"], "https://private.example/mcp")
            native_entry = document["mcp_servers"]["figma_native"]
            self.assertFalse(native_entry["enabled"])
            self.assertEqual(native_entry["url"], "https://mcp.figma.com/mcp")
            self.assertEqual(native_entry["tools"]["include"], ["get_file"])
            self.assertNotIn("headers", native_entry)
            self.assertEqual(len(ownership), 1)
            self.assertNotIn("path", receipt.__dataclass_fields__)


if __name__ == "__main__":
    unittest.main()
