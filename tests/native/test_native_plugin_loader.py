from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import time
import types
import unittest
import uuid
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from hermes_installer.native_plugin_bindings import RootSelectedPluginEffects
from hermes_installer.native_plugin_loader import (
    NativePluginLoadUnavailable,
    SelectedNativeAdapter,
    _load_selected_process_roles,
    _manifest,
    _require_protected_import_environment,
    _require_private_readonly_mount,
    _verify_closure,
    bind_current_native_plugin_package,
    selected_mount_target,
)


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


class AuthorityFixture:
    def __init__(self, resolver: dict, closure_digest: str, entrypoint_digest: str, *, expiry: float = 50.0):
        self.resolver = resolver
        self.closure_digest = closure_digest
        self.entrypoint_digest = entrypoint_digest
        self.expiry = expiry

    def bind_selected_native_package(self):
        return {
            "schema": 1,
            "opaque_binding_handle": "opaque_binding_handle_fixture_0001",
            "package_id": "native-package-fixture",
            "profile_id": "profile-fixture",
            "generation": "generation-fixture",
            "resolver_digest": self.resolver["resolver_sha256"],
            "compiled_closure_sha256": self.closure_digest,
            "entrypoint_sha256": self.entrypoint_digest,
            "expires_monotonic": self.expiry,
        }

    def read_native_resolver(self, binding_handle):
        return self.resolver


def package_fixture(tmp: Path, *, expiry: float = 50.0, with_mcp: bool = False,
                    toolset: str = "hermes-installer"):
    module = b"def register(ctx, runtime_context):\n    runtime_context.seen = ctx\n"
    closure_root = tmp / "closure"
    closure_root.mkdir()
    (closure_root / "catalog").mkdir()
    module_path = closure_root / "fixture_plugin.py"
    module_path.write_bytes(module)
    os.chmod(module_path, 0o444)
    role_module = b"PROCESS_ROLE_LOADED = True\n"
    role_path = closure_root / "process_role.py"
    role_path.write_bytes(role_module)
    os.chmod(role_path, 0o444)
    file_row = {
        "relative_path": "fixture_plugin.py",
        "sha256": hashlib.sha256(module).hexdigest(),
        "size_bytes": len(module),
        "mode": 0o444,
    }
    argument_schema = {"type": "object", "properties": {}, "required": [], "additionalProperties": False}
    result_schema = {"type": "object", "properties": {}, "additionalProperties": True}
    candidate = {
        "native_tool_name": "fixture_read",
        "adapter_id": "fixture-plugin",
        "action_id": "fixture.read",
        "argument_schema": argument_schema,
        "result_schema": result_schema,
        "native_schema_sha256": hashlib.sha256(_canonical(argument_schema)).hexdigest(),
        "observer_enrollment_ids": ["observer-fixture"],
        "native_server_name": "hermes-installer",
        "description": "Protected installer action",
        "registration_id": "fixture-plugin:tool:fixture_read",
        "toolset": toolset,
        "family": "fixture-plugin",
        "handler_kind": "effect-action",
    }
    candidates = [candidate]
    registration = {
        "registration_id": candidate["registration_id"],
        "native_tool_name": candidate["native_tool_name"],
        "native_server_name": candidate["native_server_name"],
        "toolset": candidate["toolset"],
        "family": candidate["family"],
        "adapter_id": candidate["adapter_id"],
        "argument_schema_id": "schema.fixture.args",
        "result_schema_id": "schema.fixture.result",
        "native_schema_sha256": candidate["native_schema_sha256"],
        "registration_source_artifact_id": "artifact-fixture-plugin-source",
        "registration_source_sha256": file_row["sha256"],
        "registration_source_receipt_handle": "receipt-fixture-source-0001",
        "handler_kind": candidate["handler_kind"],
        "handler_id": "handler-fixture-read",
        "selector_fields": [],
        "action_bindings": [{
            "selector_values": {}, "action_binding_id": "fixture-plugin:action:fixture.read",
            "argument_projection": [], "workflow_id": None,
        }],
        "observer_enrollment_ids": candidate["observer_enrollment_ids"],
        "generation": "generation-fixture",
    }
    registrations = [registration]
    index = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "resolver_sha256": "0" * 64,
        "candidates": candidates,
        "registration_projection_sha256": hashlib.sha256(_canonical(registrations)).hexdigest(),
        "registrations": registrations,
    }
    # The resolver digest is populated after the resolver preimage below.
    adapter = {
        "adapter_id": "fixture-plugin",
        "relative_module_path": "fixture_plugin.py",
        "module_name": "hermes_fixture_native_plugin",
        "entrypoint_symbol": "register",
        "artifact_sha256": file_row["sha256"],
        "allowed_internal_modules": [],
        "allowed_dependency_artifact_ids": [],
        "action_ids": ["fixture.read"],
    }
    role_record = {
        "role_id": "role.fixture",
        "package_id": "native-package-fixture",
        "native_package_generation": "generation-fixture",
        "profile_id": "profile-fixture",
        "profile_generation": "process-generation-fixture",
        "role_artifact_id": "artifact-fixture-process-role",
        "role_sha256": hashlib.sha256(role_module).hexdigest(),
        "role_source_receipt_handle": "receipt-fixture-process-role-0001",
        "module_name": "hermes_fixture_process_role",
        "closure_member_path": "process_role.py",
        "role_source_revision": "revision-fixture",
        "role_source_tree_sha256": "c" * 64,
        "observer_enrollment_ids": ["observer-fixture"],
        "registration_ids": [candidate["registration_id"]],
        "action_binding_ids": ["fixture-plugin:action:fixture.read"],
        "workflow_ids": [],
    }
    process_role_records = [role_record]
    process_role_digest = hashlib.sha256(_canonical(process_role_records)).hexdigest()
    resolver_body = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "process_role_records_sha256": process_role_digest,
        "adapters": [{
            "adapter_id": "fixture-plugin",
            "manifest_sha256": "a" * 64,
            "adapter_sha256": file_row["sha256"],
            "action_id": "fixture.read",
            "argument_schema_id": "schema.fixture.args",
            "result_schema_id": "schema.fixture.result",
            "effect_enrollment_id": "effect.fixture.read",
            "operation": "plugin.fixture-plugin.read",
            "capability": "plugin:fixture-plugin",
            "target_id": "plugin:fixture-plugin:target-fixture:generation-fixture",
            "recipient": None,
            "generation": "generation-fixture",
        }],
    }
    if with_mcp:
        mcp_schema = {
            "type": "object", "properties": {"resource": {"type": "string"}},
            "required": ["resource"], "additionalProperties": False,
        }
        mcp_action = "mcp.read.fixture"
        candidates.append({
            "native_tool_name": "mcp__fixture__read",
            "adapter_id": "hermes-installer.native-mcp-dispatch.v1",
            "action_id": mcp_action,
            "argument_schema": mcp_schema,
            "result_schema": {"type": "object"},
            "native_schema_sha256": hashlib.sha256(_canonical(mcp_schema)).hexdigest(),
            "observer_enrollment_ids": ["observer-fixture-mcp"],
            "native_server_name": "fixture",
            "description": "Read a protected fixture resource",
            "registration_id": "hermes-installer.native-mcp-dispatch.v1:tool:mcp__fixture__read",
            "toolset": "mcp-fixture",
            "family": "native-mcp-dispatch",
            "handler_kind": "mcp-dispatch",
        })
        registrations.append({
            "registration_id": "hermes-installer.native-mcp-dispatch.v1:tool:mcp__fixture__read",
            "native_tool_name": "mcp__fixture__read", "native_server_name": "fixture",
            "toolset": "mcp-fixture", "family": "native-mcp-dispatch",
            "adapter_id": "hermes-installer.native-mcp-dispatch.v1",
            "argument_schema_id": "schema.fixture.mcp.args",
            "result_schema_id": "schema.fixture.mcp.result",
            "native_schema_sha256": hashlib.sha256(_canonical(mcp_schema)).hexdigest(),
            "registration_source_artifact_id": "artifact-fixture-mcp-source",
            "registration_source_sha256": file_row["sha256"],
            "registration_source_receipt_handle": "receipt-fixture-mcp-0001",
            "handler_kind": "mcp-dispatch", "handler_id": mcp_action,
            "selector_fields": [],
            "action_bindings": [{
                "selector_values": {}, "action_binding_id": None,
                "argument_projection": [{"name": "resource", "source_field": "resource"}],
                "workflow_id": None,
            }],
            "observer_enrollment_ids": ["observer-fixture-mcp"],
            "generation": "generation-fixture",
        })
    resolver = {**resolver_body, "resolver_sha256": hashlib.sha256(_canonical(resolver_body)).hexdigest()}
    index["resolver_sha256"] = resolver["resolver_sha256"]
    index["registration_projection_sha256"] = hashlib.sha256(_canonical(registrations)).hexdigest()
    index_bytes = _canonical(index)
    index_path = closure_root / "catalog" / "native-candidates.json"
    index_path.write_bytes(index_bytes)
    os.chmod(index_path, 0o444)
    index_file_row = {
        "relative_path": "catalog/native-candidates.json",
        "sha256": hashlib.sha256(index_bytes).hexdigest(),
        "size_bytes": len(index_bytes),
        "mode": 0o444,
    }
    role_file_row = {
        "relative_path": "process_role.py",
        "sha256": hashlib.sha256(role_module).hexdigest(),
        "size_bytes": len(role_module),
        "mode": 0o444,
    }
    file_rows = sorted((file_row, index_file_row, role_file_row), key=lambda row: row["relative_path"])
    closure_digest = hashlib.sha256(_canonical(file_rows)).hexdigest()
    manifest = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "closure_files": file_rows,
        "adapters": [adapter],
        "dependencies": [],
        "process_role_records": process_role_records,
        "process_role_records_sha256": process_role_digest,
        "candidate_index": {
            "artifact_id": "native-candidate-index:native-package-fixture:generation-fixture",
            "relative_path": "catalog/native-candidates.json",
            "sha256": index_file_row["sha256"],
            "size_bytes": index_file_row["size_bytes"],
        },
    }
    manifest_bytes = _canonical(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    authority = AuthorityFixture(resolver, closure_digest, manifest_sha, expiry=expiry)
    selected = RootSelectedPluginEffects(authority, clock=lambda: expiry - 1.0)
    return selected, manifest, manifest_bytes, closure_root, adapter, authority


class NativePluginLoaderTests(unittest.TestCase):
    def test_selected_process_role_import_reports_actual_member_identity(self):
        from types import MappingProxyType

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            closure = root / "closure"
            closure.mkdir()
            source = closure / "role_fixture.py"
            body = b"ROLE_LOADED = True\n"
            source.write_bytes(body)
            digest = hashlib.sha256(body).hexdigest()
            module_name = f"hermes_role_fixture_{uuid.uuid4().hex}"
            role = types.SimpleNamespace(
                role_id="role.native.fixture", module_name=module_name,
                closure_member_path="role_fixture.py", role_sha256=digest,
                registration_ids=("native-registration-fixture",),
            )
            selection = types.SimpleNamespace(process_roles=(role,))
            imported = []
            try:
                origins = _load_selected_process_roles(
                    root, MappingProxyType({"role_fixture.py": source}), selection, imported,
                )
                self.assertEqual(imported, [module_name])
                module = sys.modules[module_name]
                self.assertTrue(module.ROLE_LOADED)
                stat_result = source.stat()
                self.assertEqual(origins[0].to_wire(), {
                    "role_id": role.role_id,
                    "module_name": role.module_name,
                    "closure_member_path": role.closure_member_path,
                    "module_file_sha256": digest,
                    "module_file_device": stat_result.st_dev,
                    "module_file_inode": stat_result.st_ino,
                    "module_file_size_bytes": stat_result.st_size,
                })
            finally:
                sys.modules.pop(module_name, None)

    def test_selected_process_role_import_rejects_digest_drift_and_preloaded_module(self):
        from types import MappingProxyType

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(strict=True)
            closure = root / "closure"
            closure.mkdir()
            source = closure / "role_fixture.py"
            source.write_text("ROLE_LOADED = True\n", encoding="utf-8")
            role = types.SimpleNamespace(
                role_id="role.native.fixture", module_name="hermes_role_fixture_drift",
                closure_member_path="role_fixture.py", role_sha256="0" * 64,
                registration_ids=("native-registration-fixture",),
            )
            selection = types.SimpleNamespace(process_roles=(role,))
            with self.assertRaises(NativePluginLoadUnavailable):
                _load_selected_process_roles(
                    root, MappingProxyType({"role_fixture.py": source}), selection, [],
                )
            sys.modules[role.module_name] = types.ModuleType(role.module_name)
            try:
                role.role_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
                with self.assertRaises(NativePluginLoadUnavailable):
                    _load_selected_process_roles(
                        root, MappingProxyType({"role_fixture.py": source}), selection, [],
                    )
            finally:
                sys.modules.pop(role.module_name, None)

    def test_progress_writer_requires_root_named_activation_fd(self):
        from hermes_installer.native_plugin_loader import _NativeLoaderProgressWriter

        selection = types.SimpleNamespace(
            package_id="package-fixture", generation="generation-fixture",
            _binding=types.SimpleNamespace(entrypoint_sha256="e" * 64, resolver_digest="d" * 64),
        )
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(NativePluginLoadUnavailable):
                _NativeLoaderProgressWriter.from_systemd_activation(selection)
        with patch.dict(os.environ, {
            "LISTEN_PID": "1" * 5000, "LISTEN_FDS": "1" * 5000,
            "LISTEN_FDNAMES": "hermes-loader-progress",
        }, clear=True):
            with self.assertRaises(NativePluginLoadUnavailable):
                _NativeLoaderProgressWriter.from_systemd_activation(selection)

    def test_named_progress_fd_challenge_and_three_ordered_frames(self):
        from hermes_installer.native_plugin_loader import (
            _LoadedProcessRoleOrigin, _NativeLoaderProgressWriter,
        )

        role = types.SimpleNamespace(
            role_id="role.fixture", role_sha256="f" * 64,
            module_name="fixture_role", closure_member_path="fixture_role.py",
            profile_generation="process-generation-fixture",
            registration_ids=("adapter:tool:read", "adapter:tool:write"),
        )
        selection = types.SimpleNamespace(
            package_id="package-fixture", generation="generation-fixture",
            _binding=types.SimpleNamespace(entrypoint_sha256="e" * 64, resolver_digest="d" * 64),
            process_roles=(role,),
        )
        saved_fd = None
        try:
            saved_fd = os.dup(3)
        except OSError:
            saved_fd = None
        receiver, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            receiver_fd = os.dup(receiver.fileno())
            receiver.close()
            receiver = socket.socket(fileno=receiver_fd)
            os.dup2(child.fileno(), 3)
            child.close()
            receiver.sendall(b"N" * 43)
            with patch.dict(os.environ, {
                "LISTEN_PID": str(os.getpid()), "LISTEN_FDS": "1",
                "LISTEN_FDNAMES": "hermes-loader-progress",
            }):
                writer = _NativeLoaderProgressWriter.from_systemd_activation(selection)
                origins = (_LoadedProcessRoleOrigin(
                    "role.fixture", "fixture_role", "fixture_role.py", "f" * 64,
                    1, 2, 12,
                ),)
                writer.emit(sequence=0, phase="entrypoint-imported",
                            registered_registration_ids=(), loaded_process_roles=origins)
                registrations = ("adapter:tool:read", "adapter:tool:write")
                writer.emit(sequence=1, phase="actions-registered",
                            registered_registration_ids=registrations, loaded_process_roles=origins)
                writer.emit(sequence=2, phase="ready",
                            registered_registration_ids=registrations, loaded_process_roles=origins)
            self.assertTrue(writer._closed)

            records, payloads = [], []
            for _ in range(3):
                header = receiver.recv(4)
                self.assertEqual(len(header), 4)
                size = struct.unpack("!I", header)[0]
                self.assertGreater(size, 0)
                self.assertLessEqual(size, 65_536)
                payload = bytearray()
                while len(payload) < size:
                    part = receiver.recv(size - len(payload))
                    self.assertTrue(part)
                    payload.extend(part)
                payloads.append(bytes(payload))
                records.append(json.loads(payload.decode("utf-8")))
            self.assertEqual([record["sequence"] for record in records], [0, 1, 2])
            self.assertEqual([record["phase"] for record in records], [
                "entrypoint-imported", "actions-registered", "ready",
            ])
            self.assertEqual(records[0]["registered_registration_ids"], [])
            self.assertEqual(records[1]["registered_registration_ids"], list(registrations))
            self.assertEqual(records[2]["registered_registration_ids"], list(registrations))
            self.assertEqual(records[0]["loaded_process_roles"], [origins[0].to_wire()])
            self.assertEqual(records[1]["loaded_process_roles"], records[0]["loaded_process_roles"])
            self.assertEqual(records[2]["loaded_process_roles"], records[0]["loaded_process_roles"])
            self.assertTrue(all(record["schema"] == 2 for record in records))
            self.assertTrue(all(record["generation"] == "process-generation-fixture" for record in records))
            self.assertTrue(all(record["package_generation"] == "generation-fixture" for record in records))
            self.assertTrue(all(record["launch_nonce"] == "N" * 43 for record in records))
            for record, payload in zip(records, payloads):
                self.assertEqual(payload, json.dumps(
                    record, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"), allow_nan=False,
                ).encode("utf-8"))
        finally:
            receiver.close()
            try:
                os.close(3)
            except OSError:
                pass
            if saved_fd is not None:
                os.dup2(saved_fd, 3)
                os.close(saved_fd)

    def test_mount_target_is_deterministically_bound_to_all_selected_identity_fields(self):
        target = selected_mount_target("package", "profile", "generation", "a" * 64)
        self.assertEqual(str(target), "/run/hermes-installer/native/" + hashlib.sha256(
            b"package\0profile\0generation\0" + b"a" * 64).hexdigest())
        self.assertNotEqual(target, selected_mount_target("package", "profile-other", "generation", "a" * 64))
        with self.assertRaises(NativePluginLoadUnavailable):
            selected_mount_target("../package", "profile", "generation", "a" * 64)

    def test_exact_manifest_and_closure_are_verified_and_importable(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            selected, manifest, raw, closure, adapter, _authority = package_fixture(tmp)
            parsed = _manifest(raw, selected=selected)
            modules = _verify_closure(tmp.resolve(), parsed)
            self.assertEqual(selected.entrypoint_sha256, hashlib.sha256(raw).hexdigest())
            resource_manifest_sha = selected.adapter_rows[0].manifest_sha256
            self.assertEqual(resource_manifest_sha, "a" * 64)
            self.assertNotEqual(selected.entrypoint_sha256,
                                resource_manifest_sha)
            source = modules["fixture_plugin.py"]
            spec = __import__("importlib.util", fromlist=["spec_from_file_location"]).spec_from_file_location(
                "hermes_fixture_native_plugin_test", source,
            )
            module = __import__("importlib.util", fromlist=["module_from_spec"]).module_from_spec(spec)
            spec.loader.exec_module(module)
            loaded = SelectedNativeAdapter("fixture-plugin", module, "register", ("fixture.read",),
                                           "a" * 64, module.register)
            runtime = types.SimpleNamespace()
            marker = object()
            loaded.register(marker, runtime)
            self.assertIs(runtime.seen, marker)
            self.assertEqual(parsed["adapters"][0]["adapter_id"], adapter["adapter_id"])

    def test_native_candidate_index_is_manifest_and_resolver_bound(self):
        from hermes_installer.native_plugin_loader import _parse_native_candidate_index

        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            selected, manifest, _raw, closure, _adapter, _authority = package_fixture(tmp)
            index_bytes = (closure / "catalog" / "native-candidates.json").read_bytes()
            rows = _parse_native_candidate_index(index_bytes, selected=selected,
                                                 manifest=types.MappingProxyType(manifest))
            self.assertEqual([(row.adapter_id, row.action_id) for row in rows],
                             [("fixture-plugin", "fixture.read")])
            self.assertEqual(rows[0].native_tool_name, "fixture_read")
            self.assertEqual(rows[0].toolset, "hermes-installer")
            self.assertEqual(rows[0].registration_id, "fixture-plugin:tool:fixture_read")

            tampered = json.loads(index_bytes)
            tampered["candidates"][0]["native_server_name"] = "caller-selected"
            with self.assertRaises(NativePluginLoadUnavailable):
                _parse_native_candidate_index(_canonical(tampered), selected=selected,
                                              manifest=types.MappingProxyType(manifest))

            tampered = json.loads(index_bytes)
            tampered["registration_projection_sha256"] = "f" * 64
            with self.assertRaises(NativePluginLoadUnavailable):
                _parse_native_candidate_index(_canonical(tampered), selected=selected,
                                              manifest=types.MappingProxyType(manifest))

    def test_candidate_preserves_actual_non_mcp_source_toolset(self):
        from hermes_installer.native_plugin_loader import _parse_native_candidate_index

        with tempfile.TemporaryDirectory() as temporary:
            selected, manifest, _raw, closure, _adapter, _authority = package_fixture(
                Path(temporary), toolset="github",
            )
            rows = _parse_native_candidate_index(
                (closure / "catalog" / "native-candidates.json").read_bytes(),
                selected=selected, manifest=types.MappingProxyType(manifest),
            )
            self.assertEqual(rows[0].toolset, "github")

    def test_fixed_mcp_dispatcher_is_resolver_selected_not_package_module(self):
        from hermes_installer.native_plugin_loader import _parse_native_candidate_index

        with tempfile.TemporaryDirectory() as temporary:
            selected, manifest, raw, closure, _adapter, _authority = package_fixture(
                Path(temporary), with_mcp=True,
            )
            index_bytes = (closure / "catalog" / "native-candidates.json").read_bytes()
            parsed = _manifest(raw, selected=selected)
            self.assertEqual([row["adapter_id"] for row in parsed["adapters"]], ["fixture-plugin"])
            rows = _parse_native_candidate_index(
                (closure / "catalog" / "native-candidates.json").read_bytes(),
                selected=selected, manifest=types.MappingProxyType(manifest),
            )
            self.assertEqual(
                {(row.adapter_id, row.action_id) for row in rows},
                {("fixture-plugin", "fixture.read"),
                 ("hermes-installer.native-mcp-dispatch.v1", "mcp.read.fixture")},
            )
            self.assertTrue(next(row for row in rows if row.is_native_mcp).is_native_mcp)

            tampered = json.loads(index_bytes)
            tampered["candidates"][0]["argument_schema"]["$ref"] = "file:///etc/passwd"
            tampered["candidates"][0]["native_schema_sha256"] = hashlib.sha256(
                _canonical(tampered["candidates"][0]["argument_schema"])).hexdigest()
            with self.assertRaises(NativePluginLoadUnavailable):
                _parse_native_candidate_index(_canonical(tampered), selected=selected,
                                              manifest=types.MappingProxyType(manifest))

            duplicate_key_document = index_bytes.replace(b'"schema":1', b'"schema":1,"schema":1')
            with self.assertRaises(NativePluginLoadUnavailable):
                _parse_native_candidate_index(duplicate_key_document, selected=selected,
                                              manifest=types.MappingProxyType(manifest))
            self.assertTrue(closure.is_dir())

    def test_mount_flags_must_be_readonly_nonexec_private_and_nosuid_nodev(self):
        target = Path("/run/hermes-installer/native/" + "a" * 64)
        mount = f"1 0 0:1 / {target} ro,nosuid,nodev,noexec - tmpfs tmpfs ro,nosuid,nodev,noexec\n"
        _require_private_readonly_mount(target, mount)
        for bad in (
            mount.replace("ro,nosuid", "rw,nosuid"),
            mount.replace("noexec", "exec"),
            mount.replace(" - tmpfs", " shared:1 - tmpfs"),
        ):
            with self.subTest(mount=bad), self.assertRaises(NativePluginLoadUnavailable):
                _require_private_readonly_mount(target, bad)

    def test_closure_digest_detects_changed_or_extra_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            selected, manifest, raw, closure, _, _authority = package_fixture(tmp)
            parsed = _manifest(raw, selected=selected)
            os.chmod(closure / "fixture_plugin.py", 0o644)
            (closure / "fixture_plugin.py").write_bytes(b"changed")
            with self.assertRaises(NativePluginLoadUnavailable):
                _verify_closure(tmp.resolve(), parsed)

            with tempfile.TemporaryDirectory() as temporary2:
                tmp2 = Path(temporary2)
                selected2, _manifest2, raw2, closure2, _adapter2, _authority2 = package_fixture(tmp2)
                parsed2 = _manifest(raw2, selected=selected2)
                (closure2 / "unlisted.py").write_text("x = 1\n", encoding="utf-8")
                os.chmod(closure2 / "unlisted.py", 0o444)
                with self.assertRaises(NativePluginLoadUnavailable):
                    _verify_closure(tmp2.resolve(), parsed2)

    def test_manifest_rejects_duplicate_json_keys_unselected_adapters_and_digest_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            selected, _manifest_value, raw, _closure, _adapter, _authority = package_fixture(Path(temporary))
            duplicate = b'{"schema":1,"schema":1}'
            with self.assertRaises(NativePluginLoadUnavailable):
                _manifest(duplicate, selected=selected)
            tampered = raw.replace(b"fixture-plugin", b"forged-plugin")
            with self.assertRaises(NativePluginLoadUnavailable):
                _manifest(tampered, selected=selected)

    def test_entrypoint_requires_explicit_trusted_runtime_argument(self):
        module = types.ModuleType("wrong_native_fixture")
        module.register = lambda ctx: ctx
        loaded = SelectedNativeAdapter("fixture-plugin", module, "register", (), "a" * 64, module.register)
        with self.assertRaises(NativePluginLoadUnavailable):
            loaded.register(object(), object())

    def test_bound_loader_checks_mount_resolver_role_origins_and_exposes_selected_package(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            selected, manifest, raw_manifest, closure_source, _adapter, authority = package_fixture(
                tmp, expiry=time.monotonic() + 30.0)
            resolver_body = {key: value for key, value in authority.resolver.items()
                             if key != "resolver_sha256"}
            resolver_bytes = _canonical(resolver_body)
            target = tmp.resolve() / "mount"
            (target / "closure").mkdir(parents=True)
            (target / "resolver").mkdir()
            (target / "manifest.json").write_bytes(raw_manifest)
            for member in ("fixture_plugin.py", "process_role.py"):
                (target / "closure" / member).write_bytes(
                    (closure_source / member).read_bytes())
                os.chmod(target / "closure" / member, 0o444)
            (target / "closure" / "catalog").mkdir()
            (target / "closure" / "catalog" / "native-candidates.json").write_bytes(
                (closure_source / "catalog" / "native-candidates.json").read_bytes())
            os.chmod(target / "closure" / "catalog" / "native-candidates.json", 0o444)
            (target / "resolver" / "resolver").write_bytes(resolver_bytes)
            os.chmod(target / "manifest.json", 0o444)
            os.chmod(target / "resolver" / "resolver", 0o444)

            from hermes_installer import native_plugin_loader
            original_read_text = Path.read_text

            class ProgressFixture:
                def __init__(self): self.frames, self.closed = [], False
                def emit(self, **frame): self.frames.append(frame)
                def close(self): self.closed = True

            progress = ProgressFixture()

            def read_text(path, *args, **kwargs):
                if path == Path("/proc/self/mountinfo"):
                    return f"1 0 0:1 / {target} ro,nosuid,nodev,noexec - tmpfs tmpfs ro,nosuid,nodev,noexec\n"
                return original_read_text(path, *args, **kwargs)

            with patch.object(native_plugin_loader, "selected_mount_target", return_value=target), \
                    patch.object(native_plugin_loader, "_require_protected_import_environment"), \
                    patch.object(native_plugin_loader._NativeLoaderProgressWriter,
                                 "from_systemd_activation", return_value=progress), \
                    patch.object(Path, "read_text", read_text):
                package = bind_current_native_plugin_package(authority)
            try:
                self.assertEqual(package.adapter_ids, ("fixture-plugin",))
                self.assertEqual(package.manifest_digest_for_adapter("fixture-plugin"), "a" * 64)
                self.assertIsNotNone(package.resolve("fixture-plugin", "fixture.read"))
                self.assertIsNotNone(package.resolve_adapter("fixture-plugin"))
                self.assertEqual([row.native_tool_name for row in package.candidate_rows], ["fixture_read"])
                self.assertEqual(package.candidate_rows[0].native_server_name, "hermes-installer")
                self.assertEqual([frame["phase"] for frame in progress.frames], ["entrypoint-imported"])
                self.assertEqual(progress.frames[0]["registered_registration_ids"], ())
                self.assertEqual(progress.frames[0]["loaded_process_roles"][0].module_name,
                                 "hermes_fixture_process_role")
            finally:
                package._progress_writer.close()
                sys.modules.pop("hermes_fixture_native_plugin", None)
                sys.modules.pop("hermes_fixture_process_role", None)

    def test_bound_loader_rejects_mounted_resolver_digest_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            tmp = Path(temporary)
            _selected, _manifest, raw_manifest, closure_source, _adapter, authority = package_fixture(
                tmp, expiry=time.monotonic() + 30.0)
            resolver_body = {key: value for key, value in authority.resolver.items()
                             if key != "resolver_sha256"}
            resolver_bytes = _canonical(resolver_body) + b" "
            target = tmp.resolve() / "mount"
            (target / "closure").mkdir(parents=True)
            (target / "resolver").mkdir()
            (target / "manifest.json").write_bytes(raw_manifest)
            (target / "closure" / "fixture_plugin.py").write_bytes(
                (closure_source / "fixture_plugin.py").read_bytes())
            (target / "closure" / "catalog").mkdir()
            (target / "closure" / "catalog" / "native-candidates.json").write_bytes(
                (closure_source / "catalog" / "native-candidates.json").read_bytes())
            (target / "resolver" / "resolver").write_bytes(resolver_bytes)
            for path in (target / "manifest.json", target / "closure" / "fixture_plugin.py",
                         target / "closure" / "catalog" / "native-candidates.json",
                         target / "resolver" / "resolver"):
                os.chmod(path, 0o444)
            from hermes_installer import native_plugin_loader
            original_read_text = Path.read_text

            def read_text(path, *args, **kwargs):
                if path == Path("/proc/self/mountinfo"):
                    return f"1 0 0:1 / {target} ro,nosuid,nodev,noexec - tmpfs tmpfs ro,nosuid,nodev,noexec\n"
                return original_read_text(path, *args, **kwargs)

            with patch.object(native_plugin_loader, "selected_mount_target", return_value=target), \
                    patch.object(native_plugin_loader, "_require_protected_import_environment"), \
                    patch.object(Path, "read_text", read_text):
                with self.assertRaises(NativePluginLoadUnavailable):
                    bind_current_native_plugin_package(authority)

    def test_import_environment_rejects_path_overrides_and_user_site(self):
        import hermes_installer.native_plugin_loader as loader
        with patch.dict(os.environ, {"PYTHONPATH": "/tmp/untrusted"}):
            with self.assertRaises(NativePluginLoadUnavailable):
                _require_protected_import_environment()
        with patch.object(loader, "sys", types.SimpleNamespace(flags=types.SimpleNamespace(no_user_site=0))), \
                patch.object(loader.site, "ENABLE_USER_SITE", True), \
                patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(NativePluginLoadUnavailable):
                _require_protected_import_environment()


if __name__ == "__main__":
    unittest.main()
