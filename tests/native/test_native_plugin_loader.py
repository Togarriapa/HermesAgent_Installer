from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from hermes_installer.native_plugin_bindings import RootSelectedPluginEffects
from hermes_installer.native_plugin_loader import (
    NativePluginLoadUnavailable,
    SelectedNativeAdapter,
    _manifest,
    _require_private_readonly_mount,
    _verify_closure,
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


def package_fixture(tmp: Path):
    module = b"def register(ctx, runtime_context):\n    runtime_context.seen = ctx\n"
    closure_root = tmp / "closure"
    closure_root.mkdir()
    module_path = closure_root / "fixture_plugin.py"
    module_path.write_bytes(module)
    os.chmod(module_path, 0o444)
    file_row = {
        "relative_path": "fixture_plugin.py",
        "sha256": hashlib.sha256(module).hexdigest(),
        "size_bytes": len(module),
        "mode": 0o444,
    }
    closure_digest = hashlib.sha256(_canonical([file_row])).hexdigest()
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
    manifest = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
        "closure_files": [file_row],
        "adapters": [adapter],
        "dependencies": [],
    }
    manifest_bytes = _canonical(manifest)
    manifest_sha = hashlib.sha256(manifest_bytes).hexdigest()
    resolver_body = {
        "schema": 1,
        "package_id": "native-package-fixture",
        "profile_id": "profile-fixture",
        "generation": "generation-fixture",
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
    resolver = {**resolver_body, "resolver_sha256": hashlib.sha256(_canonical(resolver_body)).hexdigest()}
    selected = RootSelectedPluginEffects(
        AuthorityFixture(resolver, closure_digest, manifest_sha), clock=lambda: 10.0,
    )
    return selected, manifest, manifest_bytes, closure_root, adapter


class NativePluginLoaderTests(unittest.TestCase):
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
            selected, manifest, raw, closure, adapter = package_fixture(tmp)
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
            selected, manifest, raw, closure, _ = package_fixture(tmp)
            parsed = _manifest(raw, selected=selected)
            os.chmod(closure / "fixture_plugin.py", 0o644)
            (closure / "fixture_plugin.py").write_bytes(b"changed")
            with self.assertRaises(NativePluginLoadUnavailable):
                _verify_closure(tmp.resolve(), parsed)

            with tempfile.TemporaryDirectory() as temporary2:
                tmp2 = Path(temporary2)
                selected2, _manifest2, raw2, closure2, _adapter2 = package_fixture(tmp2)
                parsed2 = _manifest(raw2, selected=selected2)
                (closure2 / "unlisted.py").write_text("x = 1\n", encoding="utf-8")
                os.chmod(closure2 / "unlisted.py", 0o444)
                with self.assertRaises(NativePluginLoadUnavailable):
                    _verify_closure(tmp2.resolve(), parsed2)

    def test_manifest_rejects_duplicate_json_keys_unselected_adapters_and_digest_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            selected, _manifest_value, raw, _closure, _adapter = package_fixture(Path(temporary))
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


if __name__ == "__main__":
    unittest.main()
