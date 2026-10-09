"""Cohort-level native discovery through the pinned Hermes PluginManager.

The broker, source package, and overlays are controlled fixtures. This proves
that the reviewed component implementations register through Hermes' actual
PluginContext across all preserved IDs; two bounded fixture calls exercise the
local overlay and a synthetic private GitHub read. It is not host acceptance.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import unittest

INSTALLER_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(INSTALLER_ROOT / "src"))

from hermes_installer.native_boundary_patch import apply_native_boundary_overlay

HERMES_SOURCE = Path("/tmp/hermes-agent-hi08")


class AllNativePluginManagerTests(unittest.TestCase):
    def test_all_preserved_plugins_register_and_fixture_calls_use_reviewed_handlers(self):
        if not HERMES_SOURCE.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        with __import__("tempfile").TemporaryDirectory(prefix="hermes-native-all-plugins-") as scratch:
            root = Path(scratch)
            overlay = root / "overlay"
            apply_native_boundary_overlay(HERMES_SOURCE, overlay)
            script = r'''
import hashlib, sys, time
from pathlib import Path
installer_src, overlay, upstream, home = map(Path, sys.argv[1:])
sys.path[:0] = [str(overlay), str(installer_src), str(upstream)]
from hermes_cli.plugins import PluginManager
from hermes_installer import native_plugin_loader as loader
from hermes_installer.authority.client import AuthorityClient
from hermes_installer.components.native_plugins import (
    _PLUGIN_IDS, _PLUGIN_VERSIONS, resolve_native_plugin_implementation,
)
from hermes_installer.components.plugin_effects import component_plugin_action_schema_registry
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext, ResourceIdentity, ReviewedPluginAdapterRegistry,
)
from hermes_installer.registry.source import load_bundled_source

assert len(_PLUGIN_IDS) == 18
schemas = component_plugin_action_schema_registry()
assert len(schemas._schemas) == 61

source_root = installer_src.parent / "resources/vendor/hermes-agent-resources-2.3.1/plugins"
manifests = {key: hashlib.sha256((source_root / f"{key}.yaml").read_bytes()).hexdigest()
             for key in _PLUGIN_IDS}

class FixtureAdapter:
    def __init__(self, adapter_id):
        self.adapter_id = adapter_id
        self.entrypoint = resolve_native_plugin_implementation(adapter_id)
        self.resource_manifest_sha256 = manifests[adapter_id]
        self.action_ids = tuple(sorted(action for (plugin, action) in schemas._schemas if plugin == adapter_id))
    def register(self, ctx, runtime_context):
        self.entrypoint.register(ctx, runtime_context)

class FixturePackage:
    package_id, profile_id, generation = "all-plugin-fixture", "profile-fixture", "generation-fixture"
    compiled_closure_sha256 = "b" * 64
    mount_target = Path("/fixture/root-selected-mount")
    adapter_ids = tuple(_PLUGIN_IDS)
    def resolve_adapter(self, adapter_id):
        return FixtureAdapter(adapter_id) if adapter_id in self.adapter_ids else None
    def manifest_digest_for_adapter(self, adapter_id):
        return manifests.get(adapter_id)
    def resolve(self, adapter_id, action_id):
        row = schemas.resolve(adapter_id, action_id)
        if row is None:
            return None
        return type("Selected", (), {
            "adapter_id": adapter_id, "action_id": action_id,
            "manifest_sha256": manifests[adapter_id], "adapter_sha256": row.adapter_sha256,
            "argument_schema_id": row.argument_schema_id, "result_schema_id": row.result_schema_id,
            "effect_enrollment_id": "fixture-enrollment-0001", "operation": row.operation,
            "capability": f"plugin:{adapter_id}", "target_id": "fixture-target",
            "recipient": None, "generation": self.generation,
        })()

class FixtureOverlay:
    def read(self, record_id):
        return None
    def write(self, record_id, value, expected_revision=None):
        return hashlib.sha256(value).hexdigest()
    def history(self, record_id):
        return ()
    def delete(self, record_id, expected_revision=None):
        return "c" * 64

class FixtureEffects:
    def __init__(self): self.calls = []
    def invoke(self, adapter_id, action_id, arguments, **kwargs):
        self.calls.append((adapter_id, action_id, dict(arguments)))
        # This fixture intentionally supplies only a synthetic private GitHub
        # read used to test wrapper wiring; no credential or network is used.
        if (adapter_id, action_id) != ("github", "repo.get"):
            raise PermissionError("fixture broker has no enrollment for this action")
        return {"schema": 1, "operation_id": "fixture-op-0001", "state": "read-complete",
                "result": {"full_name": arguments["repository"], "private": True,
                           "default_branch": "main", "html_url": "https://github.invalid/repo",
                           "description": "synthetic fixture"},
                "verification_status": "verified", "resume_action_id": None}

class FixtureAuthority:
    def context(self, **kwargs): raise PermissionError("no external effect in this fixture")
    def authorize_effect(self, *args, **kwargs): raise PermissionError("no external effect in this fixture")
    def verify_effect(self, *args, **kwargs): raise PermissionError("no external effect in this fixture")
    def perform_effect(self, *args, **kwargs): raise PermissionError("no external effect in this fixture")

authority = FixtureAuthority()
package = FixturePackage()
loader.bind_current_native_plugin_package = lambda _authority: package
effects = FixtureEffects()
registry_adapters = ReviewedPluginAdapterRegistry()

class ContextFactory:
    def __call__(self, adapter_id):
        identity = ResourceIdentity(adapter_id, "plugins", _PLUGIN_VERSIONS[adapter_id],
                                    f"plugins/{adapter_id}.yaml", "fixture-source", manifests[adapter_id])
        return NativePluginRuntimeContext(
            identity=identity, declared_capabilities=(), authority=authority,
            invocation_contexts=lambda **_kwargs: (), selected_adapters=registry_adapters,
            plugin_effects=effects, local_overlay_store=FixtureOverlay(),
            voice_session_enrollment_id="fixture-voice-enrollment",
        )

loader._selected_runtime_context_factory = lambda _authority, _package: ContextFactory()
AuthorityClient.for_current_process = classmethod(lambda cls, **_kwargs: authority)
manager = PluginManager(scope_key=str(home))
manager._collect_directory_manifests = lambda: []
manager._scan_entry_points = lambda: []
manager.discover_and_load()
loaded = {plugin_id: manager._plugins.get(plugin_id) for plugin_id in _PLUGIN_IDS}
assert all(row is not None and row.enabled and row.error is None for row in loaded.values()), {
    key: None if value is None else (value.enabled, value.error) for key, value in loaded.items()
}
assert all(row.tools_registered for row in loaded.values())
assert len(manager._hermes_installer_native_plugin_keys) == 18

from tools.registry import registry
overlay_read = registry.dispatch("resource_overlay_read", {"record_id": "fixture"}, scope=manager.scope_key)
assert "found" in overlay_read
github = registry.dispatch("github_repository", {"repository": "owner/private"}, scope=manager.scope_key)
assert "private" in github
assert effects.calls == [("github", "repo.get", {"repository": "owner/private"})]
# Real enrollment, account-backed calls, source capture, devices and network
# remain unavailable; the synthetic call is a code-path fixture only.
'''
            env = dict(os.environ)
            env["HERMES_HOME"] = str(root / "home")
            (root / "home").mkdir()
            completed = subprocess.run(
                [sys.executable, "-c", script, str(INSTALLER_ROOT / "src"),
                 str(overlay), str(HERMES_SOURCE), str(root / "home")],
                env=env, capture_output=True, text=True, timeout=60,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr[-5000:])


if __name__ == "__main__":
    unittest.main()
