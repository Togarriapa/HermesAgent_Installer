from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

INSTALLER_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(INSTALLER_ROOT / "src"))

from hermes_installer.native_boundary_patch import apply_native_boundary_overlay

HERMES_SOURCE = Path("/tmp/hermes-agent-hi08")


class PinnedHermesPluginManagerTests(unittest.TestCase):
    """Exercise the official PluginManager lifecycle without claiming mount acceptance.

    The adapter and root binding below are controlled fixtures.  The package
    loader's hash/mount checks have their own tests; this one proves that the
    immutable overlay reaches the exact pinned manager's predeclare, discovery,
    PluginContext registration, tool registry and invocation seams.
    """

    def test_real_manager_discovers_and_invokes_only_root_selected_adapter(self):
        if not HERMES_SOURCE.is_dir():
            self.skipTest("exact official Hermes source checkout is not available")
        with tempfile.TemporaryDirectory(prefix="hermes-native-plugin-manager-") as scratch:
            root = Path(scratch)
            overlay = root / "overlay"
            apply_native_boundary_overlay(HERMES_SOURCE, overlay)
            script = r'''
import sys
from pathlib import Path
installer_src, overlay, upstream, home = map(Path, sys.argv[1:])
sys.path[:0] = [str(overlay), str(installer_src), str(upstream)]
import hermes_cli.plugins as plugins
from hermes_cli.plugins import PluginManager
from hermes_installer import native_plugin_loader as loader
from hermes_installer.authority.client import AuthorityClient
from hermes_installer.registry.resources_runtime import (
    NativePluginRuntimeContext, ResourceIdentity, ReviewedPluginAdapterRegistry,
)
assert Path(plugins.__file__).resolve() == (overlay / "hermes_cli/plugins.py").resolve(), plugins.__file__
import hermes_cli.config
assert Path(hermes_cli.config.__file__).resolve().is_relative_to(upstream.resolve()), hermes_cli.config.__file__

class Facade:
    def __init__(self):
        self.calls = []

    def invoke(self, adapter_id, action_id, arguments, **_kwargs):
        from hermes_installer.native_invocations import current_native_invocation_binding
        binding = current_native_invocation_binding()
        if binding is None or binding.adapter_id != adapter_id or binding.action_id != action_id:
            raise PermissionError("no matching root-observed native invocation")
        if (adapter_id, action_id, arguments) != ("native-fixture", "lookup", {"key": "private"}):
            raise PermissionError("selected action mismatch")
        self.calls.append((adapter_id, action_id, dict(arguments)))
        return {"status": "ok", "data": "private"}

class Adapter:
    action_ids = ("lookup",)
    resource_manifest_sha256 = "a" * 64
    def register(self, ctx, runtime_context):
        ctx.register_tool(
            name="installer_native_fixture", toolset="installer-native",
            schema={"type": "object", "properties": {"key": {"type": "string"}}},
            handler=lambda args: runtime_context.plugin_effects.invoke(
                "native-fixture", "lookup", args),
        )

class Package:
    package_id = "package-fixture"
    profile_id = "profile-fixture"
    generation = "generation-fixture"
    compiled_closure_sha256 = "b" * 64
    mount_target = Path("/fixture/root-selected-mount")
    adapter_ids = ("native-fixture",)
    def resolve_adapter(self, adapter_id):
        return Adapter() if adapter_id == "native-fixture" else None
    def manifest_digest_for_adapter(self, adapter_id):
        return "a" * 64 if adapter_id == "native-fixture" else None
    def resolve(self, adapter_id, action_id):
        return object() if (adapter_id, action_id) == ("native-fixture", "lookup") else None

class Authority:
    def begin_native_invocation(self, producer, observed, canonical):
        import hashlib, time
        assert producer == "p" * 40 and observed == "c" * 40
        assert canonical == b'{"key":"private"}'
        return type("Binding", (), {
            "schema": 1, "invocation_handle": "i" * 40,
            "package_id": "package-fixture", "profile_id": "profile-fixture",
            "generation": "generation-fixture", "adapter_id": "native-fixture",
            "action_id": "lookup", "arguments_sha256": hashlib.sha256(canonical).hexdigest(),
            "parent_closure_digest": "b" * 64, "expires_monotonic": time.monotonic() + 30,
            "binding_sha256": "d" * 64,
        })()

authority = Authority()
context = NativePluginRuntimeContext(
    identity=ResourceIdentity("native-fixture", "plugins", "generation-fixture",
                              "root-selected-native-package", "b" * 64, "a" * 64),
    declared_capabilities=("display-only",), authority=authority,
    invocation_contexts=lambda **_kwargs: (), selected_adapters=ReviewedPluginAdapterRegistry(),
    plugin_effects=Facade(),
)
AuthorityClient.for_current_process = classmethod(lambda cls, **_kwargs: authority)
loader.bind_current_native_plugin_package = lambda _authority: Package()
loader._selected_runtime_context_factory = lambda _authority, _package: lambda _adapter: context

manager = PluginManager(scope_key=str(home))
manager._collect_directory_manifests = lambda: []
manager._scan_entry_points = lambda: []
manager.discover_and_load()
plugins._plugin_manager = manager
assert plugins.get_plugin_manager() is manager
assert manager._hermes_installer_native_plugin_keys == frozenset({"native-fixture"})
loaded = manager._plugins.get("native-fixture")
assert loaded is not None and loaded.enabled and loaded.error is None, repr(loaded)
assert loaded.tools_registered == ["installer_native_fixture"], repr(loaded)
from tools.registry import registry
from hermes_installer.native_invocations import (
    NativeInvocationUnavailable, dispatch_observed_tool_call, install_observed_tool_calls,
)
agent = type("Agent", (), {})()
install_observed_tool_calls(agent, {
    "producer_context_handle": "p" * 40,
    "tool_call_bindings": [{
        "observed_call_handle": "c" * 40,
        "provider_tool_call_id": "call-1", "tool_name": "installer_native_fixture",
        "arguments_sha256": __import__("hashlib").sha256(
            __import__("hermes_installer.native_invocations", fromlist=["canonical_tool_arguments"])
            .canonical_tool_arguments({"key": "private"})).hexdigest(),
    }],
})
try:
    result = dispatch_observed_tool_call(
        agent, tool_call_id="call-1", tool_name="installer_native_fixture",
        arguments={"key": "private"},
        execute=lambda: registry.dispatch("installer_native_fixture", {"key": "private"}, scope=manager.scope_key),
    )
except Exception as exc:
    raise AssertionError(f"actual PluginManager dispatch failed: {type(exc).__name__}: {exc!r}") from exc
assert result == '{"data":"private","status":"ok"}', result
denied = registry.dispatch(
    "installer_native_fixture", {"key": "private"}, scope=manager.scope_key,
)
assert isinstance(denied, str) and "no matching root-observed native invocation" in denied, denied
assert context.plugin_effects.calls == [("native-fixture", "lookup", {"key": "private"})]
assert Path(sys.modules["agent"].__file__).resolve() == (overlay / "agent/__init__.py").resolve(), sys.modules["agent"].__file__
'''
            env = dict(os.environ)
            env["HERMES_HOME"] = str(root / "home")
            (root / "home").mkdir()
            completed = subprocess.run(
                [sys.executable, "-c", script, str(INSTALLER_ROOT / "src"),
                 str(overlay), str(HERMES_SOURCE), str(root / "home")],
                env=env, capture_output=True, text=True, timeout=45,
            )
            if completed.returncode and "ModuleNotFoundError" in completed.stderr:
                self.skipTest("pinned Hermes runtime dependencies are not installed in this interpreter")
            self.assertEqual(completed.returncode, 0, completed.stderr[-4000:])


if __name__ == "__main__":
    unittest.main()
