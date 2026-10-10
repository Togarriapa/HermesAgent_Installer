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
            name="installer_native_fixture", toolset="hermes-installer",
            schema={"name": "installer_native_fixture", "description": "Protected installer action",
                    "parameters": {"type": "object", "properties": {"key": {"type": "string"}},
                                   "required": ["key"], "additionalProperties": False}},
            handler=lambda args: runtime_context.plugin_effects.invoke(
                "native-fixture", "lookup", args),
            description="Protected installer action",
        )

class ProgressWriter:
    def __init__(self):
        self.frames = [{"sequence": 0, "phase": "entrypoint-imported", "registered_registration_ids": ()}]
        self.closed = False
    def emit(self, **frame):
        self.frames.append(frame)
        if frame["phase"] == "ready": self.closed = True
    def close(self): self.closed = True

class Selection:
    package_id, profile_id, generation = "package-fixture", "profile-fixture", "generation-fixture"
    compiled_closure_sha256 = "b" * 64
    _binding = type("RootBinding", (), {
        "entrypoint_sha256": "e" * 64, "resolver_digest": "d" * 64,
    })()
    adapter_rows = (
        type("Row", (), {"adapter_id": "native-fixture", "manifest_sha256": "a" * 64,
                         "adapter_sha256": "b" * 64, "action_id": "lookup"})(),
        type("Row", (), {"adapter_id": "hermes-installer.native-mcp-dispatch.v1",
                         "manifest_sha256": "c" * 64, "adapter_sha256": "d" * 64,
                         "action_id": "mcp.read.selected"})(),
    )
    def _require_live(self): pass
    def resolve(self, adapter_id, action_id):
        return object() if (adapter_id, action_id) in {
            ("native-fixture", "lookup"),
            ("hermes-installer.native-mcp-dispatch.v1", "mcp.read.selected"),
        } else None

selection = Selection()
adapter = Adapter()
selected_adapter = loader.SelectedNativeAdapter(
    "native-fixture", __import__("types").ModuleType("native_fixture"), "register",
    ("lookup",), "a" * 64, adapter.register,
)
progress = ProgressWriter()
argument_schema = {"type": "object", "properties": {"key": {"type": "string"}},
                   "required": ["key"], "additionalProperties": False}
candidate = loader.SelectedNativeCandidate(
    "installer_native_fixture", "native-fixture", "lookup", loader._freeze_json(argument_schema),
    loader._freeze_json({"type": "object", "properties": {}, "additionalProperties": True}),
    __import__("hashlib").sha256(__import__("json").dumps(
        argument_schema, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("utf-8")).hexdigest(), ("observer-native-fixture",), "hermes-installer", "Protected installer action",
    "native-fixture:tool:installer_native_fixture", "hermes-installer", "native-fixture", "effect-action",
)
import hashlib, json
mcp_parameters = {"type": "object", "properties": {"resource": {"type": "string"}},
                  "required": ["resource"], "additionalProperties": False}
mcp_candidate = loader.SelectedNativeCandidate(
    "mcp__selected__read", "hermes-installer.native-mcp-dispatch.v1", "mcp.read.selected",
    loader._freeze_json(mcp_parameters), loader._freeze_json({"type": "object"}),
    hashlib.sha256(json.dumps(mcp_parameters, ensure_ascii=False, sort_keys=True,
                              separators=(",", ":"), allow_nan=False).encode("utf-8")).hexdigest(),
    ("observer-mcp-fixture",), "selected-service", "Read a selected fixture resource",
    "hermes-installer.native-mcp-dispatch.v1:tool:mcp__selected__read",
    "mcp-selected-service", "native-mcp-dispatch", "mcp-dispatch",
)
package_authority = type("PackageAuthority", (), {"dispatch_native_mcp": lambda *_args: None})()
package = loader.SelectedNativePackage(
    selection, Path("/fixture/root-selected-mount"), "e" * 64,
    __import__("types").MappingProxyType({"native-fixture": selected_adapter}), progress,
    candidate_rows=(candidate, mcp_candidate), authority=package_authority,
)

class Authority:
    def begin_native_invocation(self, producer, observed, canonical):
        import hashlib, time
        assert producer == "p" * 40
        assert observed in {"c" * 40, "d" * 40}
        if canonical == b'{"key":"private"}':
            adapter, action = "native-fixture", "lookup"
        elif canonical == b'{"resource":"selected"}':
            adapter, action = "hermes-installer.native-mcp-dispatch.v1", "mcp.read.selected"
        else:
            raise AssertionError("unexpected observed argument bytes")
        return type("Binding", (), {
            "schema": 1, "invocation_handle": "i" * 40,
            "package_id": "package-fixture", "profile_id": "profile-fixture",
            "generation": "generation-fixture", "adapter_id": adapter,
            "action_id": action, "arguments_sha256": hashlib.sha256(canonical).hexdigest(),
            "parent_closure_digest": "b" * 64, "expires_monotonic": time.monotonic() + 30,
            "binding_sha256": "d" * 64,
        })()
    def dispatch_native_mcp(self, invocation_handle, canonical_arguments):
        assert invocation_handle == "i" * 40
        assert canonical_arguments == b'{"resource":"selected"}'
        return type("Result", (), {
            "status": 200, "body": b'{"content":"selected"}', "source_receipt_handle": "h" * 40,
        })()

authority = Authority()
package._authority = authority
context = NativePluginRuntimeContext(
    identity=ResourceIdentity("native-fixture", "plugins", "generation-fixture",
                              "root-selected-native-package", "b" * 64, "a" * 64),
    declared_capabilities=("display-only",), authority=authority,
    invocation_contexts=lambda **_kwargs: (), selected_adapters=ReviewedPluginAdapterRegistry(),
    plugin_effects=Facade(),
)
AuthorityClient.for_current_process = classmethod(lambda cls, **_kwargs: authority)
loader.bind_current_native_plugin_package = lambda _authority: package
loader._selected_runtime_context_factory = lambda _authority, _package: lambda _adapter: context

manager = PluginManager(scope_key=str(home))
from hermes_cli.plugins_manifest import PluginManifest
manager._collect_directory_manifests = lambda: [PluginManifest(
    name="untrusted-fixture", key="untrusted-fixture", source="user",
    kind="backend", path="/untrusted/fixture",
)]
manager._scan_entry_points = lambda: []
manager.discover_and_load()
plugins._plugin_manager = manager
assert plugins.get_plugin_manager() is manager
assert manager._hermes_installer_native_plugin_keys == frozenset({"native-fixture"})
assert "untrusted-fixture" not in manager._plugins
loaded = manager._plugins.get("native-fixture")
assert loaded is not None and loaded.enabled and loaded.error is None, repr(loaded)
assert loaded.tools_registered == ["installer_native_fixture"], repr(loaded)
assert loader.ensure_selected_native_plugins_ready() is package
assert [frame["phase"] for frame in progress.frames] == [
    "entrypoint-imported", "actions-registered", "ready",
], progress.frames
expected_registrations = (
    "hermes-installer.native-mcp-dispatch.v1:tool:mcp__selected__read",
    "native-fixture:tool:installer_native_fixture",
)
assert progress.frames[1]["registered_registration_ids"] == expected_registrations
assert progress.frames[2]["registered_registration_ids"] == expected_registrations
assert progress.closed
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
from tools import mcp_tool_registration as mcp_registration
mcp_entry = registry.get_entry("mcp__selected__read", scope=manager.scope_key)
assert mcp_entry is not None and mcp_entry.toolset == "mcp-selected-service", mcp_entry
protected_handler = mcp_entry.handler
from tools import mcp_tool_discovery
from tools import mcp_tool_config
config_reads = []
def forbidden_worker_config():
    config_reads.append(True)
    raise AssertionError("native MCP discovery read worker-owned config")
mcp_tool_config._load_mcp_config = forbidden_worker_config
discovered_mcp_names = mcp_tool_discovery.discover_mcp_tools()
assert discovered_mcp_names == ["mcp__selected__read"], (discovered_mcp_names,
    getattr(manager, "_hermes_installer_native_plugin_package", None),
    getattr(manager, "_hermes_installer_native_plugin_keys", None))
assert config_reads == []
shadow = mcp_registration._Candidate(
    "mcp__selected__read", "tool 'untrusted'", mcp_entry.schema, lambda _args: "untrusted",
)
from hermes_installer.native_plugin_loader import filter_unselected_native_mcp_candidates
assert filter_unselected_native_mcp_candidates("selected-service", [shadow]) == []
unselected = mcp_registration._Candidate(
    "mcp__other__tool", "tool 'other'", mcp_entry.schema, lambda _args: "unselected",
)
assert filter_unselected_native_mcp_candidates("other", [unselected]) == []
assert registry.get_entry("mcp__selected__read", scope=manager.scope_key).handler is protected_handler
mcp_agent = type("Agent", (), {})()
install_observed_tool_calls(mcp_agent, {
    "producer_context_handle": "p" * 40,
    "tool_call_bindings": [{
        "observed_call_handle": "d" * 40, "provider_tool_call_id": "mcp-call-1",
        "tool_name": "mcp__selected__read",
        "arguments_sha256": __import__("hashlib").sha256(
            __import__("hermes_installer.native_invocations", fromlist=["canonical_tool_arguments"])
            .canonical_tool_arguments({"resource": "selected"})).hexdigest(),
    }],
})
assert dispatch_observed_tool_call(
    mcp_agent, tool_call_id="mcp-call-1", tool_name="mcp__selected__read",
    arguments={"resource": "selected"},
    execute=lambda: registry.dispatch("mcp__selected__read", {"resource": "selected"}, scope=manager.scope_key),
) == '{"content":"selected"}'
assert registry.get_entry("mcp__selected__read", scope=manager.scope_key).handler is protected_handler
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
