import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from hermes_installer.components.plugin_accounts_adapters import (
    PLUGIN_IMPLEMENTATIONS,
    PluginAccountAdapterUnavailable,
)
from hermes_installer.components.plugin_accounts_schemas import (
    PLUGIN_ACTION_SCHEMAS, PLUGIN_ACCOUNTS_ADAPTER_SHA256,
)
from hermes_installer.components.plugin_effects import StaticPluginActionSchemas


class Effects:
    def __init__(self, *, state="read-complete", result=None):
        self.state = state
        self.result = result or {"full_name": "team/repo", "private": False}
        self.calls = []

    def invoke(self, **kwargs):
        self.calls.append(kwargs)
        return {"schema": 1, "operation_id": "op-1", "state": self.state,
                "result": self.result if self.state in {"committed", "read-complete"} else None,
                "verification_status": "verified" if self.state == "committed" else "not-applicable",
                "resume_action_id": "reconcile-1" if self.state == "ambiguous" else None}


class Registration:
    def __init__(self):
        self.tools = {}

    def register_tool(self, *, name, toolset, schema, handler, **kwargs):
        self.tools[name] = (toolset, schema, handler, kwargs)


def runtime(plugin_id, version, effects):
    return SimpleNamespace(identity=SimpleNamespace(kind="plugins", resource_id=plugin_id, version=version),
                           plugin_effects=effects)


def test_account_schema_catalog_is_exact_and_typed():
    assert set(PLUGIN_ACTION_SCHEMAS) == {
        ("github", "repo.get"), ("github", "issues.list"), ("github", "content.get"),
        ("github", "content.put"), ("github", "issue.create"),
        ("composio", "invoke.read"), ("composio", "invoke.write"), ("codex", "run"),
    }
    assert PLUGIN_ACTION_SCHEMAS[("github", "content.put")].requires_idempotency
    assert PLUGIN_ACTION_SCHEMAS[("composio", "invoke.write")].requires_confirmation
    assert PLUGIN_ACTION_SCHEMAS[("codex", "run")].expected_state == "committed"
    assert len(StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS)._schemas) == 8
    adapter_source = Path(__file__).resolve().parents[2] / "src/hermes_installer/components/plugin_accounts_adapters.py"
    assert hashlib.sha256(adapter_source.read_bytes()).hexdigest() == PLUGIN_ACCOUNTS_ADAPTER_SHA256


def test_github_registers_fixed_read_and_write_tools_through_effect_facade():
    effects, ctx = Effects(), Registration()
    implementation = PLUGIN_IMPLEMENTATIONS["github"]
    implementation.register(ctx, runtime("github", "1.0.1", effects))
    assert set(ctx.tools) == {"github_repository", "github_list_issues", "github_read_file",
                              "github_write_file", "github_create_issue"}
    value = ctx.tools["github_repository"][2]({"repository": "team/repo"})
    assert value["full_name"] == "team/repo"
    assert effects.calls[0]["adapter_id"] == "github"
    assert effects.calls[0]["action_id"] == "repo.get"
    assert effects.calls[0]["idempotency_key"] is None

    writer = ctx.tools["github_write_file"][2]
    effects.state = "ambiguous"
    response = writer({"repository": "team/repo", "path": "README.md", "content": "x", "message": "edit"})
    assert response["state"] == "ambiguous"
    assert effects.calls[-1]["idempotency_key"]


def test_composio_requires_exact_confirm_handle_and_does_not_accept_it_as_action_input():
    effects, ctx = Effects(state="ambiguous"), Registration()
    PLUGIN_IMPLEMENTATIONS["composio"].register(ctx, runtime("composio", "1.0.0", effects))
    read = ctx.tools["composio_read"][2]
    read({"tool_slug": "GITHUB_GET_REPO", "arguments": {"owner": "team"}})
    assert effects.calls[-1]["opaque_confirmation_attestation_id"] is None
    write = ctx.tools["composio_write"][2]
    with pytest.raises(ValueError):
        write({"tool_slug": "GITHUB_CREATE_ISSUE", "arguments": {"title": "x"}})
    write({"tool_slug": "GITHUB_CREATE_ISSUE", "arguments": {"title": "x"},
           "opaque_confirmation_attestation_id": "attest-1234"})
    assert effects.calls[-1]["opaque_confirmation_attestation_id"] == "attest-1234"
    assert effects.calls[-1]["idempotency_key"]


def test_codex_wrapper_only_passes_workspace_and_prompt_and_surfaces_unknown_state():
    effects, ctx = Effects(state="ambiguous"), Registration()
    PLUGIN_IMPLEMENTATIONS["codex"].register(ctx, runtime("codex", "1.0.1", effects))
    result = ctx.tools["codex_run"][2]({"workspace_id": "task-1", "prompt": "run tests"})
    assert result["state"] == "ambiguous"
    assert effects.calls[0]["adapter_id"] == "codex"
    assert effects.calls[0]["action_id"] == "run"
    assert effects.calls[0]["idempotency_key"]
    assert "path" not in effects.calls[0]["arguments"]


@pytest.mark.parametrize("adapter,version", [("github", "1.0.0"), ("composio", "9.9.9"), ("codex", "1.0.0")])
def test_account_wrapper_rejects_mismatched_selected_plugin_identity(adapter, version):
    with pytest.raises(PluginAccountAdapterUnavailable):
        PLUGIN_IMPLEMENTATIONS[adapter].register(Registration(), runtime(adapter, version, Effects()))


def test_missing_root_effect_facade_leaves_account_plugin_unavailable():
    with pytest.raises(PluginAccountAdapterUnavailable):
        PLUGIN_IMPLEMENTATIONS["github"].register(Registration(), runtime("github", "1.0.1", None))
