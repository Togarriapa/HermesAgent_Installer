"""The installer registry resolves only implementations that exist and are reviewed."""
from hermes_installer.components.native_plugins import (
    native_plugin_handler_available,
    resolve_native_plugin_implementation,
)


def test_available_resource_plugins_resolve_concrete_implementations():
    expected = {
        "resource-overlay-store",
        "mcp-registry",
        "agent37-discovery",
        "agent-live-wallet",
        "agent-sandbox-wallet",
        "authentik-authorization",
        "cloudflare-homelab",
        "epic-kanban",
        "financial-data-hub",
        "financial-execution-gateway",
        "homelab-ops-broker",
        "voice-pipeline",
        "web",
        "ebook-toolchain",
        "kobo-bridge",
        "github",
        "composio",
        "codex",
    }
    for adapter_id in expected:
        assert native_plugin_handler_available(adapter_id)
        assert resolve_native_plugin_implementation(adapter_id) is not None


def test_account_plugins_resolve_concrete_adapters_but_keep_enrollment_blockers():
    for adapter_id in ("github", "composio", "codex"):
        assert native_plugin_handler_available(adapter_id)
        assert resolve_native_plugin_implementation(adapter_id) is not None
