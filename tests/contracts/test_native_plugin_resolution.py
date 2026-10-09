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
    }
    for adapter_id in expected:
        assert native_plugin_handler_available(adapter_id)
        assert resolve_native_plugin_implementation(adapter_id) is not None


def test_unenrolled_or_unimplemented_plugins_do_not_resolve_handlers():
    expected_unavailable = {
        "codex", "composio", "ebook-toolchain", "github", "kobo-bridge",
    }
    for adapter_id in expected_unavailable:
        assert not native_plugin_handler_available(adapter_id)
        assert resolve_native_plugin_implementation(adapter_id) is None
