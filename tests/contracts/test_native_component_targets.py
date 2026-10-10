from pathlib import Path
from types import SimpleNamespace
import hashlib
import time

import pytest

from hermes_installer.authority.native_component_targets import (
    NativeComponentTargetDenied,
    NativeComponentTargetPending,
    RootNativeComponentTargetRegistry,
    _TARGET_SEAL,
    _SOURCE_CONTRACTS,
)


ROOT = Path(__file__).resolve().parents[2]


def test_finite_public_registry_source_contract_matches_held_module_bytes():
    source = (ROOT / "src/hermes_installer/components/public_registries.py").read_bytes()

    mcp = RootNativeComponentTargetRegistry._verify_public_registry_target_source(
        "mcp-registry", source)
    agent37 = RootNativeComponentTargetRegistry._verify_public_registry_target_source(
        "agent37-discovery", source)

    assert mcp == (("registry:modelcontextprotocol", "registry-read",
                    "https://registry.modelcontextprotocol.io"),)
    assert agent37 == (("registry:agent37", "registry-agent37-read",
                       "https://www.agent37.com"),)


def test_public_registry_contract_rejects_broadened_source_catalog():
    source = (ROOT / "src/hermes_installer/components/public_registries.py").read_text()
    broadened = source.replace(
        '    "registry:agent37": "registry-agent37-read",',
        '    "registry:agent37": "registry-agent37-read",\n'
        '    "registry:unreviewed": "registry-read",')

    with pytest.raises(NativeComponentTargetPending) as raised:
        RootNativeComponentTargetRegistry._verify_public_registry_target_source(
            "mcp-registry", broadened.encode())

    assert raised.value.missing_prerequisite_ids == (
        "reviewed-finite-public-registry-source-contract",)


def test_plugin_target_contract_rejects_changed_source_owned_routes():
    source = (ROOT / "src/hermes_installer/components/native_plugins.py").read_text()
    changed = source.replace('service_id="registry:modelcontextprotocol"',
                             'service_id="registry:unreviewed"')

    with pytest.raises(NativeComponentTargetPending):
        RootNativeComponentTargetRegistry._verify_plugin_target_source(
            "mcp-registry", changed.encode())


def test_public_web_contract_is_read_from_exact_source_shape_and_rejects_bounds_drift():
    source = (ROOT / "src/hermes_installer/components/plugin_public_https.py").read_bytes()
    assert hashlib.sha256(source).hexdigest() == (
        "63e4a128f0a48f0bfcbd3c0f6c7313d94f4a3e79f83c2655dde32a339b91ff0d")
    RootNativeComponentTargetRegistry._verify_public_web_contract_source(source)

    changed = source.replace(b"response_bytes_limit <= 2_097_152",
                             b"response_bytes_limit <= 4_194_304")
    with pytest.raises(NativeComponentTargetPending) as raised:
        RootNativeComponentTargetRegistry._verify_public_web_contract_source(changed)
    assert raised.value.missing_prerequisite_ids == ("reviewed-public-web-target-contract",)


def test_target_source_inventory_is_descriptive_and_unconfigured_families_stay_pending():
    assert set(_SOURCE_CONTRACTS) == {
        "agent37-discovery", "mcp-registry", "resource-overlay-store",
    }
    assert all(row.prerequisite_ids for row in _SOURCE_CONTRACTS.values())

    with pytest.raises(NativeComponentTargetPending) as raised:
        object.__new__(RootNativeComponentTargetRegistry).source_contract(
            "unreviewed-component")

    assert raised.value.component_id == "unreviewed-component"
    assert raised.value.missing_prerequisite_ids == ("component-specific-target-adapter",)


def test_current_target_handle_uses_only_its_retained_policy_selection():
    registry = object.__new__(RootNativeComponentTargetRegistry)
    policy = SimpleNamespace(selection_handle="root-policy", expires_monotonic=time.monotonic() + 30)
    target = SimpleNamespace(
        selection_handle="root-target", native_policy_selection_handle="root-policy",
        component_id="mcp-registry", expires_monotonic=time.monotonic() + 30, _seal=_TARGET_SEAL,
    )
    validated = []
    registry._targets = {"root-target": target}
    registry._policy_selections = {"root-policy": policy}
    registry._binding = SimpleNamespace()
    registry._assert_binding_matches_selection = validated.append

    assert registry.resolve_current_target_handle("root-target") is target
    assert validated == [policy, policy]

    with pytest.raises(NativeComponentTargetDenied):
        registry.resolve_current_target_handle("caller-invented-target")
