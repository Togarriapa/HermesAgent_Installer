from pathlib import Path

import pytest

from hermes_installer.authority.native_component_targets import (
    NativeComponentTargetPending,
    RootNativeComponentTargetRegistry,
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
