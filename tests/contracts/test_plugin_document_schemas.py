from __future__ import annotations

from hashlib import sha256
from pathlib import Path

import pytest

from hermes_installer.components.plugin_document_schemas import (
    PLUGIN_ACTION_SCHEMAS,
    PLUGIN_DOCUMENT_ADAPTER_SHA256,
    validate_document_action_pins,
)
from hermes_installer.components.plugin_effects import StaticPluginActionSchemas

ROOT = Path(__file__).resolve().parents[2]


def test_document_action_catalog_is_exact_pinned_and_dispatcher_validated() -> None:
    validate_document_action_pins()
    assert set(PLUGIN_ACTION_SCHEMAS) == {
        ("ebook-toolchain", "run"), ("ebook-toolchain", "inspect"),
        ("ebook-toolchain", "validate"), ("kobo-bridge", "read"),
        ("kobo-bridge", "deliver"),
    }
    assert PLUGIN_DOCUMENT_ADAPTER_SHA256 == sha256(
        (ROOT / "src/hermes_installer/components/plugin_documents.py").read_bytes()
    ).hexdigest()
    registry = StaticPluginActionSchemas(PLUGIN_ACTION_SCHEMAS)
    assert registry.resolve("ebook-toolchain", "run").operation == "plugin.ebook-toolchain.run"
    assert registry.resolve("ebook-toolchain", "inspect").operation == "plugin.ebook-toolchain.run"
    assert registry.resolve("ebook-toolchain", "validate").operation == "plugin.ebook-toolchain.run"
    assert registry.resolve("kobo-bridge", "read").operation == "plugin.kobo-bridge.read"
    assert registry.resolve("kobo-bridge", "deliver").operation == "plugin.kobo-bridge.deliver"
    assert registry.resolve("kobo-bridge", "deliver").requires_confirmation
    assert registry.resolve("kobo-bridge", "deliver").requires_idempotency
    assert registry.resolve("ebook-toolchain", "run").requires_idempotency


def test_document_schemas_reject_manifest_drift(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import hermes_installer.components.plugin_document_schemas as schemas

    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    for adapter_id in schemas._MANIFEST_SHA256:
        (plugin_dir / f"{adapter_id}.yaml").write_text("tampered", encoding="utf-8")
    monkeypatch.setattr(schemas, "_PLUGIN_DIR", plugin_dir)
    with pytest.raises(RuntimeError, match="changed"):
        schemas.validate_document_action_pins()


def test_document_action_schemas_are_typed_bounded_and_have_no_path_inputs() -> None:
    for schema in PLUGIN_ACTION_SCHEMAS.values():
        assert schema.adapter_sha256 == PLUGIN_DOCUMENT_ADAPTER_SHA256
        assert schema.request_bytes_limit == 262_144
        assert schema.response_bytes_limit == 2_097_152
        assert schema.deadline_seconds == 30.0
        assert schema.argument_schema["additionalProperties"] is False
        assert all(not key.endswith("path") for key in schema.argument_schema["properties"])
    run = PLUGIN_ACTION_SCHEMAS[("ebook-toolchain", "run")]
    assert run.argument_schema["properties"]["format"]["enum"] == ("epub3", "pdf")
    assert run.argument_schema["properties"]["title"]["maxLength"] == 256
    delivery = PLUGIN_ACTION_SCHEMAS[("kobo-bridge", "deliver")]
    assert delivery.expected_state == "committed"
    assert delivery.result_schema["properties"]["verified"]["enum"] == (True,)
