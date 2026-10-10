"""Root-brokered local overlay operations remain bounded CAS methods."""
from __future__ import annotations

import base64
from pathlib import Path

import pytest

from hermes_installer.authority.local_resource_effects import (
    _invoke_profile_view,
    _validate_json_schema_instance,
)
from hermes_installer.registry.resources_runtime import ResourceOverlayStore, ResourceRuntimeError
from hermes_installer.state import Journal, OwnedRoot


def _profile_view(path: Path):
    owned = OwnedRoot(path)
    owned.ensure()
    return ResourceOverlayStore(owned, Journal(owned.path("state.sqlite3"))).for_profile("selected")


def test_selected_owner_overlay_methods_execute_the_actual_bounded_cas_view(tmp_path):
    view = _profile_view(tmp_path / "overlay")
    encoded = base64.b64encode(b"private native overlay").decode("ascii")

    written = _invoke_profile_view(view, "write", {
        "record_id": "notes-1", "value_base64": encoded,
    })
    assert set(written) == {"record_id", "revision"}
    assert len(written["revision"]) == 64
    _validate_json_schema_instance({
        "type": "object", "required": ["record_id", "revision"],
        "additionalProperties": False,
        "properties": {
            "record_id": {"type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,95}$"},
            "revision": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
        },
    }, written)

    read = _invoke_profile_view(view, "read", {"record_id": "notes-1"})
    assert read == {
        "found": True, "record_id": "notes-1", "value_base64": encoded,
        "revision": written["revision"],
    }
    assert _invoke_profile_view(view, "history", {"record_id": "notes-1"}) == {
        "record_id": "notes-1", "revisions": [written["revision"]],
    }
    deleted = _invoke_profile_view(view, "delete", {
        "record_id": "notes-1", "expected_revision": written["revision"],
    })
    assert set(deleted) == {"record_id", "deleted_revision"}
    assert _invoke_profile_view(view, "read", {"record_id": "notes-1"}) == {
        "found": False, "record_id": "notes-1",
    }


@pytest.mark.parametrize(("method", "args"), [
    ("read", {"record_id": "notes-1", "path": "../../etc/passwd"}),
    ("write", {"record_id": "notes-1", "value_base64": "%%%"}),
    ("write", {"record_id": "notes-1", "value_base64": "YQ==", "expected_revision": "0" * 64}),
    ("delete", {"record_id": "notes-1", "expected_revision": None}),
    ("delete", {"record_id": "notes-1", "expected_revision": "0" * 64}),
])
def test_owner_overlay_rejects_invalid_or_expanded_mutations(tmp_path, method, args):
    view = _profile_view(tmp_path / "overlay")
    with pytest.raises((TypeError, ValueError, ResourceRuntimeError)):
        _invoke_profile_view(view, method, args)
    assert _invoke_profile_view(view, "read", {"record_id": "notes-1"}) == {
        "found": False, "record_id": "notes-1",
    }


def test_root_result_schema_validator_rejects_shape_drift_and_bool_coercion():
    schema = {
        "type": "object", "required": ["found", "record_id"],
        "additionalProperties": False,
        "properties": {"found": {"const": False}, "record_id": {"type": "string"}},
    }
    _validate_json_schema_instance(schema, {"found": False, "record_id": "notes-1"})
    with pytest.raises(ValueError):
        _validate_json_schema_instance(schema, {"found": 0, "record_id": "notes-1"})
    with pytest.raises(ValueError):
        _validate_json_schema_instance(schema, {
            "found": False, "record_id": "notes-1", "unexpected": True,
        })
