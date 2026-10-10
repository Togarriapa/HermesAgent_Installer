"""Root-brokered local overlay operations remain bounded CAS methods."""
from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from hermes_installer.authority.local_resource_effects import (
    _invoke_profile_view,
    _validate_json_schema_instance,
)
from hermes_installer.registry.resources_runtime import ResourceOverlayStore, ResourceRuntimeError
from hermes_installer.state import Journal, OwnedRoot
from hermes_installer.authority.bootstrap_runtime_factory import (
    BootstrapEnrollmentPending,
    _open_root_owned_profile_overlay_directory,
)
from hermes_installer.registry.resources_runtime import RootAnchoredProfileOverlayView


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


@pytest.mark.skipif(os.geteuid() != 0, reason="root-owned overlay custody requires a disposable Linux root fixture")
def test_root_anchored_overlay_cas_survives_ancestor_rename_without_following_replacement(tmp_path):
    service_uid = service_gid = 65534
    data_root = tmp_path / "service-data"
    data_root.mkdir(mode=0o700)
    os.chown(data_root, service_uid, service_gid)
    overlays = data_root / "native-profile-overlays"
    overlays.mkdir(mode=0o700)
    service_profile = overlays / "hermes"
    service_profile.mkdir(mode=0o700)
    profile = service_profile / "resources"
    profile.mkdir(mode=0o700)
    marker = profile / ".hermes-installer-owned"
    marker.write_bytes(b"schema=1\n")
    marker.chmod(0o600)

    journal_root = OwnedRoot(tmp_path / "journal")
    journal_root.ensure()
    journal = Journal(journal_root.path("native-profile-overlays.sqlite3"))
    data_fd, view_fd, *_ = _open_root_owned_profile_overlay_directory(
        data_root, service_uid, service_gid, "hermes", "resources")
    try:
        view = RootAnchoredProfileOverlayView(view_fd, "hermes", journal)
        revision = view.write("notes-1", b"kept in selected inode", expected_revision=None)
        assert view.read("notes-1").value == b"kept in selected inode"
        assert view.history("notes-1") == (revision,)

        moved = tmp_path / "moved-overlays"
        os.rename(overlays, moved)
        decoy = tmp_path / "decoy"
        decoy.mkdir(mode=0o700)
        os.symlink(decoy, overlays)

        # A pathname based store would follow this replacement. The retained
        # view FD still names the original root-owned inode and confines writes.
        after_rename = view.write(
            "notes-1", b"still in selected inode", expected_revision=revision)
        assert view.read("notes-1").value == b"still in selected inode"
        assert not (decoy / "hermes" / "resources" / "resource-overlays").exists()
        with pytest.raises(BootstrapEnrollmentPending, match="profile overlay root re-open failed"):
            _open_root_owned_profile_overlay_directory(
                data_root, service_uid, service_gid, "hermes", "resources")

        with pytest.raises(ResourceRuntimeError, match="compare-and-swap"):
            view.write("notes-1", b"stale", expected_revision=revision)
        assert view.read("notes-1").revision == after_rename
        tombstone = view.delete("notes-1", expected_revision=after_rename)
        assert view.read("notes-1") is None
        assert view.history("notes-1") == tuple(sorted((revision, after_rename, tombstone)))
        assert journal.operation("resource-overlay:hermes:notes-1")["status"] == "overlay_tombstoned"
    finally:
        os.close(view_fd)
        os.close(data_fd)
