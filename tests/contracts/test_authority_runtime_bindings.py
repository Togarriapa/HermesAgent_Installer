from types import SimpleNamespace

import pytest

from hermes_installer.authority.runtime_bindings import RootRuntimeBindings, build_root_runtime_bindings
from hermes_installer.protected_enrollment import EnrollmentDenied
from hermes_installer.authority.types import AuthorityDenied


def test_root_runtime_composition_fails_closed_without_verified_generation_records():
    enrollment = SimpleNamespace(
        key_id="test-key",
        bindings_by_uid={},
        rules={},
        process_profiles={},
        artifact_staging_directory="/unused",
        native_bridges={},
    )
    with pytest.raises(EnrollmentDenied, match="verified generation"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )


def test_root_runtime_composition_requires_service_records_before_optional_hardware_catalogs():
    enrollment = SimpleNamespace(
        key_id="test-key",
        bindings_by_uid={},
        rules={},
        process_profiles={},
        artifact_staging_directory="/unused",
        native_bridges={},
        service_records=[],
        protected_devices=[],
        protected_build_records=[],
        protected_enrollment_digest="a" * 64,
    )
    with pytest.raises(EnrollmentDenied, match="service generation records"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )


def test_empty_device_and_build_catalogs_fail_only_when_selected():
    from hermes_installer.protected_enrollment import ProtectedBuildCatalog, ProtectedDeviceCatalog

    devices = ProtectedDeviceCatalog.from_protected_records([])
    builds = ProtectedBuildCatalog.from_protected_records([])
    with pytest.raises(EnrollmentDenied, match="stale"):
        devices.resolve("unavailable-device", "device-generation")
    with pytest.raises(EnrollmentDenied, match="stale"):
        builds.resolve("coral-cpython-build:start", "build-generation")


def test_selected_start_join_uses_fixed_recipe_and_effect_target():
    recipe = SimpleNamespace(
        process_start_target="root-fixed-start", enrollment_id="enrollment-a",
        generation="generation-a", profile_id="profile-a", principal_id="principal-a",
        service_uid=1001, service_gid=1001, operation_id="hermes-server-start-v1",
    )
    effect = SimpleNamespace(
        target="root-fixed-start", enrollment_id="enrollment-a", generation="generation-a",
        profile_id="profile-a", principal_id="principal-a", service_uid=1001, service_gid=1001,
    )
    catalog = SimpleNamespace(
        resolve_launch_recipe=lambda *_args: recipe,
        resolve_operation=lambda *_args: effect,
    )
    bindings = RootRuntimeBindings(
        enrollment_catalog=catalog, build_catalog=None, device_catalog=None,
        process_manager=None, effect_handlers={}, native_bridges={}, artifact_catalog=None,
        build_store=None, service_connector=None,
    )
    selected = bindings.resolve_selected_operation(
        "enrollment-a", "generation-a", "process.start", "hermes-server-start-v1",
    )
    assert (selected.operation, selected.operation_id, selected.target) == (
        "process.start", "hermes-server-start-v1", "root-fixed-start")
    assert (selected.profile_id, selected.principal_id, selected.service_uid) == (
        "profile-a", "principal-a", 1001)
    with pytest.raises(EnrollmentDenied, match="only protected process.start"):
        bindings.resolve_selected_operation(
            "enrollment-a", "generation-a", "process.stop", "hermes-server-start-v1",
        )


def test_package_set_manifest_may_be_absent_but_malformed_manifest_still_denies(tmp_path, monkeypatch):
    import os
    from hermes_installer import artifacts
    from hermes_installer.authority.runtime_bindings import _load_optional_package_sets

    manifest = tmp_path / "package-sets.json"
    tmp_path.chmod(0o700)
    monkeypatch.setattr(artifacts, "PACKAGE_SET_MANIFEST_PATH", manifest)
    result = _load_optional_package_sets(
        catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
    )
    assert dict(result) == {}

    manifest.write_text("{}", encoding="utf-8")
    manifest.chmod(0o600)
    with pytest.raises(AuthorityDenied) as caught:
        _load_optional_package_sets(
            catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
        )
    assert caught.value.code == "package-set.catalog"


def test_package_set_manifest_symlink_is_not_treated_as_absent(tmp_path, monkeypatch):
    import os
    from hermes_installer import artifacts
    from hermes_installer.authority.runtime_bindings import _load_optional_package_sets

    tmp_path.chmod(0o700)
    target = tmp_path / "target.json"
    target.write_text('{"schema":1,"package_sets":[]}', encoding="utf-8")
    target.chmod(0o600)
    manifest = tmp_path / "package-sets.json"
    manifest.symlink_to(target)
    monkeypatch.setattr(artifacts, "PACKAGE_SET_MANIFEST_PATH", manifest)
    with pytest.raises(AuthorityDenied):
        _load_optional_package_sets(
            catalog=None, signing_key=b"k" * 32, key_id="test-key", expected_uid=os.getuid(),
        )
