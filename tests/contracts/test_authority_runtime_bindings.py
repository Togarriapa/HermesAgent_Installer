from types import SimpleNamespace

import pytest

from hermes_installer.authority.runtime_bindings import build_root_runtime_bindings
from hermes_installer.protected_enrollment import EnrollmentDenied


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
