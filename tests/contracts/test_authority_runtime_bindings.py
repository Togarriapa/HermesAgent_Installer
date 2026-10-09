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


def test_root_runtime_composition_rejects_missing_coral_device_and_build_records():
    enrollment = SimpleNamespace(
        key_id="test-key",
        bindings_by_uid={},
        rules={},
        process_profiles={},
        artifact_staging_directory="/unused",
        native_bridges={},
        service_records=[{}],
        protected_devices=[],
        protected_build_records=[],
        protected_enrollment_digest="a" * 64,
    )
    with pytest.raises(EnrollmentDenied, match="service and exact Coral device"):
        build_root_runtime_bindings(
            enrollment, vault=None, artifact_catalog=None,
            authorization_check=lambda **_: True,
        )
