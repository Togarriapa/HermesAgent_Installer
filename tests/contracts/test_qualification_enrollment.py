from __future__ import annotations

import pytest

from hermes_installer.authority import enrollment
from hermes_installer.authority.qualification_enrollment import (
    QualificationEnrollmentUnavailable,
    RootQualificationEnrollment,
    _decode_canonical,
    _parse_artifact_catalog,
    load_qualification_enrollment,
)


def test_fixture_documents_require_canonical_duplicate_free_json() -> None:
    assert _decode_canonical(b'{"a":1,"b":2}', "test") == {"a": 1, "b": 2}
    for document in (
        b'{"a":1, "b":2}',
        b'{"a":1,"a":2}',
        b'{"a":NaN}',
        b'[]',
    ):
        with pytest.raises((ValueError, TypeError)):
            _decode_canonical(document, "test")


def test_fixture_catalog_uses_the_closed_protected_artifact_schema() -> None:
    parsed = _parse_artifact_catalog({"schema": 1, "artifacts": [], "packages": []})
    assert not parsed.artifacts
    assert not parsed.packages
    with pytest.raises(ValueError):
        _parse_artifact_catalog({"schema": 1, "artifacts": [], "packages": [], "source": "/tmp"})


def test_fixture_enrollment_constructor_cannot_be_forged() -> None:
    with pytest.raises(TypeError, match="only be minted by its held loader"):
        RootQualificationEnrollment(
            schema=1,
            publication_receipt_handle="a" * 32,
            fixture_selection_handle="b" * 32,
            authority_root_id="c" * 32,
            fixture_run_id="d" * 32,
            fixture_generation_id="e" * 32,
            policy_sha256="0" * 64,
            catalog_sha256="1" * 64,
            key_id="f" * 32,
            source_recipe_sha256="2" * 64,
            controller_lease_handle="g" * 32,
            issued_monotonic=1.0,
            expires_monotonic=2.0,
            service_generation_digest="3" * 64,
            _protected_enrollment=None,  # type: ignore[arg-type]
            _artifact_catalog=None,  # type: ignore[arg-type]
            _lease=None,  # type: ignore[arg-type]
            _publication_receipt=None,  # type: ignore[arg-type]
            _key_observation=None,  # type: ignore[arg-type]
            _publisher=None,
            _historical_session=None,
        )


def test_fixture_loader_rejects_unsealed_capabilities_before_any_file_access() -> None:
    with pytest.raises(QualificationEnrollmentUnavailable, match="sealed root capabilities"):
        load_qualification_enrollment(None, None, None, None)  # type: ignore[arg-type]


def test_production_authority_loader_remains_fixed_to_production_path() -> None:
    with pytest.raises(ValueError, match="path and owner are fixed"):
        enrollment.load_protected_enrollment(path=__import__("pathlib").Path("/tmp/authority.json"))


def test_fixture_loader_signature_has_no_path_or_document_override() -> None:
    import inspect

    parameters = tuple(inspect.signature(load_qualification_enrollment).parameters)
    assert parameters == ("lease", "publication_receipt", "key_observation", "publisher")
