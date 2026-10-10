from types import MappingProxyType
from types import SimpleNamespace

import pytest

from hermes_installer.protected_enrollment import (
    EnrollmentDenied, NativeCandidateIndexManifestEntry, NativePackageBinding,
)


def _binding():
    return NativePackageBinding(
        "package-a", "profile-a", "generation-a", "source-rev", "a" * 64,
        "closure-a", "b" * 64, "entrypoint-a", "c" * 64,
        "resolver-a", "d" * 64, "root-a", "mount-a", MappingProxyType({}),
        "generation-a", MappingProxyType({}), MappingProxyType({}),
        MappingProxyType({}), MappingProxyType({}), MappingProxyType({}),
    )


def _manifest():
    return {
        "schema": 1, "package_id": "package-a", "profile_id": "profile-a",
        "generation": "generation-a",
        "candidate_index": {
            "artifact_id": "native-candidate-index:package-a:generation-a",
            "relative_path": "catalog/native-candidates.json", "sha256": "e" * 64,
            "size_bytes": 128,
        },
        "closure_files": [{"relative_path": "catalog/native-candidates.json",
                           "sha256": "e" * 64, "size_bytes": 128, "mode": 0o444}],
    }


def test_candidate_index_manifest_pin_is_fixed_and_closure_joined():
    pin = NativeCandidateIndexManifestEntry.from_entrypoint_manifest(_manifest(), _binding())
    assert pin == NativeCandidateIndexManifestEntry(
        "native-candidate-index:package-a:generation-a", "catalog/native-candidates.json",
        "e" * 64, 128,
    )


def test_candidate_index_manifest_without_index_is_pending():
    manifest = _manifest()
    del manifest["candidate_index"]
    assert NativeCandidateIndexManifestEntry.from_entrypoint_manifest(manifest, _binding()) is None


def test_candidate_index_manifest_accepts_root_selected_structural_binding_dto():
    selected = SimpleNamespace(package_id="package-a", profile_id="profile-a",
                               generation="generation-a")
    assert NativeCandidateIndexManifestEntry.from_entrypoint_manifest(_manifest(), selected).artifact_id == (
        "native-candidate-index:package-a:generation-a"
    )


@pytest.mark.parametrize("change", [
    {"relative_path": "../native-candidates.json"},
    {"artifact_id": "native-candidate-index:other:generation-a"},
    {"sha256": "E" * 64},
    {"size_bytes": 2 * 1024 * 1024 + 1},
])
def test_candidate_index_manifest_rejects_unpinned_or_unbounded_member(change):
    manifest = _manifest()
    manifest["candidate_index"].update(change)
    with pytest.raises(EnrollmentDenied):
        NativeCandidateIndexManifestEntry.from_entrypoint_manifest(manifest, _binding())


def test_candidate_index_manifest_requires_exact_closure_member_digest():
    manifest = _manifest()
    manifest["closure_files"][0]["sha256"] = "f" * 64
    with pytest.raises(EnrollmentDenied, match="differs from its closure file"):
        NativeCandidateIndexManifestEntry.from_entrypoint_manifest(manifest, _binding())
