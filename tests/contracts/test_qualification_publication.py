from __future__ import annotations

import pytest

from hermes_installer.authority.qualification_publication import (
    RootQualificationOwnedEntry,
    RootQualificationOwnedPublication,
)


def test_qualification_cleanup_manifest_rejects_unsealed_construction() -> None:
    with pytest.raises(TypeError, match="publisher-issued"):
        RootQualificationOwnedPublication(
            "a" * 32, (1, 2), "0" * 64, "k" * 32, "e" * 32, (), None,
        )


@pytest.mark.parametrize("name", ["/etc/passwd", "nested/arbitrary", "selection.json"])
def test_qualification_cleanup_entries_cannot_name_unowned_paths(name: str) -> None:
    with pytest.raises(ValueError, match="fixed namespace"):
        RootQualificationOwnedEntry(name, "file", 1, 2, "0" * 64, 0o600)


def test_qualification_cleanup_directory_has_no_digest() -> None:
    with pytest.raises(ValueError, match="directory cannot carry"):
        RootQualificationOwnedEntry("fixture-policy", "directory", 1, 2,
                                    "0" * 64, 0o700)
