"""Small synthetic trees for source-bound portable skill adapter fixtures."""
from __future__ import annotations

from hermes_installer.components.portable_skill_adapters import PINNED_SOURCES
from hermes_installer.components.source_bundle import VerifiedComponentSource


def pinned_fixture(component_id: str, files: dict[str, bytes]) -> VerifiedComponentSource:
    identity, revision = PINNED_SOURCES[component_id]
    return VerifiedComponentSource(
        component_id=component_id,
        source_identity=identity,
        revision=revision,
        files=files,
        file_modes={name: 0o644 for name in files},
        archive_sha256="0" * 64,
        content_sha256="0" * 64,
        source_tree_sha="0" * 40,
        license="fixture-only",
        license_files=(),
        redistribution_license_review_required=True,
    )
