"""Application runtimes bind only to full installer-owned source generations."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.runtime_source import (
    ComponentRuntimeSourceError,
    bind_component_runtime_source,
)
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


def _source(component_id: str = "ecc") -> VerifiedComponentSource:
    contract = resolve_component_adapter(component_id)
    files = {"LICENSE": b"fixture license\n", "source.py": b"print('reviewed')\n"}
    modes = {name: 0o644 for name in files}
    content = hashlib.sha256()
    for name in sorted(files):
        content.update(name.encode() + b"\0")
        content.update(f"{modes[name]:o}".encode() + b"\0")
        content.update(hashlib.sha256(files[name]).digest())
    tree = _git_tree(files, modes)[0]
    archive_sha = "a" * 64
    provenance = {
        "schema": 1,
        "component_id": component_id,
        "source_identity": contract.source_identity,
        "source_url": contract.selected_source_url,
        "revision": contract.revision,
        "source_selection": contract.source_selection,
        "source_archive_sha256": archive_sha,
        "source_content_sha256": content.hexdigest(),
        "source_tree_sha": tree,
        "declared_license": contract.license,
        "license_files": ["LICENSE"],
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    files["INSTALLER-SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    modes["INSTALLER-SOURCE-PROVENANCE.json"] = 0o644
    return VerifiedComponentSource(
        component_id=component_id,
        source_identity=contract.source_identity or "",
        revision=contract.revision or "",
        files=files,
        file_modes=modes,
        archive_sha256=archive_sha,
        content_sha256=content.hexdigest(),
        source_tree_sha=tree,
        license=contract.license,
        license_files=("LICENSE",),
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )


def _with_store(root: Path, operation):
    owned = OwnedRoot(root)
    owned.ensure()
    with process_lock(owned.path("installer.lock")):
        store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
        return operation(store)


def test_binds_complete_source_to_owned_manifest_and_journal(tmp_path: Path) -> None:
    source = _source()
    generation = _with_store(
        tmp_path / "profile-data",
        lambda store: bind_component_runtime_source(source, store, component_id="ecc"),
    )
    assert generation.verify() == generation.root
    assert generation.root.is_relative_to(tmp_path / "profile-data" / "generations")
    assert (generation.root / "source.py").read_bytes() == b"print('reviewed')\n"


def test_rejects_changed_source_map_and_wrong_selected_component(tmp_path: Path) -> None:
    source = _source()
    changed_files = dict(source.files)
    changed_files["unreviewed.py"] = b"import os\n"
    from dataclasses import replace

    changed_modes = dict(source.file_modes)
    changed_modes["unreviewed.py"] = 0o644
    changed = replace(source, files=changed_files, file_modes=changed_modes)
    with pytest.raises(ComponentRuntimeSourceError, match="tree differs"):
        _with_store(
            tmp_path / "changed",
            lambda store: bind_component_runtime_source(changed, store, component_id="ecc"),
        )
    with pytest.raises(ComponentRuntimeSourceError, match="immutable component pin"):
        _with_store(
            tmp_path / "wrong-component",
            lambda store: bind_component_runtime_source(source, store, component_id="public-apis-public-apis"),
        )


def test_revalidates_generation_after_source_tree_was_bound(tmp_path: Path) -> None:
    source = _source()
    generation = _with_store(
        tmp_path / "tampered",
        lambda store: bind_component_runtime_source(source, store, component_id="ecc"),
    )
    (generation.root / "source.py").chmod(0o600)
    (generation.root / "source.py").write_bytes(b"changed\n")
    with pytest.raises(ComponentRuntimeSourceError, match="ownership/integrity"):
        generation.verify()
