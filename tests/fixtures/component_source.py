from __future__ import annotations

import hashlib

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.source import _git_tree


def verified_component_source(component_id: str, files: dict[str, bytes], *, executable: tuple[str, ...] = ()) -> VerifiedComponentSource:
    contract = resolve_component_adapter(component_id)
    modes = {name: 0o755 if name in executable else 0o644 for name in files}
    tree_sha, _ = _git_tree(files, modes)
    content = hashlib.sha256()
    for name in sorted(files):
        content.update(name.encode("utf-8") + b"\0")
        content.update(f"{modes[name]:o}".encode("ascii") + b"\0")
        content.update(hashlib.sha256(files[name]).digest())
    license_files = tuple(sorted(
        name for name in files
        if name.rsplit("/", 1)[-1].casefold().startswith(("license", "copying", "notice"))
    ))
    assert contract.source_identity and contract.revision
    return VerifiedComponentSource(
        component_id=contract.component_id,
        source_identity=contract.source_identity,
        revision=contract.revision,
        files=files,
        file_modes=modes,
        archive_sha256="a" * 64,
        content_sha256=content.hexdigest(),
        source_tree_sha=tree_sha,
        license=contract.license,
        license_files=license_files,
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )
