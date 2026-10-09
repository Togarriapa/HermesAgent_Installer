"""Bind application runtimes to complete, journal-owned source generations."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.source import _git_tree


class ComponentRuntimeSourceError(ValueError):
    """A runtime source is not the selected immutable installer generation."""


@dataclass(frozen=True, slots=True)
class VerifiedComponentGeneration:
    """A complete selected source tree verified against its installer journal."""

    component_id: str
    source_identity: str
    revision: str
    source_tree_sha: str
    root: Path
    generation_digest: str
    _store: Any

    def verify(self) -> Path:
        """Recheck manifest, ownership ledger, path and generation digest on use."""
        try:
            root, _manifest, digest = self._store._verify(
                f"component-{self.component_id}-{self.revision[:12]}"
            )
            expected_parent = self._store.root.resolve(strict=True)
            actual = root.resolve(strict=True)
        except Exception as exc:
            raise ComponentRuntimeSourceError(
                "component runtime generation failed its ownership/integrity check"
            ) from exc
        if (actual != self.root or actual.is_symlink()
                or not actual.is_relative_to(expected_parent)
                or digest != self.generation_digest):
            raise ComponentRuntimeSourceError(
                "component runtime generation identity or digest changed"
            )
        return actual


def bind_component_runtime_source(
    source: VerifiedComponentSource, store: object, *, component_id: str,
) -> VerifiedComponentGeneration:
    """Verify the entire source bundle and journal-owned generation before execution.

    The operation must run under the installer's source-mutation lock. The
    selected source bundle is checked against its full git tree and provenance;
    the staged generation is then checked against the bundle and ownership
    journal. Critical-file hash checks alone are intentionally insufficient.
    """
    if not isinstance(source, VerifiedComponentSource):
        raise ComponentRuntimeSourceError("runtime installation requires a verified pinned source bundle")
    contract = resolve_component_adapter(component_id)
    if (contract.unresolved_reason()
            or source.component_id != component_id
            or source.source_identity != contract.source_identity
            or source.revision != contract.revision):
        raise ComponentRuntimeSourceError("runtime source differs from the selected immutable component pin")
    if (source.license != contract.license
            or type(source.redistribution_license_review_required) is not bool
            or source.redistribution_license_review_required != contract.redistribution_license_review_required):
        raise ComponentRuntimeSourceError("runtime source license state differs from the selected source contract")
    if not isinstance(source.archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", source.archive_sha256):
        raise ComponentRuntimeSourceError("runtime source archive digest is invalid")

    upstream_files = {
        name: body for name, body in source.files.items()
        if name != "INSTALLER-SOURCE-PROVENANCE.json"
    }
    upstream_modes = {
        name: mode for name, mode in source.file_modes.items()
        if name in upstream_files
    }
    if set(upstream_modes) != set(upstream_files):
        raise ComponentRuntimeSourceError("runtime source modes are incomplete")
    content = hashlib.sha256()
    for name in sorted(upstream_files):
        body, mode = upstream_files[name], upstream_modes[name]
        if not isinstance(body, bytes) or type(mode) is not int:
            raise ComponentRuntimeSourceError("runtime source file metadata is invalid")
        content.update(name.encode("utf-8") + b"\0")
        content.update(f"{mode:o}".encode("ascii") + b"\0")
        content.update(hashlib.sha256(body).digest())
    try:
        tree_sha, _ = _git_tree(upstream_files, upstream_modes)
    except Exception as exc:
        raise ComponentRuntimeSourceError("runtime source tree is invalid") from exc
    if tree_sha != source.source_tree_sha or content.hexdigest() != source.content_sha256:
        raise ComponentRuntimeSourceError("runtime source tree differs from its immutable pin evidence")

    provenance_bytes = source.files.get("INSTALLER-SOURCE-PROVENANCE.json")
    try:
        provenance = json.loads(provenance_bytes.decode("utf-8")) if isinstance(provenance_bytes, bytes) else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        provenance = None
    license_files = tuple(sorted(
        name for name in upstream_files
        if Path(name).name.casefold().startswith(("license", "copying", "notice"))
    ))
    expected_provenance = {
        "schema": 1,
        "component_id": source.component_id,
        "source_identity": source.source_identity,
        "source_url": contract.selected_source_url,
        "revision": source.revision,
        "source_selection": contract.source_selection,
        "source_archive_sha256": source.archive_sha256,
        "source_content_sha256": source.content_sha256,
        "source_tree_sha": source.source_tree_sha,
        "declared_license": contract.license,
        "license_files": list(license_files),
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    if source.license_files != license_files or provenance != expected_provenance:
        raise ComponentRuntimeSourceError("runtime source provenance differs from its selected immutable contract")

    try:
        root = source.stage(store).resolve(strict=True)
        actual_root, manifest, digest = store._verify(source.generation_id)
        if actual_root.resolve(strict=True) != root or not root.is_relative_to(store.root.resolve(strict=True)):
            raise ComponentRuntimeSourceError("staged component generation escaped installer-owned storage")
        compiled_files, compiled_modes = source.compiled_files()
        expected_manifest = {
            name: {
                "sha256": hashlib.sha256(body).hexdigest(),
                "mode": store._private_mode(compiled_modes[name]),
            }
            for name, body in compiled_files.items()
        }
        if manifest.get("files") != expected_manifest:
            raise ComponentRuntimeSourceError("staged component generation differs from the verified source bundle")
    except ComponentRuntimeSourceError:
        raise
    except Exception as exc:
        raise ComponentRuntimeSourceError("component source could not be bound to its installer generation") from exc
    return VerifiedComponentGeneration(
        component_id=component_id,
        source_identity=source.source_identity,
        revision=source.revision,
        source_tree_sha=source.source_tree_sha,
        root=root,
        generation_digest=digest,
        _store=store,
    )
