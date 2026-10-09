"""Pinned Diagram Design skill checks and offline SVG export adapter.

The skill tree is imported and profile-bound by ``skill_binding``. This module
keeps the upstream helper in that immutable tree and invokes it through the
installer's managed component supervisor with network access denied.
"""
from __future__ import annotations

import os
import re
import stat
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlsplit

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.application_handlers import (
    ComponentInvocation,
    ManagedComponentSupervisor,
    RuntimeProfileError,
    _absolute_path,
)
from hermes_installer.components.skill_binding import ComponentSkillBinding
from hermes_installer.components.skill_handlers import SkillAdapterError, discover_component_skills
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.source import _git_tree


_COMPONENT_ID = "diagram-design"
_SOURCE_IDENTITY = "cathrynlavery/diagram-design"
_SOURCE_REVISION = "f4547ee95f88e5b28a52517feff6b6c11cc657f9"
_SKILL_FILE = "skills/diagram-design/SKILL.md"
_EXPORT_HELPER = "skills/diagram-design/scripts/export_svg.py"
_REQUIRED_REFERENCES = (
    "skills/diagram-design/references/export.md",
    "skills/diagram-design/references/output-spec.md",
    "skills/diagram-design/references/style-guide.md",
    "skills/diagram-design/assets/template.html",
)
_MAX_EXPORT_BYTES = 16 * 1024 * 1024
_SVG_NAMESPACE = "http://www.w3.org/2000/svg"


def verify_diagram_design_source(source: VerifiedComponentSource) -> dict[str, object]:
    """Check the pinned skill/helper tree before it is staged into a profile."""
    contract = resolve_component_adapter(_COMPONENT_ID)
    if (contract.source_identity != _SOURCE_IDENTITY or contract.revision != _SOURCE_REVISION
            or contract.selected_source_url != "https://github.com/cathrynlavery/diagram-design"):
        raise RuntimeProfileError("Diagram Design reviewed source pin changed")
    if (source.component_id != _COMPONENT_ID or source.source_identity != _SOURCE_IDENTITY
            or source.revision != _SOURCE_REVISION):
        raise RuntimeProfileError("Diagram Design source does not match the reviewed pinned revision")
    source_files = {
        name: body for name, body in source.files.items()
        if name != "INSTALLER-SOURCE-PROVENANCE.json"
    }
    source_modes = {name: mode for name, mode in source.file_modes.items() if name in source_files}
    try:
        actual_tree, _ = _git_tree(source_files, source_modes)
    except Exception as exc:
        raise RuntimeProfileError(f"Diagram Design source tree is invalid: {exc}") from None
    if actual_tree != source.source_tree_sha:
        raise RuntimeProfileError("Diagram Design files differ from their verified Git tree")
    try:
        discovery = discover_component_skills(_COMPONENT_ID, source.files)
    except (SkillAdapterError, ValueError, KeyError) as exc:
        raise RuntimeProfileError(f"Diagram Design source tree is not importable: {exc}") from None
    selected = [item for item in discovery.skills if item.skill_file == _SKILL_FILE]
    if len(selected) != 1:
        raise RuntimeProfileError("pinned Diagram Design tree must contain exactly one native skill")
    required = {_EXPORT_HELPER, *_REQUIRED_REFERENCES}
    missing = sorted(required - set(source_files))
    if missing:
        raise RuntimeProfileError("Diagram Design source is missing required helper/reference/asset files: "
                                  + ", ".join(missing))
    if any(not isinstance(source_files[path], bytes) or not source_files[path] for path in required):
        raise RuntimeProfileError("Diagram Design helper/reference/asset file is empty or invalid")
    return {
        "source_identity": _SOURCE_IDENTITY,
        "revision": _SOURCE_REVISION,
        "source_tree_sha": actual_tree,
        "skill_file": _SKILL_FILE,
        "helper_file": _EXPORT_HELPER,
        "reference_count": len(selected[0].references),
        "preserved_required_files": tuple(sorted(required)),
        "status": "source_tree_importable; native_discovery_pending",
    }


def _path_under(root: Path, candidate: str, label: str, *, allow_missing: bool) -> Path:
    path = Path(_absolute_path(candidate, label))
    try:
        canonical_root = root.resolve(strict=True)
        if root.is_symlink() or canonical_root != root:
            raise RuntimeProfileError(f"{label} root must be canonical and contain no symlink")
        parent = path.parent.resolve(strict=True)
        if path.is_symlink() or parent != path.parent or not parent.is_relative_to(canonical_root):
            raise RuntimeProfileError(f"{label} must remain inside its managed root")
        if path.exists():
            resolved = path.resolve(strict=True)
            if resolved != path or not resolved.is_relative_to(canonical_root):
                raise RuntimeProfileError(f"{label} must remain inside its managed root")
        elif not allow_missing:
            raise RuntimeProfileError(f"{label} is unavailable")
        return path
    except OSError:
        raise RuntimeProfileError(f"{label} is unavailable") from None


def _private_directory(path: Path, label: str) -> None:
    try:
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_mode & 0o077 or path.resolve(strict=True) != path):
            raise RuntimeProfileError(f"{label} must be a private installer-owned directory")
    except OSError:
        raise RuntimeProfileError(f"{label} is unavailable") from None


def build_diagram_export_invocation(
    binding: ComponentSkillBinding,
    python_executable: str,
    source_html: str,
    output_svg: str,
    work_root: str,
) -> ComponentInvocation:
    """Build the fixed, network-denied invocation for the upstream SVG helper."""
    contract = resolve_component_adapter(_COMPONENT_ID)
    if (binding.component_id != _COMPONENT_ID or binding.source_identity != _SOURCE_IDENTITY
            or binding.revision != _SOURCE_REVISION or binding.redistribution_license_review_required
            != contract.redistribution_license_review_required):
        raise RuntimeProfileError("Diagram Design binding does not match the reviewed pinned source")
    if binding.status != "staged_pending_native_discovery":
        raise RuntimeProfileError("Diagram Design binding is not a staged source generation")
    root = Path(_absolute_path(str(binding.external_dir), "Diagram Design source root"))
    _private_directory(root, "Diagram Design source root")
    helper = _path_under(root, str(root / _EXPORT_HELPER), "Diagram Design export helper", allow_missing=False)
    try:
        info = helper.lstat()
    except OSError:
        raise RuntimeProfileError("Diagram Design export helper is unavailable") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > 512 * 1024:
        raise RuntimeProfileError("Diagram Design export helper is not a bounded regular file")

    work = Path(_absolute_path(work_root, "Diagram Design work root"))
    _private_directory(work, "Diagram Design work root")
    html_path = _path_under(work, source_html, "diagram HTML input", allow_missing=False)
    svg_path = _path_under(work, output_svg, "diagram SVG output", allow_missing=True)
    if html_path == svg_path:
        raise RuntimeProfileError("diagram SVG output cannot replace its HTML source")
    try:
        source_info = html_path.lstat()
    except OSError:
        raise RuntimeProfileError("diagram HTML input is unavailable") from None
    if not stat.S_ISREG(source_info.st_mode) or source_info.st_size > _MAX_EXPORT_BYTES:
        raise RuntimeProfileError("diagram HTML input is not a bounded regular file")

    python = _absolute_path(python_executable, "Python executable")
    return ComponentInvocation(
        component_id=_COMPONENT_ID,
        executable=python,
        argv=(python, str(helper), str(html_path), str(svg_path)),
        cwd=str(work),
        environment=(),
        credential_references=(),
        capability_scopes=("component.diagram-design.read-private-source",
                           "component.diagram-design.write-private-work"),
        sensitivity="PRIVATE",
        network="deny",
        timeout_seconds=60,
        memory_limit_mb=512,
    )


def verify_diagram_export_result(
    result: object,
    output_svg: str,
    work_root: str,
    *,
    expected_text: tuple[str, ...],
) -> dict[str, object]:
    """Validate the helper's exported XML, diagram content, and local assets."""
    if not isinstance(result, Mapping) or result.get("exit_code") != 0:
        raise RuntimeProfileError("Diagram Design SVG export did not exit successfully")
    work = Path(_absolute_path(work_root, "Diagram Design work root"))
    output = _path_under(work, output_svg, "diagram SVG output", allow_missing=False)
    try:
        info = output.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size <= 64
                or info.st_size > _MAX_EXPORT_BYTES or info.st_mode & 0o022):
            raise RuntimeProfileError("Diagram Design output is not a bounded private regular SVG")
        fd = os.open(output, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            opened = os.fstat(fd)
            if opened.st_ino != info.st_ino or opened.st_dev != info.st_dev or opened.st_nlink != 1:
                raise RuntimeProfileError("Diagram Design SVG changed while it was being inspected")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                payload = stream.read(_MAX_EXPORT_BYTES + 1)
        finally:
            os.close(fd)
    except OSError:
        raise RuntimeProfileError("Diagram Design output cannot be safely read") from None
    if len(payload) > _MAX_EXPORT_BYTES:
        raise RuntimeProfileError("Diagram Design SVG exceeds the export size limit")
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeProfileError(f"Diagram Design output is not well-formed SVG XML: {exc}") from None
    if root.tag != f"{{{_SVG_NAMESPACE}}}svg" or not root.attrib.get("viewBox"):
        raise RuntimeProfileError("Diagram Design output lacks an SVG root or viewBox")
    visible_text = " ".join((node.text or "") for node in root.iter())
    missing_text = [value for value in expected_text if not isinstance(value, str) or not value or value not in visible_text]
    if missing_text:
        raise RuntimeProfileError("Diagram Design SVG omitted expected fixture content")

    assets: list[str] = []
    for node in root.iter():
        for key, value in node.attrib.items():
            if key.rsplit("}", 1)[-1] not in {"href", "src"}:
                continue
            parsed = urlsplit(value)
            if parsed.scheme or parsed.netloc or parsed.path.startswith("/") or not parsed.path:
                raise RuntimeProfileError("Diagram Design SVG fixture contains a non-local asset reference")
            relative = PurePosixPath(unquote(parsed.path))
            if ".." in relative.parts or "\\" in parsed.path:
                raise RuntimeProfileError("Diagram Design SVG asset path escapes the export directory")
            asset = output.parent.joinpath(*relative.parts)
            try:
                asset_info = asset.lstat()
                if (asset.is_symlink() or not stat.S_ISREG(asset_info.st_mode)
                        or asset.resolve(strict=True) != asset):
                    raise RuntimeProfileError("Diagram Design SVG asset is not a local regular file")
            except OSError:
                raise RuntimeProfileError(f"Diagram Design SVG asset is missing: {relative.as_posix()}") from None
            assets.append(relative.as_posix())
    if len(set(assets)) != len(assets):
        assets = sorted(set(assets))
    return {"format": "svg+xml", "content_verified": True,
            "resolved_local_assets": tuple(sorted(assets)), "bytes": len(payload),
            "status": "fixture_export_verified; target_acceptance_pending"}


async def run_diagram_export_fixture(
    supervisor: ManagedComponentSupervisor,
    binding: ComponentSkillBinding,
    python_executable: str,
    source_html: str,
    output_svg: str,
    work_root: str,
    *,
    expected_text: tuple[str, ...],
) -> dict[str, object]:
    """Run a bounded local fixture through the injected managed supervisor."""
    invocation = build_diagram_export_invocation(
        binding, python_executable, source_html, output_svg, work_root
    )
    result = await supervisor.invoke(invocation)
    return verify_diagram_export_result(
        result, output_svg, work_root, expected_text=expected_text
    )
