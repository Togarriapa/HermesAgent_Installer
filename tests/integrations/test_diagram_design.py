from __future__ import annotations

import asyncio
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from hermes_installer.components.diagram_design import (
    build_diagram_export_invocation,
    run_diagram_export_fixture,
    verify_diagram_design_source,
    verify_diagram_export_result,
)
from hermes_installer.components.skill_binding import ComponentSkillBinding
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.source import _git_tree


_FIXTURE = Path(__file__).parents[1] / "fixtures" / "diagram_design"
_PINNED_HELPER_SHA256 = "3dcf516f8262f6f295b7e8e4b71d923bde8ef6242275182d13343860d6a3b913"
_SOURCE = "cathrynlavery/diagram-design"
_REVISION = "f4547ee95f88e5b28a52517feff6b6c11cc657f9"


def _files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    }


def _verified_source(root: Path) -> VerifiedComponentSource:
    files = _files(root)
    modes = {name: 0o644 for name in files}
    tree_sha, content_sha = _git_tree(files, modes)
    return VerifiedComponentSource(
        component_id="diagram-design",
        source_identity=_SOURCE,
        revision=_REVISION,
        files=files,
        file_modes=modes,
        archive_sha256="a" * 64,
        content_sha256=content_sha,
        source_tree_sha=tree_sha,
        license="MIT",
        license_files=("LICENSE",),
        redistribution_license_review_required=False,
    )


class _LocalManagedSupervisor:
    """Execute only the fixed offline invocation built by the adapter."""

    async def invoke(self, invocation):
        assert invocation.component_id == "diagram-design"
        assert invocation.network == "deny"
        assert not invocation.credential_references
        completed = subprocess.run(
            invocation.argv,
            cwd=invocation.cwd,
            env={"PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1"},
            capture_output=True,
            text=True,
            check=False,
            timeout=invocation.timeout_seconds,
        )
        return {"exit_code": completed.returncode, "stdout": completed.stdout,
                "stderr": completed.stderr}


def _binding(source_root: Path) -> ComponentSkillBinding:
    return ComponentSkillBinding(
        profile_id="fixture-profile",
        component_id="diagram-design",
        source_identity=_SOURCE,
        revision=_REVISION,
        external_dir=source_root,
        skill_files=("skills/diagram-design/SKILL.md",),
        names=("diagram-design",),
        source_sha256="fixture-source-digest",
        redistribution_license_review_required=False,
    )


def _stage_source_fixture(destination: Path) -> Path:
    source_root = destination / "diagram-design-source"
    shutil.copytree(_FIXTURE / "source", source_root)
    for path in sorted(source_root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        if path.is_dir():
            path.chmod(0o700)
        else:
            path.chmod(0o400)
    source_root.chmod(0o700)
    return source_root.resolve()


def _write_render_fixture(work: Path) -> tuple[Path, Path]:
    work.mkdir(mode=0o700)
    asset = work / "diagram-mark.svg"
    asset.write_text(
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8">'
        '<circle cx="4" cy="4" r="3" fill="#c45b42"/></svg>',
        encoding="utf-8",
    )
    html = work / "harmless-diagram.html"
    html.write_text('''<!doctype html>
<html><head><meta charset="utf-8"><title>Fixture page</title>
<style>body { color: #24313a; } .node { fill: #dce9e3; stroke: #24313a; }
.label { fill: #24313a; font-family: sans-serif; }</style></head>
<body><svg role="img" aria-labelledby="fixture-title fixture-desc"
  viewBox="0 0 320 160"><title id="fixture-title">Diagram Design fixture</title>
  <desc id="fixture-desc">A harmless local export with a resolved icon asset.</desc>
  <defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="6" refY="3">
    <path d="M0,0 L0,6 L6,3 z" fill="#24313a"/></marker></defs>
  <rect class="node" x="24" y="35" width="186" height="72" rx="6"/>
  <text class="label" x="38" y="66">Fixture Node</text>
  <text class="label" x="38" y="88">local-asset-ok</text>
  <image href="diagram-mark.svg" x="234" y="50" width="32" height="32"/>
  <path d="M210 71 H230" stroke="#24313a" marker-end="url(#arrow)"/>
</svg></body></html>''', encoding="utf-8")
    return html, work / "harmless-diagram.svg"


def test_pinned_skill_tree_keeps_reference_helper_and_asset_closure() -> None:
    helper = _FIXTURE / "source/skills/diagram-design/scripts/export_svg.py"
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == _PINNED_HELPER_SHA256
    report = verify_diagram_design_source(_verified_source(_FIXTURE / "source"))
    assert report["source_identity"] == _SOURCE
    assert report["revision"] == _REVISION
    assert report["reference_count"] >= 3
    assert "skills/diagram-design/scripts/export_svg.py" in report["preserved_required_files"]
    assert report["status"] == "source_tree_importable; native_discovery_pending"


def test_export_helper_renders_and_exports_svg_with_content_and_resolved_asset(tmp_path: Path) -> None:
    work = tmp_path / "private-work"
    html, output = _write_render_fixture(work)
    binding = _binding(_stage_source_fixture(tmp_path))
    proof = asyncio.run(run_diagram_export_fixture(
        _LocalManagedSupervisor(), binding, sys.executable,
        str(html), str(output), str(work),
        expected_text=("Diagram Design fixture", "Fixture Node", "local-asset-ok"),
    ))
    assert proof["format"] == "svg+xml"
    assert proof["content_verified"] is True
    assert proof["resolved_local_assets"] == ("diagram-mark.svg",)
    assert output.is_file()
    exported = output.read_text(encoding="utf-8")
    assert "harmless-diagram-arrow" in exported
    assert "#harmless-diagram-arrow" in exported
    assert "#harmless-diagram-root .node" in exported


def test_export_invocation_refuses_external_inputs_and_bad_results(tmp_path: Path) -> None:
    work = tmp_path / "private-work"
    html, output = _write_render_fixture(work)
    binding = _binding(_stage_source_fixture(tmp_path))
    with pytest.raises(ValueError, match="inside"):
        build_diagram_export_invocation(
            binding, sys.executable, str(tmp_path / "outside.html"), str(output), str(work)
        )
    with pytest.raises(ValueError, match="exit successfully"):
        verify_diagram_export_result(
            {"exit_code": 2, "stdout": ""}, str(output), str(work),
            expected_text=("Fixture Node",),
        )
    assert html.is_file()
    assert not output.exists()
