from __future__ import annotations

import json

import pytest

from hermes_installer.components.portable_skill_adapters import PortableSkillError
from hermes_installer.components.ui_ux_pro_max import (
    SOURCE_REVISION,
    review_ui_ux_source,
    search_design_data,
)
from portable_skill_fixtures import pinned_fixture


def _source() -> object:
    return pinned_fixture("ui-ux-pro-max", {
        "src/ui-ux-pro-max/scripts/search.py": b"# pinned helper fixture\n",
        "src/ui-ux-pro-max/data/catalog-summary.json": b'{"domains":["style"]}\n',
        "src/ui-ux-pro-max/data/styles.csv": (
            b"Style ID,Style Category,Best For,Accessibility\n"
            b"calm-grid,Editorial grid,Dashboard for reading,Strong contrast\n"
            b"night-market,Neon,Music launch page,Review contrast\n"
        ),
        "cli/package.json": json.dumps({"name": "ui-ux-pro-max-cli"}).encode(),
    })


def test_selected_local_design_search_returns_guidance_and_pinned_provenance():
    source = _source()
    assert review_ui_ux_source(source) == "ui-ux-pro-max-cli"
    result = search_design_data(source, "dashboard accessibility", domain="style")
    assert result.revision == SOURCE_REVISION
    assert result.source_path == "src/ui-ux-pro-max/data/styles.csv"
    assert result.rows[0]["Style ID"] == "calm-grid"
    assert result.rows[0]["Accessibility"] == "Strong contrast"
    assert len(result.source_sha256) == 64


def test_search_denies_unknown_domains_missing_helper_and_wrong_cli_package():
    source = _source()
    with pytest.raises(PortableSkillError, match="domain"):
        search_design_data(source, "dashboard", domain="shell")
    with pytest.raises(PortableSkillError, match="package name"):
        review_ui_ux_source(pinned_fixture("ui-ux-pro-max", {
            **source.files,
            "cli/package.json": b'{"name":"lookalike"}',
        }))
    with pytest.raises(PortableSkillError, match="helper"):
        review_ui_ux_source(pinned_fixture("ui-ux-pro-max", {
            key: value for key, value in source.files.items()
            if key != "src/ui-ux-pro-max/scripts/search.py"
        }))
