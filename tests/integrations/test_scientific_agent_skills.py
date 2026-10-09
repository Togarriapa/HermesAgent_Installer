from __future__ import annotations

import importlib.util
import io
import json
import tarfile
import tempfile
from pathlib import Path

import pytest

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.scientific_agent_skills import (
    COMPONENT_ID,
    POLARS_VERSION,
    SOURCE_IDENTITY,
    SOURCE_REVISION,
    ScientificAgentSkillsComponent,
    ScientificSkillError,
    run_polars_fixture,
)
from hermes_installer.components.source_bundle import HttpResponse, VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock


def _polars_skill_files() -> dict[str, bytes]:
    return {
        "skills/polars/SKILL.md": (
            "---\nname: polars\ndescription: local columnar data analysis\nlicense: MIT\n---\n"
            "# Polars\nInstall with `uv pip install \"polars==1.44.2\"`.\n"
            "Read [review](references/review.md) and load `references/data.md`.\n"
        ).encode(),
        "skills/polars/references/review.md": b"# Reviewed examples\nSee [operations](operations.md).\n",
        "skills/polars/references/operations.md": b"# Operations\nGroup and aggregate local fixture data.\n",
        "skills/polars/references/data.md": b"# Fixture data notes\nMeasurements remain synthetic.\n",
    }


def test_pinned_polars_skill_discovers_complete_reference_closure():
    adapter = ScientificAgentSkillsComponent(resolve_component_adapter(COMPONENT_ID))
    selection = adapter.discover(_polars_skill_files())

    assert (selection.source_identity, selection.revision) == (SOURCE_IDENTITY, SOURCE_REVISION)
    assert selection.skill.name == "polars"
    assert selection.source_closure == (
        "skills/polars/SKILL.md",
        "skills/polars/references/data.md",
        "skills/polars/references/operations.md",
        "skills/polars/references/review.md",
    )
    assert selection.environment_name == "scientific-agent-skills/polars"
    assert selection.requirements == (
        f"polars=={POLARS_VERSION}\npolars-runtime-32=={POLARS_VERSION}\n"
    )
    assert selection.readiness == "runtime_pin_available_host_arm64_pending"


def test_missing_transitive_reference_blocks_skill_registration():
    adapter = ScientificAgentSkillsComponent()
    files = _polars_skill_files()
    files.pop("skills/polars/references/operations.md")

    with pytest.raises(ScientificSkillError, match="source is incomplete"):
        adapter.discover(files)


def test_missing_inline_reference_blocks_skill_registration():
    adapter = ScientificAgentSkillsComponent()
    files = _polars_skill_files()
    files.pop("skills/polars/references/data.md")

    with pytest.raises(ScientificSkillError, match="missing a referenced file"):
        adapter.discover(files)


def test_other_skill_content_does_not_claim_a_ready_runtime():
    adapter = ScientificAgentSkillsComponent()
    files = {
        "skills/astropy/SKILL.md": b"---\nname: astropy\ndescription: astronomy\n---\n# Astropy\n"
    }

    selection = adapter.discover(files, skill_name="astropy")

    assert selection.skill.name == "astropy"
    assert selection.environment_name is None
    assert selection.requirements is None
    assert selection.readiness == "skill_content_available_runtime_readiness_required"


def test_large_source_uses_bounded_component_specific_fetch_limits():
    adapter = ScientificAgentSkillsComponent()
    fetcher = adapter.source_fetcher()

    assert fetcher.max_archive_bytes == 320 * 1024 * 1024
    assert fetcher.max_unpacked_bytes == 2 * 1024 * 1024 * 1024
    assert fetcher.max_file_bytes == 64 * 1024 * 1024
    assert fetcher.max_files == 50_000
    assert fetcher.timeout_seconds == 120


def test_fetch_verifies_full_pinned_tree_but_audits_only_selected_skill(monkeypatch):
    files = _polars_skill_files()
    files["skills/rdkit/SKILL.md"] = b"---\nname: rdkit\ndescription: unrelated\n---\n[bad](references/missing.md)\n"
    modes = {name: 0o644 for name in files}
    tree_sha, _ = _git_tree(files, modes)
    monkeypatch.setattr("hermes_installer.components.scientific_agent_skills.SOURCE_TREE_SHA", tree_sha)
    archive_buffer = io.BytesIO()
    archive_root = f"K-Dense-AI-scientific-agent-skills-{SOURCE_REVISION[:7]}"
    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive:
        for name, body in sorted(files.items()):
            info = tarfile.TarInfo(f"{archive_root}/{name}")
            info.mode = modes[name]
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
    commit_body = json.dumps({
        "sha": SOURCE_REVISION,
        "html_url": f"https://github.com/{SOURCE_IDENTITY}/commit/{SOURCE_REVISION}",
        "commit": {"tree": {"sha": tree_sha}},
    }).encode()

    class Transport:
        def get(self, url, *, max_bytes, timeout_seconds):
            if url == f"https://api.github.com/repos/{SOURCE_IDENTITY}/commits/{SOURCE_REVISION}":
                body = commit_body
            elif url == f"https://codeload.github.com/{SOURCE_IDENTITY}/legacy.tar.gz/{SOURCE_REVISION}":
                body = archive_buffer.getvalue()
            else:
                raise AssertionError("source fetcher requested an unexpected URL")
            assert len(body) <= max_bytes
            return HttpResponse(200, url, body)

    adapter = ScientificAgentSkillsComponent()
    source = adapter.fetch_source(adapter.source_fetcher(Transport()))
    selection = adapter.discover(source.files)

    assert source.source_tree_sha == tree_sha
    assert "skills/rdkit/SKILL.md" in source.files
    assert selection.source_closure == (
        "skills/polars/SKILL.md",
        "skills/polars/references/data.md",
        "skills/polars/references/operations.md",
        "skills/polars/references/review.md",
    )


def test_profile_stage_contains_only_selected_pinned_skill_closure(monkeypatch):
    files = _polars_skill_files()
    files["skills/rdkit/SKILL.md"] = b"---\nname: rdkit\ndescription: unrelated\n---\n[bad](references/missing.md)\n"
    modes = {name: 0o644 for name in files}
    tree_sha, _ = _git_tree(files, modes)
    source = VerifiedComponentSource(
        component_id=COMPONENT_ID,
        source_identity=SOURCE_IDENTITY,
        revision=SOURCE_REVISION,
        files=files,
        file_modes=modes,
        archive_sha256="a" * 64,
        content_sha256="b" * 64,
        source_tree_sha=tree_sha,
        license="MIT",
        license_files=(),
        redistribution_license_review_required=False,
    )
    from hermes_installer.components import scientific_agent_skills
    monkeypatch.setattr(scientific_agent_skills, "SOURCE_TREE_SHA", tree_sha)
    with tempfile.TemporaryDirectory() as temporary:
        profile_root = Path(temporary) / "profiles" / "default"
        owned = OwnedRoot(profile_root)
        owned.ensure()
        with process_lock(owned.path("installer.lock")):
            store = GenerationStore(
                owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True,
            )
            binding = ScientificAgentSkillsComponent().stage_for_profile(
                source, store, profile_id="default", profile_data_root=profile_root,
            )

        assert binding.skill_files == ("skills/polars/SKILL.md",)
        assert binding.names == ("polars",)
        assert (binding.external_dir / "skills/polars/SKILL.md").is_file()
        assert not (binding.external_dir / "skills/rdkit/SKILL.md").exists()


@pytest.mark.skipif(importlib.util.find_spec("polars") is None, reason="requires isolated Polars feature environment")
def test_polars_feature_environment_executes_deterministic_grouped_data_fixture():
    result = run_polars_fixture()

    assert result == {
        "skill": "polars",
        "package_version": POLARS_VERSION,
        "groups": [
            {"condition": "control", "mean": 2.0},
            {"condition": "treated", "mean": 5.0},
        ],
    }
