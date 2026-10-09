"""Functional fixture against the exact upstream ScrapeGraphAI source/lock.

Set HERMES_SCRAPEGRAPH_AI_SOURCE and HERMES_SCRAPEGRAPH_AI_PYTHON to the
source generation and isolated Python installed with its pinned uv.lock. The
portable verifier tests run without those optional runtime artifacts.
"""
from __future__ import annotations

import os
import json
import subprocess
import hashlib
from pathlib import Path
from pathlib import PurePosixPath

import pytest

from hermes_installer.components.scrapegraph_ai import (
    FIXTURE_HTML,
    FIXTURE_NAME,
    ScrapeGraphFixtureError,
    stage_scrapegraph_ai_fixture,
    verify_scrapegraph_ai_fixture_result,
    verify_scrapegraph_source,
)
from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.runtime_source import bind_component_runtime_source
from hermes_installer.components.source_bundle import VerifiedComponentSource
from hermes_installer.registry.generation import GenerationStore
from hermes_installer.registry.source import _git_tree
from hermes_installer.state import Journal, OwnedRoot, process_lock
from hermes_installer.components.workloads import Workload, WorkloadScheduler


def _verified_source_from_checkout(source_root: Path) -> VerifiedComponentSource:
    """Build test evidence from the exact clean Git tree, including its full tree SHA."""
    contract = resolve_component_adapter("scrapegraph-ai")
    revision = contract.revision
    assert revision == "194055e203afce41ed4e70365dbc416bad756115"
    head = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", "HEAD"],
        check=True, text=True, capture_output=True, timeout=10,
    ).stdout.strip()
    assert head == revision
    status = subprocess.run(
        ["git", "-C", str(source_root), "status", "--porcelain", "--untracked-files=no"],
        check=True, text=True, capture_output=True, timeout=10,
    ).stdout
    assert not status
    raw_entries = subprocess.run(
        ["git", "-C", str(source_root), "ls-tree", "-rz", "--full-tree", revision],
        check=True, capture_output=True, timeout=30,
    ).stdout
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    for entry in raw_entries.split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode_text, kind, oid = metadata.decode("ascii").split(" ")
        name = raw_path.decode("utf-8")
        if kind != "blob" or mode_text not in {"100644", "100755"}:
            raise AssertionError("pinned runtime source has an unsupported non-regular Git entry")
        relative = PurePosixPath(name)
        if relative.is_absolute() or ".." in relative.parts or relative.as_posix() != name:
            raise AssertionError("pinned runtime source contains an unsafe path")
        path = source_root.joinpath(*relative.parts)
        if path.is_symlink() or not path.is_file():
            raise AssertionError("pinned runtime source entry is not a regular checkout file")
        output = path.read_bytes()
        git_blob = hashlib.sha1(b"blob " + str(len(output)).encode("ascii") + b"\0" + output).hexdigest()
        assert git_blob == oid
        files[name] = output
        modes[name] = 0o755 if mode_text == "100755" else 0o644
    tree_sha, _ = _git_tree(files, modes)
    expected_tree = subprocess.run(
        ["git", "-C", str(source_root), "rev-parse", f"{revision}^{{tree}}"],
        check=True, text=True, capture_output=True, timeout=10,
    ).stdout.strip()
    assert tree_sha == expected_tree
    for relative, expected in {
        "pyproject.toml": "c88e138a741bcac006d58dd41303c4a68b48f925b929067af4b43c04bfd5b886",
        "uv.lock": "2fd36ae40e1eda563043b7204bd32755b67078abc471c8cf29f3f48c9c309771",
        "scrapegraphai/graphs/smart_scraper_graph.py": "1e9cd02492172c3ea629b8745d685203776351afe3f783458a5f33e1acd706dc",
    }.items():
        assert hashlib.sha256(files[relative]).hexdigest() == expected
    content = hashlib.sha256()
    for name in sorted(files):
        content.update(name.encode("utf-8") + b"\0")
        content.update(f"{modes[name]:o}".encode("ascii") + b"\0")
        content.update(hashlib.sha256(files[name]).digest())
    license_files = tuple(sorted(
        name for name in files
        if Path(name).name.casefold().startswith(("license", "copying", "notice"))
    ))
    archive_sha = hashlib.sha256(raw_entries).hexdigest()
    provenance = {
        "schema": 1,
        "component_id": contract.component_id,
        "source_identity": contract.source_identity,
        "source_url": contract.selected_source_url,
        "revision": revision,
        "source_selection": contract.source_selection,
        "source_archive_sha256": archive_sha,
        "source_content_sha256": content.hexdigest(),
        "source_tree_sha": tree_sha,
        "declared_license": contract.license,
        "license_files": list(license_files),
        "redistribution_license_review_required": contract.redistribution_license_review_required,
    }
    files["INSTALLER-SOURCE-PROVENANCE.json"] = (
        json.dumps(provenance, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    modes["INSTALLER-SOURCE-PROVENANCE.json"] = 0o644
    return VerifiedComponentSource(
        component_id=contract.component_id,
        source_identity=contract.source_identity or "",
        revision=revision,
        files=files,
        file_modes=modes,
        archive_sha256=archive_sha,
        content_sha256=content.hexdigest(),
        source_tree_sha=tree_sha,
        license=contract.license,
        license_files=license_files,
        redistribution_license_review_required=contract.redistribution_license_review_required,
    )


def test_fixture_verifier_rejects_failed_ambiguous_and_incomplete_proofs() -> None:
    with pytest.raises(ScrapeGraphFixtureError, match="process failed"):
        verify_scrapegraph_ai_fixture_result({"exit_code": 1, "stdout": ""})
    with pytest.raises(ScrapeGraphFixtureError, match="missing or ambiguous"):
        verify_scrapegraph_ai_fixture_result({"exit_code": 0, "stdout": ""})
    with pytest.raises(ScrapeGraphFixtureError, match="missing or ambiguous"):
        verify_scrapegraph_ai_fixture_result({
            "exit_code": 0,
            "stdout": "HERMES_SCRAPEGRAPH_AI_PROOF={}\nHERMES_SCRAPEGRAPH_AI_PROOF={}",
        })


@pytest.mark.parametrize(
    "field,value",
    [
        ("structured_result", {"name": "Cedar Mug"}),
        ("model", "public/openai-gpt"),
        ("source_kind", "url"),
        ("local_fetch_calls", 0),
        ("network_attempts", 1),
        ("telemetry_enabled", True),
        ("metered_cost_usd", 0.01),
    ],
)
def test_fixture_verifier_rejects_incomplete_model_network_or_policy_proof(
    field: str, value: object,
) -> None:
    proof: dict[str, object] = {
        "source_revision": "194055e203afce41ed4e70365dbc416bad756115",
        "upstream_class": "scrapegraphai.graphs.SmartScraperGraph",
        "upstream_source": "/private/source/scrapegraphai/__init__.py",
        "nodes": ["Fetch", "GenerateAnswer"],
        "source_kind": "local_dir",
        "local_fetch_calls": 1,
        "model": "allowlisted-fixture-mock",
        "model_calls": 1,
        "observed_fixture_values": True,
        "structured_result": {"name": "Cedar Mug", "price": "$18.50"},
        "network_attempts": 0,
        "telemetry_enabled": False,
        "metered_cost_usd": 0,
    }
    proof[field] = value
    with pytest.raises(ScrapeGraphFixtureError, match="required local graph effects"):
        verify_scrapegraph_ai_fixture_result({
            "exit_code": 0,
            "stdout": "HERMES_SCRAPEGRAPH_AI_PROOF=" + json.dumps(proof),
        })


def test_source_verifier_rejects_an_unavailable_or_unpinned_generation(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir(mode=0o700)
    (source / "pyproject.toml").write_text("[project]\nname='unrelated'\n")
    with pytest.raises(ScrapeGraphFixtureError, match="digest mismatch"):
        verify_scrapegraph_source(str(source))
    with pytest.raises(ScrapeGraphFixtureError, match="must already exist"):
        verify_scrapegraph_source(str(tmp_path / "missing"))


def test_stage_fixture_uses_fixed_local_html_and_rejects_mutation(tmp_path: Path) -> None:
    work = tmp_path / "private-work"
    work.mkdir(mode=0o700)
    fixture = stage_scrapegraph_ai_fixture(str(work))
    assert fixture.name == FIXTURE_NAME
    assert fixture.read_text() == FIXTURE_HTML
    assert fixture.stat().st_mode & 0o777 == 0o444
    assert "Cedar Mug" in fixture.read_text()
    fixture.chmod(0o644)
    fixture.write_text("<html>changed</html>")
    with pytest.raises(ScrapeGraphFixtureError, match="conflicts"):
        stage_scrapegraph_ai_fixture(str(work))


def test_pinned_upstream_smart_scraper_executes_local_html_graph_with_mock_boundary(
    tmp_path: Path,
) -> None:
    source_value = os.environ.get("HERMES_SCRAPEGRAPH_AI_SOURCE")
    python_value = os.environ.get("HERMES_SCRAPEGRAPH_AI_PYTHON")
    if not source_value or not python_value:
        pytest.skip("pinned full source, locked isolated runtime, and Python 3.12 fixture runner are not enrolled")

    source = _verified_source_from_checkout(Path(source_value))
    work = tmp_path / "private-scrapegraph-work"
    work.mkdir(mode=0o700)
    owned = OwnedRoot(tmp_path / "profile-data")
    owned.ensure()
    def run(invocation):
        environment = {
            "PATH": os.environ.get("PATH", ""),
            **dict(invocation.environment),
        }
        completed = subprocess.run(
            invocation.argv,
            cwd=invocation.cwd,
            env=environment,
            text=True,
            capture_output=True,
            timeout=invocation.timeout_seconds,
            check=False,
        )
        return {
            "exit_code": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
        }

    with process_lock(owned.path("installer.lock")):
        store = GenerationStore(owned, Journal(owned.path("journal.sqlite3")), mutation_locked=True)
        generation = bind_component_runtime_source(source, store, component_id="scrapegraph-ai")
        scheduler = WorkloadScheduler(
            run,
            frozenset({"component.scrapegraph-ai.read-fixture",
                       "component.scrapegraph-ai.fixture-model"}),
            runtime_roots={"scrapegraph-ai-python": python_value},
            work_roots={"scrapegraph-ai": str(work)},
            memory_budget_mb=2048,
            source_generations={"scrapegraph-ai": generation},
        )
        proof = scheduler.execute(Workload("scrapegraph-local-fixture"))
    assert proof["component_id"] == "scrapegraph-ai"
    assert proof["structured_result"] == {"name": "Cedar Mug", "price": "$18.50"}
    assert proof["local_fetch_calls"] == 1
    assert proof["network_attempts"] == 0
    assert proof["metered_cost_usd"] == 0
    assert Path(str(proof["upstream_source"])).resolve().is_relative_to(generation.root.resolve())
