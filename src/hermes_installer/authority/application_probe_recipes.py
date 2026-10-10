"""Finite fixed application qualification-effect recipe/source catalog.

These immutable rows select reviewed installer-owned probe bytes and strict
result parsers. They are not artifact receipts: callers must resolve every
member through the root release observer and current setup selection before
building or dispatching. This catalog is deliberately separate from the
runtime ABI/import-origin probe receipt.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence


class ApplicationProbeRecipeUnavailable(PermissionError):
    """The selected application has no complete fixed effect recipe."""


@dataclass(frozen=True, slots=True)
class ApplicationProbeMember:
    member_id: str
    relative_path: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class ApplicationQualificationEffectRecipe:
    application_id: str
    workflow_id: str
    workload_id: str
    runtime_kind: str
    source_identity: str
    source_revision: str
    entrypoint_member_id: str
    module_member_ids: tuple[str, ...]
    result_schema_id: str
    result_schema_sha256: str
    semantic_contract_id: str
    members: tuple[ApplicationProbeMember, ...]


@dataclass(frozen=True, slots=True)
class ValidatedApplicationQualificationEffectResult:
    """Canonical semantic result; root authority separately retains terminal lineage."""

    application_id: str
    workflow_id: str
    workload_id: str
    source_revision: str
    semantic_contract_id: str
    result_sha256: str
    canonical_result: bytes


_RECIPES: Mapping[str, ApplicationQualificationEffectRecipe] = {
    "graphify": ApplicationQualificationEffectRecipe(
        application_id="graphify", workflow_id="qualify-graphify-v1",
        workload_id="graphify-code-fixture", runtime_kind="python",
        source_identity="Graphify-Labs/graphify",
        source_revision="5b74d7d74911cf435c8f1636b6f96ea202cc6246",
        entrypoint_member_id="graphify-probe-entrypoint-v1",
        module_member_ids=("graphify-probe-entrypoint-v1", "graphify-probe-helper-v1",
                           "graphify-probe-result-validator-v1"),
        result_schema_id="urn:hermes-installer:graphify-probe-result:v1",
        result_schema_sha256="0649acf5c5e96c629b73e884683df7fe2f98e1fead448c1548f52c22cdd18136",
        semantic_contract_id="graphify-two-source-one-extracted-import-edge-v1",
        members=(
            ApplicationProbeMember("graphify-probe-entrypoint-v1", "src/hermes_installer/components/probes/graphify_fixture/entrypoint.py", "db0e49e0878f0406d9dba29c9f9860bee2bc7260e59c9ac7e20ecf88b5a03378", 153),
            ApplicationProbeMember("graphify-probe-helper-v1", "src/hermes_installer/components/probes/graphify_fixture/helper.py", "acc16fab89297ad11006519103d1033d611b1315529b5614098a3d60c80c2f74", 155),
            ApplicationProbeMember("graphify-probe-result-validator-v1", "src/hermes_installer/components/probes/graphify_result.py", "f3f0b44d9d9d707daceee4d563be1d028080ec661c11a29e85e1f38cda0901e9", 6481),
            ApplicationProbeMember("graphify-probe-result-schema-v1", "src/hermes_installer/components/probes/graphify_probe_result.schema.json", "0649acf5c5e96c629b73e884683df7fe2f98e1fead448c1548f52c22cdd18136", 1157),
        ),
    ),
    "browser-use": ApplicationQualificationEffectRecipe(
        application_id="browser-use", workflow_id="qualify-browser-use-v1",
        workload_id="browser-fixture", runtime_kind="python",
        source_identity="browser-use/browser-use",
        source_revision="c75e8476e26d18b7617643bc2ae082fae8eae431",
        entrypoint_member_id="browser-use-probe-v1",
        module_member_ids=("browser-use-probe-v1", "browser-use-result-validator-v1"),
        result_schema_id="urn:hermes-installer:browser-use-probe-result:v1",
        result_schema_sha256="2e27c93d701de22792fae24ddb097d3d0dd7424dd5a25ce510ee75fecc90740f",
        semantic_contract_id="browser-use-owned-loopback-navigate-click-screenshot-v1",
        members=(
            ApplicationProbeMember("browser-use-probe-v1", "src/hermes_installer/components/browser_use_qualification_probe.py", "2f939a6cd82f73f4e7474ed7f0c412e9a22fb65df01e7765c1a87cf675a52e58", 4404),
            ApplicationProbeMember("browser-use-result-validator-v1", "src/hermes_installer/components/browser_use.py", "2e27c93d701de22792fae24ddb097d3d0dd7424dd5a25ce510ee75fecc90740f", 6531),
        ),
    ),
    "scrapegraph-ai": ApplicationQualificationEffectRecipe(
        application_id="scrapegraph-ai", workflow_id="qualify-scrapegraph-v1",
        workload_id="scrapegraph-local-fixture", runtime_kind="python",
        source_identity="ScrapeGraphAI/Scrapegraph-ai",
        source_revision="194055e203afce41ed4e70365dbc416bad756115",
        entrypoint_member_id="scrapegraph-ai-probe-v1",
        module_member_ids=("scrapegraph-ai-probe-v1", "scrapegraph-ai-result-validator-v1"),
        result_schema_id="urn:hermes-installer:scrapegraph-ai-probe-result:v1",
        result_schema_sha256="e2ac08afa32b9940705403eb9e2af35b08e21cc6f61ed6731438a6c1c1c98dcb",
        semantic_contract_id="scrapegraph-local-fetch-mock-model-zero-network-v1",
        members=(
            ApplicationProbeMember("scrapegraph-ai-probe-v1", "src/hermes_installer/components/probes/scrapegraph_ai_probe.py", "30974c44d2bd9e60847bcad6ba3849cf8b2a262f8c08f79b832a9bba723ed6ab", 5446),
            ApplicationProbeMember("scrapegraph-ai-result-validator-v1", "src/hermes_installer/components/scrapegraph_ai.py", "e2ac08afa32b9940705403eb9e2af35b08e21cc6f61ed6731438a6c1c1c98dcb", 11891),
        ),
    ),
    "hyperframes": ApplicationQualificationEffectRecipe(
        application_id="hyperframes", workflow_id="qualify-hyperframes-v1",
        workload_id="hyperframes-render-fixture", runtime_kind="node",
        source_identity="heygen-com/hyperframes",
        source_revision="46f6cb356785bed79e1ce7b79d7e7accc697786a",
        entrypoint_member_id="hyperframes-probe-v1",
        module_member_ids=("hyperframes-probe-v1", "hyperframes-composition-v1"),
        result_schema_id="urn:hermes-installer:hyperframes-media-probe:v1",
        result_schema_sha256="f4a63a90b4467ae2db4fcdf7d874bc8f6b75e6b1f02910e326e75fcb49d498aa",
        semantic_contract_id="hyperframes-local-two-frame-h264-render-v1",
        members=(
            ApplicationProbeMember("hyperframes-probe-v1", "src/hermes_installer/components/probes/hyperframes_probe.py", "f4a63a90b4467ae2db4fcdf7d874bc8f6b75e6b1f02910e326e75fcb49d498aa", 12692),
            ApplicationProbeMember("hyperframes-composition-v1", "src/hermes_installer/components/probes/hyperframes_fixture/composition.html", "fc20eaf85de0fe9bbc63bf4b315892a4fb0934d19819eb8b9450fa5bb7ed6052", 707),
        ),
    ),
}


def resolve_application_qualification_effect_recipe(
    application_id: str, *, workflow_id: str, runtime_kind: str,
    source_identity: str, source_revision: str,
) -> ApplicationQualificationEffectRecipe:
    """Resolve the one finite recipe matching a current protected selection."""
    recipe = _RECIPES.get(application_id)
    if (recipe is None or recipe.workflow_id != workflow_id
            or recipe.runtime_kind != runtime_kind
            or recipe.source_identity != source_identity
            or recipe.source_revision != source_revision
            or not recipe.result_schema_sha256
            or any(member.size_bytes <= 0 or not member.sha256 for member in recipe.members)):
        raise ApplicationProbeRecipeUnavailable(
            "selected application has no complete reviewed qualification-effect recipe")
    return recipe


def resolve_application_qualification_effect_recipe_for_selection(
    source_selection: Any,
) -> ApplicationQualificationEffectRecipe:
    """Select a recipe from a sealed root source-preparation selection.

    The caller must first resolve this object through the source-preparation
    registry and recheck it before effects; this helper only performs fixed
    catalog matching and never confers authority.
    """
    from hermes_installer.authority.application_source_preparation import (
        RootApplicationSourcePreparationSelection,
    )
    if type(source_selection) is not RootApplicationSourcePreparationSelection:
        raise ApplicationProbeRecipeUnavailable("effect recipe requires a typed root source selection")
    runtime_kind = "node" if source_selection.application_id == "hyperframes" else "python"
    return resolve_application_qualification_effect_recipe(
        source_selection.application_id, workflow_id=source_selection.workflow_id,
        runtime_kind=runtime_kind, source_identity=source_selection.source_identity,
        source_revision=source_selection.source_revision)


def verify_qualification_effect_member(recipe: ApplicationQualificationEffectRecipe,
                                        member_id: str, body: bytes) -> None:
    """Compare a held root-observed release member to its reviewed pin."""
    if (type(recipe) is not ApplicationQualificationEffectRecipe
            or recipe != _RECIPES.get(getattr(recipe, "application_id", None))
            or type(body) is not bytes):
        raise ApplicationProbeRecipeUnavailable("effect source member is not a typed recipe byte sequence")
    member = next((row for row in recipe.members if row.member_id == member_id), None)
    if member is None or len(body) != member.size_bytes or hashlib.sha256(body).hexdigest() != member.sha256:
        raise ApplicationProbeRecipeUnavailable("effect source member differs from its reviewed release pin")


def verify_qualification_effect_member_set(
    recipe: ApplicationQualificationEffectRecipe,
    held_members: Mapping[str, bytes],
) -> None:
    """Require exact complete recipe closure from root-held release bytes."""
    if type(recipe) is not ApplicationQualificationEffectRecipe or recipe != _RECIPES.get(recipe.application_id):
        raise ApplicationProbeRecipeUnavailable("effect member closure is not a catalog recipe")
    expected = {member.member_id for member in recipe.members}
    if (not isinstance(held_members, Mapping) or set(held_members) != expected
            or any(type(value) is not bytes for value in held_members.values())):
        raise ApplicationProbeRecipeUnavailable("effect source member closure is incomplete or unexpected")
    for member in recipe.members:
        verify_qualification_effect_member(recipe, member.member_id, held_members[member.member_id])


def validate_application_qualification_effect_result(
    recipe: ApplicationQualificationEffectRecipe,
    managed_stage_results: Sequence[Mapping[str, Any]], *,
    expected_fixture_url: str | None = None,
    work_roots: Mapping[str, str] | None = None,
) -> ValidatedApplicationQualificationEffectResult:
    """Validate bounded, manager-retained effect outputs using the app parser."""
    if (type(recipe) is not ApplicationQualificationEffectRecipe
            or recipe != _RECIPES.get(getattr(recipe, "application_id", None))
            or not isinstance(managed_stage_results, Sequence)
            or isinstance(managed_stage_results, (str, bytes))):
        raise ApplicationProbeRecipeUnavailable("managed effect stages are not a typed result sequence")
    if not 1 <= len(managed_stage_results) <= 4 or any(not isinstance(row, Mapping) for row in managed_stage_results):
        raise ApplicationProbeRecipeUnavailable("managed effect stage count or shape is outside its recipe")
    roots = work_roots or {}
    try:
        if recipe.application_id == "graphify":
            if len(managed_stage_results) != 1 or "graphify" not in roots:
                raise ApplicationProbeRecipeUnavailable("Graphify requires its exact query stage and private work root")
            from hermes_installer.components.probes.graphify_result import build_graphify_probe_result
            row = managed_stage_results[0]
            if row.get("exit_code") != 0:
                raise ApplicationProbeRecipeUnavailable("Graphify managed query failed")
            graph_root = Path(roots["graphify"])
            graph_dir = graph_root / "graphify-out"
            graph_path = graph_dir / "graph.json"
            root_info, dir_info, path_info = graph_root.lstat(), graph_dir.lstat(), graph_path.lstat()
            if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.geteuid()
                    or root_info.st_mode & 0o077 or graph_root.resolve(strict=True) != graph_root
                    or not stat.S_ISDIR(dir_info.st_mode) or dir_info.st_uid != os.geteuid()
                    or dir_info.st_mode & 0o077 or graph_dir.resolve(strict=True) != graph_dir
                    or not stat.S_ISREG(path_info.st_mode) or path_info.st_uid != os.geteuid()
                    or path_info.st_nlink != 1 or path_info.st_mode & 0o022
                    or path_info.st_size > 8 * 1024 * 1024):
                raise ApplicationProbeRecipeUnavailable("Graphify graph output is not a bounded private file")
            fd = os.open(graph_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                opened = os.fstat(fd)
                if (opened.st_ino != path_info.st_ino or opened.st_dev != path_info.st_dev
                        or opened.st_nlink != 1 or opened.st_size != path_info.st_size):
                    raise ApplicationProbeRecipeUnavailable("Graphify graph output changed during verification")
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    graph = stream.read(8 * 1024 * 1024 + 1)
            finally:
                os.close(fd)
            value = build_graphify_probe_result(graph)
        elif recipe.application_id == "browser-use":
            if len(managed_stage_results) != 1 or not expected_fixture_url:
                raise ApplicationProbeRecipeUnavailable("Browser Use requires one managed stage and owned fixture URL")
            from hermes_installer.components.browser_use import verify_browser_use_fixture_result
            value = verify_browser_use_fixture_result(managed_stage_results[0])
            if value.get("navigation_url") != expected_fixture_url:
                raise ApplicationProbeRecipeUnavailable("Browser Use result differs from owned fixture receipt")
        elif recipe.application_id == "scrapegraph-ai":
            if len(managed_stage_results) != 1:
                raise ApplicationProbeRecipeUnavailable("ScrapeGraphAI requires its one fixed local graph stage")
            from hermes_installer.components.scrapegraph_ai import verify_scrapegraph_ai_fixture_result
            value = verify_scrapegraph_ai_fixture_result(managed_stage_results[0])
        elif recipe.application_id == "hyperframes":
            if len(managed_stage_results) != 3 or "hyperframes" not in roots:
                raise ApplicationProbeRecipeUnavailable("Hyperframes requires render, media, and frame-change stages")
            from hermes_installer.components.probes.hyperframes_probe import verify_hyperframes_probe_results
            value = verify_hyperframes_probe_results(managed_stage_results, roots)
        else:
            raise ApplicationProbeRecipeUnavailable("application has no fixed effect result verifier")
    except ApplicationProbeRecipeUnavailable:
        raise
    except Exception as exc:
        raise ApplicationProbeRecipeUnavailable("managed application result failed its fixed semantic contract") from exc
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, allow_nan=False).encode("utf-8")
    return ValidatedApplicationQualificationEffectResult(
        recipe.application_id, recipe.workflow_id, recipe.workload_id,
        recipe.source_revision, recipe.semantic_contract_id,
        hashlib.sha256(canonical).hexdigest(), canonical)
