"""Contracts for the root-only Resources profile/skill installation handoff."""
from __future__ import annotations

import json
import hashlib
import os
import sqlite3
from types import SimpleNamespace
from pathlib import Path

import pytest

from hermes_installer.authority.native_materialization import (
    PINNED_HERMES_REVISION,
    NativeMaterializationDenied,
    NativeMaterializationReceipt,
    NativeMaterializationSelection,
    NativeMaterializedItem,
    _retained_resource_definitions,
    RootNativeMaterialization,
    _atomic_service_write_at,
    _hash_file_at,
    _open_parent,
    _selected_files,
)
from hermes_installer.registry.native import NativeRegistry
from hermes_installer.registry.source import BundledRegistrySource, PinnedSource
from hermes_installer.registry.native_install import NativeInstallReceipt


def _registry() -> NativeRegistry:
    bundle = (Path(__file__).parents[2] / "src" / "hermes_installer" / "registry"
              / "bundle_data")
    pin = PinnedSource.from_mapping(json.loads(
        (bundle / "hermes-agent-resources.pin.json").read_text(encoding="utf-8")))
    verified = BundledRegistrySource(pin).load(
        (bundle / "hermes-agent-resources-2.3.1.tar.gz").read_bytes())
    return NativeRegistry.from_verified_source(verified)


def test_root_operation_selects_only_native_profile_and_resolved_skill_closure() -> None:
    registry = _registry()
    all_profiles = sorted(key.split("/", 1)[1].split("@", 1)[0]
                          for key in registry.resolver.raw if key.startswith("profiles/"))
    profile_id = all_profiles[0]
    discovery = registry.discover([f"profiles/{profile_id}@*"])
    compiled = registry.materialize(discovery)

    selected = _selected_files(compiled, profile_id)
    assert f"profiles/{profile_id}/SOUL.md" in selected
    assert f"profiles/{profile_id}/profile.yaml" in selected
    skill_paths = [path for path in selected if "/skills/" in path]
    expected_skills = {item.resource.id for item in discovery.resources
                       if item.resource.kind.value == "skills"}
    assert {path.split("/skills/", 1)[1].split("/", 1)[0]
            for path in skill_paths} == expected_skills
    assert all(path.startswith(f"profiles/{profile_id}/") for path in selected)
    assert all(path.startswith("homes/profiles/") or path.startswith("homes/skills/")
               for path in compiled if path.startswith("homes/"))


def test_all_bundled_profiles_compile_to_their_exact_profile_local_skill_closures() -> None:
    registry = _registry()
    profile_ids = sorted(key.split("/", 1)[1].split("@", 1)[0]
                         for key in registry.resolver.raw if key.startswith("profiles/"))
    assert len(profile_ids) == 208
    discovered_skills = set()
    for profile_id in profile_ids:
        discovery = registry.discover([f"profiles/{profile_id}@*"])
        compiled = registry.materialize(discovery)
        selected = _selected_files(compiled, profile_id)
        expected = {item.resource.id for item in discovery.resources
                    if item.resource.kind.value == "skills"}
        actual = {path.split("/skills/", 1)[1].split("/", 1)[0]
                  for path in selected if "/skills/" in path}
        assert actual == expected, profile_id
        assert all(path.startswith(f"profiles/{profile_id}/") for path in selected)
        discovered_skills.update(actual)
    assert len(discovered_skills) == 396


def test_materialization_definition_projection_retains_transformed_source_and_native_members() -> None:
    registry = _registry()
    profile_id = sorted(key.split("/", 1)[1].split("@", 1)[0]
                        for key in registry.resolver.raw if key.startswith("profiles/"))[0]
    discovery = registry.discover([f"profiles/{profile_id}@*"])
    compiled = registry.materialize(discovery)
    definitions = _retained_resource_definitions(registry, discovery, compiled)

    profile = next(row for row in definitions
                   if row.kind == "profiles" and row.resource_id == profile_id)
    raw = registry.resolver.raw[f"profiles/{profile_id}@{profile.version}"]
    assert profile.source_revision == registry.source.revision
    assert profile.source_document_sha256 == raw.content_digest
    assert any(row.relative_path == profile.source_path for row in profile.members)
    assert all(hashlib.sha256(compiled[row.relative_path]).hexdigest() == row.sha256
               and len(compiled[row.relative_path]) == row.size_bytes
               for row in profile.members)

    selected_skills = {item.resource.id for item in discovery.resources
                       if item.resource.kind.value == "skills"}
    retained_skills = {row.resource_id for row in definitions if row.kind == "skills"}
    assert retained_skills == selected_skills
    assert all(any(member.relative_path == f"homes/skills/{skill}/SKILL.md"
                   for member in row.members)
               for skill in selected_skills
               for row in definitions if row.kind == "skills" and row.resource_id == skill)


def test_crosswalk_path_tampering_is_rejected_before_writes() -> None:
    registry = _registry()
    profile_id = sorted(key.split("/", 1)[1].split("@", 1)[0]
                        for key in registry.resolver.raw if key.startswith("profiles/"))[0]
    compiled = dict(registry.materialize(registry.discover([f"profiles/{profile_id}@*"])))
    ledger = json.loads(compiled["installer-registry/crosswalk.json"])
    next(row for row in ledger["native_materialization"]["files"]
         if row["staged"].startswith("homes/profiles/"))["target"] = "../../outside"
    compiled["installer-registry/crosswalk.json"] = json.dumps(ledger).encode()
    with pytest.raises(NativeMaterializationDenied, match="differs from its selected Hermes destination"):
        _selected_files(compiled, profile_id)


def test_duplicate_hermes_destination_is_rejected() -> None:
    registry = _registry()
    profile_id = sorted(key.split("/", 1)[1].split("@", 1)[0]
                        for key in registry.resolver.raw if key.startswith("profiles/"))[0]
    compiled = dict(registry.materialize(registry.discover([f"profiles/{profile_id}@*"])))
    ledger = json.loads(compiled["installer-registry/crosswalk.json"])
    first = next(row for row in ledger["native_materialization"]["files"]
                 if row["staged"].startswith("homes/profiles/"))
    ledger["native_materialization"]["files"].append(dict(first))
    compiled["installer-registry/crosswalk.json"] = json.dumps(ledger).encode()
    with pytest.raises(NativeMaterializationDenied, match="multiple files"):
        _selected_files(compiled, profile_id)


def test_public_materialization_receipt_cannot_contain_filesystem_paths() -> None:
    names = set(NativeMaterializationReceipt.__dataclass_fields__)
    assert not any("path" in name.casefold() or name.endswith("_root") for name in names)


def test_native_mutation_is_denied_outside_root_authority() -> None:
    operation = RootNativeMaterialization.__new__(RootNativeMaterialization)
    operation._authority_uid = 0
    with pytest.raises(NativeMaterializationDenied, match="requires the root setup authority"):
        operation._require_authority()


def test_discovery_receipt_is_durably_inserted_and_keeps_exact_selection(tmp_path: Path) -> None:
    operation = RootNativeMaterialization.__new__(RootNativeMaterialization)
    operation._database = tmp_path / "journal.sqlite3"
    operation._monotonic = lambda: 10.0
    operation._registry = SimpleNamespace(source=SimpleNamespace(
        revision="resources-revision", content_digest="a" * 64))
    with sqlite3.connect(operation._database) as db:
        db.executescript("""
            CREATE TABLE plans(operation_id TEXT PRIMARY KEY,payload TEXT,state TEXT,updated REAL);
            CREATE TABLE receipts(handle TEXT PRIMARY KEY,enrollment_id TEXT,service_generation TEXT,
                protected_enrollment_digest TEXT,service_profile_id TEXT,resource_profile_id TEXT,
                resources_revision TEXT,resources_content_digest TEXT,selected_closure_digest TEXT,
                items TEXT,skill_ids TEXT,state TEXT,expires REAL,discovery TEXT);
            INSERT INTO plans VALUES('operation','{}','applying',1.0);
        """)
    selection = NativeMaterializationSelection(
        "enrollment", "generation", "service", "b" * 64, 123, 456,
        "home-id", "data-id", "source-artifact", "c" * 32, "d" * 32)
    discovery = NativeInstallReceipt(
        PINNED_HERMES_REVISION, "3.14.7", "profile", True, True,
        ("skill-one",), ("skill-one",), {"profile": "d" * 64})
    operation._record_receipt(
        "e" * 32, selection, "profile", "f" * 64,
        (NativeMaterializedItem("profile", "profile", "d" * 64, "installed"),
         NativeMaterializedItem("skill", "skill-one", "e" * 64, "installed")),
        70.0, "operation", discovery)
    stored = operation._receipt("e" * 32)
    assert stored["enrollment_id"] == "enrollment"
    assert stored["service_generation"] == "generation"
    assert stored["resource_profile_id"] == "profile"
    assert stored["state"] == "discovered"
    public = operation._public_receipt(stored, "discovered")
    assert public.hermes_revision == PINNED_HERMES_REVISION
    assert public.python_version == "3.14.7"


def test_pm_python_resolver_is_bound_to_the_selected_receipt(tmp_path: Path) -> None:
    executable = tmp_path / "python3.14"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    seen = {}

    class Resolver:
        def resolve_python(self, **kwargs):
            seen.update(kwargs)
            return executable

    operation = RootNativeMaterialization.__new__(RootNativeMaterialization)
    operation._pm_runtime_resolver = Resolver()
    selection = NativeMaterializationSelection(
        "enrollment", "generation", "service", "b" * 64, 123, 456,
        "home-id", "data-id", "source-artifact", "c" * 32, "d" * 32)
    assert operation._resolve_hermes_python(selection) == executable
    assert seen == {
        "pm_runtime_handle": "d" * 32,
        "enrollment_id": "enrollment",
        "service_generation": "generation",
        "source_artifact_id": "source-artifact",
    }

    operation._pm_runtime_resolver = SimpleNamespace(
        resolve_python=lambda **_kwargs: str(executable))
    with pytest.raises(NativeMaterializationDenied, match="did not resolve an executable"):
        operation._resolve_hermes_python(selection)


def test_fixed_home_write_is_atomic_service_owned_and_symlink_safe(tmp_path: Path) -> None:
    home = tmp_path / "hermes-home"
    home.mkdir(mode=0o700)
    uid, gid = os.getuid(), os.getgid()
    relative = "profiles/demo/skills/local/SKILL.md"
    expected = b"---\nname: local\ndescription: fixture\n---\nA local fixture skill.\n"
    with _open_parent(home, relative, uid=uid, gid=gid,
                      create_parents=True) as (parent_fd, leaf):
        _atomic_service_write_at(parent_fd, leaf, expected, uid=uid, gid=gid)
        assert _hash_file_at(parent_fd, leaf)
    installed = home / relative
    assert installed.read_bytes() == expected
    assert installed.stat().st_uid == uid and installed.stat().st_gid == gid
    assert installed.stat().st_mode & 0o777 == 0o644

    outside = tmp_path / "outside"
    outside.mkdir()
    (home / "profiles" / "escaped").symlink_to(outside, target_is_directory=True)
    with pytest.raises(NativeMaterializationDenied, match="without following links"):
        with _open_parent(home, "profiles/escaped/SOUL.md", uid=uid, gid=gid,
                          create_parents=True):
            pass
