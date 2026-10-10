from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from hermes_installer.authority.application_effect_source_catalog import (
    APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID,
    APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
    APPLICATION_EFFECT_SOURCE_CATALOG_SHA256,
    APPLICATION_EFFECT_SOURCE_CATALOG_SIZE,
    APPLICATION_EFFECT_SOURCE_MEMBERS,
)
from hermes_installer.authority.application_effect_source_observer import (
    RootApplicationEffectSourceObserver,
)
from hermes_installer.authority.application_probe_recipes import (
    resolve_application_qualification_effect_recipe,
)
from hermes_installer.authority.application_workload_execution import (
    RootResolvedApplicationEffectMembers,
)


REPO = Path(__file__).resolve().parents[2]


class _Actor:
    def verify_current(self, release: object) -> None:
        return None


class _Release:
    release_commit = "1" * 40
    deployment_receipt_sha256 = "2" * 64

    def __init__(self, *, wrong_role: bool = False, changed_bytes: bytes | None = None):
        self._paths: dict[str, Path] = {}
        rows = []
        catalog_path = REPO / APPLICATION_EFFECT_SOURCE_CATALOG_PATH
        self._add(rows, APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID,
                  APPLICATION_EFFECT_SOURCE_CATALOG_PATH, "amendment", catalog_path)
        changed_member_path: Path | None = None
        for artifact_id, path, role, digest, size in APPLICATION_EFFECT_SOURCE_MEMBERS:
            source = REPO / path
            if source.exists():
                if changed_bytes is not None and artifact_id == APPLICATION_EFFECT_SOURCE_MEMBERS[0][0]:
                    fd, filename = tempfile.mkstemp()
                    os.write(fd, source.read_bytes())
                    os.close(fd)
                    source = Path(filename)
                    changed_member_path = source
                self._add(rows, artifact_id, path,
                          "module" if wrong_role and artifact_id == APPLICATION_EFFECT_SOURCE_MEMBERS[0][0] else role,
                          source)
        self.files = tuple(rows)
        if changed_member_path is not None and changed_bytes is not None:
            with changed_member_path.open("r+b") as stream:
                stream.write(changed_bytes)
                stream.truncate()

    def _add(self, rows: list[object], artifact_id: str, path: str, role: str, source: Path) -> None:
        info = source.stat()
        body = source.read_bytes()
        rows.append(SimpleNamespace(
            artifact_id=artifact_id, relative_path=path, roles=(role,),
            sha256=hashlib.sha256(body).hexdigest(), size_bytes=len(body),
            device=info.st_dev, inode=info.st_ino, mode=stat.S_IMODE(info.st_mode),
        ))
        self._paths.setdefault(artifact_id, source)

    def open_file(self, artifact_id: str) -> int:
        return os.open(self._paths[artifact_id], os.O_RDONLY)

    def verify_current(self) -> None:
        return None


class ApplicationEffectSourceObserverTests(unittest.TestCase):
    def _observer(self, *, wrong_role: bool = False, changed_bytes: bytes | None = None):
        release = _Release(wrong_role=wrong_role, changed_bytes=changed_bytes)
        if changed_bytes is not None:
            self.addCleanup(release._paths[APPLICATION_EFFECT_SOURCE_MEMBERS[0][0]].unlink, missing_ok=True)
        plan = SimpleNamespace(allowed_artifact_ids=frozenset(row.artifact_id for row in release.files))
        session = SimpleNamespace(
            _factory=SimpleNamespace(
                _release=release, _actor=_Actor(),
                resolver=SimpleNamespace(resolve=lambda _artifact_id: plan),
            ),
            _authorization=SimpleNamespace(plan_artifact_id="plan"),
        )
        return RootApplicationEffectSourceObserver(session), release

    def test_fixed_catalog_mirrors_append_only_v175_descriptor(self) -> None:
        catalog_path = REPO / APPLICATION_EFFECT_SOURCE_CATALOG_PATH
        body = catalog_path.read_bytes()
        self.assertEqual(hashlib.sha256(body).hexdigest(), APPLICATION_EFFECT_SOURCE_CATALOG_SHA256)
        self.assertEqual(len(body), APPLICATION_EFFECT_SOURCE_CATALOG_SIZE)
        actual = json.loads(body)
        rows = tuple((item["artifact_id"], item["release_member_path"], item["role"],
                      item["sha256"], item["size_bytes"]) for item in actual["members"])
        self.assertEqual(rows, APPLICATION_EFFECT_SOURCE_MEMBERS)

    def test_held_release_effect_rows_resolve_only_with_exact_roles_and_bytes(self) -> None:
        recipe = resolve_application_qualification_effect_recipe(
            "graphify", workflow_id="qualify-graphify-v1", runtime_kind="python",
            source_identity="Graphify-Labs/graphify",
            source_revision="5b74d7d74911cf435c8f1636b6f96ea202cc6246",
        )
        observer, _release = self._observer()
        _catalog, rows, _catalog_row, _plan = observer._catalog_and_rows(recipe)
        self.assertEqual(tuple(member.member_id for member, _descriptor, _row in rows),
                         tuple(member.member_id for member in recipe.members))

        wrong_role, _release = self._observer(wrong_role=True)
        with self.assertRaises(PermissionError):
            wrong_role._catalog_and_rows(recipe)

    def test_held_member_byte_mutation_is_rejected_against_observed_fd(self) -> None:
        artifact_id, path, _role, digest, _size = APPLICATION_EFFECT_SOURCE_MEMBERS[0]
        original = (REPO / path).read_bytes()
        mutated = bytes([original[0] ^ 1]) + original[1:]
        observer, release = self._observer(changed_bytes=mutated)
        row = next(row for row in release.files if row.artifact_id == artifact_id)
        with self.assertRaises(PermissionError):
            observer._read_fd(release, row, limit=128 * 1024)
        self.assertEqual(hashlib.sha256(original).hexdigest(), digest)

    def test_currentness_rejects_changed_closure_and_member_bytes(self) -> None:
        observer, _release = self._observer()
        context = SimpleNamespace(application_id="graphify")
        recipe = SimpleNamespace()
        state = SimpleNamespace(release_selection_handle="release", context=context, recipe=recipe)
        observer._sets[("selection", "graphify")] = state
        canonical = RootResolvedApplicationEffectMembers(
            schema=1, application_id="graphify", workflow_id="qualify-graphify-v1",
            release_selection_handle="release", source_receipt_handles=("source",),
            source_closure_sha256="a" * 64, member_receipt_handles=(("entry", "member"),),
            member_bytes={"entry": b"approved"}, service_generation_digest="b" * 64,
            expires_monotonic=100.0,
        )
        observer._clock = lambda: 1.0
        with patch.object(observer, "resolve_application_effect_members", return_value=canonical):
            self.assertTrue(observer.is_application_effect_members_current(canonical))
            changed = replace(canonical, source_closure_sha256="c" * 64)
            self.assertFalse(observer.is_application_effect_members_current(changed))
            changed_bytes = replace(canonical, member_bytes={"entry": b"changed"})
            self.assertFalse(observer.is_application_effect_members_current(changed_bytes))


if __name__ == "__main__":
    unittest.main()
