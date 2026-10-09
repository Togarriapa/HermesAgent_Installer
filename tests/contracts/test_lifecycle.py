from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock

from hermes_installer.lifecycle import GenerationStore, LifecycleError, LifecycleRecovery
from hermes_installer.state import Journal, OwnedRoot, OwnershipError


class LifecycleRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.data = OwnedRoot(root / "data")
        self.data.ensure()
        self.state = OwnedRoot(root / "state")
        self.state.ensure()
        self.journal = Journal(self.state.path("journal.sqlite3"))
        self.store = GenerationStore(self.data, self.journal)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_stage_health_failure_activation_and_atomic_rollback(self) -> None:
        old = self.store.stage("agent-v1", {"bin/hermes": b"version 1"})
        new = self.store.stage("agent-v2", {"bin/hermes": b"version 2"})
        with self.assertRaisesRegex(LifecycleError, "health probe"):
            self.store.activate(new, health_check=lambda _: False)
        self.assertIsNone(self.store.current())
        self.store.activate(old, health_check=lambda generation: generation.files == 1)
        self.store.activate(new, health_check=lambda _: True)
        self.assertEqual(self.store.current().identity, "agent-v2")
        self.assertEqual(self.store.rollback(health_check=lambda _: True).identity, "agent-v1")
        self.assertEqual(self.store.current().identity, "agent-v1")

    def test_integrity_and_path_traversal_are_rejected(self) -> None:
        with self.assertRaises(OwnershipError):
            self.store.stage("agent-v1", {"../escape": b"x"})
        generation = self.store.stage("agent-v1", {"bin/hermes": b"verified"})
        (generation / "bin/hermes").chmod(0o600)
        (generation / "bin/hermes").write_bytes(b"changed")
        with self.assertRaisesRegex(LifecycleError, "digest"):
            self.store.activate(generation, health_check=lambda _: True)

    def test_materialization_updates_only_untouched_installer_files(self) -> None:
        first = self.store.stage("registry-v1", {
            "homes/profiles/default/SOUL.md": b"default v1", "installer-registry/crosswalk.json": json.dumps({
                "native_materialization": {"schema": 1, "destination_root": "data_root", "preserve_existing": True,
                    "files": [{"staged": "homes/profiles/default/SOUL.md", "target": "profiles/default/SOUL.md", "conflict_policy": "preserve-existing"}]}}).encode()})
        result = self.store.apply_registry_materialization(first)
        target = self.data.path("profiles/default/SOUL.md")
        self.assertEqual(result["installed"], ["profiles/default/SOUL.md"])
        target.write_bytes(b"private user overlay")
        second = self.store.stage("registry-v2", {
            "homes/profiles/default/SOUL.md": b"default v2", "installer-registry/crosswalk.json": json.dumps({
                "native_materialization": {"schema": 1, "destination_root": "data_root", "preserve_existing": True,
                    "files": [{"staged": "homes/profiles/default/SOUL.md", "target": "profiles/default/SOUL.md", "conflict_policy": "preserve-existing"}]}}).encode()})
        result = self.store.apply_registry_materialization(second)
        self.assertEqual(result["preserved"], ["profiles/default/SOUL.md"])
        self.assertEqual(target.read_bytes(), b"private user overlay")

    def test_backup_restore_recovers_sqlite_and_preserves_conflicting_overlay(self) -> None:
        profile = self.data.path("profiles/default/SOUL.md")
        profile.parent.mkdir(parents=True)
        profile.write_text("snapshot overlay")
        secret = self.data.path("profiles/default/.env")
        secret.write_text("OPENAI_API_KEY=should-not-be-archived")
        db_path = self.state.path("journal.sqlite3")
        self.journal.checkpoint("synthetic-db", "before", {"revision": "v1"})
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        backup = recovery.backup(database=db_path)
        profile.write_text("newer user overlay")
        self.journal.checkpoint("synthetic-db", "after", {"revision": "v2"})
        result = recovery.restore(backup, database_destination=db_path)
        self.assertEqual(result["database_restored_to"], str(db_path))
        self.assertEqual(result["conflicts_preserved"], ["data/profiles/default/SOUL.md"])
        self.assertEqual(profile.read_text(), "newer user overlay")
        journal_after_restore = Journal(db_path)
        self.assertEqual(journal_after_restore.operation("synthetic-db")["payload"]["revision"], "v1")
        with tarfile_open(backup / "user-data.tar") as archive:
            names = archive.getnames()
        self.assertNotIn("data/profiles/default/.env", names)

    def test_uninstall_removes_only_marked_inactive_generation_and_retains_user_data(self) -> None:
        generation = self.store.stage("agent-v1", {"bin/hermes": b"installer product"})
        overlay = self.data.path("profiles/default/SOUL.md")
        overlay.parent.mkdir(parents=True)
        overlay.write_text("keep")
        foreign = self.data.path("generations/foreign")
        foreign.mkdir()
        (foreign / "my-file").write_text("keep")
        result = LifecycleRecovery(self.data, self.state, self.journal).uninstall()
        self.assertEqual(result["removed_generations"], ["agent-v1"])
        self.assertEqual(overlay.read_text(), "keep")
        self.assertEqual((foreign / "my-file").read_text(), "keep")
        self.assertIsNone(self.store.current())

    def test_restore_refuses_backup_from_outside_owned_backup_root(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(OwnershipError):
                LifecycleRecovery(self.data, self.state, self.journal).restore(Path(outside))

    def test_restore_checks_each_file_against_manifest_before_installing_any_file(self) -> None:
        first = self.data.path("profiles/default/SOUL.md")
        second = self.data.path("overlays/private.md")
        first.parent.mkdir(parents=True)
        second.parent.mkdir(parents=True)
        first.write_bytes(b"profile snapshot")
        second.write_bytes(b"overlay snapshot")
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        backup = recovery.backup()
        manifest_path = backup / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["entries"][0]["sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest))

        first.unlink()
        second.unlink()
        with self.assertRaisesRegex(LifecycleError, "manifest digest"):
            recovery.restore(backup)
        self.assertFalse(first.exists())
        self.assertFalse(second.exists())

    def test_backup_recovers_committed_rename_after_power_loss(self) -> None:
        profile = self.data.path("profiles/default/SOUL.md")
        profile.parent.mkdir(parents=True)
        profile.write_bytes(b"user profile")
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        backup = recovery.backup()
        operation = "lifecycle:backup:" + backup.name
        stage_name = ".stage-" + "a" * 32
        self.journal.checkpoint(operation, "running", {
            "backup": backup.name, "staging_path": stage_name, "schema_version": 1})

        recovery.backup()

        recovered = self.journal.operation(operation)
        self.assertEqual(recovered["status"], "complete_recovered")
        self.assertTrue(recovered["payload"]["recovered_after_interruption"])
        self.assertTrue((backup / "user-data.tar").is_file())

    def test_backup_recovery_removes_only_recorded_private_stage(self) -> None:
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        stage_name = ".stage-" + "b" * 32
        stage = recovery.backups / stage_name
        stage.mkdir(mode=0o700)
        (stage / "partial.tar").write_bytes(b"incomplete")
        operation = "lifecycle:backup:20261009T120000Z-1234abcd"
        self.journal.checkpoint(operation, "running", {
            "backup": "20261009T120000Z-1234abcd", "staging_path": stage_name})

        recovery.backup()

        self.assertFalse(stage.exists())
        self.assertEqual(self.journal.operation(operation)["status"], "interrupted_cleaned")
        self.assertEqual(self.journal.operation(operation)["payload"]["resume"], "hermes-installer data backup")

    def test_backup_recovery_never_follows_a_recorded_stage_symlink(self) -> None:
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        with tempfile.TemporaryDirectory() as temporary:
            foreign = Path(temporary)
            keep = foreign / "keep.txt"
            keep.write_text("foreign data")
            stage_name = ".stage-" + "d" * 32
            (recovery.backups / stage_name).symlink_to(foreign, target_is_directory=True)
            operation = "lifecycle:backup:20261009T120001Z-5678abcd"
            self.journal.checkpoint(operation, "running", {
                "backup": "20261009T120001Z-5678abcd", "staging_path": stage_name})

            recovery.backup()

            self.assertTrue((recovery.backups / stage_name).is_symlink())
            self.assertEqual(keep.read_text(), "foreign data")
            self.assertEqual(self.journal.operation(operation)["status"], "running")

    def test_backup_failed_stage_creation_preserves_preexisting_path(self) -> None:
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        stage = recovery.backups / (".stage-" + "2" * 32)
        stage.mkdir(mode=0o700)
        sentinel = stage / "foreign.txt"
        sentinel.write_text("preserve")

        with mock.patch("hermes_installer.lifecycle.uuid.uuid4", side_effect=[
                uuid.UUID(hex="1" * 32), uuid.UUID(hex="2" * 32)]):
            with self.assertRaises(FileExistsError):
                recovery.backup()

        self.assertEqual(sentinel.read_text(), "preserve")
        failed = self.journal.operations(prefix="lifecycle:backup:", statuses=("failed",))
        self.assertEqual(len(failed), 1)
        self.assertEqual(failed[0]["id"].rsplit("-", 1)[-1], "11111111")

    def test_restore_failed_stage_creation_preserves_preexisting_path(self) -> None:
        profile = self.data.path("profiles/default/SOUL.md")
        profile.parent.mkdir(parents=True)
        profile.write_bytes(b"snapshot")
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        backup = recovery.backup()
        stage = self.data.root / (".hermes-restore-" + "3" * 32)
        stage.mkdir(mode=0o700)
        sentinel = stage / "foreign.txt"
        sentinel.write_text("preserve")

        with mock.patch("hermes_installer.lifecycle.uuid.uuid4", return_value=uuid.UUID(hex="3" * 32)):
            with self.assertRaises(FileExistsError):
                recovery.restore(backup)

        self.assertEqual(sentinel.read_text(), "preserve")
        self.assertEqual(self.journal.operation("lifecycle:restore:" + backup.name)["status"], "failed")

    def test_restore_crash_recovery_removes_recorded_stage_then_resumes(self) -> None:
        profile = self.data.path("profiles/default/SOUL.md")
        profile.parent.mkdir(parents=True)
        profile.write_bytes(b"restorable profile")
        recovery = LifecycleRecovery(self.data, self.state, self.journal)
        backup = recovery.backup()
        profile.unlink()
        stage_name = ".hermes-restore-" + "c" * 32
        stage = self.data.root / stage_name
        stage.mkdir(mode=0o700)
        (stage / "partial").write_bytes(b"partial restore")
        operation = "lifecycle:restore:" + backup.name
        self.journal.checkpoint(operation, "restoring_entry", {
            "backup": backup.name, "staging_path": stage_name, "entry": "data/profiles/default/SOUL.md"})

        result = recovery.restore(backup)

        self.assertFalse(stage.exists())
        self.assertEqual(self.journal.events(operation)[0]["event"], "interrupted_cleaned")
        self.assertEqual(result["restored"], ["data/profiles/default/SOUL.md"])
        self.assertEqual(profile.read_bytes(), b"restorable profile")


def tarfile_open(path: Path):
    import tarfile
    return tarfile.open(path, "r")


if __name__ == "__main__":
    unittest.main()
