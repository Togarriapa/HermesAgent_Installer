"""Effect contracts for the explicitly separate manual Jarvis skill MVP.

These tests are prepared for an authorized isolated target only; do not run them
on a developer workstation against a real Hermes home.
"""
import argparse
import hashlib
import io
import json
import os
import pwd
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest.mock import patch

from hermes_installer.registry.manual_jarvis_skills import (
    _BUNDLE_PROFILE_COUNT,
    _BUNDLE_SKILL_COUNT,
    ManualJarvisSkillsError,
    PRIMARY_SKILLS,
    _read_artifact,
    _verify_owner_skill_overlay_transition,
    build_manual_jarvis_skills_artifact,
    install_and_verify_manual_jarvis_skills,
    install_manual_jarvis_skills,
    _verify_owned_generation,
)
from hermes_installer.registry import manual_jarvis_skills as manual_skills
from hermes_installer.registry.resources_skill_overlay import (
    ResourcesSkillOverlayError, build_effective_artifact, pinned_skill_bytes,
)
from hermes_installer.registry.native_install import NativeInstallReceipt
from hermes_installer import core_runtime
from hermes_installer.registry.jarvis_master_semantics import (
    JarvisSemanticsError,
    effective_profile_spec,
    overlay_identity,
)


def _archive_with_helper(archive_bytes, helper_bytes):
    with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
        members = {info.filename: archive.read(info.filename) for info in archive.infolist()}
    manifest = json.loads(members["manifest.json"])
    manifest["installer"] = {
        "archive_path": manual_skills._HELPER_ARCHIVE_PATH,
        "size_bytes": len(helper_bytes),
        "sha256": hashlib.sha256(helper_bytes).hexdigest(),
    }
    members["manifest.json"] = manual_skills._canonical_json(manifest)
    members[manual_skills._HELPER_ARCHIVE_PATH] = helper_bytes
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        manual_skills._zip_write(archive, "manifest.json", members.pop("manifest.json"))
        for name, content in sorted(members.items()):
            manual_skills._zip_write(archive, name, content)
    return output.getvalue()


class ManualJarvisSkillsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bundle = build_manual_jarvis_skills_artifact()
        cls.digest = hashlib.sha256(cls.bundle).hexdigest()

    def make_home(self, root):
        home = Path(root) / ".hermes"
        home.mkdir()
        (home / "SOUL.md").write_text("# Jarvis\n", encoding="utf-8")
        (home / "config.yaml").write_text("provider: existing\n", encoding="utf-8")
        (home / "memories").mkdir()
        (home / "memories" / "keep.txt").write_text("preserve me\n", encoding="utf-8")
        (home / "skills").mkdir()
        (home / "skills" / "user-owned").mkdir()
        (home / "skills" / "user-owned" / "SKILL.md").write_text("user bytes\n", encoding="utf-8")
        return home

    def helper_pipe(self):
        target = manual_skills._JARVIS_HOME / "skills" / manual_skills._GENERATION
        return patch.object(manual_skills, "_verify_helper_transition_origin", return_value=target)

    def test_helper_only_transition_preserves_full_generation_and_retains_old_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            home = self.make_home(Path(directory))
            old_archive = _archive_with_helper(self.bundle, b"old helper bytes; never execute")
            old_sha = hashlib.sha256(old_archive).hexdigest()
            next_sha = self.digest
            old_manifest, old_files, _old_helper = manual_skills._read_transition_archive(
                old_archive, old_sha)
            new_manifest, new_files, next_helper = manual_skills._read_transition_archive(
                self.bundle, next_sha)
            self.assertEqual(next_helper, Path(manual_skills.__file__).read_bytes())
            self.assertTrue(manual_skills.verify_same_materialization_transition(
                old_manifest, old_files, new_manifest, new_files))
            install_manual_jarvis_skills(old_archive, hermes_home=home,
                                         expected_sha256=old_sha)

            origin = self.helper_pipe()
            with origin:
                result = manual_skills.install_same_materialization_transition(
                    self.bundle, old_archive, hermes_home=home,
                    next_sha256=next_sha, previous_sha256=old_sha,
                    shared_manifest_sha256=manual_skills._same_materialization_digests(
                        new_manifest, new_files)[0],
                    shared_materialization_sha256=manual_skills._same_materialization_digests(
                        new_manifest, new_files)[1],
                    shared_member_count=manual_skills._same_materialization_digests(
                        new_manifest, new_files)[2],
                    backup_name=".jarvis-resources-skills-helper-transition-" + "a" * 32)

            target = home / "skills" / manual_skills._GENERATION
            backup = Path(result["previous_generation_backup"])
            self.assertEqual(result["state"], "staged")
            self.assertEqual(result["artifact_sha256"], next_sha)
            self.assertEqual(backup.name, ".jarvis-resources-skills-helper-transition-" + "a" * 32)
            self.assertEqual((home / "SOUL.md").read_bytes(), b"# Jarvis\n")
            manual_skills._verify_owned_generation(target, new_files, next_sha)
            manual_skills._verify_owned_generation(backup, old_files, old_sha)
            self.assertEqual(
                {name: (target / name).read_bytes() for name in new_files}, new_files)
            self.assertEqual(
                {name: (backup / name).read_bytes() for name in old_files}, old_files)

    def test_helper_only_classifier_rejects_materialized_or_manifest_drift(self):
        old_archive = _archive_with_helper(self.bundle, b"old helper bytes")
        old_sha = hashlib.sha256(old_archive).hexdigest()
        old_manifest, old_files, _ = manual_skills._read_transition_archive(old_archive, old_sha)
        new_manifest, new_files, _ = manual_skills._read_transition_archive(self.bundle, self.digest)

        semantic_change = json.loads(json.dumps(new_manifest))
        semantic_change["readiness"]["enabled"] = True
        self.assertFalse(manual_skills.verify_same_materialization_transition(
            old_manifest, old_files, semantic_change, new_files))

        changed_files = dict(new_files)
        member = next(iter(changed_files))
        changed_files[member] += b" changed"
        self.assertFalse(manual_skills.verify_same_materialization_transition(
            old_manifest, old_files, new_manifest, changed_files))

        unknown_installer_field = json.loads(json.dumps(new_manifest))
        unknown_installer_field["installer"]["ignored"] = True
        self.assertFalse(manual_skills.verify_same_materialization_transition(
            old_manifest, old_files, unknown_installer_field, new_files))

    def test_helper_only_transition_rejects_wrong_root_bound_shared_digest_before_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            home = self.make_home(Path(directory))
            old_archive = _archive_with_helper(self.bundle, b"old helper bytes")
            old_sha = hashlib.sha256(old_archive).hexdigest()
            old_manifest, old_files, _ = manual_skills._read_transition_archive(old_archive, old_sha)
            new_manifest, new_files, _ = manual_skills._read_transition_archive(self.bundle, self.digest)
            install_manual_jarvis_skills(old_archive, hermes_home=home, expected_sha256=old_sha)
            target = home / "skills" / manual_skills._GENERATION
            before = {name: (target / name).read_bytes() for name in old_files}
            shared_manifest, shared_tree, shared_count = manual_skills._same_materialization_digests(
                new_manifest, new_files)

            origin = self.helper_pipe()
            with origin, self.assertRaisesRegex(
                    manual_skills.ManualJarvisSkillsError, "proof digest differs"):
                manual_skills.install_same_materialization_transition(
                    self.bundle, old_archive, hermes_home=home,
                    next_sha256=self.digest, previous_sha256=old_sha,
                    shared_manifest_sha256=shared_manifest,
                    shared_materialization_sha256="0" * 64,
                    shared_member_count=shared_count,
                    backup_name=".jarvis-resources-skills-helper-transition-" + "b" * 32)

            self.assertEqual({name: (target / name).read_bytes() for name in old_files}, before)
            self.assertFalse(any(path.name.startswith(".jarvis-resources-skills-")
                                 for path in home.iterdir()))

    def test_helper_transition_restore_exchanges_only_the_exact_retained_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            home = self.make_home(Path(directory))
            old_archive = _archive_with_helper(self.bundle, b"old helper bytes; retained, never executed")
            old_sha = hashlib.sha256(old_archive).hexdigest()
            old_manifest, old_files, _ = manual_skills._read_transition_archive(old_archive, old_sha)
            new_manifest, new_files, _ = manual_skills._read_transition_archive(self.bundle, self.digest)
            shared = manual_skills._same_materialization_digests(new_manifest, new_files)
            manual_skills.install_manual_jarvis_skills(
                old_archive, hermes_home=home, expected_sha256=old_sha)
            backup_name = ".jarvis-resources-skills-helper-transition-" + "c" * 32
            origin = self.helper_pipe()
            with patch.object(manual_skills, "_JARVIS_HOME", home), origin:
                staged = manual_skills.install_same_materialization_transition(
                    self.bundle, old_archive, hermes_home=home,
                    next_sha256=self.digest, previous_sha256=old_sha,
                    shared_manifest_sha256=shared[0],
                    shared_materialization_sha256=shared[1],
                    shared_member_count=shared[2], backup_name=backup_name)
            current_path = home / "skills" / manual_skills._GENERATION
            retained_path = home / backup_name
            self.assertEqual(staged["previous_generation_backup"], str(retained_path))
            with patch.object(manual_skills, "_JARVIS_HOME", home), origin:
                restored = manual_skills.restore_same_materialization_generation(
                    self.bundle, old_archive, hermes_home=home,
                    current_sha256=self.digest, restore_sha256=old_sha,
                    backup_name=backup_name, shared_manifest_sha256=shared[0],
                    shared_materialization_sha256=shared[1], shared_member_count=shared[2])
            self.assertEqual(restored["state"], "restored")
            manual_skills._verify_owned_generation(current_path, old_files, old_sha)
            manual_skills._verify_owned_generation(retained_path, new_files, self.digest)
            self.assertEqual({name: (current_path / name).read_bytes() for name in old_files}, old_files)
            self.assertEqual({name: (retained_path / name).read_bytes() for name in new_files}, new_files)

    def test_helper_transition_restore_refuses_changed_retained_backup_before_exchange(self):
        with tempfile.TemporaryDirectory() as directory:
            home = self.make_home(Path(directory))
            old_archive = _archive_with_helper(self.bundle, b"old helper bytes")
            old_sha = hashlib.sha256(old_archive).hexdigest()
            old_manifest, old_files, _ = manual_skills._read_transition_archive(old_archive, old_sha)
            new_manifest, new_files, _ = manual_skills._read_transition_archive(self.bundle, self.digest)
            shared = manual_skills._same_materialization_digests(new_manifest, new_files)
            manual_skills.install_manual_jarvis_skills(
                old_archive, hermes_home=home, expected_sha256=old_sha)
            backup_name = ".jarvis-resources-skills-helper-transition-" + "d" * 32
            origin = self.helper_pipe()
            with patch.object(manual_skills, "_JARVIS_HOME", home), origin:
                manual_skills.install_same_materialization_transition(
                    self.bundle, old_archive, hermes_home=home,
                    next_sha256=self.digest, previous_sha256=old_sha,
                    shared_manifest_sha256=shared[0],
                    shared_materialization_sha256=shared[1],
                    shared_member_count=shared[2], backup_name=backup_name)
            backup = home / backup_name
            (backup / "foreign-edit").write_bytes(b"must be preserved")
            current = home / "skills" / manual_skills._GENERATION
            before = {name: (current / name).read_bytes() for name in new_files}
            with patch.object(manual_skills, "_JARVIS_HOME", home), \
                    patch.object(manual_skills, "_verify_helper_transition_origin", return_value=current), \
                    self.assertRaises(manual_skills.ManualJarvisSkillsError):
                manual_skills.restore_same_materialization_generation(
                    self.bundle, old_archive, hermes_home=home,
                    current_sha256=self.digest, restore_sha256=old_sha,
                    backup_name=backup_name, shared_manifest_sha256=shared[0],
                    shared_materialization_sha256=shared[1], shared_member_count=shared[2])
            self.assertEqual({name: (current / name).read_bytes() for name in new_files}, before)
            self.assertEqual((backup / "foreign-edit").read_bytes(), b"must be preserved")

    def test_import_bundled_migration_main_reads_retained_archive_from_stdin(self):
        previous_archive = b"exact retained prior Resources archive"
        previous_sha = manual_skills.LEGACY_MATERIALIZED_ARTIFACT_SHA256
        receipt = {"state": "installed", "artifact_sha256": "a" * 64}
        stdin = io.TextIOWrapper(io.BytesIO(previous_archive))
        with patch("sys.stdin", stdin), \
             patch.object(manual_skills, "install_bundled_resources",
                           return_value=receipt) as importer:
            result = manual_skills.main([
                "import-bundled", "--home", "/tmp/hermes-home",
                "--hermes-source", "/opt/hermes-source", "--python", "/opt/python",
                "--replace-owned-from-sha256", previous_sha,
            ])
        self.assertEqual(result, 0)
        importer.assert_called_once_with(
            hermes_home="/tmp/hermes-home", hermes_source="/opt/hermes-source",
            python="/opt/python", replace_owned_from_archive=previous_archive,
            replace_owned_from_sha256=previous_sha,
        )

    def test_helper_transition_cli_denies_direct_caller_before_any_generation_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            home = self.make_home(Path(directory))
            args = [
                "import-helper-transition", "--home", str(home),
                "--next-sha256", "a" * 64, "--previous-sha256", "b" * 64,
                "--shared-manifest-sha256", "c" * 64,
                "--shared-materialization-sha256", "d" * 64,
                "--shared-member-count", "1",
            ]
            stdin = io.TextIOWrapper(io.BytesIO(b"not an inherited root pipe"))
            with patch("sys.stdin", stdin), patch.object(
                    manual_skills, "install_same_materialization_transition") as importer:
                with self.assertRaises(SystemExit):
                    manual_skills.main(args)
            importer.assert_not_called()
            self.assertFalse((home / "skills" / manual_skills._GENERATION).exists())

    def test_helper_transition_origin_rejects_foreign_regular_file_before_parent_lookup(self):
        account = manual_skills.pwd.getpwnam("admin")
        with tempfile.TemporaryDirectory() as directory:
            foreign = Path(directory) / "foreign-input"
            foreign.write_bytes(b"archives cannot authorize this transition")
            with foreign.open("rb") as source:
                with patch.object(manual_skills.sys, "platform", "linux"), \
                     patch.object(manual_skills.os, "getresuid",
                                  return_value=(account.pw_uid,) * 3), \
                     patch.object(manual_skills.os, "geteuid", return_value=account.pw_uid), \
                     patch.object(manual_skills.os, "getresgid",
                                  return_value=(account.pw_gid,) * 3), \
                     patch.object(manual_skills.os, "fstat", return_value=os.fstat(source.fileno())), \
                     patch.object(manual_skills, "_proc_identity") as parent_lookup:
                    with self.assertRaises(ManualJarvisSkillsError):
                        manual_skills._verify_helper_transition_origin(
                            argparse.Namespace(home="/home/admin/.hermes"))
                    parent_lookup.assert_not_called()

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0,
                         "requires the identified Linux Pi root test role")
    def test_helper_transition_origin_requires_stable_runuser_parent_lineage(self):
        account = pwd.getpwnam("admin")
        with tempfile.TemporaryDirectory(prefix="hermes-origin-lineage-") as directory:
            home = self.make_home(Path(directory))
            target = home / "skills" / manual_skills._GENERATION
            target.mkdir()
            os.chown(home, account.pw_uid, account.pw_gid)
            os.chown(home / "skills", account.pw_uid, account.pw_gid)
            os.chown(target, account.pw_uid, account.pw_gid)
            pipe = type("PipeStat", (), {
                "st_mode": stat.S_IFIFO | 0o600, "st_uid": 0,
                "st_ino": 987654, "st_dev": 1,
            })()
            child_pid = os.getpid()
            parent_pid = child_pid + 1
            parent_identity = (child_pid + 2, 12345, "runuser", (0, 0, 0, 0))
            real_readlink = os.readlink

            def readlink(path, *args, **kwargs):
                if path == "/proc/self/fd/0":
                    return f"pipe:[{pipe.st_ino}]"
                return real_readlink(path, *args, **kwargs)

            with patch.object(manual_skills.os, "getresuid",
                              return_value=(account.pw_uid,) * 3), \
                 patch.object(manual_skills.os, "geteuid", return_value=account.pw_uid), \
                 patch.object(manual_skills.os, "getresgid",
                              return_value=(account.pw_gid,) * 3), \
                 patch.object(manual_skills.os, "getppid", return_value=parent_pid), \
                 patch.object(manual_skills.os, "fstat", return_value=pipe), \
                 patch("fcntl.fcntl", return_value=os.O_RDONLY), \
                 patch.object(manual_skills.os, "readlink", side_effect=readlink), \
                 patch.object(manual_skills, "_proc_identity",
                              return_value=parent_identity) as identity:
                self.assertEqual(manual_skills._verify_helper_transition_origin(
                    argparse.Namespace(home=str(home))), target)
            self.assertEqual(identity.call_count, 2)

            changed = (parent_identity[0], parent_identity[1] + 1,
                       parent_identity[2], parent_identity[3])
            with patch.object(manual_skills.os, "getresuid",
                              return_value=(account.pw_uid,) * 3), \
                 patch.object(manual_skills.os, "geteuid", return_value=account.pw_uid), \
                 patch.object(manual_skills.os, "getresgid",
                              return_value=(account.pw_gid,) * 3), \
                 patch.object(manual_skills.os, "getppid", return_value=parent_pid), \
                 patch.object(manual_skills.os, "fstat", return_value=pipe), \
                 patch("fcntl.fcntl", return_value=os.O_RDONLY), \
                 patch.object(manual_skills.os, "readlink", side_effect=readlink), \
                 patch.object(manual_skills, "_proc_identity",
                              side_effect=(parent_identity, changed)):
                with self.assertRaisesRegex(
                        ManualJarvisSkillsError, "fixed root runuser and inherited root pipe"):
                    manual_skills._verify_helper_transition_origin(
                        argparse.Namespace(home=str(home)))

    @unittest.skipUnless(sys.platform.startswith("linux") and os.geteuid() == 0
                         and Path("/usr/sbin/runuser").is_file()
                         and core_runtime.PYTHON.is_file(),
                         "requires the identified Linux Pi root test environment")
    def test_helper_transition_cli_root_runuser_pipe_preserves_full_generation(self):
        account = pwd.getpwnam("admin")
        old_archive = _archive_with_helper(self.bundle, b"retained old helper fixture")
        old_sha = hashlib.sha256(old_archive).hexdigest()
        old_manifest, old_files, _old_helper = manual_skills._read_transition_archive(
            old_archive, old_sha)
        new_manifest, new_files, _new_helper = manual_skills._read_transition_archive(
            self.bundle, self.digest)
        self.assertTrue(manual_skills.verify_same_materialization_transition(
            old_manifest, old_files, new_manifest, new_files))
        shared_manifest, shared_tree, shared_count = manual_skills._same_materialization_digests(
            new_manifest, new_files)

        # The runuser child validates and resolves this admin-owned home. The
        # runner's TMPDIR is intentionally root-private, so put only this real
        # cross-UID fixture under the searchable system /run parent.
        with tempfile.TemporaryDirectory(prefix="hermes-helper-transition-", dir="/run") as directory:
            base = Path(directory)
            os.chown(base, account.pw_uid, account.pw_gid)
            home = self.make_home(base)
            backup_name = ".jarvis-resources-skills-helper-transition-" + "e" * 32
            manual_skills.install_manual_jarvis_skills(
                old_archive, hermes_home=home, expected_sha256=old_sha)
            for root, directories, filenames in os.walk(home, topdown=False, followlinks=False):
                for filename in filenames:
                    os.chown(Path(root) / filename, account.pw_uid, account.pw_gid,
                             follow_symlinks=False)
                for dirname in directories:
                    os.chown(Path(root) / dirname, account.pw_uid, account.pw_gid,
                             follow_symlinks=False)
            os.chown(home, account.pw_uid, account.pw_gid)

            cli_args = [
                "hermes_installer.registry.manual_jarvis_skills", "import-helper-transition",
                "--home", str(home), "--next-sha256", self.digest,
                "--previous-sha256", old_sha,
                "--shared-manifest-sha256", shared_manifest,
                "--shared-materialization-sha256", shared_tree,
                "--shared-member-count", str(shared_count),
                "--backup-name", backup_name,
            ]
            env = {
                "HOME": str(home.parent), "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8", "PYTHONPATH": str(Path(manual_skills.__file__).parents[2]),
                "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
            }
            # The origin verifier compares the runuser child's argv with its
            # own sys.executable. Use the resolved executable spelling so a
            # venv symlink cannot make the legitimate root invocation differ.
            interpreter = str(Path(core_runtime.PYTHON).resolve(strict=True))
            framed = struct.pack(">QQ", len(self.bundle), len(old_archive)) + self.bundle + old_archive
            direct_owner_script = (
                "import subprocess,sys; "
                "p=subprocess.run([sys.executable,'-P','-m',"
                "'hermes_installer.registry.manual_jarvis_skills',*sys.argv[1:]], "
                "input=sys.stdin.buffer.read(33554449),stdout=subprocess.PIPE,"
                "stderr=subprocess.PIPE,check=False); "
                "raise SystemExit(0 if p.returncode==2 and "
                "b'fixed root runuser and inherited root pipe' in p.stderr else 91)"
            )
            direct_owner = subprocess.run(
                ["/usr/sbin/runuser", "-u", "admin", "--", interpreter,
                 "-P", "-c", direct_owner_script, *cli_args[1:]],
                input=framed, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=600, env=env, check=False)
            self.assertEqual(direct_owner.returncode, 0,
                             direct_owner.stderr.decode("utf-8", "replace"))

            command = [
                "/usr/sbin/runuser", "-u", "admin", "--", interpreter, "-P", "-m",
                *cli_args,
            ]
            result = subprocess.run(command, input=framed, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=600, env=env, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            receipt = json.loads(result.stdout)
            target = home / "skills" / manual_skills._GENERATION
            backup = Path(receipt["previous_generation_backup"])
            self.assertEqual(receipt["state"], "staged")
            self.assertEqual(receipt["previous_artifact_sha256"], old_sha)
            self.assertEqual(backup, home / backup_name)

            def assert_generation(path, files, digest):
                expected_files = set(files) | {manual_skills._OWNER_FILE}
                expected_dirs = {
                    "/".join(Path(name).parts[:depth])
                    for name in files for depth in range(1, len(Path(name).parts))
                }
                actual_files = {item.relative_to(path).as_posix() for item in path.rglob("*")
                                if item.is_file() and not item.is_symlink()}
                actual_dirs = {item.relative_to(path).as_posix() for item in path.rglob("*")
                               if item.is_dir() and not item.is_symlink()}
                self.assertEqual(actual_files, expected_files)
                self.assertEqual(actual_dirs, expected_dirs)
                self.assertEqual((path / manual_skills._OWNER_FILE).read_bytes(),
                                 manual_skills._owned_generation_journal(files, digest))
                for name, content in files.items():
                    member = path / name
                    metadata = member.lstat()
                    self.assertTrue(stat.S_ISREG(metadata.st_mode))
                    self.assertEqual(metadata.st_uid, account.pw_uid)
                    self.assertEqual(metadata.st_size, len(content))
                    self.assertEqual(hashlib.sha256(member.read_bytes()).digest(),
                                     hashlib.sha256(content).digest())

            assert_generation(target, new_files, self.digest)
            assert_generation(backup, old_files, old_sha)

    def test_compiled_master_semantics_are_distinct_from_verbatim_upstream(self):
        manifest, files = _read_artifact(self.bundle, self.digest)
        overlay = manifest["effective_overlay"]
        profiles = {row["source_id"]: row for row in manifest["profile_members"]}
        self.assertEqual(overlay["overlay_id"], "jarvis-master-semantics-v2")
        self.assertEqual(overlay["approval_commit"], "aab3b666023559c0d9112633212e0194dcc7af97")
        self.assertEqual(overlay["sha256"], overlay_identity()["sha256"])
        self.assertEqual(len(manifest["skill_members"]), 396)
        self.assertEqual(len(manifest["profile_members"]), 208)
        self.assertEqual(set(overlay["compiled_profiles"]), {"hermes", "orchestrator"})
        for profile_id in ("hermes", "orchestrator"):
            row = profiles[profile_id]
            self.assertNotEqual(row["upstream_compiled_identity_sha256"], row["identity_sha256"])
            original = files[f"registry/package/upstream-source/profiles/{profile_id}.yaml"]
            self.assertNotEqual(row["source_document_sha256"], row["source_declaration_sha256"])
            self.assertEqual(hashlib.sha256(original).hexdigest(), row["source_declaration_sha256"])
            self.assertEqual(overlay["source_declarations"][f"profiles/{profile_id}.yaml"],
                             hashlib.sha256(original).hexdigest())
        for profile_id, row in profiles.items():
            if profile_id not in {"hermes", "orchestrator"}:
                self.assertEqual(row["upstream_compiled_identity_sha256"], row["identity_sha256"])
        jarvis = files["registry/profiles/hermes/SOUL.md"].decode("utf-8")
        coordinator = files["registry/profiles/orchestrator/SOUL.md"].decode("utf-8")
        self.assertIn("sole user-facing MASTER", jarvis)
        self.assertIn("OneShot", jarvis)
        self.assertIn("Only Jarvis may make the final", jarvis)
        self.assertIn("not a mandatory hop", jarvis)
        self.assertNotIn("Compose every user-facing response using all six sections", jarvis)
        self.assertIn("directSpecialistDispatch: internal-only", jarvis)
        self.assertIn("without creating a project board", coordinator)
        self.assertIn("Never publish or perform final external", coordinator)
        self.assertEqual(hashlib.sha256(
            files[overlay["compiled_bundle"]["effective_archive_path"]]).hexdigest(),
            overlay["compiled_bundle"]["effective_sha256"])

    def test_master_overlay_rejects_unpinned_upstream_source(self):
        with self.assertRaises(JarvisSemanticsError):
            effective_profile_spec("hermes", {"instructions": []},
                                   {"revision": "0" * 40, "source_tree": "1" * 40})

    def test_generation_migration_proof_rejects_any_modified_owned_member(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            staged = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            _manifest, files = _read_artifact(self.bundle, self.digest)
            generation = Path(staged["generation_path"])
            expected_dirs = {
                "/".join(Path(name).parts[:depth])
                for name in files for depth in range(1, len(Path(name).parts))
            }
            self.assertEqual(_verify_owned_generation(generation, files, self.digest), expected_dirs)
            victim = generation / "registry/profiles/orchestrator/SOUL.md"
            victim.write_bytes(victim.read_bytes() + b"user edit")
            with self.assertRaises(ManualJarvisSkillsError):
                _verify_owned_generation(generation, files, self.digest)

    def test_resources_skill_overlay_changes_only_selected_pinned_document(self):
        original_manifest, original_files = _read_artifact(self.bundle, self.digest)
        skill_id = "conversation-gateway"
        original = pinned_skill_bytes(self.bundle, skill_id)
        edited = original + b"\nOwner note: use the reviewed local gateway.\n"
        effective, effective_sha = build_effective_artifact(self.bundle, skill_id, edited)
        next_manifest, next_files = _read_artifact(effective, effective_sha)
        self.assertEqual(original_files, _read_artifact(self.bundle, self.digest)[1])
        changed = {name for name in original_files if original_files[name] != next_files[name]}
        self.assertEqual(changed, {f"skills/{skill_id}/SKILL.md"})
        self.assertEqual(next_files[f"skills/{skill_id}/SKILL.md"], edited)
        self.assertEqual(next_manifest["source"], original_manifest["source"])
        self.assertEqual(next_manifest["profile_members"], original_manifest["profile_members"])
        _verify_owner_skill_overlay_transition(original_manifest, original_files, self.digest,
                                               next_manifest, next_files)

    def test_resources_skill_overlay_rejects_identity_change_and_protected_delta(self):
        with self.assertRaises(ResourcesSkillOverlayError):
            build_effective_artifact(self.bundle, "conversation-gateway",
                b"---\nname: other-skill\n\nnot the selected identity\n")
        original_manifest, original_files = _read_artifact(self.bundle, self.digest)
        effective, effective_sha = build_effective_artifact(self.bundle, "conversation-gateway",
            pinned_skill_bytes(self.bundle, "conversation-gateway") + b"\nowner edit\n")
        next_manifest, next_files = _read_artifact(effective, effective_sha)
        protected = "registry/profiles/orchestrator/SOUL.md"
        altered_files = dict(next_files)
        altered_files[protected] += b"unexpected change"
        with self.assertRaises(ManualJarvisSkillsError):
            _verify_owner_skill_overlay_transition(original_manifest, original_files, self.digest,
                                                   next_manifest, altered_files)

    def test_stage_is_namespaced_owned_idempotent_and_preserves_existing_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            before = {
                "soul": (home / "SOUL.md").read_bytes(),
                "config": (home / "config.yaml").read_bytes(),
                "memory": (home / "memories" / "keep.txt").read_bytes(),
                "user_skill": (home / "skills/user-owned/SKILL.md").read_bytes(),
            }
            result = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(result["state"], "staged")
            self.assertFalse(result["discovered"])
            generation = Path(result["generation_path"])
            journal = json.loads((generation / ".hermes-installer-resource-ownership.json").read_text())
            _manifest, artifact_files = _read_artifact(self.bundle, self.digest)
            self.assertEqual(len(journal["members"]), len(artifact_files))
            expected_skill_paths = {
                f"installer-resources-113f42d33be9/{name}"
                for name in artifact_files if name.startswith("skills/")
            }
            self.assertEqual(
                {row["path"] for row in journal["members"]
                 if row["path"].startswith("installer-resources-113f42d33be9/skills/")
                 and row["path"].endswith("/SKILL.md")},
                expected_skill_paths)
            self.assertEqual(len(list((generation / "skills").glob("*/SKILL.md"))), _BUNDLE_SKILL_COUNT)
            self.assertEqual(len(list((generation / "registry/profiles").glob("*/SOUL.md"))), _BUNDLE_PROFILE_COUNT)
            self.assertFalse((home / "profiles").exists())
            self.assertEqual((home / "SOUL.md").read_bytes(), before["soul"])
            self.assertEqual((home / "config.yaml").read_bytes(), before["config"])
            self.assertEqual((home / "memories/keep.txt").read_bytes(), before["memory"])
            self.assertEqual((home / "skills/user-owned/SKILL.md").read_bytes(), before["user_skill"])

            again = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(again["state"], "already-staged")
            self.assertEqual(again["generation_path"], result["generation_path"])

    def test_nested_generation_permissions_ignore_umask_and_repair_only_verified_drift(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            previous = os.umask(0o002)
            try:
                result = install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            finally:
                os.umask(previous)
            generation = Path(result["generation_path"])
            nested = generation / "skills" / "conversation-gateway"
            self.assertEqual(nested.stat().st_mode & 0o777, 0o755)
            nested.chmod(0o775)
            unrelated = home / "skills" / "user-owned"
            unrelated.chmod(0o775)

            repeated = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)

            self.assertEqual(repeated["state"], "already-staged")
            self.assertEqual(nested.stat().st_mode & 0o777, 0o755)
            self.assertEqual(unrelated.stat().st_mode & 0o777, 0o775)

    def test_unowned_generation_conflict_and_wrong_bundle_digest_fail_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            target = home / "skills/installer-resources-113f42d33be9"
            target.mkdir()
            sentinel = target / "keep.txt"
            sentinel.write_text("unowned bytes\n", encoding="utf-8")
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256="0" * 64)
            self.assertEqual(sentinel.read_text(), "unowned bytes\n")
            self.assertEqual(set(p.name for p in (home / "skills").iterdir()),
                             {target.name, "user-owned"})
            self.assertEqual((home / "skills/user-owned/SKILL.md").read_text(), "user bytes\n")

    def test_modified_owned_skill_is_preserved_and_rerun_refuses_adoption(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            result = install_manual_jarvis_skills(
                self.bundle, hermes_home=home, expected_sha256=self.digest)
            skill = Path(result["generation_path"]) / "skills/conversation-gateway/SKILL.md"
            skill.write_text("user edit\n", encoding="utf-8")
            with self.assertRaises(ManualJarvisSkillsError):
                install_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest)
            self.assertEqual(skill.read_text(), "user edit\n")

    def test_import_receipt_requires_actual_native_readback_for_every_bundled_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            manifest, files = _read_artifact(self.bundle, self.digest)
            skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
            content_digests = {
                f"skill:{name}": hashlib.sha256(files[f"skills/{name}/SKILL.md"]).hexdigest()
                for name in skill_ids
            }
            content_digests["profile:default"] = hashlib.sha256(
                files["registry/profiles/hermes/SOUL.md"]).hexdigest()
            receipt = NativeInstallReceipt(
                hermes_revision="7085fbf7753266fc4943c55ac04926186bc90005",
                python_version="3.14.7", profile_id="default", discovered_profile=True,
                profile_identity_loaded=True, profile_display_name="Jarvis",
                discovered_skills=skill_ids, loaded_skills=skill_ids,
                content_digests=content_digests,
            )
            with patch("hermes_installer.registry.native_install.discover_and_load_selected",
                       return_value=receipt) as discover:
                result = install_and_verify_manual_jarvis_skills(
                    self.bundle, hermes_home=home, expected_sha256=self.digest,
                    hermes_source="/pin/hermes", python="/pin/python")
            self.assertEqual(result["state"], "discovered")
            self.assertTrue(result["discovered"])
            self.assertEqual(result["resource_counts"]["native_skills"], _BUNDLE_SKILL_COUNT)
            self.assertEqual(result["resource_counts"]["internal_profiles"], _BUNDLE_PROFILE_COUNT - 1)
            self.assertEqual(result["native_receipt"]["loaded_skill_count"], _BUNDLE_SKILL_COUNT)
            self.assertEqual(set(result["selectable_profile_mutations"]), set())
            self.assertTrue(result["native_receipt"]["active_prompt_matches_bundled_primary"])
            discover.assert_called_once()
            self.assertEqual(set(discover.call_args.kwargs["skill_ids"]), set(skill_ids))

    def test_import_never_claims_native_discovery_when_loaded_bytes_differ(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = self.make_home(tmp)
            manifest, files = _read_artifact(self.bundle, self.digest)
            skill_ids = tuple(sorted(row["skill_id"] for row in manifest["skill_members"]))
            content_digests = {
                f"skill:{name}": hashlib.sha256(files[f"skills/{name}/SKILL.md"]).hexdigest()
                for name in skill_ids
            }
            content_digests["skill:" + skill_ids[0]] = "0" * 64
            receipt = NativeInstallReceipt(
                hermes_revision="7085fbf7753266fc4943c55ac04926186bc90005",
                python_version="3.14.7", profile_id="default", discovered_profile=True,
                profile_identity_loaded=True, profile_display_name="Jarvis",
                discovered_skills=skill_ids, loaded_skills=skill_ids,
                content_digests=content_digests,
            )
            with patch("hermes_installer.registry.native_install.discover_and_load_selected",
                       return_value=receipt):
                with self.assertRaises(ManualJarvisSkillsError):
                    install_and_verify_manual_jarvis_skills(
                        self.bundle, hermes_home=home, expected_sha256=self.digest,
                        hermes_source="/pin/hermes", python="/pin/python")
            self.assertTrue((home / "skills/installer-resources-113f42d33be9").is_dir())

    def test_artifact_reader_rejects_duplicate_archive_members(self):
        output = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(self.bundle), "r") as original:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as changed:
                    for info in original.infolist():
                        changed.writestr(info.filename, original.read(info.filename))
                    duplicate = next(name for name in original.namelist()
                                     if name.startswith("skills/") and name.endswith("/SKILL.md"))
                    changed.writestr(duplicate, original.read(duplicate))
        data = output.getvalue()
        with self.assertRaises(ManualJarvisSkillsError):
            _read_artifact(data, hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
