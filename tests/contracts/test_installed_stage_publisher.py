"""Effect and recovery tests for fixed root installed-stage publication."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentError, BootstrapEnrollmentPending
from hermes_installer.authority.installed_stage_publisher import (
    _build_rows, _canonical, _ensure_release_store_children, _open_owned_directory_chain,
    _publish_retained_build, _recover_staging_journals, _sha,
    _rollback_update_transaction, _write_update_transaction,
)
from hermes_installer.authority import installer_release_build as release_build
from hermes_installer.authority.installer_release import REVIEWED_SOURCE_ARTIFACTS, REVIEWED_SOURCE_MODULES
from hermes_installer.authority.application_effect_source_catalog import APPLICATION_EFFECT_SOURCE_MEMBERS


@dataclass(frozen=True)
class FileRow:
    relative_path: str
    sha256: str
    size_bytes: int
    mode: int
    roles: tuple[str, ...]
    device: int
    inode: int


@dataclass(frozen=True)
class Predecessor:
    parent_device: int
    parent_inode: int
    state: str = "absent"
    sha256: str | None = None
    device: int | None = None
    inode: int | None = None
    candidate_git_sha: str | None = None


class BuildReceipt:
    def __init__(self, path: Path, files: tuple[FileRow, ...], output_root: Path):
        self.candidate_git_sha = "a" * 40
        self.receipt_handle = "receipt_handle_for_test_0123456789abcdef"
        self.files = files
        self.output_device = os.stat(output_root).st_dev
        self.closure_manifest_relative_path = "release-manifest.json"
        self.closure_manifest_sha256 = ""  # The writer independently recomputes the canonical closure manifest.
        rows = [{"relative_path": f.relative_path, "sha256": f.sha256,
                 "size_bytes": f.size_bytes, "mode": f.mode, "roles": list(f.roles)} for f in files]
        self.role_closure_manifest_sha256 = _sha(_canonical({
            "schema": 1, "candidate_git_sha": self.candidate_git_sha, "files": rows}))
        self.closure_manifest_sha256 = self.role_closure_manifest_sha256
        self.baseline_tree_sha256 = _sha(_canonical({
            f.relative_path.removeprefix("plans/2026-10-09-v1/"): f.sha256
            for f in files if f.relative_path.startswith("plans/2026-10-09-v1/")
        }))
        self.source_tree_sha256 = "b" * 64
        self._path = path

    def verify_current(self):
        return None

    def open_file(self, relative_path: str) -> int:
        if relative_path != self.files[0].relative_path:
            raise ValueError("unexpected path")
        return os.open(self._path, os.O_RDONLY | os.O_NOFOLLOW)


class InstalledStagePublicationTests(unittest.TestCase):
    def _fixture(self, temp: str):
        root = Path(temp).resolve()
        output = root / "output"
        output.mkdir(mode=0o700)
        source = output / "baseline-file"
        source.write_bytes(b"verified source bytes")
        os.chmod(source, 0o444)
        data = source.read_bytes()
        source_info = os.stat(source)
        row = FileRow("plans/2026-10-09-v1/README.md", hashlib.sha256(data).hexdigest(),
                      len(data), 0o444, ("baseline",), source_info.st_dev, source_info.st_ino)
        receipt = BuildReceipt(source, (row,), output)
        deploy = root / "deployments"
        deploy.mkdir(mode=0o700)
        releases = root / "releases"
        releases.mkdir(mode=0o700)
        predecessor = Predecessor(os.stat(deploy).st_dev, os.stat(deploy).st_ino)
        return root, receipt, deploy / "current.json", releases / receipt.candidate_git_sha, predecessor

    def test_fixed_release_store_children_are_created_once_without_touching_siblings(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "usr-lib"
            parent.mkdir(mode=0o700)
            sentinel = parent / "foreign-service"
            sentinel.write_bytes(b"preserve")
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _ensure_release_store_children(parent_fd, expected_uid=os.getuid(), expected_gid=os.getgid())
                first = parent / "hermes-installer" / "releases"
                identity = (first.stat().st_dev, first.stat().st_ino)
                _ensure_release_store_children(parent_fd, expected_uid=os.getuid(), expected_gid=os.getgid())
                self.assertEqual((first.stat().st_dev, first.stat().st_ino), identity)
                self.assertEqual(first.stat().st_mode & 0o777, 0o755)
                self.assertEqual(sentinel.read_bytes(), b"preserve")
                self.assertEqual({item.name for item in parent.iterdir()},
                                 {"foreign-service", "hermes-installer"})
            finally:
                os.close(parent_fd)

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "usr-lib"
            parent.mkdir(mode=0o700)
            hermes = parent / "hermes-installer"
            hermes.mkdir(mode=0o755)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _ensure_release_store_children(parent_fd, expected_uid=os.getuid() + 1,
                                                   expected_gid=os.getgid())
                self.assertEqual(hermes.stat().st_uid, os.getuid())
                self.assertFalse((hermes / "releases").exists())
            finally:
                os.close(parent_fd)

    def test_missing_release_store_is_created_before_local_publication_and_readback(self):
        with tempfile.TemporaryDirectory() as temp:
            root, receipt, record_path, _unused_release, _ = self._fixture(temp)
            deploy = record_path.parent
            predecessor = Predecessor(os.stat(deploy).st_dev, os.stat(deploy).st_ino)
            base = root / "usr-lib"
            base.mkdir(mode=0o700)
            base_fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _ensure_release_store_children(base_fd, expected_uid=os.getuid(), expected_gid=os.getgid())
            finally:
                os.close(base_fd)
            release = base / "hermes-installer" / "releases" / receipt.candidate_git_sha
            self.assertTrue(release.parent.is_dir())
            _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                    expected_uid=os.getuid(), predecessor=predecessor)
            record = json.loads(record_path.read_bytes())
            self.assertEqual(record["release_root"], str(release))
            self.assertEqual((release / "plans/2026-10-09-v1/README.md").read_bytes(),
                             b"verified source bytes")
            self.assertEqual(release.stat().st_mode & 0o777, 0o555)

    def test_update_controller_expiry_at_pre_cas_keeps_exact_predecessor_pointer(self):
        """A delayed update cannot switch the pointer after its explicit TTY proof expires."""
        with tempfile.TemporaryDirectory() as temp:
            root, receipt, record_path, release, _absent = self._fixture(temp)
            deploy = record_path.parent
            old_release = root / "releases" / ("c" * 40)
            old_release.mkdir(mode=0o555)
            old_info = old_release.stat()
            old_record = {
                "schema": 1,
                "receipt_id": "r" * 32,
                "candidate_git_sha": "c" * 40,
                "release_root": str(old_release),
                "release_device": old_info.st_dev,
                "release_inode": old_info.st_ino,
                "closure_manifest_relative_path": "release-manifest.json",
                "closure_manifest_sha256": "d" * 64,
                "baseline_tree_sha256": "e" * 64,
                "published_monotonic": 1.0,
            }
            old_raw = _canonical(old_record)
            record_path.write_bytes(old_raw)
            os.chmod(record_path, 0o600)
            pointer_info = record_path.stat()
            parent_info = deploy.stat()
            predecessor = release_build.DeploymentPredecessor(
                "present", parent_info.st_dev, parent_info.st_ino, _sha(old_raw),
                pointer_info.st_dev, pointer_info.st_ino, "c" * 40)
            snapshot = {
                "schema": 1,
                "update_transaction_handle": "u" * 43,
                "candidate_git_sha": receipt.candidate_git_sha,
                "selection_choice_sha256": "f" * 64,
                "lifecycle_action": "update",
                "pointer": {
                    "parent_device": predecessor.parent_device,
                    "parent_inode": predecessor.parent_inode,
                    "candidate_git_sha": predecessor.candidate_git_sha,
                    "sha256": predecessor.sha256,
                    "device": predecessor.device,
                    "inode": predecessor.inode,
                    "canonical_bytes_b64": __import__("base64").b64encode(old_raw).decode("ascii"),
                },
                "release": {
                    "root_device": old_info.st_dev,
                    "root_inode": old_info.st_ino,
                    "closure_manifest_sha256": "d" * 64,
                    "baseline_tree_sha256": "e" * 64,
                    "amendment_manifest_sha256": "a" * 64,
                },
            }
            transition = release_build.RootAdmittedInstallerUpdate(
                release_build._UPDATE_TRANSITION_SEAL,
                update_transaction_handle=snapshot["update_transaction_handle"],
                candidate_git_sha=receipt.candidate_git_sha,
                selection_choice_sha256=snapshot["selection_choice_sha256"],
                predecessor_json=release_build._canonical_json(snapshot),
            )
            expired = BootstrapEnrollmentPending("root TTY candidate controller is no longer current")
            controller = {
                "candidate_git_sha": receipt.candidate_git_sha,
                "lifecycle_action": "update",
                "controller_pid": os.getpid(),
                "controller_start_ticks": 1,
                "expires_monotonic": 2.0,
            }
            with tempfile.TemporaryDirectory(dir=root) as tx_temp:
                tx_root = Path(tx_temp) / "transactions"
                tx_root.mkdir(mode=0o700)
                with (patch.object(release_build.RootAdmittedInstallerUpdate,
                                   "verify_current", return_value=None),
                      patch("hermes_installer.authority.installer_release_build._verify_current_selection_snapshot",
                            side_effect=[None, expired])):
                    with self.assertRaises(BootstrapEnrollmentPending):
                        _publish_retained_build(
                            receipt=receipt, release_root=release, receipt_path=record_path,
                            expected_uid=os.getuid(), predecessor=predecessor,
                            update_transition=transition, controller_snapshot=controller,
                            update_transaction_root=tx_root,
                        )
                transaction = json.loads(
                    (tx_root / (snapshot["update_transaction_handle"] + ".json")).read_bytes())
                self.assertEqual(transaction["state"], "publication-prepared")
            self.assertEqual(record_path.read_bytes(), old_raw)

    def test_update_rollback_never_overwrites_a_concurrent_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            deploy = root / "deployments"
            deploy.mkdir(mode=0o700)
            transactions = root / "transactions"
            transactions.mkdir(mode=0o700)
            handle = "n" * 43
            candidate_raw = _canonical({"candidate_git_sha": "a" * 40, "owned": True})
            newer_raw = _canonical({"candidate_git_sha": "b" * 40, "foreign": True})
            current = deploy / "current.json"
            current.write_bytes(newer_raw)
            os.chmod(current, 0o600)
            transaction = {
                "schema": 1,
                "state": "pointer-published",
                "update_transaction_handle": handle,
                "candidate_git_sha": "a" * 40,
                "candidate_pointer_b64": __import__("base64").b64encode(candidate_raw).decode("ascii"),
                "candidate_pointer_sha256": _sha(candidate_raw),
                "candidate_release_root": str(root / "releases" / ("a" * 40)),
                "candidate_closure_manifest_sha256": "c" * 64,
                "old_pointer": {},
                "old_release": {},
            }
            _write_update_transaction(transactions, handle, transaction, os.getuid())
            with self.assertRaisesRegex(BootstrapEnrollmentPending, "newer or foreign"):
                _rollback_update_transaction(transactions, handle, current, os.getuid())
            self.assertEqual(current.read_bytes(), newer_raw)

    def test_fixed_release_store_directory_conflicts_are_preserved_and_denied(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "usr-lib"
            parent.mkdir(mode=0o700)
            target = Path(temp) / "foreign-target"
            target.mkdir()
            marker = target / "keep"
            marker.write_bytes(b"preserve")
            (parent / "hermes-installer").symlink_to(target, target_is_directory=True)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _ensure_release_store_children(parent_fd, expected_uid=os.getuid(), expected_gid=os.getgid())
                self.assertTrue((parent / "hermes-installer").is_symlink())
                self.assertEqual(marker.read_bytes(), b"preserve")
                self.assertEqual({item.name for item in parent.iterdir()}, {"hermes-installer"})
            finally:
                os.close(parent_fd)

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "usr-lib"
            parent.mkdir(mode=0o700)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            real_open = os.open
            attempts = 0

            def replace_after_mkdir(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal attempts
                if path == "hermes-installer" and dir_fd is not None:
                    attempts += 1
                    if attempts == 2:
                        os.rename("hermes-installer", ".created-original",
                                  src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                        os.mkdir("hermes-installer", 0o755, dir_fd=parent_fd)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            try:
                with patch("hermes_installer.authority.installed_stage_publisher.os.open",
                           side_effect=replace_after_mkdir):
                    with self.assertRaises(BootstrapEnrollmentError):
                        _ensure_release_store_children(parent_fd, expected_uid=os.getuid(),
                                                       expected_gid=os.getgid())
                replacement = parent / "hermes-installer"
                self.assertTrue(replacement.is_dir())
                self.assertEqual({item.name for item in replacement.iterdir()}, set())
                self.assertTrue((parent / ".created-original").is_dir())
                self.assertFalse((replacement / "releases").exists())
            finally:
                os.close(parent_fd)

        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "usr-lib"
            parent.mkdir(mode=0o700)
            hermes = parent / "hermes-installer"
            hermes.mkdir(mode=0o777)
            os.chmod(hermes, 0o777)
            parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _ensure_release_store_children(parent_fd, expected_uid=os.getuid(), expected_gid=os.getgid())
                self.assertEqual(hermes.stat().st_mode & 0o777, 0o777)
                self.assertFalse((hermes / "releases").exists())
            finally:
                os.close(parent_fd)

    def test_fixed_release_store_ancestor_chain_rejects_symlink_and_bad_mode(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir(mode=0o700)
            target_marker = target / "keep"
            target_marker.write_bytes(b"preserve")
            (root / "usr").symlink_to(target, target_is_directory=True)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _open_owned_directory_chain(root_fd, ("usr", "lib"),
                                                 expected_uid=os.getuid(), expected_gid=os.getgid())
                self.assertTrue((root / "usr").is_symlink())
                self.assertEqual(target_marker.read_bytes(), b"preserve")
                self.assertEqual({item.name for item in root.iterdir()}, {"target", "usr"})
            finally:
                os.close(root_fd)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            usr = root / "usr"
            usr.mkdir(mode=0o700)
            lib = usr / "lib"
            lib.mkdir(mode=0o777)
            os.chmod(lib, 0o777)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _open_owned_directory_chain(root_fd, ("usr", "lib"),
                                                 expected_uid=os.getuid(), expected_gid=os.getgid())
                self.assertEqual(lib.stat().st_mode & 0o777, 0o777)
                self.assertEqual(tuple(item.name for item in usr.iterdir()), ("lib",))
            finally:
                os.close(root_fd)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            usr = root / "usr"
            usr.mkdir(mode=0o755)
            lib = usr / "lib"
            lib.mkdir(mode=0o755)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _open_owned_directory_chain(root_fd, ("usr", "lib"),
                                                 expected_uid=os.getuid() + 1,
                                                 expected_gid=os.getgid())
                self.assertTrue(lib.is_dir())
                self.assertEqual({item.name for item in root.iterdir()}, {"usr"})
            finally:
                os.close(root_fd)

    def test_stages_verified_closure_and_publishes_pointer_last(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                    expected_uid=os.getuid(), predecessor=predecessor)
            record = json.loads(record_path.read_bytes())
            self.assertEqual(record["release_root"], str(release))
            self.assertEqual(record["closure_manifest_relative_path"], "release-manifest.json")
            self.assertEqual((release / "plans/2026-10-09-v1/README.md").read_bytes(),
                             b"verified source bytes")
            self.assertEqual((release / "release-manifest.json").read_bytes(), _canonical({
                "schema": 1, "candidate_git_sha": receipt.candidate_git_sha,
                "files": [{"relative_path": receipt.files[0].relative_path,
                           "sha256": receipt.files[0].sha256,
                           "size_bytes": receipt.files[0].size_bytes,
                           "mode": receipt.files[0].mode,
                           "roles": ["baseline"]}]}))
            self.assertEqual(os.stat(release).st_mode & 0o777, 0o555)
            self.assertEqual(os.stat(record_path).st_mode & 0o777, 0o600)

    def test_build_rows_accept_runtime_member_and_reject_unknown_role(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source"
            source.write_bytes(b"retained runtime member")
            info = os.stat(source)
            member = FileRow("runtime/lib/python3.14/os.py", _sha(source.read_bytes()),
                             source.stat().st_size, 0o444, ("runtime-member",), info.st_dev, info.st_ino)
            receipt = BuildReceipt(source, (member,), root)
            self.assertEqual(_build_rows(receipt)[0].roles, ("runtime-member",))
            malformed = FileRow(member.relative_path, member.sha256, member.size_bytes, member.mode,
                                ("invented-runtime-role",), member.device, member.inode)
            with self.assertRaises(BootstrapEnrollmentError):
                _build_rows(BuildReceipt(source, (malformed,), root))

    def _real_role_receipt(self, output: Path, *, overrides=None):
        """Build a sealed typed receipt from the real producer's row sealer."""
        repo = Path(__file__).parents[2]
        overrides = overrides or {}
        output.mkdir(mode=0o700)
        staged = []
        for _artifact_id, path, digest, size, role in REVIEWED_SOURCE_MODULES:
            if role != "source-module":
                continue
            body = (repo / path).read_bytes()
            target = path
            row_override = overrides.get(target)
            if row_override is not None:
                target, row_role, body = row_override
            else:
                row_role = role
                self.assertEqual((len(body), _sha(body)), (size, digest))
            destination = output / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            os.chmod(destination, 0o444)
            staged.append((target, _sha(body), len(body), 0o444, (row_role,)))
        for _artifact_id, path, role, digest, size in APPLICATION_EFFECT_SOURCE_MEMBERS:
            body = (repo / path).read_bytes()
            row_override = overrides.get(path)
            if row_override is not None:
                target, row_role, body = row_override
            else:
                target, row_role = path, role
                self.assertEqual((len(body), _sha(body)), (size, digest))
            destination = output / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            os.chmod(destination, 0o444)
            staged.append((target, _sha(body), len(body), 0o444, (row_role,)))
        for _artifact_id, path, digest, size, role in REVIEWED_SOURCE_ARTIFACTS:
            if role != "native-health-fixture":
                continue
            source_path = {
                "fixtures/native-health/request.txt": "src/hermes_installer/native_health_fixture/request.txt",
                "fixtures/native-health/seed-value.txt": "src/hermes_installer/native_health_fixture/seed-value.txt",
                "fixtures/native-health/expected-tool-result.json":
                    "src/hermes_installer/native_health_fixture/expected-tool-result.json",
                "fixtures/native-health/tool-result.schema.json":
                    "src/hermes_installer/native_health_fixture/tool-result.schema.json",
                "fixtures/native-health/recipe.json": "src/hermes_installer/native_health_fixture/recipe.json",
            }[path]
            body = (repo / source_path).read_bytes()
            row_override = overrides.get(path)
            if row_override is not None:
                target, row_role, body = row_override
            else:
                target, row_role = path, role
                self.assertEqual((len(body), _sha(body)), (size, digest))
            destination = output / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(body)
            os.chmod(destination, 0o444)
            staged.append((target, _sha(body), len(body), 0o444, (row_role,)))

        output_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        try:
            rows = release_build.RootInstalledReleaseBuilder._seal_output_rows(
                object.__new__(release_build.RootInstalledReleaseBuilder), output_fd, staged)
        finally:
            os.close(output_fd)
        candidate = "a" * 40
        manifest = release_build._canonical_json({
            "schema": 1,
            "candidate_git_sha": candidate,
            "files": [{"relative_path": row.relative_path, "sha256": row.sha256,
                       "size_bytes": row.size_bytes, "mode": row.mode,
                       "roles": list(row.roles)} for row in rows],
        })
        (output / release_build.RELEASE_MANIFEST_PATH).write_bytes(manifest)
        os.chmod(output / release_build.RELEASE_MANIFEST_PATH, 0o444)
        root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
        info = os.fstat(root_fd)
        receipt = release_build.VerifiedInstallerReleaseBuildReceipt(
            release_build._SEAL,
            handle="test-build-receipt",
            candidate_git_sha=candidate,
            distribution_receipt_handle="test-distribution",
            interpreter_receipt_handle="test-interpreter",
            source_tree_sha256="b" * 64,
            baseline_tree_sha256="c" * 64,
            amendment_manifest_sha256="d" * 64,
            source_catalog_sha256="e" * 64,
            role_closure_manifest_sha256=_sha(manifest),
            root_setup_plan_sha256="f" * 64,
            builder_artifact_sha256="1" * 64,
            issued_monotonic=time.monotonic(),
            deployment_predecessor=release_build.DeploymentPredecessor(
                "absent", info.st_dev, info.st_ino),
            files=rows,
            manifest_sha256=_sha(manifest),
            root_fd=root_fd,
            expected_uid=os.geteuid(),
        )
        return receipt

    def test_real_build_receipt_rows_accept_exact_source_and_all_ten_application_members(self):
        with tempfile.TemporaryDirectory() as temp:
            receipt = self._real_role_receipt(Path(temp) / "output")
            try:
                receipt.verify_current()
                rows = _build_rows(receipt)
                self.assertEqual(
                    {row.relative_path for row in rows if row.roles == ("source-module",)},
                    ({item[1] for item in REVIEWED_SOURCE_MODULES if item[4] == "source-module"}
                     | {item[1] for item in APPLICATION_EFFECT_SOURCE_MEMBERS
                        if item[2] == "source-module"}),
                )
                self.assertEqual(
                    {row.relative_path for row in rows if row.roles == ("native-health-fixture",)},
                    {item[1] for item in REVIEWED_SOURCE_ARTIFACTS
                     if item[4] == "native-health-fixture"},
                )
                effect_members_by_path = {item[1]: item for item in APPLICATION_EFFECT_SOURCE_MEMBERS}
                effect_rows = [row for row in rows if row.relative_path in effect_members_by_path]
                self.assertEqual(len(effect_rows), len(APPLICATION_EFFECT_SOURCE_MEMBERS))
                self.assertEqual(
                    {(effect_members_by_path[row.relative_path][0], row.relative_path,
                      row.roles[0], row.sha256, row.size_bytes)
                     for row in effect_rows},
                    set(APPLICATION_EFFECT_SOURCE_MEMBERS),
                )
            finally:
                os.close(receipt._root_fd)

    def test_real_build_receipt_rows_reject_misassigned_swapped_and_unpinned_members(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(__file__).parents[2]
            path = "fixtures/native-health/expected-tool-result.json"
            receipt = self._real_role_receipt(Path(temp) / "misassigned", overrides={
                path: (path, "module",
                       (repo / "src/hermes_installer/native_health_fixture/expected-tool-result.json").read_bytes()),
            })
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _build_rows(receipt)
            finally:
                os.close(receipt._root_fd)

        source_members = [item for item in REVIEWED_SOURCE_MODULES if item[4] == "source-module"]
        first, second = source_members
        with tempfile.TemporaryDirectory() as temp:
            receipt = self._real_role_receipt(Path(temp) / "path-swapped", overrides={
                first[1]: (first[1] + ".swapped", "source-module",
                           (Path(__file__).parents[2] / first[1]).read_bytes()),
            })
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _build_rows(receipt)
            finally:
                os.close(receipt._root_fd)

        with tempfile.TemporaryDirectory() as temp:
            repo = Path(__file__).parents[2]
            receipt = self._real_role_receipt(Path(temp) / "swapped", overrides={
                first[1]: (first[1], "source-module", (repo / second[1]).read_bytes()),
            })
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _build_rows(receipt)
            finally:
                os.close(receipt._root_fd)

        with tempfile.TemporaryDirectory() as temp:
            receipt = self._real_role_receipt(Path(temp) / "unpinned", overrides={
                first[1]: (first[1], "source-module", b"different source bytes"),
            })
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _build_rows(receipt)
            finally:
                os.close(receipt._root_fd)

        fixture_id, fixture_path, _role, _digest, _size = next(
            item for item in APPLICATION_EFFECT_SOURCE_MEMBERS
            if item[2] == "application-effect-fixture")
        with tempfile.TemporaryDirectory() as temp:
            receipt = self._real_role_receipt(Path(temp) / "fixture-path-swapped", overrides={
                fixture_path: (fixture_path + ".unknown", "application-effect-fixture",
                               (Path(__file__).parents[2] / fixture_path).read_bytes()),
            })
            try:
                with self.assertRaises(BootstrapEnrollmentError):
                    _build_rows(receipt)
            finally:
                os.close(receipt._root_fd)

    def test_stale_predecessor_denies_before_release_or_pointer_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            record_path.write_bytes(_canonical({"candidate_git_sha": "c" * 40}))
            os.chmod(record_path, 0o600)
            before = record_path.read_bytes()
            with self.assertRaises(BootstrapEnrollmentPending):
                _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                        expected_uid=os.getuid(), predecessor=predecessor)
            self.assertEqual(record_path.read_bytes(), before)
            self.assertFalse(release.exists())

    def test_existing_candidate_with_extra_content_is_preserved_and_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            release.mkdir(mode=0o555)
            os.chmod(release, 0o755)
            marker = release / "foreign"
            marker.write_bytes(b"keep")
            os.chmod(marker, 0o444)
            os.chmod(release, 0o555)
            with self.assertRaises(BootstrapEnrollmentError):
                _publish_retained_build(receipt=receipt, release_root=release, receipt_path=record_path,
                                        expected_uid=os.getuid(), predecessor=predecessor)
            self.assertEqual(marker.read_bytes(), b"keep")
            self.assertFalse(record_path.exists())

    def test_failed_pointer_replace_keeps_prior_pointer(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            prior = {"schema": 1, "receipt_id": "prior", "candidate_git_sha": "c" * 40,
                     "release_root": "/tmp/other", "release_device": 1, "release_inode": 2,
                     "closure_manifest_relative_path": "release-manifest.json",
                     "closure_manifest_sha256": "d" * 64, "baseline_tree_sha256": "e" * 64,
                     "published_monotonic": 1.0}
            raw = _canonical(prior)
            record_path.write_bytes(raw)
            os.chmod(record_path, 0o600)
            info = os.stat(record_path)
            predecessor = Predecessor(os.stat(record_path.parent).st_dev,
                                      os.stat(record_path.parent).st_ino,
                                      "present", _sha(raw), info.st_dev, info.st_ino, "c" * 40)
            with patch("hermes_installer.authority.installed_stage_publisher.os.replace",
                       side_effect=OSError("injected pointer failure")):
                with self.assertRaises(OSError):
                    _publish_retained_build(receipt=receipt, release_root=release,
                                            receipt_path=record_path, expected_uid=os.getuid(),
                                            predecessor=predecessor)
            self.assertEqual(record_path.read_bytes(), raw)
            self.assertEqual(json.loads(record_path.read_bytes())["receipt_id"], "prior")

    def test_interrupted_candidate_stage_is_recovered_for_same_build_receipt(self):
        with tempfile.TemporaryDirectory() as temp:
            _, receipt, record_path, release, predecessor = self._fixture(temp)
            with patch("hermes_installer.authority.installed_stage_publisher._rename_noreplace",
                       side_effect=OSError("injected release rename failure")):
                with self.assertRaises(OSError):
                    _publish_retained_build(receipt=receipt, release_root=release,
                                            receipt_path=record_path, expected_uid=os.getuid(),
                                            predecessor=predecessor)
            stage_journals = tuple((record_path.parent.parent / "releases").glob(".stage-*.journal.json"))
            self.assertEqual(len(stage_journals), 1)
            self.assertFalse(release.exists())
            _publish_retained_build(receipt=receipt, release_root=release,
                                    receipt_path=record_path, expected_uid=os.getuid(),
                                    predecessor=predecessor)
            self.assertTrue(release.is_dir())
            self.assertTrue(record_path.is_file())
            self.assertEqual(tuple((record_path.parent.parent / "releases").glob(".stage-*.journal.json")), ())

    def test_recovery_refuses_matching_symlink_journal_and_preserves_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root, receipt, record_path, release, _ = self._fixture(temp)
            releases = release.parent
            source = root / "important"
            source.write_bytes(b"preserve")
            prefix = f".stage-{receipt.candidate_git_sha}-{_sha(receipt.receipt_handle.encode())[:16]}-"
            journal = releases / (prefix + "foreign.journal.json")
            journal.symlink_to(source)
            with self.assertRaises(BootstrapEnrollmentPending):
                _recover_staging_journals(releases, receipt, _canonical({}), os.getuid())
            self.assertTrue(journal.is_symlink())
            self.assertEqual(source.read_bytes(), b"preserve")


if __name__ == "__main__":
    unittest.main()
