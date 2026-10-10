"""Failure tests for stage-zero installed release custody."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import tempfile
import sys
from types import ModuleType
import unittest
from pathlib import Path
from unittest.mock import patch

from hermes_installer.authority.installer_release import (
    DEPLOYMENT_RECEIPT_PATH, InstalledRootReleaseVerifier, InstallerReleaseError,
    RootActorObservation, VerifiedInstallerReleaseReceipt, VerifiedReleaseFile,
    REVIEWED_SOURCE_MODULES, REVIEWED_SOURCE_ARTIFACTS, FIXED_TEMPLATES, LAUNCHER_PATH, INTERPRETER_PATH,
    PLAN_PATH, ARTIFACT_CATALOG_PATH, REQUIRED_LAUNCHER_MODULES, _fixed_roles, _open_verified_fd,
    _read_fixed_file, _safe_relative, _verify_complete_tree, _SEAL,
    _artifact_id_for, _module_name, _validate_fixed_layout_role,
)
from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending
from hermes_installer.authority.application_effect_source_catalog import (
    APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID, APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
    APPLICATION_EFFECT_SOURCE_CATALOG_SHA256, APPLICATION_EFFECT_SOURCE_CATALOG_SIZE,
    APPLICATION_EFFECT_SOURCE_MEMBERS,
)


class InstalledReleaseVerifierTests(unittest.TestCase):
    def test_dtos_cannot_be_constructed_without_verifier_seal(self):
        with self.assertRaises(TypeError):
            VerifiedInstallerReleaseReceipt(None, release_root=Path("/"), release_commit="0" * 40,
                deployment_receipt_sha256="0" * 64, root_device=0, root_inode=1,
                closure_manifest_relative_path="closure.json", closure_manifest_sha256="0" * 64,
                baseline_tag_object="0" * 40, baseline_commit="0" * 40,
                baseline_tree_sha256="0" * 64, amendment_manifest_sha256="0" * 64,
                files=(), selected_plan_artifact_id="", selected_plan_sha256="0" * 64,
                root_fd=-1, expected_uid=0)
        with self.assertRaises(TypeError):
            RootActorObservation(None, pid=1, uid=0, gid=0, start_time=1,
                launcher=("/x", 1, 1, "0" * 64), interpreter=("/y", 1, 1, "0" * 64),
                module_origins=(), namespace_inodes=(), isolated_import_facts=(), pidfd=-1)

    def test_production_constructor_has_no_caller_path_override(self):
        self.assertEqual(DEPLOYMENT_RECEIPT_PATH, Path("/var/lib/hermes-installer/deployments/current.json"))
        with self.assertRaises(InstallerReleaseError):
            InstalledRootReleaseVerifier._load_deployment_receipt(Path("/tmp/fake.json"), expected_uid=0)
        if not os.sys.platform.startswith("linux"):
            with self.assertRaises(BootstrapEnrollmentPending):
                InstalledRootReleaseVerifier.from_current_root_process()

    @unittest.skipUnless(os.sys.platform.startswith("linux") and hasattr(os, "pidfd_open"),
                         "requires Linux PIDFD")
    def test_actor_rejects_stale_process_starttime(self):
        pidfd = os.pidfd_open(os.getpid(), 0)
        actor = RootActorObservation(_SEAL, pid=os.getpid(), uid=os.getuid(), gid=os.getgid(),
            start_time=1, launcher=("/missing", 0, 0, "0" * 64),
            interpreter=("/missing", 0, 0, "0" * 64), module_origins=(),
            namespace_inodes=(), isolated_import_facts=(), pidfd=pidfd)
        class LiveRelease:
            def verify_current(self):
                return None
        try:
            with self.assertRaises(InstallerReleaseError):
                actor.verify_current(LiveRelease())
        finally:
            actor.close()

    def test_actor_still_rejects_late_module_injection_and_origin_substitution(self):
        pid = os.getpid()
        executable = Path(sys.executable).resolve()
        tracked = []
        for name, module in tuple(sys.modules.items()):
            if name == "hermes_installer" or name.startswith("hermes_installer."):
                origin = getattr(getattr(module, "__spec__", None), "origin", None)
                if origin is not None:
                    tracked.append((name, origin, 0, 0, "0" * 64))
        pidfd, pidfd_writer = os.pipe()
        actor = RootActorObservation(
            _SEAL, pid=pid, uid=0, gid=0, start_time=123,
            launcher=(str(executable), 0, 0, "0" * 64),
            interpreter=(str(executable), 0, 0, "0" * 64),
            module_origins=tuple(tracked), namespace_inodes=(),
            isolated_import_facts=(), pidfd=pidfd)

        class LiveRelease:
            def verify_current(self):
                return None

        original_resolve = Path.resolve

        def resolve_process_executable(path, **kwargs):
            if str(path) == f"/proc/{pid}/exe":
                return executable
            return original_resolve(path, **kwargs)

        try:
            with patch("hermes_installer.authority.installer_release.os.getuid", return_value=0), \
                 patch("hermes_installer.authority.installer_release.os.geteuid", return_value=0), \
                 patch("hermes_installer.authority.installer_release.os.getgid", return_value=0), \
                 patch("hermes_installer.authority.installer_release._process_start_time", return_value=123), \
                 patch("hermes_installer.authority.installer_release._namespace_inodes", return_value=()), \
                 patch("hermes_installer.authority.installer_release._isolated_import_facts", return_value=()), \
                 patch("hermes_installer.authority.installer_release._verify_actor_path"), \
                 patch.object(Path, "resolve", resolve_process_executable):
                actor.verify_current(LiveRelease())

                injected_name = "hermes_installer.unreviewed_injected_for_test"
                injected = ModuleType(injected_name)
                injected.__spec__ = importlib.util.spec_from_loader(injected_name, loader=None,
                                                                     origin="/tmp/unreviewed.py")
                sys.modules[injected_name] = injected
                try:
                    with self.assertRaisesRegex(InstallerReleaseError, "unreviewed Hermes installer module"):
                        actor.verify_current(LiveRelease())
                finally:
                    del sys.modules[injected_name]

                module = sys.modules["hermes_installer.authority.installer_release"]
                prior_origin = module.__spec__.origin
                module.__spec__.origin = "/tmp/substituted-installer-release.py"
                try:
                    with self.assertRaises(InstallerReleaseError):
                        actor.verify_current(LiveRelease())
                finally:
                    module.__spec__.origin = prior_origin
        finally:
            actor.close()
            os.close(pidfd_writer)

    def test_relative_paths_reject_traversal_and_platform_separators(self):
        for path in ("../etc/passwd", "a/../../x", "a\\b", "/absolute", "", "a//b"):
            self.assertFalse(_safe_relative(path), path)
        self.assertTrue(_safe_relative("plans/bootstrap-policy.json"))

    def test_installed_release_roles_use_exact_paths_and_module_ids(self):
        self.assertEqual(_module_name("lib/python/hermes_installer/authority/daemon.py"),
                         "hermes_installer.authority.daemon")
        self.assertEqual(_module_name("lib/python/hermes_installer/__init__.py"),
                         "hermes_installer")
        for malformed in (
            "src/hermes_installer/authority/daemon.py",
            "lib/python/a..b.py",
            "lib/python/trailing..py",
            "lib/python/__init__.py",
            "lib/python/a/b.pyc",
        ):
            with self.subTest(path=malformed), self.assertRaises(InstallerReleaseError):
                _module_name(malformed)
        self.assertEqual(_artifact_id_for("lib/python/hermes_installer/authority/daemon.py", ["module"]),
                         "installer-module:hermes_installer.authority.daemon")
        _validate_fixed_layout_role("runtime/bin/python", "1" * 64, 10, ["interpreter"])
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("runtime/bin/python3", "1" * 64, 10, ["interpreter"])
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("templates/bootstrap-compiler-template-v1.json",
                                        "0" * 64, 4281, ["template"])
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role("plans/bootstrap-policy-v1.json",
                                        "1" * 64, 10, ["bootstrap-policy"])

    def test_current_fixed_template_closure_includes_literal_existing_model_store_root(self):
        from hermes_installer.authority.installer_release import FIXED_TEMPLATES
        expected = {
            "templates/root-setup-plan-template-v1.json":
                ("installer-root-setup-plan-template-v1",
                 "210114d336b54ec86b40861a1d808508db48d20c9ecfb0a20b30049b2e4f84f5", 920),
            "templates/bootstrap-receipt-bindings-template-v1.json":
                ("installer-bootstrap-receipt-bindings-template-v1",
                 "2036e9443b8c1c085cf7c90a4eb26c162f7d787f030cd759e35d92ca17b3e609", 10195),
            "templates/composio-whatsapp-catalog-read-policy-v1.json":
                ("installer-composio-whatsapp-catalog-read-policy-v1",
                 "319076116a060e371c10886e5c2cfea274ed4d985aa03f5e66a4f611f949cfc5", 528),
            "templates/existing-model-store-root-template-v1.json":
                ("installer-existing-model-store-root-template-v1",
                 "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f", 712),
        }
        actual = {path: (artifact_id, digest, size)
                  for artifact_id, path, digest, size in FIXED_TEMPLATES}
        for path, value in expected.items():
            self.assertEqual(actual[path], value)
        self.assertEqual(len(actual), 8)
        self.assertEqual(
            _artifact_id_for("templates/existing-model-store-root-template-v1.json", ["template"]),
            "installer-existing-model-store-root-template-v1",
        )
        _validate_fixed_layout_role(
            "templates/existing-model-store-root-template-v1.json",
            "3a145ddd21cf8ba524307844a1ab7fb78a4a066afad59bfbbb9164327c2f570f",
            712, ["template"],
        )
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role(
                "templates/composio-whatsapp-catalog-read-policy-v1.json",
                "0" * 64, 528, ["template"],
            )

    def test_reviewed_native_source_modules_are_finite_pinned_release_rows(self):
        expected = {
            "installer-module:hermes_installer.components.native_plugins": (
                "lib/python/hermes_installer/components/native_plugins.py",
                "a027311518a746a6b1bcd126fc677190f4fe0ec2ac91b941872b3cdc542a79e7", 28_259, "module"),
            "installer-module:hermes_installer.components.public_registries": (
                "lib/python/hermes_installer/components/public_registries.py",
                "c4568783265044b6b877d581c7ece596d582b003221cccb8e0b7cfe78ac8cb0f", 29_374, "module"),
            "installer-native-invocations-module-v137": (
                "src/hermes_installer/native_invocations.py",
                "78a3452289df5b7343e5c650ad4260d51b3aa1056e2eedea02cc3a0bff7b8226", 40_107, "source-module"),
            "installer-native-boundary-module-v137": (
                "src/hermes_installer/native_boundary.py",
                "ac18137d35fee29db635eb4f91327c3d02d5b5a563353acf60ad020085043cdb", 14_356, "source-module"),
            "installer-native-source-definitions-module-v137": (
                "lib/python/hermes_installer/authority/native_source_definitions.py",
                "ca57637fd1eea4df70549391ba91b14b3842806ef6b789a4baa9d8954c7fdc22", 16_819, "module"),
        }
        self.assertEqual({artifact_id: (path, digest, size, role)
                          for artifact_id, path, digest, size, role in REVIEWED_SOURCE_MODULES}, expected)
        rows = [
            VerifiedReleaseFile("installer-root-setup-launcher-v1", ("launcher",), LAUNCHER_PATH,
                                "1" * 64, 1, 1, 1, 0o555),
            VerifiedReleaseFile("installer-root-setup-interpreter-v1", ("interpreter",), INTERPRETER_PATH,
                                "2" * 64, 1, 1, 2, 0o555),
            VerifiedReleaseFile("installer-root-setup-plan-v1", ("plan",), PLAN_PATH,
                                "3" * 64, 1, 1, 3, 0o444),
            VerifiedReleaseFile("installer-protected-artifact-catalog-v1", ("artifact-catalog",),
                                ARTIFACT_CATALOG_PATH, "4" * 64, 1, 1, 4, 0o444),
        ]
        rows.extend(VerifiedReleaseFile(artifact_id, ("template",), path, digest, size, 1, 10 + i, 0o444)
                    for i, (artifact_id, path, digest, size) in enumerate(FIXED_TEMPLATES))
        rows.extend(VerifiedReleaseFile(artifact_id, (role,), path, digest, size, 1, 100 + i, 0o444)
                    for i, (artifact_id, path, digest, size, role) in enumerate(REVIEWED_SOURCE_MODULES))
        rows.extend(VerifiedReleaseFile(artifact_id, ("module",), path, f"{i + 8:064x}", 100 + i,
                                        1, 300 + i, 0o444)
                    for i, (artifact_id, path) in enumerate(REQUIRED_LAUNCHER_MODULES))
        rows.append(VerifiedReleaseFile("runtime-member:python3", ("runtime-member",),
                                        "runtime/bin/python3", "7" * 64, 1, 1, 7, 0o555))
        rows.extend(VerifiedReleaseFile(artifact_id, (role,), path, digest, size, 1, 150 + i, 0o444)
                    for i, (artifact_id, path, digest, size, role) in enumerate(REVIEWED_SOURCE_ARTIFACTS)
                    if role == "native-health-fixture")
        rows.extend((
            VerifiedReleaseFile("baseline-file", ("baseline",), "plans/2026-10-09-v1/file.json",
                                "5" * 64, 1, 1, 200, 0o444),
            VerifiedReleaseFile("amendment-file", ("amendment",), "plans/amendments/ref/file.json",
                                "6" * 64, 1, 1, 201, 0o444),
        ))
        rows.append(VerifiedReleaseFile(APPLICATION_EFFECT_SOURCE_CATALOG_ARTIFACT_ID, ("amendment",),
                                        APPLICATION_EFFECT_SOURCE_CATALOG_PATH,
                                        APPLICATION_EFFECT_SOURCE_CATALOG_SHA256,
                                        APPLICATION_EFFECT_SOURCE_CATALOG_SIZE, 1, 210, 0o444))
        rows.extend(VerifiedReleaseFile(artifact_id, (role,), path, digest, size, 1, 220 + i, 0o444)
                    for i, (artifact_id, path, role, digest, size)
                    in enumerate(APPLICATION_EFFECT_SOURCE_MEMBERS))
        self.assertEqual(_fixed_roles(rows, "closure.json"), ("installer-root-setup-plan-v1", "3" * 64))
        bad = list(rows)
        index = next(i for i, row in enumerate(bad) if row.artifact_id == REVIEWED_SOURCE_MODULES[0][0])
        row = bad[index]
        bad[index] = VerifiedReleaseFile(row.artifact_id, row.roles, row.relative_path,
                                         "0" * 64, row.size_bytes, row.device, row.inode, row.mode)
        with self.assertRaises(InstallerReleaseError):
            _fixed_roles(bad, "closure.json")
        worker = next(i for i, row in enumerate(rows)
                      if row.artifact_id == "installer-native-invocations-module-v137")
        bad_role = list(rows)
        row = bad_role[worker]
        bad_role[worker] = VerifiedReleaseFile(row.artifact_id, ("module",), row.relative_path,
                                               row.sha256, row.size_bytes, row.device, row.inode, row.mode)
        with self.assertRaises(InstallerReleaseError):
            _fixed_roles(bad_role, "closure.json")

    def test_glm_source_artifact_ids_bind_exact_baseline_and_amendment_members(self):
        repo = Path(__file__).parents[2]
        expected = {
            "installer-application-toolchain-source-policy-v144": (
                "plans/amendments/2026-10-10-hyperframes-toolchain-source-v144/hyperframes-toolchain-source-v1.json",
                "81b9e3655ddb627c46d828690687a1600fd9a7455af4c4fc5a90c32b3991a5d6", 7_060, "amendment"),
            "installer-application-pep517-backend-sources-v1": (
                "plans/amendments/2026-10-10-pep517-backend-source-closure-v152/application-pep517-backend-source-table-v1.json",
                "c7d64c6ca0a186437d32b8093df0be0a3dc660fc721172e7ce1a56fd5a87c623", 15_907, "amendment"),
            "glm52-artifact-metadata-v1": (
                "planning/glm52-artifact-metadata.json",
                "b42e3fa6fd5c287b95fcda4d370697bd4c0ef226767ddc08fae4e5bebcfecd1a", 56_232, "baseline"),
            "glm52-upstream-mit-license-cf457fa": (
                "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-upstream-MIT-LICENSE.txt",
                "f4a18c6ae40b0a8e7d2b7667f52f6e1994e54a46430d2e172b73cb8c9b5eb0d7", 1_065, "amendment"),
            "glm52-quantized-readme-6bbb01e": (
                "plans/amendments/2026-10-10-glm-source-license-pins-v135/glm52-quantized-README.md",
                "85fc4cf947276c376f09ad1226926ebc03eefbb99d184cd05f34412d32d8406b", 17_468, "amendment"),
            "installer-native-input-capture-profile-v1": (
                "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-input-capture-profile-v1.json",
                "bfdf7175ee1df681b60ab4b707ffe9d314d8cc7fdc5a30a56e19d2cb1372c1d0", 837, "amendment"),
            "installer-native-tool-result-capture-profile-v1": (
                "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-tool-result-capture-profile-v1.json",
                "470fcc43b3d268a6594e0d6bdf2c635ba3bf4e6cd0cfe2dfcd57840d7bee105a", 984, "amendment"),
            "installer-native-provider-result-capture-profile-v1": (
                "plans/amendments/2026-10-10-native-capture-profiles-v158/installer-native-provider-result-capture-profile-v1.json",
                "a2c6ae9243a7854f114ed492afd395d867f02ed58d50a3f1692fe0ea7efbd8eb", 993, "amendment"),
            "hermes-agent-health-request-v1": (
                "fixtures/native-health/request.txt",
                "a8ff376fd03484db8c7dc0af141e8e894671467cdc5833ee50a08571d0ee3e7c", 182, "native-health-fixture"),
            "hermes-agent-health-seed-v1": (
                "fixtures/native-health/seed-value.txt",
                "b7cf82519f80550d09ae0ef0f183ad6be9543cc4c15873982cea91819e9a962a", 67, "native-health-fixture"),
            "hermes-agent-health-expected-result-v1": (
                "fixtures/native-health/expected-tool-result.json",
                "23a5b879d3b43b985c468917f34bdd7b592ab35cfd72e767287f16764436523a", 240, "native-health-fixture"),
            "hermes-agent-health-overlay-read-result-v1": (
                "fixtures/native-health/tool-result.schema.json",
                "6b89864f728e6e3e65b34d935c486bad0bc3c0a57bcee92dde5eec33fb1286f5", 526, "native-health-fixture"),
            "hermes-agent-health-fixture-v1": (
                "fixtures/native-health/recipe.json",
                "ba7486d3070f725d125ed0e8c42aa986969bc8a597c2473024705d6fd8ac05a7", 845, "native-health-fixture"),
            "installer-native-mcp-discovery-capture-profile-v171": (
                "plans/amendments/2026-10-10-mcp-discovery-capture-v171/mcp-discovery-capture-v1.json",
                "bf9b3b649bf995d5743a38597415ef003928e1d67dc337ab5c7f3e7ec9643e8a", 4_601, "amendment"),
        }
        self.assertEqual({artifact_id: (path, digest, size, role)
                          for artifact_id, path, digest, size, role in REVIEWED_SOURCE_ARTIFACTS}, expected)
        source_paths = {
            "fixtures/native-health/request.txt": "src/hermes_installer/native_health_fixture/request.txt",
            "fixtures/native-health/seed-value.txt": "src/hermes_installer/native_health_fixture/seed-value.txt",
            "fixtures/native-health/expected-tool-result.json": "src/hermes_installer/native_health_fixture/expected-tool-result.json",
            "fixtures/native-health/tool-result.schema.json": "src/hermes_installer/native_health_fixture/tool-result.schema.json",
            "fixtures/native-health/recipe.json": "src/hermes_installer/native_health_fixture/recipe.json",
        }
        for path, digest, size, _role in expected.values():
            body = (repo / source_paths.get(path, path)).read_bytes()
            self.assertEqual((len(body), hashlib.sha256(body).hexdigest()), (size, digest))

    def test_native_health_fixture_role_is_closed_to_five_exact_data_members(self):
        from hermes_installer.authority.installer_release import _validate_fixed_layout_role
        for artifact_id, path, digest, size, role in REVIEWED_SOURCE_ARTIFACTS:
            if role != "native-health-fixture":
                continue
            _validate_fixed_layout_role(path, digest, size, [role])
            with self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, "0" * 64, size, [role])
            with self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, digest, size, ["module"])

    def test_application_effect_members_have_exact_roles_paths_content_and_read_only_modes(self):
        from hermes_installer.authority.installer_release import _validate_fixed_layout_role
        self.assertEqual(len(APPLICATION_EFFECT_SOURCE_MEMBERS), 10)
        for _artifact_id, path, role, digest, size in APPLICATION_EFFECT_SOURCE_MEMBERS:
            _validate_fixed_layout_role(path, digest, size, [role], mode=0o444)
            with self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, "0" * 64, size, [role], mode=0o444)
            with self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, digest, size, ["module"], mode=0o444)
            with self.assertRaises(InstallerReleaseError):
                _validate_fixed_layout_role(path, digest, size, [role], mode=0o644)
        with self.assertRaises(InstallerReleaseError):
            _validate_fixed_layout_role(
                "src/hermes_installer/unknown_application_fixture.json",
                "0" * 64, 1, ["application-effect-fixture"], mode=0o444)

    def test_open_verified_file_checks_digest_and_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "good").write_bytes(b"approved")
            os.chmod(root / "good", 0o444)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                expected = hashlib.sha256(b"approved").hexdigest()
                fd = _open_verified_fd(root_fd, "good", expected,
                                       expected_uid=os.getuid(), expected_size=8)
                try:
                    self.assertEqual(os.read(fd, 8), b"approved")
                finally:
                    os.close(fd)
                with self.assertRaises(InstallerReleaseError):
                    _open_verified_fd(root_fd, "good", "0" * 64, expected_uid=os.getuid())
                (root / "link").symlink_to(root / "good")
                with self.assertRaises(InstallerReleaseError):
                    _open_verified_fd(root_fd, "link", expected, expected_uid=os.getuid())
            finally:
                os.close(root_fd)

    def test_receipt_requires_exact_keys_candidate_path_and_baseline(self):
        receipt = {
            "schema": 1, "receipt_id": "installer-release:" + "a" * 40,
            "candidate_git_sha": "a" * 40,
            "release_root": "/usr/lib/hermes-installer/releases/" + "a" * 40,
            "release_device": 1, "release_inode": 2,
            "closure_manifest_relative_path": "release-closure.json",
            "closure_manifest_sha256": "1" * 64, "baseline_tree_sha256": "2" * 64,
            "published_monotonic": 10.0,
        }
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt.json"
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                parsed = InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                                 expected_uid=os.getuid())
            self.assertEqual(parsed["candidate_git_sha"], "a" * 40)
            receipt["release_root"] = "/tmp/attacker"
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                with self.assertRaises(InstallerReleaseError):
                    InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                             expected_uid=os.getuid())
            receipt["release_root"] = "/usr/lib/hermes-installer/releases/" + "a" * 40
            receipt["unexpected"] = True
            with patch("hermes_installer.authority.installer_release._read_fixed_file",
                       return_value=(json.dumps(receipt).encode(), os.statvfs(td))):
                with self.assertRaises(InstallerReleaseError):
                    InstalledRootReleaseVerifier._load_deployment_receipt(DEPLOYMENT_RECEIPT_PATH,
                                                                             expected_uid=os.getuid())

    def test_complete_tree_rejects_unlisted_and_symlink_files(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "sub").mkdir()
            (root / "sub" / "listed").write_bytes(b"listed")
            (root / "closure.json").write_bytes(b"manifest")
            os.chmod(root / "sub" / "listed", 0o444)
            os.chmod(root / "closure.json", 0o444)
            os.chmod(root / "sub", 0o555)
            os.chmod(root, 0o555)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
                os.chmod(root, 0o755)
                (root / "extra").write_bytes(b"unlisted")
                os.chmod(root / "extra", 0o444)
                os.chmod(root, 0o555)
                with self.assertRaises(InstallerReleaseError):
                    _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
                os.chmod(root, 0o755)
                (root / "extra").unlink()
                (root / "bad-link").symlink_to(root / "closure.json")
                os.chmod(root, 0o555)
                with self.assertRaises(InstallerReleaseError):
                    _verify_complete_tree(root_fd, {"sub/listed"}, "closure.json", os.getuid())
            finally:
                os.close(root_fd)

    def test_receipt_reader_rejects_writable_or_oversized_file(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "receipt"
            path.write_bytes(b"x")
            os.chmod(path, 0o666)
            with patch("hermes_installer.authority.installer_release._verify_parents"):
                with self.assertRaises(InstallerReleaseError):
                    _read_fixed_file(DEPLOYMENT_RECEIPT_PATH, 8, os.getuid(), required_mode=0o600)


if __name__ == "__main__":
    unittest.main()
