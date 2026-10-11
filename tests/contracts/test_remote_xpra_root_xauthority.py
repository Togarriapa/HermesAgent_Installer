"""Exact-source tests for the selected Xpra root-cookie overlay."""
from __future__ import annotations

import os
import ast
import hashlib
import io
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.xpra_root_xauthority import (
    OVERLAY_ARTIFACT_ID,
    XPRA_SOURCE_COMMIT,
    XpraOverlayDenied,
    build_pinned_xpra_root_xauthority_overlay,
    _copy_and_expand_source_links,
    verify_pinned_xpra_overlay,
)


@unittest.skipUnless(os.environ.get("XPRA_SOURCE_ROOT"), "pinned Xpra source is supplied by CI")
class PinnedXpraRootCookieOverlayTests(unittest.TestCase):
    def test_overlay_is_pinned_compilable_and_never_mutates_selected_cookie(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-overlay-") as temp:
            output = Path(temp) / "xpra-overlay"
            receipt = build_pinned_xpra_root_xauthority_overlay(source, output)
            self.assertEqual(receipt.source_commit, XPRA_SOURCE_COMMIT)
            for digest in (receipt.source_tree_sha256, receipt.transformed_tree_sha256,
                           receipt.overlay_sha256, receipt.manifest_sha256,
                           receipt.output_artifact_sha256):
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertNotEqual(receipt.overlay_sha256, receipt.manifest_sha256)
            self.assertNotEqual(receipt.transformed_tree_sha256, receipt.output_artifact_sha256)
            # The source-tree pin includes executable bits; overlay copying must
            # preserve the official runtime tree's file modes exactly.
            self.assertEqual(
                stat.S_IMODE((output / "xpra/audio/common.py").stat().st_mode),
                stat.S_IMODE((source / "xpra/audio/common.py").stat().st_mode),
            )
            self.assertTrue(verify_pinned_xpra_overlay(
                receipt, artifact_id=OVERLAY_ARTIFACT_ID,
                expected_overlay_sha256=receipt.overlay_sha256,
            ))
            self.assertEqual(set(receipt.output_sha256), {
                "xpra/scripts/server.py", "xpra/server/subsystem/xvfb.py",
                "xpra/x11/vfb_util.py",
            })
            self.assertEqual(
                subprocess.run(
                    [sys.executable, "-m", "py_compile", *map(str, (
                        output / "xpra/scripts/server.py",
                        output / "xpra/server/subsystem/xvfb.py",
                        output / "xpra/x11/vfb_util.py",
                    ))], capture_output=True, timeout=10,
                ).returncode,
                0,
            )
            xvfb = (output / "xpra/server/subsystem/xvfb.py").read_text()
            vfb = (output / "xpra/x11/vfb_util.py").read_text()
            server = (output / "xpra/scripts/server.py").read_text()
            self.assertIn("selected display is already active", xvfb)
            self.assertIn('if os.environ.get("XAUTHORITY") != "/run/hermes-installer/display/Xauthority":', xvfb)
            self.assertIn("writes are disabled", vfb)
            self.assertIn('xauth_data: str = ""', server)
            self.assertIn('self.xvfb_cmd.extend(("-auth", "/run/hermes-installer/display/Xauthority"))', xvfb)
            self.assertIn("if self.displayfd:", xvfb)
            self.assertNotIn("get_hex_uuid()", server)
            self.assertNotIn("xauth_add(", xvfb)
            self.assertNotIn("get_xauthority_path", xvfb)
            self.assertNotIn("xauth_cmd", vfb)
            self.assertNotIn("xauth_data]", vfb)

            patched_module = ast.parse(vfb)
            function = next(node for node in patched_module.body
                            if isinstance(node, ast.FunctionDef) and node.name == "xauth_add")
            isolated = compile(ast.Module(body=[function], type_ignores=[]), "xpra-vfb-util", "exec")
            namespace = {}
            exec(isolated, namespace)
            with self.assertRaisesRegex(PermissionError, "disabled") as denied:
                namespace["xauth_add"](
                    "/run/hermes-installer/display/Xauthority", ":99", "private-cookie-value", 1000, 1000,
                )
            self.assertNotIn("private-cookie-value", str(denied.exception))

            changed_file = output / "xpra/x11/vfb_util.py"
            changed_file.chmod(0o644)
            changed_file.write_text(changed_file.read_text() + "\n# changed\n")
            with self.assertRaises(XpraOverlayDenied):
                verify_pinned_xpra_overlay(
                    receipt, artifact_id=OVERLAY_ARTIFACT_ID,
                    expected_overlay_sha256=receipt.overlay_sha256,
                )

    def test_wrong_pin_or_existing_destination_fails_without_source_edits(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        before = (source / "xpra/server/subsystem/xvfb.py").read_bytes()
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-overlay-negative-") as temp:
            output = Path(temp) / "already-there"
            output.mkdir()
            with self.assertRaises(XpraOverlayDenied):
                build_pinned_xpra_root_xauthority_overlay(source, output)
            self.assertEqual((source / "xpra/server/subsystem/xvfb.py").read_bytes(), before)

    def test_regular_only_runner_stage_expands_exact_aliases_and_required_parent(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-regular-stage-") as temp:
            root = Path(temp)
            archive_bytes = subprocess.run(
                ["git", "-C", str(source), "archive", "--format=tar", XPRA_SOURCE_COMMIT],
                check=True, capture_output=True, timeout=30,
                env={"PATH": os.defpath, "HOME": "/nonexistent", "GIT_CONFIG_NOSYSTEM": "1"},
            ).stdout
            archive_root = root / "archive"
            archive_root.mkdir()
            with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:") as package:
                package.extractall(archive_root, filter="data")
            # `git archive` places repository paths directly at the extraction
            # root; it does not add a wrapper directory. Stage the complete
            # pinned tree so the regular-file and directory closure checks see
            # the same source that the runtime verifier will receive.
            pinned_tree = archive_root
            regular_stage = root / "regular-source"
            regular_stage.mkdir()
            for current, names, files in os.walk(pinned_tree, followlinks=False):
                relative = Path(current).relative_to(pinned_tree)
                destination = regular_stage / relative
                destination.mkdir(parents=True, exist_ok=True)
                for name in names:
                    entry = Path(current) / name
                    if not entry.is_symlink():
                        (destination / name).mkdir(exist_ok=True)
                for name in files:
                    entry = Path(current) / name
                    if not entry.is_symlink():
                        shutil.copy2(entry, destination / name)

            expanded = root / "private-work" / "source"
            expanded.parent.mkdir()
            from hermes_installer.remote.xpra_root_xauthority import _SOURCE_LINKS
            self.assertEqual(_copy_and_expand_source_links(regular_stage, expanded),
                             "f52b4ce760b86c24a4d6d930f47e58357442a984d9ff2478d7abf338ff48e467")
            self.assertTrue((expanded / "fs/share/doc").is_dir())
            for relative, (target, target_sha256, target_size) in _SOURCE_LINKS.items():
                link = expanded / relative
                self.assertTrue(link.is_symlink())
                self.assertEqual(os.readlink(link), target)
                self.assertEqual(len(target.encode()), target_size)
                self.assertEqual(hashlib.sha256(target.encode()).hexdigest(), target_sha256)
            self.assertEqual((expanded / "xpra/audio/common.py").stat().st_mode & 0o777,
                             (regular_stage / "xpra/audio/common.py").stat().st_mode & 0o777)


if __name__ == "__main__":
    unittest.main()
