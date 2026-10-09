"""Exact-source tests for the selected Xpra root-cookie overlay."""
from __future__ import annotations

import os
import ast
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from hermes_installer.remote.xpra_root_xauthority import (
    XPRA_SOURCE_COMMIT,
    XpraOverlayDenied,
    build_pinned_xpra_root_xauthority_overlay,
)


@unittest.skipUnless(os.environ.get("XPRA_SOURCE_ROOT"), "pinned Xpra source is supplied by CI")
class PinnedXpraRootCookieOverlayTests(unittest.TestCase):
    def test_overlay_is_pinned_compilable_and_never_mutates_selected_cookie(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-overlay-") as temp:
            output = Path(temp) / "xpra-overlay"
            receipt = build_pinned_xpra_root_xauthority_overlay(source, output)
            self.assertEqual(receipt.source_commit, XPRA_SOURCE_COMMIT)
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
            self.assertIn("if xauthority != \"/run/hermes-installer/display/Xauthority\":", xvfb)
            self.assertIn("readonly and cannot be modified", vfb)
            self.assertIn("xauth_data: str = \"\" if _hermes_root_xauth", server)
            self.assertIn('self.xvfb_cmd.extend(("-auth", "/run/hermes-installer/display/Xauthority"))', xvfb)
            selected = xvfb.index('if os.environ.get("XAUTHORITY") == "/run/hermes-installer/display/Xauthority":')
            no_repair = xvfb.index('return start_vfb, "", use_display', selected)
            repair_generation = xvfb.index("if not xauth_data:", selected)
            self.assertLess(no_repair, repair_generation)

            patched_module = ast.parse(vfb)
            function = next(node for node in patched_module.body
                            if isinstance(node, ast.FunctionDef) and node.name == "xauth_add")
            isolated = compile(ast.Module(body=[function], type_ignores=[]), "xpra-vfb-util", "exec")
            namespace = {}
            exec(isolated, namespace)
            with self.assertRaisesRegex(PermissionError, "readonly") as denied:
                namespace["xauth_add"](
                    "/run/hermes-installer/display/Xauthority", ":99", "private-cookie-value", 1000, 1000,
                )
            self.assertNotIn("private-cookie-value", str(denied.exception))

    def test_wrong_pin_or_existing_destination_fails_without_source_edits(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        before = (source / "xpra/server/subsystem/xvfb.py").read_bytes()
        with tempfile.TemporaryDirectory(prefix="hermes-xpra-overlay-negative-") as temp:
            output = Path(temp) / "already-there"
            output.mkdir()
            with self.assertRaises(XpraOverlayDenied):
                build_pinned_xpra_root_xauthority_overlay(source, output)
            self.assertEqual((source / "xpra/server/subsystem/xvfb.py").read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
