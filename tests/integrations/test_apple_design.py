"""Apple Design remains private pending source-rights review."""
import os
import subprocess
import unittest
from pathlib import Path

from hermes_installer.components.adapters import resolve_component_adapter
from hermes_installer.components.apple_design import apple_design_status
from hermes_installer.components.skill_refs import audit_skill_references


SOURCE = Path(os.environ.get("HERMES_APPLE_DESIGN_SOURCE", "/missing/apple-design-skill"))
PIN = "904b0eedc7cc778152f545506075d5bb5219ce77"


@unittest.skipUnless(SOURCE.is_dir(), "set HERMES_APPLE_DESIGN_SOURCE to the pinned upstream checkout")
class AppleDesignTests(unittest.TestCase):
    def test_selected_reference_is_attributed_and_stays_unavailable_without_license_review(self):
        self.assertEqual(PIN, subprocess.check_output(
            ["git", "-C", str(SOURCE), "rev-parse", "HEAD"], text=True
        ).strip())
        self.assertEqual(1, len(audit_skill_references(SOURCE).skill_files))
        self.assertFalse((SOURCE / "LICENSE").exists())
        self.assertFalse((SOURCE / "LICENSE.md").exists())

        contract = resolve_component_adapter("apple-design")
        self.assertEqual("dickwu/apple-design-skill", contract.source_identity)
        self.assertTrue(contract.redistribution_license_review_required)
        status = apple_design_status()
        self.assertFalse(status.activation_available)
        self.assertFalse(status.xcode_required)
        self.assertIn("not Apple-owned", status.attribution)
        self.assertIn("verify redistribution", status.reason)


if __name__ == "__main__":
    unittest.main()
