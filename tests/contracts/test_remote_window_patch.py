import unittest
from hermes_installer.remote.xpra_window_patch import patch_can_send_window
class XpraWindowPatchTests(unittest.TestCase):
 def test_unmatched_window_falls_through_to_deny(self):
  source="""    def can_send_window(self, window) -> bool:\n        if self.window_filters and self.window_enabled and not window.is_tray():\n            for uuid, window_filter in self.window_filters:\n                if window_filter.matches(window):\n                    v = uuid in (\"*\", self.uuid)\n                    return v\n        if self.window_enabled and self.system_tray:\n            v = True\n"""
  patched=patch_can_send_window(source);self.assertIn("Installer patch: filters are a security allowlist",patched);self.assertIn("            return False\n        if self.window_enabled",patched);self.assertEqual(patched.count("return False"),1)
