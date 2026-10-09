import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
from hermes_installer.remote.xpra_window_patch import PINNED_WINDOW_SOURCE_GIT_BLOB,install_pinned_window_patch,patch_can_send_window
METHOD="""    def can_send_window(self, window) -> bool:
        if self.window_filters and self.window_enabled and not window.is_tray():
            for uuid, window_filter in self.window_filters:
                if window_filter.matches(window):
                    v = uuid in ("*", self.uuid)
                    filterslog("can_send_window(%s)=%s", window, v)
                    return v
        if self.window_enabled and self.system_tray:
            v = True
"""
SOURCE="""        self.window_filters = window.window_filters
        self.readonly = server.readonly
    def can_send_window(self, window) -> bool:
        if self.window_filters and self.window_enabled and not window.is_tray():
            for uuid, window_filter in self.window_filters:
                if window_filter.matches(window):
                    v = uuid in ("*", self.uuid)
                    filterslog("can_send_window(%s)=%s", window, v)
                    return v
        if self.window_enabled and self.system_tray:
            v = True
    ######################################################################
"""
class XpraWindowPatchTests(unittest.TestCase):
 def test_unmatched_class_is_denied_after_allowlist_filter_scan(self):
  patched=patch_can_send_window(METHOD)
  self.assertIn("Installer patch: filters are a security allowlist",patched)
  self.assertIn("            return False\n        if self.window_enabled",patched)
  self.assertEqual(patched.count("return False"),1)
 def test_source_update_is_pinned_atomic_and_idempotent(self):
  with TemporaryDirectory() as tmp:
   root=Path(tmp);target=root/"xpra/server/window.py";target.parent.mkdir(parents=True);target.write_text(SOURCE)
   with patch("hermes_installer.remote.xpra_window_patch._git_blob_id",return_value=PINNED_WINDOW_SOURCE_GIT_BLOB):
    self.assertTrue(install_pinned_window_patch(root,{"HermesDesktop"}))
    first=target.read_text()
    self.assertIn("HermesInstaller-Xpra-Allowed-Classes:HermesDesktop",first)
    self.assertIn("get_window_filter(\"window\", \"class-instance\", \"=\", value)",first)
    self.assertIn("return False",first)
    self.assertFalse(install_pinned_window_patch(root,{"HermesDesktop"}))
    with self.assertRaises(ValueError):install_pinned_window_patch(root,{"OtherDesktop"})
 def test_unknown_revision_or_symlink_is_rejected(self):
  with TemporaryDirectory() as tmp:
   root=Path(tmp);target=root/"xpra/server/window.py";target.parent.mkdir(parents=True);target.write_text(SOURCE)
   with patch("hermes_installer.remote.xpra_window_patch._git_blob_id",return_value="0"*40):
    with self.assertRaises(ValueError):install_pinned_window_patch(root,{"HermesDesktop"})
   target.unlink();target.symlink_to(Path(__file__))
   with self.assertRaises(ValueError):install_pinned_window_patch(root,{"HermesDesktop"})
