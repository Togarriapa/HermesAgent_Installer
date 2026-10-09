import unittest
from hermes_installer.remote.session import SessionSpec,SessionUnavailable,server_policy,require_sandbox_evidence
from hermes_installer.remote.launcher import XpraLauncher
class RemoteSessionTests(unittest.TestCase):
 def setUp(self):self.spec=SessionSpec("hermes-remote",":81","/var/lib/hermes-remote","/opt/hermes/bin/hermes-desktop","a"*40,frozenset({"HermesDesktop"}))
 def test_server_policy_disables_shell_file_and_host_desktop(self):
  p=server_policy(self.spec);self.assertEqual(p["mode"],"seamless")
  for key in ("start_new_commands","start_desktop","start_shadow","start_proxy","shell","dbus","file_transfer","clipboard"):self.assertFalse(p[key])
  self.assertEqual(p["window_policy"],"deny_unmatched_server_side")
 def test_no_sandbox_fallback_blocks_readiness(self):
  with self.assertRaises(SessionUnavailable):require_sandbox_evidence(renderer_sandboxed=False,no_sandbox_marker=True)
 def test_launcher_passes_closed_feature_arguments_and_checks_live_probes(self):
  launcher=XpraLauncher(self.spec,xpra="/usr/bin/xpra",runtime_dir=__import__("pathlib").Path("/run/user/1/remote"),sandbox_probe=lambda _: (True,False),process_probe=lambda _: {})
  cmd=launcher.command();self.assertIn("--bind-tcp=none",cmd);self.assertIn("--clipboard=no",cmd);self.assertIn("--control=no",cmd);self.assertIn("--start-child="+self.spec.hermes_executable,cmd)
