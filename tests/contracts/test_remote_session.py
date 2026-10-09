import unittest
from pathlib import Path
from hermes_installer.remote.session import SessionSpec,SessionUnavailable,server_policy,require_sandbox_evidence
from hermes_installer.remote.launcher import XpraLauncher
class RemoteSessionTests(unittest.TestCase):
 def setUp(self):self.spec=SessionSpec("hermes-remote",":81","/var/lib/hermes-remote","/opt/hermes/bin/hermes-desktop","a"*40,frozenset({"HermesDesktop"}),uid=1000,hermes_arguments=("--user-data-dir=/var/lib/hermes-remote/profile",),hermes_environment={"HERMES_HOME":"/opt/hermes"})
 def test_server_policy_disables_shell_file_and_host_desktop(self):
  p=server_policy(self.spec);self.assertEqual(p["mode"],"seamless")
  for key in ("start_new_commands","start_desktop","start_shadow","start_proxy","shell","dbus","file_transfer","clipboard"):self.assertFalse(p[key])
  self.assertEqual(p["window_policy"],"patched_default_deny_allowlist");self.assertEqual(p["bind_tcp"],"127.0.0.1:14500");self.assertEqual(p["allowed_window_classes"],("HermesDesktop",))
 def test_sandbox_fallback_and_unapproved_environment_fail_closed(self):
  with self.assertRaises(SessionUnavailable):require_sandbox_evidence(renderer_sandboxed=False,no_sandbox_marker=True)
  with self.assertRaises(SessionUnavailable):SessionSpec("hermes-remote",":81","/home/a","/opt/hermes/desktop","b"*40,frozenset({"HermesDesktop"}),hermes_environment={"CLOUDFLARE_TOKEN":"secret"})
 def test_launcher_requires_patch_custody_and_actual_renderer_probes(self):
  launcher=XpraLauncher(self.spec,xpra="/usr/bin/xpra",runtime_dir=Path("/run/hermes-remote"),sandbox_probe=lambda _: (True,False),process_probe=lambda _:{},window_patch_ready=lambda _:True,stop_scope=lambda _:None)
  cmd=launcher.command();self.assertIn("--bind-tcp=127.0.0.1:14500",cmd);self.assertIn("--html=on",cmd);self.assertIn("--clipboard=no",cmd);self.assertIn("--control=no",cmd)
  with self.assertRaises(SessionUnavailable):XpraLauncher(SessionSpec("hermes-remote",":81","/home/a","/opt/hermes/desktop","a"*40,frozenset({"HermesDesktop"})),xpra="/usr/bin/xpra",runtime_dir=Path("/run/hermes-remote"),sandbox_probe=lambda _: (True,False),process_probe=lambda _:{},window_patch_ready=lambda _:True,stop_scope=lambda _:None)
