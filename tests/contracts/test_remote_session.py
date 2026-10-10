import unittest
from pathlib import Path

from hermes_installer.remote.session import (
    SessionSpec, SessionUnavailable, server_policy, require_sandbox_evidence,
)
from hermes_installer.remote.launcher import build_xpra_command


class RemoteSessionTests(unittest.TestCase):
    def setUp(self):
        self.spec = SessionSpec(
            "hermes-remote", ":81", "/hermes/profiles/hermes-desktop",
            "/hermes/profiles/hermes-desktop/bin/hermes-desktop", "a" * 40,
            frozenset({"HermesDesktop"}), uid=1000,
            hermes_arguments=("--user-data-dir=/hermes/profiles/hermes-desktop/profile",),
            hermes_environment={"HERMES_HOME": "/hermes"},
            xvfb_artifact_ref="artifact:xvfb:" + "b" * 64,
        )

    def test_server_policy_disables_shell_file_and_host_desktop(self):
        policy = server_policy(self.spec)
        self.assertEqual(policy["mode"], "seamless")
        self.assertEqual(policy["forbidden_modes"], ("desktop", "shadow", "proxy"))
        for key in ("start_new_commands", "shell", "commands", "control", "dbus", "file_transfer", "clipboard", "http_scripts"):
            self.assertFalse(policy[key])
        self.assertEqual(policy["window_policy"], "patched_default_deny_allowlist")
        self.assertEqual(policy["bind_tcp"], "127.0.0.1:14500")
        self.assertEqual(policy["allowed_window_classes"], ("HermesDesktop",))

    def test_sandbox_fallback_and_unapproved_environment_fail_closed(self):
        with self.assertRaises(SessionUnavailable):
            require_sandbox_evidence(renderer_sandboxed=False, no_sandbox_marker=True)
        with self.assertRaises(SessionUnavailable):
            SessionSpec(
                "hermes-remote", ":81", "/home/a", "/opt/hermes/desktop", "b" * 40,
                frozenset({"HermesDesktop"}), hermes_environment={"CLOUDFLARE_TOKEN": "secret"},
                xvfb_artifact_ref="artifact:xvfb:" + "b" * 64,
            )

    def test_xvfb_must_be_an_opaque_pinned_child_artifact(self):
        with self.assertRaises(SessionUnavailable):
            SessionSpec(
                "hermes-remote", ":81", "/home/a", "/opt/hermes/desktop", "b" * 40,
                frozenset({"HermesDesktop"}), xvfb_artifact_ref="/usr/bin/Xvfb",
            )

    def test_command_uses_valid_pinned_mode_and_never_invents_mode_flags(self):
        command = build_xpra_command(self.spec, "/usr/bin/xpra", Path("/hermes/profiles/hermes-desktop/run"))
        self.assertEqual(command[:3], ["/usr/bin/xpra", "seamless", ":81"])
        for option in (
            "--bind-tcp=127.0.0.1:14500", "--html=on", "--clipboard=no", "--control=no",
            "--commands=no", "--shell=no", "--dbus=no", "--daemon=no",
            "--systemd-run=no", "--exit-with-children=yes",
            "--use-display=no", "--xvfb",
        ):
            self.assertIn(option, command)
        self.assertEqual(command[command.index("--xvfb") + 1], self.spec.xvfb_artifact_ref)
        self.assertFalse(any(option.startswith("--start-child") for option in command))
        self.assertFalse(any(option.startswith((
            "--start-new-session", "--start-desktop", "--start-shadow", "--start-proxy", "--dbus-proxy",
        )) for option in command))
