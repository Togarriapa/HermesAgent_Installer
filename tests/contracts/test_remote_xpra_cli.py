"""Parse the generated server command with the exact upstream Xpra parser pin."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from hermes_installer.remote.launcher import XpraLauncher
from hermes_installer.remote.session import SessionSpec, XPRA_CLI_SOURCE_COMMIT


_PARSER_PROBE = r"""
import json, sys
if sys.platform == "darwin":
    # This probe exercises Linux server option parsing only; it does not start Xpra.
    sys.platform = "linux"
from xpra.scripts.config import InitException
from xpra.scripts.parsing import MODE_ALIAS, parse_cmdline
argv = ["xpra", *json.loads(sys.argv[1])]
try:
    options, args = parse_cmdline(argv)
except Exception as exc:
    raise SystemExit(f"pinned Xpra parser rejected launcher argv: {type(exc).__name__}: {exc}")
if len(args) != 2 or MODE_ALIAS.get(args[0], args[0]) != "seamless":
    raise SystemExit(f"unexpected Xpra server mode arguments: {args!r}")
checks = {
    "commands": False, "shell": False, "control": False,
    "start_new_commands": False, "start_via_proxy": False,
    "proxy_start_sessions": False, "dbus": "no", "dbus_control": False,
    "file_transfer": "no", "open_files": "no", "open_url": "no",
    "printing": "no", "clipboard": "no", "webcam": "no", "audio": False,
    "speaker": "off", "microphone": "off", "remote_logging": "off",
    "http_scripts": "no", "ssh_upgrade": False, "rfb_upgrade": 0,
    "rdp_upgrade": False, "daemon": False, "systemd_run": "no",
    "exit_with_children": True, "attach": False,
    "html": "on", "bind_tcp": ["127.0.0.1:14500"],
    "socket_dirs": [sys.argv[2]], "socket_permissions": "600",
}
for name, expected in checks.items():
    actual = getattr(options, name)
    if actual != expected:
        raise SystemExit(f"unexpected parsed {name}: {actual!r} (wanted {expected!r})")
"""


@unittest.skipUnless(os.environ.get("XPRA_SOURCE_ROOT"), "pinned Xpra source is supplied by CI")
class PinnedXpraCliTests(unittest.TestCase):
    def test_generated_command_is_accepted_with_real_pinned_parser(self):
        source = Path(os.environ["XPRA_SOURCE_ROOT"]).resolve(strict=True)
        revision = subprocess.check_output(
            ["git", "-C", str(source), "rev-parse", "HEAD"], text=True, timeout=5
        ).strip()
        self.assertEqual(revision, XPRA_CLI_SOURCE_COMMIT)

        runtime = Path("/tmp/hermes-remote-xpra-parser")
        spec = SessionSpec(
            "hermes-remote", ":81", "/var/lib/hermes-remote",
            "/opt/hermes/bin/hermes-desktop", "a" * 40,
            frozenset({"HermesDesktop"}), uid=1000,
            hermes_arguments=("--user-data-dir=/var/lib/hermes-remote/profile",),
            hermes_environment={"HERMES_HOME": "/opt/hermes"},
        )
        command = XpraLauncher(
            spec, xpra="/usr/bin/xpra", runtime_dir=runtime,
            sandbox_probe=lambda _pid: (True, False), process_probe=lambda _pid: {},
            window_patch_ready=lambda _classes: True, stop_scope=lambda _pid: None,
        ).command()
        env = dict(os.environ)
        env["PYTHONPATH"] = os.pathsep.join(
            value for value in (str(source), env.get("PYTHONPATH", "")) if value
        )
        result = subprocess.run(
            [sys.executable, "-c", _PARSER_PROBE, json.dumps(command[1:]), str(runtime)],
            capture_output=True, text=True, env=env, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
