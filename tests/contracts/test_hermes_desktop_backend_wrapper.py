from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
WRAPPER = REPO / "scripts" / "hermes_desktop_backend.sh"
SOURCE = "/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532"
PYTHON = "/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python"
PREFIX = "/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv"


class HermesDesktopBackendWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="hermes-desktop-wrapper-")
        self.root = Path(self.temp.name)
        self.source = self.root / "held source"
        (self.source / "hermes_cli").mkdir(parents=True)
        (self.source / "hermes_cli" / "main.py").write_text("# fixture module\n")
        self.prefix = self.root / "pm venv"
        self.prefix.mkdir()
        self.capture = self.root / "exec.json"
        self.python = self.root / "python"
        self.python.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "if sys.argv[1] == '-c':\n"
            "    if os.environ.get('FIXTURE_PREFLIGHT_FAIL'): raise SystemExit(41)\n"
            "    raise SystemExit(0)\n"
            "if sys.argv[1:3] != ['-m', 'hermes_cli.main']: raise SystemExit(42)\n"
            "pathlib.Path(os.environ['FIXTURE_CAPTURE']).write_text(json.dumps({"
            "'argv':sys.argv[1:], 'cwd':os.getcwd(), 'home':os.environ.get('HOME'),"
            "'hermes_home':os.environ.get('HERMES_HOME'), 'pythonpath':os.environ.get('PYTHONPATH'),"
            "'pythonhome':os.environ.get('PYTHONHOME'), 'pythonstartup':os.environ.get('PYTHONSTARTUP'),"
            "'pythonuserbase':os.environ.get('PYTHONUSERBASE')}))\n"
            "raise SystemExit(int(os.environ.get('FIXTURE_BACKEND_EXIT', '0')))\n"
        )
        self.python.chmod(0o755)
        script = WRAPPER.read_text()
        script = script.replace(f"SOURCE='{SOURCE}'", f"SOURCE={shlex.quote(str(self.source))}")
        script = script.replace(f"PYTHON='{PYTHON}'", f"PYTHON={shlex.quote(str(self.python))}")
        script = script.replace(f"EXPECTED_PREFIX='{PREFIX}'", f"EXPECTED_PREFIX={shlex.quote(str(self.prefix))}")
        self.wrapper = self.root / "wrapper.sh"
        self.wrapper.write_text(script)
        self.wrapper.chmod(0o755)
        self.cwd = self.root / "working directory"
        self.cwd.mkdir()
        self.env = {
            **os.environ,
            "HOME": "/home/admin",
            "HERMES_HOME": "/home/admin/.hermes",
            "PYTHONHOME": "/must-be-cleared",
            "PYTHONSTARTUP": "/must-be-cleared",
            "PYTHONUSERBASE": "/must-be-cleared",
            "FIXTURE_CAPTURE": str(self.capture),
            "PATH": f"{self.root}:{os.environ.get('PATH', '')}",
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_wrapper(self, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.wrapper), *args], cwd=self.cwd, env=env or self.env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )

    def test_executes_official_module_with_arguments_and_preserves_profile_context(self) -> None:
        result = self.run_wrapper("--version")
        self.assertEqual(result.returncode, 0, result.stderr)
        import json
        observed = json.loads(self.capture.read_text())
        self.assertEqual(observed["argv"], ["-m", "hermes_cli.main", "--version"])
        self.assertEqual(observed["cwd"], str(self.cwd.resolve()))
        self.assertEqual(observed["home"], "/home/admin")
        self.assertEqual(observed["hermes_home"], "/home/admin/.hermes")
        self.assertEqual(observed["pythonpath"], str(self.source))
        self.assertIsNone(observed["pythonhome"])
        self.assertIsNone(observed["pythonstartup"])
        self.assertIsNone(observed["pythonuserbase"])

    def test_backend_exit_status_is_not_hidden(self) -> None:
        env = {**self.env, "FIXTURE_BACKEND_EXIT": "23"}
        self.assertEqual(self.run_wrapper("--version", env=env).returncode, 23)

    def test_missing_source_fails_before_python_execution(self) -> None:
        (self.source / "hermes_cli" / "main.py").unlink()
        result = self.run_wrapper("--version")
        self.assertEqual(result.returncode, 126)
        self.assertIn("source generation is unavailable", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_interpreter_identity_failure_fails_before_backend_execution(self) -> None:
        env = {**self.env, "FIXTURE_PREFLIGHT_FAIL": "1"}
        result = self.run_wrapper("--version", env=env)
        self.assertEqual(result.returncode, 126)
        self.assertIn("identity check failed", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_rejects_unexpected_home(self) -> None:
        env = {**self.env, "HOME": "/tmp/other-home"}
        result = self.run_wrapper("--version", env=env)
        self.assertEqual(result.returncode, 126)
        self.assertIn("profile owner/home", result.stderr)
        self.assertFalse(self.capture.exists())

    def test_rejects_root_before_backend_execution(self) -> None:
        id_command = self.root / "id"
        id_command.write_text("#!/bin/sh\nprintf '0\\n'\n")
        id_command.chmod(0o755)
        result = self.run_wrapper("--version")
        self.assertEqual(result.returncode, 126)
        self.assertIn("must not run as root", result.stderr)
        self.assertFalse(self.capture.exists())


if __name__ == "__main__":
    unittest.main()
