from __future__ import annotations

import json
import io
import os
import subprocess
import sys
import tempfile
import time
import os
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from hermes_installer.cli import main
from hermes_installer.preflight import discover_host
from hermes_installer.results import OutcomeState
from hermes_installer.runner import CommandRejected, CommandRunner, _capture_bounded, _terminate_group


class BootstrapContractTests(unittest.TestCase):
    def test_cli_help_and_read_only_plan_work(self) -> None:
        help_run = subprocess.run([str(ROOT / "install.sh"), "--help"], cwd=tempfile.gettempdir(), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, capture_output=True, text=True, check=False)
        self.assertEqual(help_run.returncode, 0, help_run.stderr)
        self.assertIn("plan", help_run.stdout)
        self.assertIn("verify", help_run.stdout)
        guide_run = subprocess.run([str(ROOT / "install.sh")], cwd=tempfile.gettempdir(), env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, capture_output=True, text=True, check=False)
        self.assertEqual(guide_run.returncode, 0, guide_run.stderr)
        self.assertIn("guided setup", guide_run.stdout)

        with patch("hermes_installer.cli._host_findings", return_value=()):
            self.assertEqual(main(["plan", "--json"]), 0)

    def test_install_rejects_unenrolled_development_host_without_writes(self) -> None:
        with patch("hermes_installer.cli.discover_host") as discover:
            discover.return_value = type("Facts", (), {"supported_arm64_linux": False})()
            with patch("hermes_installer.cli._host_findings", return_value=()):
                self.assertEqual(main(["install", "--json"]), 3)
            discover.assert_called_once()

    def test_runner_uses_argument_array_and_rejects_unreviewed_program(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runner = CommandRunner(allowed_programs={"uname"})
            result = runner.run(["uname", "-m"], cwd=root)
            self.assertEqual(result.returncode, 0)
            self.assertNotIn("SECRET", result.stdout)
            with self.assertRaises(CommandRejected):
                runner.run(["python3", "-c", "raise SystemExit(9)"], cwd=root)
            with self.assertRaises(CommandRejected):
                runner.run(["/tmp/uname", "-m"], cwd=root)
            with self.assertRaises(CommandRejected):
                runner.run(["uname", "-m"], cwd=root, env={"PATH": "/tmp"})

    def test_runner_discards_output_after_fixed_capture_limit(self) -> None:
        chunks: list[bytes] = []
        _capture_bounded(io.BytesIO(b"0123456789abcdef"), chunks, 7)
        self.assertEqual(b"".join(chunks), b"0123456")

    def test_timeout_cleanup_kills_process_group_descendants(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pidfile = root / "child.pid"
            parent_code = "import subprocess,sys,time; c=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)']); open(sys.argv[1],'w').write(str(c.pid)); time.sleep(30)"
            process = subprocess.Popen([sys.executable, "-c", parent_code, str(pidfile)], cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline = time.monotonic() + 2
            while not pidfile.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(pidfile.exists())
            child_pid = int(pidfile.read_text())
            _terminate_group(process)
            self.assertIsNotNone(process.poll())
            for _ in range(50):
                try:
                    os.kill(child_pid, 0)
                    time.sleep(0.02)
                except ProcessLookupError:
                    break
            else:
                self.fail("child process survived process-group cleanup")


if __name__ == "__main__":
    unittest.main()
