from __future__ import annotations

import contextlib
import io
import unittest
from unittest.mock import patch

from hermes_installer.root_setup import (
    RootSetupAction,
    RootSetupResult,
    RootSetupState,
    launcher_status,
    main,
    run_root_setup_action,
)


class RootSetupBoundaryTests(unittest.TestCase):
    def test_action_schema_is_finite_and_extra_arguments_are_rejected(self) -> None:
        for action in ("install", "resume", "update"):
            with self.subTest(action=action):
                self.assertEqual(RootSetupAction(action).value, action)
        with self.assertRaises(ValueError):
            RootSetupAction("configure")
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as raised:
                main(["install", "--config", "/tmp/caller.json"])
        self.assertEqual(raised.exception.code, 2)

    def test_result_carries_only_bounded_state_and_fixed_resume_command(self) -> None:
        result = RootSetupResult(
            RootSetupAction.RESUME,
            RootSetupState.PENDING,
            "runtime",
            "The owned checkpoint is valid; runtime receipt recovery and continuation are not yet connected.",
            "sudo -- hermes-installer-root-setup resume",
            4,
            "RUNTIME_HANDLERS_UNAVAILABLE",
            RootSetupAction.RESUME,
        )
        self.assertEqual(result.resume_command, "sudo -- hermes-installer-root-setup resume")
        with self.assertRaises(ValueError):
            RootSetupResult(
                RootSetupAction.RESUME, RootSetupState.PENDING, "runtime", "pending",
                "sudo -- hermes-installer-root-setup resume --path /tmp/state", 4,
                "RUNTIME_HANDLERS_UNAVAILABLE", RootSetupAction.RESUME,
            )

    def test_user_mode_launcher_status_never_claims_root_attestation(self) -> None:
        with patch("hermes_installer.root_setup.os.getuid", return_value=501), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=501), \
             patch("hermes_installer.root_setup.sys.platform", "darwin"):
            status = launcher_status()
        self.assertEqual(status.state, "unverified")
        self.assertEqual(status.blocker_code, "ROOT_ATTESTATION_REQUIRED")
        self.assertNotIn("sudo", status.message)

    def test_non_linux_host_is_rejected_before_any_release_access(self) -> None:
        with patch("hermes_installer.root_setup.sys.platform", "darwin"), \
             patch("hermes_installer.root_setup.os.getuid", return_value=0), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=0):
            result = run_root_setup_action("install", target_account_name="hermes")
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "admission")

    def test_launcher_never_accepts_arbitrary_root_actions_or_json(self) -> None:
        output = io.StringIO()
        with patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=False), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=False), \
             contextlib.redirect_stderr(output):
            code = main(["install"])
        self.assertEqual(code, 4)
        self.assertIn("controlling terminal", output.getvalue())
        self.assertNotIn("sudo -- hermes-installer-root-setup install", output.getvalue())
        self.assertNotIn("/tmp", output.getvalue())


if __name__ == "__main__":
    unittest.main()
