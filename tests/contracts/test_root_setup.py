from __future__ import annotations

import builtins
import contextlib
import io
import os
import time
import unittest
from unittest.mock import patch

import hermes_installer.root_setup as root_setup
from hermes_installer.root_setup import (
    RootBootstrapCandidateSelectionRegistry,
    RootSetupAction,
    RootSetupExplicitChoices,
    RootSetupResult,
    RootSetupState,
    launcher_status,
    main,
    run_root_setup_action,
)


class RootSetupBoundaryTests(unittest.TestCase):
    def test_candidate_choice_is_exact_root_tty_input_and_one_use(self) -> None:
        registry = RootBootstrapCandidateSelectionRegistry()
        candidate = "a" * 40
        stdin_fd = os.open(os.devnull, os.O_RDONLY)
        pidfd = os.open(os.devnull, os.O_RDONLY)
        tty = os.fstat(stdin_fd)
        proof = root_setup._RootTTYProof(
            stdin_fd, pidfd, os.getpid(), 1, 0, 0, 1, os.getpgrp(), tty.st_dev,
            tty.st_ino, tty.st_rdev, time.monotonic(), time.monotonic() + 30,
        )
        with patch("hermes_installer.root_setup.sys.platform", "linux"), \
             patch("hermes_installer.root_setup.os.getuid", return_value=0), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=0), \
             patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=True), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=True), \
             patch("hermes_installer.root_setup._capture_root_tty_proof", return_value=proof), \
             patch("hermes_installer.root_setup._verify_root_tty_proof"), \
             patch.object(builtins, "input", return_value=candidate):
            choice = registry.issue_explicit_tty_choice(RootSetupAction.INSTALL)
        self.assertEqual(choice.candidate_git_sha, candidate)
        receipt = registry.resolve(choice)
        self.assertEqual(receipt.candidate_git_sha, candidate)
        self.assertIs(receipt.lifecycle_action, RootSetupAction.INSTALL)
        self.assertEqual(receipt.input_origin, "root_tty_explicit")
        self.assertEqual(len(receipt.choice_sha256), 64)
        with self.assertRaises(RuntimeError):
            registry.resolve(choice)
        with patch("hermes_installer.root_setup._verify_root_tty_proof"):
            snapshot = registry.consume_verified_selection(receipt)
        self.assertEqual(snapshot.controller_pid, os.getpid())
        self.assertEqual(snapshot.controller_start_ticks, 1)
        self.assertIs(snapshot.lifecycle_action, RootSetupAction.INSTALL)
        controller_pidfd, controller_tty = snapshot.duplicate_controller_fds()
        self.assertGreaterEqual(os.fstat(controller_pidfd).st_ino, 0)
        self.assertGreaterEqual(os.fstat(controller_tty).st_ino, 0)
        os.close(controller_pidfd)
        os.close(controller_tty)
        snapshot.close()
        with self.assertRaises(RuntimeError):
            registry.consume_verified_selection(receipt)

    def test_candidate_choice_rejects_forgery_and_noncanonical_sha(self) -> None:
        with self.assertRaises(TypeError):
            RootSetupExplicitChoices("a" * 40, RootSetupAction.INSTALL)
        registry = RootBootstrapCandidateSelectionRegistry()
        stdin_fd = os.open(os.devnull, os.O_RDONLY)
        pidfd = os.open(os.devnull, os.O_RDONLY)
        tty = os.fstat(stdin_fd)
        proof = root_setup._RootTTYProof(
            stdin_fd, pidfd, os.getpid(), 1, 0, 0, 1, os.getpgrp(), tty.st_dev,
            tty.st_ino, tty.st_rdev, time.monotonic(), time.monotonic() + 30,
        )
        with patch("hermes_installer.root_setup.sys.platform", "linux"), \
             patch("hermes_installer.root_setup.os.getuid", return_value=0), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=0), \
             patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=True), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=True), \
             patch("hermes_installer.root_setup._capture_root_tty_proof", return_value=proof), \
             patch.object(builtins, "input", return_value="A" * 40):
            with self.assertRaises(ValueError):
                registry.issue_explicit_tty_choice(RootSetupAction.INSTALL)

    def test_interrupted_candidate_input_closes_captured_controller_proof(self) -> None:
        registry = RootBootstrapCandidateSelectionRegistry()
        stdin_fd = os.open(os.devnull, os.O_RDONLY)
        pidfd = os.open(os.devnull, os.O_RDONLY)
        tty = os.fstat(stdin_fd)
        proof = root_setup._RootTTYProof(
            stdin_fd, pidfd, os.getpid(), 1, 0, 0, 1, os.getpgrp(), tty.st_dev,
            tty.st_ino, tty.st_rdev, time.monotonic(), time.monotonic() + 30,
        )
        with patch("hermes_installer.root_setup.sys.platform", "linux"), \
             patch("hermes_installer.root_setup.os.getuid", return_value=0), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=0), \
             patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=True), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=True), \
             patch("hermes_installer.root_setup._capture_root_tty_proof", return_value=proof), \
             patch.object(builtins, "input", side_effect=EOFError):
            with self.assertRaises(EOFError):
                registry.issue_explicit_tty_choice(RootSetupAction.INSTALL)
        self.assertEqual(proof.stdin_fd, -1)
        self.assertEqual(proof.pidfd, -1)

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
        self.assertEqual(status.schema, 1)
        self.assertEqual(status.state, "root-setup-required")
        self.assertFalse(status.authority)
        self.assertEqual(status.resume_command, "")
        self.assertEqual(status.blocker_code, "ROOT_ATTESTATION_REQUIRED")
        self.assertNotIn("sudo", status.message)

    def test_non_linux_host_is_rejected_before_any_release_access(self) -> None:
        with patch("hermes_installer.root_setup.sys.platform", "darwin"), \
             patch("hermes_installer.root_setup.os.getuid", return_value=0), \
             patch("hermes_installer.root_setup.os.geteuid", return_value=0):
            result = run_root_setup_action("install", target_account_name="hermes")
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "admission")

    def test_first_source_bootstrap_requires_proven_absent_predecessor_and_keeps_action(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending

        predecessor = type("Predecessor", (), {"state": "absent", "verify_current": lambda self: None})()
        registry = RootBootstrapCandidateSelectionRegistry()
        choice = object()
        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch.object(root_setup, "RootBootstrapCandidateSelectionRegistry", return_value=registry), \
             patch.object(registry, "issue_explicit_tty_choice", return_value=choice) as issue, \
             patch("hermes_installer.authority.installer_release_build.bootstrap_selected_release",
                   side_effect=BootstrapEnrollmentPending("exec handoff unavailable")) as bootstrap, \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   side_effect=AssertionError("must not inspect installed actor for absent deployment")):
            result = run_root_setup_action(RootSetupAction.UPDATE)
        issue.assert_called_once_with(RootSetupAction.UPDATE)
        bootstrap.assert_called_once_with(choice, registry)
        self.assertEqual(result.state, RootSetupState.PENDING)
        self.assertEqual(result.phase, "distribution")

    def test_present_predecessor_never_starts_first_source_bootstrap(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending

        predecessor = type("Predecessor", (), {
            "state": "present-verified", "verified_release_receipt_handle": "opaque-handle",
            "verify_current": lambda self: None,
        })()
        held = type("Held", (), {"close": lambda self: None})()
        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch("hermes_installer.authority.installer_release_build.resolve_verified_deployment_release",
                   return_value=held) as resolve, \
             patch("hermes_installer.authority.installer_release_build.bootstrap_selected_release") as bootstrap, \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   side_effect=BootstrapEnrollmentPending("current actor not installed")):
            result = run_root_setup_action("resume")
        resolve.assert_called_once_with("opaque-handle", consume=True)
        bootstrap.assert_not_called()
        self.assertEqual(result.state, RootSetupState.PENDING)

    def test_unverifiable_present_predecessor_fails_without_bootstrap_or_actor_fallback(self) -> None:
        from hermes_installer.authority.installer_release_build import InstallerReleaseBuildError

        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   side_effect=InstallerReleaseBuildError("present deployment is unverifiable")), \
             patch("hermes_installer.authority.installer_release_build.bootstrap_selected_release") as bootstrap, \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   side_effect=AssertionError("must not fall through to actor verification")):
            result = run_root_setup_action("install")
        bootstrap.assert_not_called()
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "distribution")

    def test_caller_cannot_supply_target_account_name(self) -> None:
        with patch.object(root_setup, "_require_root_linux"):
            result = run_root_setup_action("install", target_account_name="hermes")
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "admission")
        self.assertIn("controlling terminal", result.message)

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

    def test_qualification_dispatch_is_finite_and_never_enters_setup_lifecycle(self) -> None:
        with patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=True), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=True), \
             patch("hermes_installer.root_setup._require_root_linux"), \
             patch("hermes_installer.root_setup.run_root_setup_action",
                   side_effect=AssertionError("qualification must not run install/resume/update")), \
             patch("hermes_installer.root_setup._run_installed_qualification", return_value=4) as dispatch:
            code = main(["qualify", "--suite", "resource-cron-task-v1"])
        dispatch.assert_called_once_with("resource-cron-task-v1")
        self.assertEqual(code, 4)

    def test_qualification_rejects_missing_or_unreviewed_suite(self) -> None:
        with self.assertRaises(SystemExit):
            main(["qualify"])
        with self.assertRaises(SystemExit):
            main(["qualify", "--suite", "caller-selected-suite"])
        with self.assertRaises(SystemExit):
            main(["install", "--suite", "resource-cron-task-v1"])


if __name__ == "__main__":
    unittest.main()
