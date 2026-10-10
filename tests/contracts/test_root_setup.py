from __future__ import annotations

import builtins
import contextlib
import errno
import io
import importlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

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
    def test_source_bootstrap_os_diagnostic_is_finite_and_redacts_exception_details(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import BootstrapSystemCallFailure
        from hermes_installer.authority.installer_release_build import _bootstrap_os_error_step

        private_path = "/etc/hermes-installer/credentials/provider-token"
        original = OSError(errno.EACCES, "private diagnostic sentinel", private_path)
        with self.assertRaises(BootstrapSystemCallFailure) as caught:
            with _bootstrap_os_error_step("source_cas.materialize"):
                raise original

        failure = caught.exception
        self.assertIsInstance(failure, OSError)
        self.assertEqual(failure.step, "source_cas.materialize")
        self.assertEqual(failure.errno_name, "EACCES")
        safe = root_setup._safe_reason(failure)
        self.assertEqual(safe, "Root setup failed at source_cas.materialize [EACCES].")
        self.assertNotIn(private_path, safe)
        self.assertNotIn("private diagnostic sentinel", safe)
        self.assertNotIn(private_path, str(failure))
        self.assertNotIn("private diagnostic sentinel", str(failure))

        unknown = BootstrapSystemCallFailure("source_cas.materialize", 987654)
        self.assertEqual(unknown.errno_name, "UNKNOWN")
        self.assertNotIn("987654", root_setup._safe_reason(unknown))

        unknown.errno_name = private_path
        self.assertEqual(
            root_setup._safe_reason(unknown),
            "Root setup failed at source_cas.materialize.",
        )
        unknown.step = private_path
        self.assertEqual(
            root_setup._safe_reason(unknown),
            "Root setup could not verify its required authority (OSError).",
        )

        class MalformedDiagnostic(BootstrapSystemCallFailure):
            def __getattribute__(self, name: str) -> object:
                if name in {"step", "errno_name"}:
                    return private_path
                return super().__getattribute__(name)

        subclass_failure = MalformedDiagnostic("source_cas.materialize", errno.EACCES)
        self.assertEqual(
            root_setup._safe_reason(subclass_failure),
            "Root setup could not verify its required authority (OSError).",
        )
        self.assertNotIn(private_path, root_setup._safe_reason(subclass_failure))

        trust_failure = RuntimeError("untrusted detail must remain suppressed")
        self.assertEqual(
            root_setup._safe_reason(trust_failure),
            "Root setup could not verify its required authority (RuntimeError).",
        )

    def test_bootstrap_runtime_step_diagnostic_is_fixed_and_redacts_details(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import (
            BootstrapEnrollmentPending, BootstrapRuntimeStepFailure,
            bootstrap_runtime_error_step,
        )

        self.assertEqual(BootstrapRuntimeStepFailure.STEPS, frozenset({
            "bootstrap.tty_selection", "source_cas.construct", "source_cas.registry",
            "source_cas.acquire", "source_cas.resolve", "installer_runtime.registry",
            "installer_runtime.provision", "bootstrap.handoff", "bootstrap.reexec",
            "installed_release.predecessor", "installed_release.import_closure",
            "installed_release.actor_observation", "installed_release.actor_verification",
        }))
        private_detail = "/etc/hermes-installer/credentials/provider-token\nAPI_KEY=sentinel"
        with self.assertRaises(BootstrapRuntimeStepFailure) as caught:
            with bootstrap_runtime_error_step("source_cas.acquire"):
                raise RuntimeError(private_detail)
        failure = caught.exception
        safe = root_setup._safe_reason(failure)
        self.assertEqual(safe, "Root setup failed at source_cas.acquire (RuntimeError).")
        self.assertNotIn(private_detail, safe)
        self.assertNotIn(private_detail, str(failure))
        self.assertEqual(failure.step, "source_cas.acquire")
        self.assertEqual(failure.error_kind, "RuntimeError")

        for step in BootstrapRuntimeStepFailure.STEPS:
            with self.subTest(step=step):
                with self.assertRaises(BootstrapRuntimeStepFailure) as staged:
                    with bootstrap_runtime_error_step(step):
                        raise RuntimeError(private_detail)
                self.assertEqual(root_setup._safe_reason(staged.exception),
                                 f"Root setup failed at {step} (RuntimeError).")
                self.assertNotIn(private_detail, root_setup._safe_reason(staged.exception))

        failure.step = private_detail
        self.assertEqual(
            root_setup._safe_reason(failure),
            "Root setup could not verify its required authority (RuntimeError).",
        )
        failure.step = object()
        self.assertEqual(
            root_setup._safe_reason(failure),
            "Root setup could not verify its required authority (RuntimeError).",
        )
        failure.step = "source_cas.acquire"
        failure.error_kind = private_detail
        self.assertEqual(
            root_setup._safe_reason(failure),
            "Root setup could not verify its required authority (RuntimeError).",
        )
        failure.error_kind = None
        self.assertEqual(
            root_setup._safe_reason(failure),
            "Root setup could not verify its required authority (RuntimeError).",
        )

        with self.assertRaises(ValueError):
            with bootstrap_runtime_error_step(private_detail):
                raise RuntimeError("not reached")

        class UntrustedRuntimeError(RuntimeError):
            def __str__(self) -> str:
                raise AssertionError("diagnostic formatter must not stringify exceptions")

        original = UntrustedRuntimeError(private_detail)
        with self.assertRaises(UntrustedRuntimeError) as unwrapped:
            with bootstrap_runtime_error_step("bootstrap.reexec"):
                raise original
        self.assertIs(unwrapped.exception, original)
        self.assertEqual(
            root_setup._safe_reason(original),
            "Root setup could not verify its required authority (UntrustedRuntimeError).",
        )

        pending = BootstrapEnrollmentPending(private_detail)
        with self.assertRaises(BootstrapEnrollmentPending) as pending_error:
            with bootstrap_runtime_error_step("bootstrap.reexec"):
                raise pending
        self.assertIs(pending_error.exception, pending)
        self.assertEqual(
            root_setup._safe_reason(pending),
            "A required root-selected setup prerequisite is pending; rerun the root setup action after resolving it.",
        )
        with self.assertRaises(PermissionError):
            with bootstrap_runtime_error_step("bootstrap.reexec"):
                raise PermissionError(private_detail)

    def test_source_choice_runtime_failure_reports_only_fixed_boundary(self) -> None:
        predecessor = type("Predecessor", (), {"state": "absent", "verify_current": lambda self: None})()
        registry = RootBootstrapCandidateSelectionRegistry()
        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch.object(root_setup, "RootBootstrapCandidateSelectionRegistry", return_value=registry), \
             patch.object(registry, "issue_explicit_tty_choice",
                          side_effect=RuntimeError("/secret/provider-token")), \
             patch("hermes_installer.authority.installer_release_build.bootstrap_selected_release") as bootstrap:
            result = run_root_setup_action(RootSetupAction.INSTALL)
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "distribution")
        self.assertEqual(result.message,
                         "Root setup failed at bootstrap.tty_selection (RuntimeError).")
        self.assertNotIn("provider-token", result.message)
        bootstrap.assert_not_called()

    def test_installed_actor_observation_runtime_failure_reports_only_fixed_boundary(self) -> None:
        predecessor = type("Predecessor", (), {
            "state": "present-verified", "verified_release_receipt_handle": "opaque-handle",
            "verify_current": lambda self: None,
        })()
        held = type("Held", (), {"close": lambda self: None})()
        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch("hermes_installer.authority.installer_release_build.resolve_verified_deployment_release",
                   return_value=held), \
             patch.object(root_setup, "_import_v180_native_support_closure"), \
             patch.object(root_setup, "_import_v187_listener_activation_closure"), \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   side_effect=RuntimeError("/secret/provider-token")):
            result = run_root_setup_action(RootSetupAction.INSTALL)
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "distribution")
        self.assertEqual(result.message,
                         "Root setup failed at installed_release.actor_observation (RuntimeError).")
        self.assertNotIn("provider-token", result.message)

    def test_installed_actor_verification_runtime_failure_reports_only_fixed_boundary(self) -> None:
        from types import SimpleNamespace

        predecessor = type("Predecessor", (), {
            "state": "present-verified", "verified_release_receipt_handle": "opaque-handle",
            "verify_current": lambda self: None,
        })()
        held = type("Held", (), {"close": lambda self: None})()
        actor = SimpleNamespace(
            verify_current=Mock(side_effect=RuntimeError("/secret/token")),
            close=Mock(),
        )
        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch("hermes_installer.authority.installer_release_build.resolve_verified_deployment_release",
                   return_value=held), \
             patch.object(root_setup, "_import_v180_native_support_closure"), \
             patch.object(root_setup, "_import_v187_listener_activation_closure"), \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   return_value=(SimpleNamespace(close=Mock()), actor)):
            result = run_root_setup_action(RootSetupAction.INSTALL)
        self.assertEqual(result.state, RootSetupState.FAILED)
        self.assertEqual(result.phase, "runtime")
        self.assertEqual(result.message,
                         "Root setup failed at installed_release.actor_verification (RuntimeError).")
        self.assertNotIn("/secret/token", result.message)
        actor.close.assert_called_once_with()

    def test_fixed_authority_daemon_action_is_finite_and_not_tty_dispatched(self) -> None:
        activation_id = "a" * 32
        with patch.object(root_setup, "_require_root_linux") as require_root, \
             patch.object(root_setup, "_import_v187_listener_activation_closure") as load_closure, \
             patch("hermes_installer.authority.daemon.main_adopt", return_value=23) as adopt, \
             patch("hermes_installer.root_setup.sys.stdin.isatty", return_value=False), \
             patch("hermes_installer.root_setup.sys.stderr.isatty", return_value=False):
            result = main(["authority-daemon-adopt", "--activation-id", activation_id])
        self.assertEqual(result, 23)
        require_root.assert_called_once_with()
        load_closure.assert_called_once_with()
        adopt.assert_called_once_with(activation_id)

    def test_authority_daemon_action_rejects_extra_arguments(self) -> None:
        stderr = io.StringIO()
        with patch.object(root_setup, "_require_root_linux") as require_root, \
             patch("sys.stderr", stderr):
            result = main(["authority-daemon-adopt", "--activation-id", "a" * 32, "--unsafe"])
        self.assertEqual(result, 1)
        require_root.assert_not_called()
        self.assertIn("Use exactly:", stderr.getvalue())

    def test_reviewed_runtime_factory_is_imported_before_actor_observation(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending

        module_name = "hermes_installer.authority.bootstrap_runtime_factory"
        prior_module = sys.modules.pop(module_name, None)
        authority_package = importlib.import_module("hermes_installer.authority")
        prior_attribute = getattr(authority_package, "bootstrap_runtime_factory", None)
        if hasattr(authority_package, "bootstrap_runtime_factory"):
            delattr(authority_package, "bootstrap_runtime_factory")
        predecessor = type("Predecessor", (), {
            "state": "present-verified", "verified_release_receipt_handle": "held-release",
            "verify_current": lambda self: None,
        })()
        held = type("Held", (), {"close": lambda self: None})()
        observed: list[object] = []

        def observe_after_composition_import() -> object:
            module = sys.modules.get(module_name)
            self.assertIsNotNone(module)
            self.assertEqual(Path(module.__spec__.origin).resolve(),
                             (Path(__file__).parents[2] / "src/hermes_installer/authority/bootstrap_runtime_factory.py").resolve())
            self.assertTrue(callable(module.RootBootstrapRuntimeFactory))
            observed.append(module)
            raise BootstrapEnrollmentPending("stop after ordering assertion")

        try:
            with patch.object(root_setup, "_require_root_linux"), \
                 patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                       return_value=predecessor), \
                 patch("hermes_installer.authority.installer_release_build.resolve_verified_deployment_release",
                       return_value=held), \
                 patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                       side_effect=observe_after_composition_import):
                result = run_root_setup_action("install")
            self.assertEqual(len(observed), 1)
            self.assertEqual(result.state, RootSetupState.PENDING)
        finally:
            sys.modules.pop(module_name, None)
            if prior_module is not None:
                sys.modules[module_name] = prior_module
            if prior_attribute is not None:
                authority_package.bootstrap_runtime_factory = prior_attribute
            elif hasattr(authority_package, "bootstrap_runtime_factory"):
                delattr(authority_package, "bootstrap_runtime_factory")

    def test_qualification_composition_imports_precede_actor_observation(self) -> None:
        from hermes_installer.authority.installer_release import InstalledRootReleaseVerifier

        module_name = "hermes_installer.authority.installed_qualification"
        prior_module = sys.modules.pop(module_name, None)
        authority_package = importlib.import_module("hermes_installer.authority")
        prior_attribute = getattr(authority_package, "installed_qualification", None)
        if hasattr(authority_package, "installed_qualification"):
            delattr(authority_package, "installed_qualification")
        observed: list[object] = []

        def observe_after_finite_imports() -> object:
            module = sys.modules.get(module_name)
            self.assertIsNotNone(module)
            for name in (
                "hermes_installer.authority.qualification_resource_cron_recipe",
                "hermes_installer.authority.qualification_resource_cron_schema",
                "hermes_installer.authority.root_controller_custody",
                "hermes_installer.managed_process_custodian",
                "hermes_installer.protected_enrollment",
            ):
                self.assertIn(name, sys.modules)
            observed.append(module)
            raise RuntimeError("stop after ordering assertion")

        try:
            with patch.object(root_setup, "_require_root_linux"), \
                 patch.object(InstalledRootReleaseVerifier, "from_current_root_process",
                       side_effect=observe_after_finite_imports):
                result = root_setup._run_installed_qualification("resource-cron-task-v1")
            self.assertEqual(len(observed), 1)
            self.assertEqual(result, 4)
        finally:
            sys.modules.pop(module_name, None)
            if prior_module is not None:
                sys.modules[module_name] = prior_module
            if prior_attribute is not None:
                authority_package.installed_qualification = prior_attribute
            elif hasattr(authority_package, "installed_qualification"):
                delattr(authority_package, "installed_qualification")

    def test_installed_launcher_disables_runtime_bytecode_writes(self) -> None:
        source = Path(__file__).parents[2] / "scripts/hermes-installer-root-setup"
        with tempfile.TemporaryDirectory() as temporary:
            release = Path(temporary) / "release"
            launcher = release / "bin/hermes-installer-root-setup"
            interpreter = release / "runtime/bin/python"
            capture = Path(temporary) / "argv.txt"
            launcher.parent.mkdir(parents=True)
            interpreter.parent.mkdir(parents=True)
            launcher.write_bytes(source.read_bytes())
            launcher.chmod(0o755)
            interpreter.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$CAPTURE\"\n",
                encoding="utf-8",
            )
            interpreter.chmod(0o755)

            environment = {**os.environ, "CAPTURE": str(capture)}
            result = subprocess.run([str(launcher), "install"], env=environment,
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", errors="replace"))
            args = capture.read_text(encoding="utf-8").splitlines()
            self.assertEqual(args[:4], ["-B", "-I", "-S", "-c"])
            self.assertEqual(args[-1], "install")

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

    def test_first_install_ensures_fixed_prefixes_before_credential_vault_composition(self) -> None:
        from hermes_installer.authority.bootstrap_enrollment import BootstrapEnrollmentPending

        class Held:
            def close(self):
                pass

            def verify_current(self, *_args):
                pass

        predecessor = type("Predecessor", (), {
            "state": "present-verified", "verified_release_receipt_handle": "held-release",
            "verify_current": lambda self: None,
        })()
        actor = Held()
        release = Held()

        def compose_initial(*_args, **_kwargs):
            self.assertTrue(ensure_prefixes.called)
            raise BootstrapEnrollmentPending("composition fixture stop")

        with patch.object(root_setup, "_require_root_linux"), \
             patch("hermes_installer.authority.installer_release_build.observe_deployment_predecessor",
                   return_value=predecessor), \
             patch("hermes_installer.authority.installer_release_build.resolve_verified_deployment_release",
                   return_value=Held()), \
             patch("hermes_installer.authority.installer_release.InstalledRootReleaseVerifier.from_current_root_process",
                   return_value=(release, actor)), \
             patch.object(root_setup.Path, "lstat", side_effect=FileNotFoundError), \
             patch("hermes_installer.authority.installer_release_build.ensure_initial_setup_fixed_prefixes") as ensure_prefixes, \
             patch("hermes_installer.authority.bootstrap_runtime_factory.RootInitialSetupAggregate",
                   side_effect=compose_initial):
            result = run_root_setup_action(RootSetupAction.INSTALL)
        ensure_prefixes.assert_called_once_with()
        self.assertEqual(result.state, RootSetupState.PENDING)
        self.assertEqual(result.phase, "runtime")

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
            main(["qualify", "--suite", "resource-cron-task-v1", "--suite", "display-xauthority-v1"])
        with self.assertRaises(SystemExit):
            main(["--suite", "resource-cron-task-v1", "qualify"])
        with self.assertRaises(SystemExit):
            main(["install", "--suite", "resource-cron-task-v1"])


if __name__ == "__main__":
    unittest.main()
