"""Root-local first-install launcher for the reviewed Hermes installer.

This module is intentionally a small command boundary. It accepts only the
three lifecycle intents understood by the installed root setup actor; policy,
paths, credentials, and artifact bytes are resolved by the root-owned
registries.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import StrEnum
import os
import re
import sys
from typing import Sequence


class RootSetupAction(StrEnum):
    INSTALL = "install"
    RESUME = "resume"
    UPDATE = "update"


class RootSetupState(StrEnum):
    READY = "ready"
    PENDING = "pending"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class RootSetupResult:
    action: RootSetupAction
    state: RootSetupState
    phase: str
    message: str
    resume_command: str
    exit_code: int

    def __post_init__(self) -> None:
        if not isinstance(self.action, RootSetupAction) or not isinstance(self.state, RootSetupState):
            raise TypeError("root setup results require finite action and state values")
        if self.phase not in {"admission", "distribution", "prepared", "runtime", "materialization", "health"}:
            raise ValueError("root setup phase is not a reviewed phase")
        if not self.message or len(self.message) > 512 or "\n" in self.message:
            raise ValueError("root setup message must be one bounded line")
        if self.resume_command != f"sudo -- hermes-installer-root-setup {self.action.value}":
            raise ValueError("root setup resume command is not the fixed launcher command")
        expected = {RootSetupState.READY: 0, RootSetupState.PENDING: 4, RootSetupState.FAILED: 1}[self.state]
        if self.exit_code != expected:
            raise ValueError("root setup exit code does not match its state")


_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")


def verify_installed_launcher() -> bool:
    """Verify the current root process is the installed launcher and closure.

    This is deliberately a current-process check. User-mode callers cannot
    turn file presence or a caller-provided path into launcher authority.
    """
    from .authority.installer_release import InstalledRootReleaseVerifier

    release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    try:
        actor.verify_current(release)
        return True
    finally:
        actor.close()
        release.close()


def run_root_setup_action(
    action: RootSetupAction | str,
    *,
    selection_handle: str | None = None,
    target_account_name: str | None = None,
) -> RootSetupResult:
    """Run one bounded root setup intent through the installed actor.

    Selection handles are accepted only as opaque root-issued references.
    Their resolution remains inside the installed registries. The current
    runtime graph does not yet expose the recovery/update/materialization and
    health consumers, so this function reports their exact pending phase.
    """
    try:
        selected_action = RootSetupAction(action)
    except (TypeError, ValueError):
        raise ValueError("root setup action must be install, resume, or update") from None

    try:
        _require_root_linux()
    except RuntimeError as exc:
        return _result(selected_action, RootSetupState.FAILED, "admission", _safe_reason(exc))
    if selection_handle is not None and not _HANDLE.fullmatch(selection_handle):
        return _result(selected_action, RootSetupState.FAILED, "admission",
                       "The selected root setup reference is malformed.")
    if selection_handle is not None:
        return _result(selected_action, RootSetupState.PENDING, "runtime",
                       "The selected root reference is validly shaped, but its installed resolver is not connected.")
    from .authority.bootstrap_enrollment import BootstrapEnrollmentPending
    from .authority.installer_release import InstalledRootReleaseVerifier
    from .authority.bootstrap_runtime_factory import RootBootstrapRuntimeFactory

    try:
        release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    except BootstrapEnrollmentPending as exc:
        return _result(selected_action, RootSetupState.PENDING, "distribution", _safe_reason(exc))
    except (OSError, RuntimeError) as exc:
        return _result(selected_action, RootSetupState.FAILED, "distribution", _safe_reason(exc))

    factory: RootBootstrapRuntimeFactory | None = None
    session = None
    try:
        actor.verify_current(release)
        account = target_account_name if target_account_name is not None else _read_target_account_name()
        if not _ACCOUNT.fullmatch(account):
            return _result(selected_action, RootSetupState.FAILED, "admission",
                           "The target account name is invalid.")
        # Constructor composition takes ownership of the held release and
        # actor receipts, including its failure paths.
        release_for_factory, actor_for_factory = release, actor
        release = actor = None  # type: ignore[assignment]
        factory = RootBootstrapRuntimeFactory(_release=release_for_factory, _actor=actor_for_factory)
        if selected_action is RootSetupAction.UPDATE:
            return _result(selected_action, RootSetupState.PENDING, "runtime",
                           "Fresh-generation update and rollback publication are not yet connected to the root setup runtime.")
        mode = "resume" if selected_action is RootSetupAction.RESUME else "install"
        session = factory.begin(mode, account)
        if selected_action is RootSetupAction.RESUME:
            # begin(resume) verifies and adopts only an owned, checkpointed
            # transaction. The actual continuation phases are connected below
            # once their sealed root APIs are available.
            return _result(selected_action, RootSetupState.PENDING, "runtime",
                           "The owned checkpoint is valid; runtime receipt recovery and continuation are not yet connected.")
        receipt = session.provision()
        if receipt.state != "prepared" or receipt.enrollment_ids:
            return _result(selected_action, RootSetupState.FAILED, "prepared",
                           "Initial setup did not produce the required empty prepared generation.")
        return _result(selected_action, RootSetupState.PENDING, "prepared",
                       "The root prepared generation is recorded; source/runtime receipts, native materialization, publication, and health checks still need their verified runtime handlers.")
    except BootstrapEnrollmentPending as exc:
        return _result(selected_action, RootSetupState.PENDING, "runtime", _safe_reason(exc))
    except (OSError, RuntimeError, ValueError) as exc:
        return _result(selected_action, RootSetupState.FAILED, "runtime", _safe_reason(exc))
    finally:
        try:
            if session is not None:
                session.close()
        finally:
            try:
                if factory is not None:
                    factory.close()
            finally:
                if actor is not None:
                    actor.close()
                if release is not None:
                    release.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hermes-installer-root-setup")
    parser.add_argument("action", choices=tuple(item.value for item in RootSetupAction))
    args = parser.parse_args(argv)
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        result = _result(RootSetupAction(args.action), RootSetupState.PENDING, "admission",
                         "Root setup requires its controlling terminal for local operator intake.")
    else:
        try:
            result = run_root_setup_action(args.action)
        except RuntimeError as exc:
            result = _result(RootSetupAction(args.action), RootSetupState.PENDING,
                             "admission", _safe_reason(exc))
        except ValueError as exc:
            result = _result(RootSetupAction(args.action), RootSetupState.FAILED,
                             "admission", _safe_reason(exc))
    print(result.message, file=sys.stderr)
    if result.state is RootSetupState.PENDING:
        print(f"Resume with: {result.resume_command}", file=sys.stderr)
    return result.exit_code


def _require_root_linux() -> None:
    if not sys.platform.startswith("linux"):
        raise RuntimeError("root setup is available only in the installed Linux process")
    if os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError("root setup requires the installed root launcher")


def _read_target_account_name() -> str:
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        raise RuntimeError("target account selection requires the root controlling terminal")
    value = input("Existing non-root Linux account for Hermes: ").strip()
    if not _ACCOUNT.fullmatch(value):
        raise ValueError("target account name is invalid")
    return value


def _safe_reason(error: BaseException) -> str:
    from .authority.bootstrap_enrollment import BootstrapEnrollmentPending

    if isinstance(error, BootstrapEnrollmentPending):
        return "A required root-selected setup prerequisite is pending; rerun the root setup action after resolving it."
    return f"Root setup could not verify its required authority ({type(error).__name__})."


def _result(action: RootSetupAction, state: RootSetupState, phase: str, message: str) -> RootSetupResult:
    code = {RootSetupState.READY: 0, RootSetupState.PENDING: 4, RootSetupState.FAILED: 1}[state]
    return RootSetupResult(action, state, phase, message,
                           f"sudo -- hermes-installer-root-setup {action.value}", code)


__all__ = ["RootSetupAction", "RootSetupResult", "RootSetupState", "main",
           "run_root_setup_action", "verify_installed_launcher"]
