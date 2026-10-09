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
import hashlib
import os
import re
import secrets
import sys
from typing import Sequence


class RootSetupAction(StrEnum):
    INSTALL = "install"
    RESUME = "resume"
    UPDATE = "update"


class RootSetupState(StrEnum):
    ACTIVE = "active"
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
    blocker_code: str | None = None
    resume_action: RootSetupAction | None = None
    session_id: str | None = None
    transaction_ref: str | None = None
    generation_ref: str | None = None
    receipt_refs: tuple[str, ...] = ()
    cleanup_verified: bool | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.action, RootSetupAction) or not isinstance(self.state, RootSetupState):
            raise TypeError("root setup results require finite action and state values")
        if self.phase not in {"admission", "distribution", "prepared", "runtime", "materialization", "health"}:
            raise ValueError("root setup phase is not a reviewed phase")
        if not self.message or len(self.message) > 512 or "\n" in self.message:
            raise ValueError("root setup message must be one bounded line")
        if self.state is RootSetupState.PENDING:
            if ((self.resume_action is None) != (self.resume_command == "")
                    or (self.resume_action is not None and self.resume_action is not self.action)
                    or (self.resume_command and self.resume_command !=
                        f"sudo -- hermes-installer-root-setup {self.action.value}")):
                raise ValueError("root setup resume command is not the fixed launcher command")
        elif self.resume_command or self.resume_action is not None:
            raise ValueError("only pending root setup results may carry a resume command")
        expected = {RootSetupState.ACTIVE: 0, RootSetupState.PENDING: 4, RootSetupState.FAILED: 1}[self.state]
        if self.exit_code != expected:
            raise ValueError("root setup exit code does not match its state")
        if self.blocker_code is not None and not re.fullmatch(r"[A-Z][A-Z0-9_]{0,47}", self.blocker_code):
            raise ValueError("root setup blocker code is malformed")
        if self.session_id is not None and not re.fullmatch(r"setup-[0-9a-f]{32}", self.session_id):
            raise ValueError("root setup session identifier is malformed")
        for value in (self.transaction_ref, self.generation_ref, *self.receipt_refs):
            if value is not None and not re.fullmatch(r"[0-9a-f]{16}", value):
                raise ValueError("root setup report reference is malformed")


@dataclass(frozen=True, slots=True)
class LauncherStatus:
    state: str
    blocker_code: str | None
    message: str

    def __post_init__(self) -> None:
        if self.state not in {"verified", "unverified"}:
            raise ValueError("launcher status must be verified or unverified")
        if self.state == "unverified" and self.blocker_code != "ROOT_ATTESTATION_REQUIRED":
            raise ValueError("unverified launcher status needs its fixed blocker code")
        if not self.message or len(self.message) > 256 or "\n" in self.message:
            raise ValueError("launcher status message must be one bounded line")


_ACCOUNT = re.compile(r"[a-z_][a-z0-9_-]{0,31}\Z")
_HANDLE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_CANDIDATE_SHA = re.compile(r"[0-9a-f]{40}\Z")
_CHOICE_SEAL = object()


@dataclass(frozen=True, slots=True, init=False)
class RootSetupExplicitChoices:
    """Nonsecret source choice captured by the root process from its TTY."""

    candidate_git_sha: str
    _seal: object

    def __init__(self, candidate_git_sha: str, *, _seal: object | None = None):
        if _seal is not _CHOICE_SEAL:
            raise TypeError("root setup choices must be issued by the root TTY selection registry")
        if not isinstance(candidate_git_sha, str) or not _CANDIDATE_SHA.fullmatch(candidate_git_sha):
            raise ValueError("candidate source choice must be an exact lowercase 40-character Git SHA")
        object.__setattr__(self, "candidate_git_sha", candidate_git_sha)
        object.__setattr__(self, "_seal", _seal)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedRootBootstrapCandidateSelection:
    """Sealed proof that a candidate SHA was read from the root controlling TTY."""

    candidate_git_sha: str
    candidate_selection_handle: str
    input_origin: str
    choice_sha256: str
    _seal: object

    def __init__(self, candidate_git_sha: str, candidate_selection_handle: str,
                 choice_sha256: str, *, _seal: object | None = None):
        if _seal is not _CHOICE_SEAL:
            raise TypeError("candidate selection proofs can only be minted by the root selection registry")
        if (not isinstance(candidate_git_sha, str) or not _CANDIDATE_SHA.fullmatch(candidate_git_sha)
                or not isinstance(candidate_selection_handle, str)
                or not _HANDLE.fullmatch(candidate_selection_handle)
                or not isinstance(choice_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", choice_sha256)):
            raise ValueError("candidate selection proof is malformed")
        object.__setattr__(self, "candidate_git_sha", candidate_git_sha)
        object.__setattr__(self, "candidate_selection_handle", candidate_selection_handle)
        object.__setattr__(self, "input_origin", "root_tty_explicit")
        object.__setattr__(self, "choice_sha256", choice_sha256)
        object.__setattr__(self, "_seal", _seal)


class RootBootstrapCandidateSelectionRegistry:
    """One-use in-process proof that an exact source SHA came from root TTY input."""

    def __init__(self) -> None:
        self._choices: dict[int, RootSetupExplicitChoices] = {}
        self._receipts: dict[str, VerifiedRootBootstrapCandidateSelection] = {}

    def issue_explicit_tty_choice(self) -> RootSetupExplicitChoices:
        if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
            raise RuntimeError("candidate source choice requires the Linux root setup process")
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise RuntimeError("candidate source choice requires the root controlling terminal")
        candidate = input("Exact Hermes installer source commit (40 lowercase hex characters): ").strip()
        choice = RootSetupExplicitChoices(candidate, _seal=_CHOICE_SEAL)
        self._choices[id(choice)] = choice
        return choice

    def resolve(self, choices: RootSetupExplicitChoices) -> VerifiedRootBootstrapCandidateSelection:
        if not isinstance(choices, RootSetupExplicitChoices) or choices._seal is not _CHOICE_SEAL:
            raise RuntimeError("root source choice was not issued by this selection registry")
        issued = self._choices.pop(id(choices), None)
        if issued is not choices:
            raise RuntimeError("root source choice is absent, foreign, or already consumed")
        handle = secrets.token_urlsafe(32)
        receipt = VerifiedRootBootstrapCandidateSelection(
            choices.candidate_git_sha,
            handle,
            hashlib.sha256(choices.candidate_git_sha.encode("ascii")).hexdigest(),
            _seal=_CHOICE_SEAL,
        )
        self._receipts[handle] = receipt
        return receipt

    def resolve_handle(self, handle: str) -> VerifiedRootBootstrapCandidateSelection:
        if not isinstance(handle, str) or not _HANDLE.fullmatch(handle):
            raise RuntimeError("candidate selection handle is malformed")
        receipt = self._receipts.pop(handle, None)
        if receipt is None:
            raise RuntimeError("candidate selection receipt is absent or already consumed")
        return receipt


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
    actor_verified = False
    try:
        actor.verify_current(release)
        actor_verified = True
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
                           "Fresh-generation update and rollback publication are not yet connected to the root setup runtime.",
                           resume_allowed=True)
        mode = "resume" if selected_action is RootSetupAction.RESUME else "install"
        session = factory.begin(mode, account)
        if selected_action is RootSetupAction.RESUME:
            # begin(resume) verifies and adopts only an owned, checkpointed
            # transaction. The actual continuation phases are connected below
            # once their sealed root APIs are available.
            return _result(selected_action, RootSetupState.PENDING, "runtime",
                           "The owned checkpoint is valid; runtime receipt recovery and continuation are not yet connected.",
                           resume_allowed=True)
        receipt = session.provision()
        if receipt.state != "prepared" or receipt.enrollment_ids:
            return _result(selected_action, RootSetupState.FAILED, "prepared",
                           "Initial setup did not produce the required empty prepared generation.")
        return _result(
            selected_action, RootSetupState.PENDING, "prepared",
            "The root prepared generation is recorded; source/runtime receipts, native materialization, publication, and health checks still need their verified runtime handlers.",
            resume_allowed=True,
            session_id=session._handle.session_id,
            transaction_ref=_report_ref(receipt.transaction_handle),
            generation_ref=_report_ref(receipt.generation_id),
            receipt_refs=(_report_ref(receipt.provision_receipt_handle),),
        )
    except BootstrapEnrollmentPending as exc:
        return _result(selected_action, RootSetupState.PENDING, "runtime", _safe_reason(exc),
                       resume_allowed=actor_verified)
    except (OSError, RuntimeError, ValueError) as exc:
        return _result(selected_action, RootSetupState.FAILED, "runtime", _safe_reason(exc),
                       resume_allowed=actor_verified)
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
    if result.state is RootSetupState.PENDING and result.resume_command:
        print(f"Resume with: {result.resume_command}", file=sys.stderr)
    return result.exit_code


def launcher_status() -> LauncherStatus:
    """Return only current-process evidence; do not expose root file metadata.

    The unprivileged lifecycle CLI cannot attest the protected release receipt
    or selected launcher. It therefore receives an explicit unverified state
    and no privileged command to display.
    """
    if os.getuid() != 0 or os.geteuid() != 0 or not sys.platform.startswith("linux"):
        return LauncherStatus("unverified", "ROOT_ATTESTATION_REQUIRED",
                              "The installed launcher has not been verified by its root actor.")
    try:
        if verify_installed_launcher():
            return LauncherStatus("verified", None, "The current process matches the installed root launcher.")
    except (OSError, RuntimeError, ValueError):
        pass
    return LauncherStatus("unverified", "ROOT_ATTESTATION_REQUIRED",
                          "The installed launcher has not been verified by its root actor.")


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


def _result(action: RootSetupAction, state: RootSetupState, phase: str, message: str, *,
            resume_allowed: bool = False, session_id: str | None = None,
            transaction_ref: str | None = None, generation_ref: str | None = None,
            receipt_refs: tuple[str, ...] = ()) -> RootSetupResult:
    code = {RootSetupState.ACTIVE: 0, RootSetupState.PENDING: 4, RootSetupState.FAILED: 1}[state]
    blocker = None if state is RootSetupState.ACTIVE else {
        (RootSetupState.FAILED, "admission"): "INVALID_ADMISSION",
        (RootSetupState.FAILED, "distribution"): "DISTRIBUTION_VERIFICATION_FAILED",
        (RootSetupState.FAILED, "runtime"): "RUNTIME_VERIFICATION_FAILED",
        (RootSetupState.FAILED, "prepared"): "PREPARED_GENERATION_FAILED",
        (RootSetupState.PENDING, "admission"): "ROOT_TTY_REQUIRED",
        (RootSetupState.PENDING, "distribution"): "SOURCE_BOOTSTRAP_UNAVAILABLE",
        (RootSetupState.PENDING, "prepared"): "RUNTIME_HANDLERS_UNAVAILABLE",
        (RootSetupState.PENDING, "runtime"): "RUNTIME_HANDLERS_UNAVAILABLE",
        (RootSetupState.PENDING, "materialization"): "MATERIALIZATION_UNAVAILABLE",
        (RootSetupState.PENDING, "health"): "HEALTH_UNAVAILABLE",
    }.get((state, phase), "SETUP_PENDING")
    resume = action if state is RootSetupState.PENDING and resume_allowed else None
    return RootSetupResult(action, state, phase, message,
                           f"sudo -- hermes-installer-root-setup {action.value}" if resume else "", code,
                           blocker, resume, session_id, transaction_ref, generation_ref,
                           receipt_refs)


def _report_ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


__all__ = ["LauncherStatus", "RootBootstrapCandidateSelectionRegistry", "RootSetupAction",
           "RootSetupExplicitChoices", "RootSetupResult", "RootSetupState",
           "VerifiedRootBootstrapCandidateSelection",
           "launcher_status", "main", "run_root_setup_action", "verify_installed_launcher"]
