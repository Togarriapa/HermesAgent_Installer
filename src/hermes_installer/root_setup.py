"""Root-local first-install launcher for the reviewed Hermes installer.

This module is intentionally a small command boundary. It accepts only the
three lifecycle intents plus the finite installed qualification selector;
policy, paths, credentials, and artifact bytes are resolved by root-owned
registries.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from enum import StrEnum
import hashlib
import os
import re
import stat
import sys
import time
from pathlib import Path
from typing import Any, Sequence


class RootSetupAction(StrEnum):
    INSTALL = "install"
    RESUME = "resume"
    UPDATE = "update"
    QUALIFY = "qualify"


class RootInstalledQualificationSuite(StrEnum):
    RESOURCE_CRON_TASK = "resource-cron-task-v1"
    DISPLAY_XAUTHORITY = "display-xauthority-v1"


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
        if self.phase not in {"admission", "distribution", "prepared", "runtime", "materialization",
                              "publication", "health"}:
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
    schema: int
    state: str
    candidate_git_sha: str | None
    authority: bool
    resume_command: str
    blocker_code: str | None
    message: str

    def __post_init__(self) -> None:
        if self.schema != 1:
            raise ValueError("launcher status schema is unsupported")
        if self.state not in {"root-setup-required", "prepared", "active", "pending", "failed"}:
            raise ValueError("launcher status state is not a reviewed lifecycle value")
        if self.authority is not False:
            raise ValueError("read-only launcher status cannot carry authority")
        if self.candidate_git_sha is not None and not _CANDIDATE_SHA.fullmatch(self.candidate_git_sha):
            raise ValueError("launcher status candidate SHA is malformed")
        if self.resume_command and self.resume_command not in {
            "sudo -- hermes-installer-root-setup install",
            "sudo -- hermes-installer-root-setup resume",
            "sudo -- hermes-installer-root-setup update",
        }:
            raise ValueError("launcher status resume command is outside the fixed launcher schema")
        if self.state == "root-setup-required" and self.blocker_code != "ROOT_ATTESTATION_REQUIRED":
            raise ValueError("root-setup-required status needs its fixed blocker code")
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
    lifecycle_action: RootSetupAction
    _seal: object

    def __init__(self, candidate_git_sha: str, lifecycle_action: RootSetupAction, *,
                 _seal: object | None = None):
        if _seal is not _CHOICE_SEAL:
            raise TypeError("root setup choices must be issued by the root TTY selection registry")
        if not isinstance(candidate_git_sha, str) or not _CANDIDATE_SHA.fullmatch(candidate_git_sha):
            raise ValueError("candidate source choice must be an exact lowercase 40-character Git SHA")
        if (not isinstance(lifecycle_action, RootSetupAction)
                or lifecycle_action is RootSetupAction.QUALIFY):
            raise ValueError("source bootstrap accepts only install, resume, or update")
        object.__setattr__(self, "candidate_git_sha", candidate_git_sha)
        object.__setattr__(self, "lifecycle_action", lifecycle_action)
        object.__setattr__(self, "_seal", _seal)


@dataclass(frozen=True, slots=True, init=False)
class VerifiedRootBootstrapCandidateSelection:
    """Sealed proof that a candidate SHA was read from the root controlling TTY."""

    candidate_git_sha: str
    lifecycle_action: RootSetupAction
    input_origin: str
    choice_sha256: str
    _seal: object

    def __init__(self, candidate_git_sha: str, lifecycle_action: RootSetupAction,
                 choice_sha256: str, *, _seal: object | None = None):
        if _seal is not _CHOICE_SEAL:
            raise TypeError("candidate selection proofs can only be minted by the root selection registry")
        if (not isinstance(candidate_git_sha, str) or not _CANDIDATE_SHA.fullmatch(candidate_git_sha)
                or not isinstance(choice_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", choice_sha256)):
            raise ValueError("candidate selection proof is malformed")
        object.__setattr__(self, "candidate_git_sha", candidate_git_sha)
        object.__setattr__(self, "lifecycle_action", lifecycle_action)
        object.__setattr__(self, "input_origin", "root_tty_explicit")
        object.__setattr__(self, "choice_sha256", choice_sha256)
        object.__setattr__(self, "_seal", _seal)


@dataclass(frozen=True, slots=True, init=False)
class RootBootstrapCandidateSelectionSnapshot:
    candidate_git_sha: str
    lifecycle_action: RootSetupAction
    input_origin: str
    choice_sha256: str
    controller_pid: int
    controller_start_ticks: int
    controller_uid: int
    controller_gid: int
    session_id: int
    process_group_id: int
    tty_device: int
    tty_inode: int
    tty_rdevice: int
    issued_monotonic: float
    expires_monotonic: float
    _pidfd: int
    _tty_fd: int
    _closed: bool
    _seal: object

    def __init__(self, *, _seal: object, **fields: object):
        if _seal is not _CHOICE_SEAL:
            raise TypeError("root candidate snapshots can only be minted by the selection registry")
        for name, value in fields.items():
            object.__setattr__(self, name, value)
        object.__setattr__(self, "_closed", False)
        object.__setattr__(self, "_seal", _seal)

    def duplicate_controller_fds(self) -> tuple[int, int]:
        if self._seal is not _CHOICE_SEAL or self._closed:
            raise RuntimeError("candidate selection snapshot has no live controller descriptors")
        return os.dup(self._pidfd), os.dup(self._tty_fd)

    def close(self) -> None:
        if self._closed:
            return
        for fd in (self._pidfd, self._tty_fd):
            if fd >= 0:
                os.close(fd)
        object.__setattr__(self, "_pidfd", -1)
        object.__setattr__(self, "_tty_fd", -1)
        object.__setattr__(self, "_closed", True)


@dataclass(slots=True)
class _RootTTYProof:
    stdin_fd: int
    pidfd: int
    controller_pid: int
    controller_start_ticks: int
    controller_uid: int
    controller_gid: int
    session_id: int
    process_group_id: int
    tty_device: int
    tty_inode: int
    tty_rdevice: int
    issued_monotonic: float
    expires_monotonic: float

    def close(self) -> None:
        for fd in (self.stdin_fd, self.pidfd):
            if fd >= 0:
                os.close(fd)
        self.stdin_fd = self.pidfd = -1


class RootBootstrapCandidateSelectionRegistry:
    """One-use in-process proof that an exact source SHA came from root TTY input."""

    def __init__(self) -> None:
        self._choices: dict[int, RootSetupExplicitChoices] = {}
        self._choice_proofs: dict[int, _RootTTYProof] = {}
        self._selection_proofs: dict[int, tuple[VerifiedRootBootstrapCandidateSelection, _RootTTYProof]] = {}

    def issue_explicit_tty_choice(self, action: RootSetupAction) -> RootSetupExplicitChoices:
        if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
            raise RuntimeError("candidate source choice requires the Linux root setup process")
        if (not isinstance(action, RootSetupAction)
                or action is RootSetupAction.QUALIFY):
            raise ValueError("root source bootstrap accepts only install, resume, or update")
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            raise RuntimeError("candidate source choice requires the root controlling terminal")
        proof = _capture_root_tty_proof()
        try:
            candidate = input("Exact Hermes installer source commit (40 lowercase hex characters): ").strip()
            choice = RootSetupExplicitChoices(candidate, action, _seal=_CHOICE_SEAL)
        except BaseException:
            proof.close()
            raise
        self._choices[id(choice)] = choice
        self._choice_proofs[id(choice)] = proof
        return choice

    def resolve(self, choices: RootSetupExplicitChoices) -> VerifiedRootBootstrapCandidateSelection:
        if not isinstance(choices, RootSetupExplicitChoices) or choices._seal is not _CHOICE_SEAL:
            raise RuntimeError("root source choice was not issued by this selection registry")
        issued = self._choices.pop(id(choices), None)
        if issued is not choices:
            raise RuntimeError("root source choice is absent, foreign, or already consumed")
        proof = self._choice_proofs.pop(id(choices))
        if proof.expires_monotonic <= time.monotonic():
            proof.close()
            raise RuntimeError("root TTY candidate choice expired before verification")
        selection = VerifiedRootBootstrapCandidateSelection(
            choices.candidate_git_sha,
            choices.lifecycle_action,
            hashlib.sha256(
                choices.lifecycle_action.value.encode("ascii") + b"\0"
                + choices.candidate_git_sha.encode("ascii")
            ).hexdigest(),
            _seal=_CHOICE_SEAL,
        )
        self._selection_proofs[id(selection)] = (selection, proof)
        return selection

    def consume_verified_selection(
        self, selection: VerifiedRootBootstrapCandidateSelection
    ) -> RootBootstrapCandidateSelectionSnapshot:
        proof_row = self._selection_proofs.pop(id(selection), None)
        if (proof_row is None or proof_row[0] is not selection
                or selection._seal is not _CHOICE_SEAL):
            raise RuntimeError("candidate selection proof is foreign, absent, or already consumed")
        proof = proof_row[1]
        try:
            _verify_root_tty_proof(proof)
            pidfd, tty_fd = os.dup(proof.pidfd), os.dup(proof.stdin_fd)
            try:
                return RootBootstrapCandidateSelectionSnapshot(
                    _seal=_CHOICE_SEAL,
                    candidate_git_sha=selection.candidate_git_sha,
                    lifecycle_action=selection.lifecycle_action,
                    input_origin=selection.input_origin,
                    choice_sha256=selection.choice_sha256,
                    controller_pid=proof.controller_pid,
                    controller_start_ticks=proof.controller_start_ticks,
                    controller_uid=proof.controller_uid,
                    controller_gid=proof.controller_gid,
                    session_id=proof.session_id,
                    process_group_id=proof.process_group_id,
                    tty_device=proof.tty_device,
                    tty_inode=proof.tty_inode,
                    tty_rdevice=proof.tty_rdevice,
                    issued_monotonic=proof.issued_monotonic,
                    expires_monotonic=proof.expires_monotonic,
                    _pidfd=pidfd,
                    _tty_fd=tty_fd,
                )
            except BaseException:
                os.close(pidfd)
                os.close(tty_fd)
                raise
        finally:
            proof.close()

    def close(self) -> None:
        for proof in (*self._choice_proofs.values(), *(row[1] for row in self._selection_proofs.values())):
            proof.close()
        self._choices.clear()
        self._choice_proofs.clear()
        self._selection_proofs.clear()


def verify_installed_launcher() -> bool:
    """Verify the current root process is the installed launcher and closure.

    This is deliberately a current-process check. User-mode callers cannot
    turn file presence or a caller-provided path into launcher authority.
    """
    from .authority.installer_release import InstalledRootReleaseVerifier

    pointer = InstalledRootReleaseVerifier.verify_installed_release()
    pointer.close()
    _import_v180_native_support_closure()
    release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    try:
        actor.verify_current(release)
        return True
    finally:
        actor.close()
        release.close()


def _import_v180_native_support_closure() -> None:
    """Load the finite native support and worker source closure before actor observation."""
    from .components import native_plugins, public_registries
    from . import native_boundary_patch, native_plugin_bindings, native_plugin_loader
    from .authority import (
        local_resource_effects,
        native_assembler,
        native_definition_composition,
        native_policy_preparation,
        native_registration_projection,
        native_health_source,
        native_source_definitions,
        native_worker_recipes,
        native_worker_start_recipe,
        owner_overlay_capture_schemas,
        pm_runtime,
        runtime_root_custody,
    )
    from .registry import resource_backends

    # Keep explicit references so this remains a finite, intentional import set.
    _ = (native_assembler, native_registration_projection, native_plugins, public_registries,
         native_definition_composition, native_policy_preparation,
         native_health_source, native_source_definitions, local_resource_effects,
         native_worker_recipes, native_worker_start_recipe,
         owner_overlay_capture_schemas,
         runtime_root_custody,
         native_plugin_loader, native_boundary_patch, native_plugin_bindings,
         resource_backends, pm_runtime)


def _import_v187_listener_activation_closure() -> None:
    """Load the finite installed daemon/adoption modules before actor capture."""
    from .authority import daemon, listener_activation, native_worker_endpoint_custody

    # The worker and supervisor use the same pinned endpoint implementation;
    # keep these imports explicit so the installed actor sees the full closure.
    _ = (daemon, listener_activation, native_worker_endpoint_custody)


def run_root_setup_action(
    action: RootSetupAction | str,
    *,
    selection_handle: str | None = None,
    target_account_name: str | None = None,
) -> RootSetupResult:
    """Run one bounded root setup intent through the installed actor.

    Selection handles are accepted only as opaque root-issued references.
    Their resolution remains inside the installed registries. Lifecycle
    recovery and update are kept pending until their durable rehydration and
    generation-CAS consumers are available; installation drives current
    source/runtime and native materialization before requiring distinct
    allowlisted runtime-role receipts for strict active enrollment.
    """
    try:
        selected_action = RootSetupAction(action)
    except (TypeError, ValueError):
        raise ValueError("root setup action must be install, resume, update, or qualify") from None
    if selected_action is RootSetupAction.QUALIFY:
        raise ValueError("qualification requires the fixed --suite selector")

    try:
        _require_root_linux()
    except RuntimeError as exc:
        return _result(selected_action, RootSetupState.FAILED, "admission", _safe_reason(exc))
    if target_account_name is not None:
        return _result(selected_action, RootSetupState.FAILED, "admission",
                       "The target account must be entered on the verified root controlling terminal.")
    if selection_handle is not None and not _HANDLE.fullmatch(selection_handle):
        return _result(selected_action, RootSetupState.FAILED, "admission",
                       "The selected root setup reference is malformed.")
    if selection_handle is not None:
        return _result(selected_action, RootSetupState.PENDING, "runtime",
                       "The selected root reference is validly shaped, but its installed resolver is not connected.")
    from .authority.bootstrap_enrollment import BootstrapEnrollmentPending
    from .authority.installer_release import InstalledRootReleaseVerifier
    from .authority.installer_release_build import (
        InstallerReleaseBuildError,
        bootstrap_selected_release,
        observe_deployment_predecessor,
        resolve_verified_deployment_release,
    )

    # A missing deployment pointer is the only state that permits the reviewed
    # source/runtime bootstrap. Present-but-invalid and inaccessible pointers
    # are errors, never invitations to replace the installed release.
    try:
        predecessor = observe_deployment_predecessor()
        predecessor.verify_current()
        if predecessor.state == "absent":
            selection_registry = RootBootstrapCandidateSelectionRegistry()
            try:
                choices = selection_registry.issue_explicit_tty_choice(selected_action)
                bootstrap_selected_release(choices, selection_registry)
                return _result(selected_action, RootSetupState.FAILED, "distribution",
                               "Isolated source bootstrap returned without its required same-process handoff.")
            finally:
                selection_registry.close()
        if predecessor.state != "present-verified":
            raise InstallerReleaseBuildError("deployment predecessor state is outside the reviewed schema")
        if predecessor.verified_release_receipt_handle is None:
            raise InstallerReleaseBuildError("verified deployment predecessor has no retained release receipt")
        held_release = resolve_verified_deployment_release(
            predecessor.verified_release_receipt_handle, consume=True)
        held_release.close()
    except BootstrapEnrollmentPending as exc:
        return _result(selected_action, RootSetupState.PENDING, "distribution", _safe_reason(exc))
    except (OSError, RuntimeError, ValueError, InstallerReleaseBuildError) as exc:
        return _result(selected_action, RootSetupState.FAILED, "distribution", _safe_reason(exc))

    # Import the one reviewed setup composition graph before observing this
    # process. The actor snapshot deliberately rejects every later installer
    # module load, including legitimate fixed modules; importing arbitrary
    # modules here would weaken that boundary, so keep this finite import at
    # the installed-release handoff only.
    from .authority.installer_release import InstalledRootReleaseVerifier
    # The predecessor probe above already verified the installed pointer.
    _import_v180_native_support_closure()
    _import_v187_listener_activation_closure()
    from .authority.bootstrap_runtime_factory import (
        RootBootstrapRuntimeFactory,
        RootInitialSetupAggregate,
    )

    try:
        release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    except BootstrapEnrollmentPending as exc:
        return _result(selected_action, RootSetupState.PENDING, "distribution", _safe_reason(exc))
    except (OSError, RuntimeError) as exc:
        return _result(selected_action, RootSetupState.FAILED, "distribution", _safe_reason(exc))

    factory: RootBootstrapRuntimeFactory | None = None
    initial_aggregate: RootInitialSetupAggregate | None = None
    session = None
    actor_verified = False
    try:
        actor.verify_current(release)
        actor_verified = True
        selection_leaf = Path("/etc/hermes-installer/root-setup-selection.json")
        try:
            selection_leaf.lstat()
            selection_present = True
        except FileNotFoundError:
            selection_present = False
        if not selection_present:
            if selected_action is not RootSetupAction.INSTALL:
                return _result(selected_action, RootSetupState.PENDING, "admission",
                               "No installed root selection exists; run install to begin fresh setup.")
            from .authority.installer_release_build import ensure_initial_setup_fixed_prefixes
            ensure_initial_setup_fixed_prefixes()
            initial_aggregate = RootInitialSetupAggregate(release, actor)
            release = actor = None  # type: ignore[assignment]
            account = _read_target_account_name()
            initial = initial_aggregate.begin_install(account)
            if not (sys.stdin.isatty() and sys.stderr.isatty()):
                raise RuntimeError("Initial capability and identity-domain choices require the root controlling terminal")
            print("Choose the initial principal domain before entering any credentials.")
            print("  local: owner-scoped Resources overlay operations; no host or Authentik authority")
            print("  authentik: selected homelab administration through the protected System-membership path")
            identity_lane = input("Initial principal [local/authentik]: ").strip().casefold()
            if identity_lane == "local":
                print("Select local overlay operations: read, history, write, delete (blank selects none).")
                operation_text = input("Local operations: ").strip().casefold()
                operations = tuple(item.strip() for item in operation_text.split(",") if item.strip())
                operation_ids = {
                    "read": "resource-overlay-store:tool:resource_overlay_read",
                    "history": "resource-overlay-store:tool:resource_overlay_history",
                    "write": "resource-overlay-store:tool:resource_overlay_write",
                    "delete": "resource-overlay-store:tool:resource_overlay_delete",
                }
                if (len(set(operations)) != len(operations)
                        or any(item not in operation_ids for item in operations)):
                    raise RuntimeError("Local capability choice must use read, history, write, and/or delete")
                initial_aggregate.select_initial_local_owner(
                    initial.compilation_session_handle,
                    selected_registration_ids=tuple(operation_ids[item] for item in operations))
            elif identity_lane == "authentik":
                origin = input("Authentik HTTPS origin: ").strip()
                system_group_id = input("Authentik system group ID: ").strip()
                recipient_group_id = input("Authentik recipient group ID: ").strip()
                initial_aggregate.select_initial_identity(
                    initial.compilation_session_handle, https_origin=origin,
                    system_group_id=system_group_id, recipient_group_id=recipient_group_id)
            else:
                raise RuntimeError("Initial principal domain must be local or authentik")
            handoff = initial_aggregate.publish_prepared_selection(
                initial.compilation_session_handle)
            factory, session = initial_aggregate.adopt_prepared_selection(handoff.handoff_handle)
            initial_aggregate.close()
            initial_aggregate = None
        else:
            account = _read_target_account_name()
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
        if session is None:
            session = factory.begin(mode, account)
        if selected_action is RootSetupAction.RESUME:
            # Factory.begin("resume") reissues only the exact current empty
            # prepared checkpoint after checking the current authority snapshot,
            # unique transaction journal, prior session record, and service
            # identity marker. Source/runtime/materialization receipts are then
            # reacquired under this new live session below.
            receipt = session.selected_installation.resolve_current_prepared_enrollment()
        else:
            receipt = session.provision()
        if receipt.state != "prepared" or receipt.enrollment_ids:
            return _result(selected_action, RootSetupState.FAILED, "prepared",
                           "Initial setup did not produce the required empty prepared generation.")

        # v186 requires observing the real preactive endpoint after prepared
        # service identity custody exists and before any native policy choice
        # can be signed. On unsupported hosts or incomplete custody, keep the
        # setup resumable and stop before source selection; never synthesize a
        # future socket path or continue with an empty endpoint binding.
        try:
            # Root custody owns the fixed /run parent before the endpoint
            # custodian binds beneath it. The endpoint method revalidates this
            # same retained receipt; this call makes the required ordering
            # explicit at the installer dispatch boundary.
            session.ensure_current_prepared_authority_runtime_root()
            session.ensure_current_prepared_native_worker_endpoint()
        except BootstrapEnrollmentPending as exc:
            return _result(
                selected_action, RootSetupState.PENDING, "endpoint", _safe_reason(exc),
                resume_allowed=True, session_id=session._handle.session_id,
                transaction_ref=_report_ref(receipt.transaction_handle),
                generation_ref=_report_ref(receipt.generation_id),
                receipt_refs=(_report_ref(receipt.provision_receipt_handle),),
            )

        # Keep this sequence inside the installed root actor: every path,
        # resource revision, profile choice, and receipt is resolved by the
        # live factory/session. In particular, no caller-provided path or JSON
        # can substitute for the pinned source, PM runtime, or TTY selection.
        bundle = None
        worker_recipe_candidates: tuple[Any, ...] = ()
        precompile = None
        role_closure = None
        try:
            bundle = session.prepare_selected_native_bundle()
            worker_recipe_candidates = session.resolve_prepared_native_worker_recipe_candidates(bundle)
            native_policy_selection = session.observe_native_policy_configuration(
                worker_recipe_candidates=worker_recipe_candidates)
            from .authority.native_policy_preparation import RootNativePolicyPreparationSelection
            if (type(native_policy_selection) is not RootNativePolicyPreparationSelection
                    or getattr(native_policy_selection, "setup_session_id", None)
                    != session._handle.session_id
                    or getattr(native_policy_selection, "transaction_handle", None)
                    != receipt.transaction_handle
                    or getattr(native_policy_selection, "prepared_generation_id", None)
                    != receipt.generation_id
                    or getattr(native_policy_selection, "resource_profile_selection_handle", None)
                    != bundle.resource_profile_selection_receipt_handle):
                raise RuntimeError("native policy choice is not bound to the current prepared transaction")
            # The active compiler reserves the exact five generated outputs
            # and binds their current PM/output role closure before any active
            # generation is compiled. This is the same reservation consumed
            # later by the selected worker producer; it avoids a second,
            # unbound package compilation path.
            compiler = session.selected_installation.resolve_current_active_policy_compilation_registry()
            precompile = compiler.begin_active_policy_precompile(session._handle, bundle)
            role_closure = session.selected_installation.resolve_selected_runnable_roles(
                bundle.pm_runtime_receipt_handle, precompile.reservation_handle)
            if compiler.verify_current_precompile_capability(precompile) is not precompile:
                raise BootstrapEnrollmentPending("native active precompile reservation is no longer current")
            if native_policy_selection.selected_worker_recipe_handles:
                recipe_registry = session.resolve_current_native_worker_recipe_registry()
                recipe_registry.retain_runnable_closure(native_policy_selection, role_closure)
                session.resolve_current_native_worker_service_generation_producer()

                # Compile and durably publish the exact selected active policy,
                # then let the session build its native generation from the
                # sealed six-role projection. The empty generic receipt map is
                # intentional here: PM plus the five outputs are supplied by
                # the root-owned typed projection, never fabricated as CAS
                # receipts.
                active_claim_handle = compiler.compile_active_policy(
                    session._handle, bundle, precompile,
                )
                predecessor = session.selected_installation.resolve_current_active_policy_predecessor(
                    active_claim_handle,
                )
                publication = session.selected_installation.resolve_current_active_policy_publisher().publish(
                    active_claim_handle, predecessor,
                )
                active_receipt = session.activate_runnable({})
                if active_receipt.state != "committed" or not active_receipt.enrollment_ids:
                    raise BootstrapEnrollmentPending(
                        "selected typed native role projection did not commit an active enrollment")
                current_publication = session.selected_installation.resolve_current_active_policy_publication()
                if current_publication.publication_handle != publication.publication_handle:
                    raise BootstrapEnrollmentPending(
                        "active publication changed before supervised listener activation")

                endpoint = session._native_worker_endpoint_receipt
                endpoint_custodian = session._native_worker_endpoint_custodian
                authority_root_receipt = session._prepared_authority_runtime_root_receipt
                if endpoint is None or endpoint_custodian is None or authority_root_receipt is None:
                    raise BootstrapEnrollmentPending(
                        "committed native enrollment lacks its held endpoint and authority-root receipts")
                from .authority.listener_activation import (
                    ListenerActivationUnavailable,
                    RootAuthorityListenerActivationSupervisor,
                )
                supervisor = None
                active_listener_receipt = None
                functional_health_witness = None
                try:
                    supervisor = RootAuthorityListenerActivationSupervisor.from_root_setup(
                        session.selected_installation, endpoint_custodian,
                        session._factory._release, session._factory._actor,
                        authority_root_receipt,
                    )
                    active_listener_receipt = supervisor.begin_active_listener_activation(
                        endpoint.receipt_handle, current_publication,
                    )
                    session._health_activation_supervisor = supervisor
                    from .authority.listener_activation import RootSetupHealthIntentIssuer
                    health_issuer = RootSetupHealthIntentIssuer.from_current_root_setup(
                        session.selected_installation, session._factory._release,
                        session._factory._actor, supervisor,
                    )
                    health_intent = health_issuer.issue_after_activation(
                        endpoint.receipt_handle, current_publication, active_listener_receipt,
                    )
                    completion_handle, _completion_sha256 = supervisor.request_functional_health(
                        health_intent,
                    )
                    functional_health_witness = session.record_functional_health(
                        active_receipt, (health_intent.intent_handle, completion_handle),
                    )
                except ListenerActivationUnavailable as exc:
                    raise BootstrapEnrollmentPending(
                        f"committed active enrollment awaits daemon-owned functional health ({type(exc).__name__})"
                    ) from None
                except (OSError, RuntimeError, ValueError) as exc:
                    raise BootstrapEnrollmentPending(
                        f"committed active enrollment awaits daemon-owned functional health ({type(exc).__name__})"
                    ) from None
                finally:
                    if supervisor is not None:
                        supervisor.close()
                    if hasattr(session, "_health_activation_supervisor"):
                        del session._health_activation_supervisor

                # Functional health is a distinct protected receipt phase; an
                # authenticated ACK is still insufficient without the actual
                # completion row re-read by the original setup actor.
                if functional_health_witness is None:
                    raise BootstrapEnrollmentPending(
                        "daemon returned no current committed functional-health witness")
                return _result(
                    selected_action, RootSetupState.ACTIVE, "health",
                    "Active enrollment, supervised listener, and daemon-owned functional-health witness are current.",
                    session_id=session._handle.session_id,
                    transaction_ref=_report_ref(active_receipt.transaction_handle),
                    generation_ref=_report_ref(active_receipt.generation_id),
                    receipt_refs=(_report_ref(active_receipt.provision_receipt_handle),
                                  _report_ref(publication.receipt_handle),
                                  _report_ref(active_listener_receipt.activation_id),
                                  _report_ref(functional_health_witness.body["health_receipt_handle"])),
                )
        except BootstrapEnrollmentPending as exc:
            failure_refs = [_report_ref(receipt.provision_receipt_handle)]
            if bundle is not None:
                failure_refs.append(_report_ref(bundle.materialization_receipt_handle))
            if precompile is not None:
                failure_refs.append(_report_ref(precompile.reservation_handle))
            return _result(
                selected_action, RootSetupState.PENDING, "materialization", _safe_reason(exc),
                resume_allowed=True, session_id=session._handle.session_id,
                transaction_ref=_report_ref(receipt.transaction_handle),
                generation_ref=_report_ref(receipt.generation_id),
                receipt_refs=tuple(failure_refs),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            return _result(
                selected_action, RootSetupState.PENDING, "materialization", _safe_reason(exc),
                resume_allowed=True, session_id=session._handle.session_id,
                transaction_ref=_report_ref(receipt.transaction_handle),
                generation_ref=_report_ref(receipt.generation_id),
                receipt_refs=(_report_ref(receipt.provision_receipt_handle),),
            )

        # The reserved five outputs and runnable closure are now retained by
        # the active compiler. Installer launcher/runtime receipts and the
        # supervised listener ACK remain separate typed requirements; do not
        # equate package outputs with those receipts.
        references = [_report_ref(receipt.provision_receipt_handle),
                      _report_ref(bundle.materialization_receipt_handle)]
        if precompile is not None:
            references.extend(_report_ref(item) for item in precompile.receipt_ids)
            references.append(_report_ref(precompile.reservation_handle))
        if role_closure is not None:
            references.append(_report_ref(role_closure.role_closure_handle))
        worker_status = (
            "the selected signed worker recipe, "
            if native_policy_selection.selected_worker_recipe_handles else "the no-worker choice, "
        )
        return _result(
            selected_action, RootSetupState.PENDING, "publication",
            "Pinned source, PM runtime, " + worker_status +
            "reserved native outputs, and exact runnable role closure are retained; active publication still requires the separately allowlisted runtime receipts and supervised listener acknowledgement.",
            resume_allowed=True,
            session_id=session._handle.session_id,
            transaction_ref=_report_ref(receipt.transaction_handle),
            generation_ref=_report_ref(receipt.generation_id),
            receipt_refs=tuple(references),
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
                try:
                    if initial_aggregate is not None:
                        initial_aggregate.close()
                finally:
                    try:
                        if actor is not None:
                            actor.close()
                    finally:
                        if release is not None:
                            release.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hermes-installer-root-setup")
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "authority-daemon-adopt":
        if (len(arguments) != 3 or arguments[1] != "--activation-id"
                or not re.fullmatch(r"[0-9a-f]{32}", arguments[2])):
            print("Use exactly: authority-daemon-adopt --activation-id <32 lowercase hexadecimal characters>.",
                  file=sys.stderr)
            return 1
        try:
            _require_root_linux()
        except RuntimeError:
            print("Authority daemon adoption requires the installed Linux root actor.", file=sys.stderr)
            return 4
        try:
            _import_v187_listener_activation_closure()
            from .authority.daemon import main_adopt

            return main_adopt(arguments[2])
        except Exception as exc:
            # Never forward daemon/runtime exception details into a unit log.
            print(f"Authority daemon adoption failed ({type(exc).__name__}).", file=sys.stderr)
            return 1
    parser.add_argument("action", choices=tuple(item.value for item in RootSetupAction))
    parser.add_argument("--suite", choices=tuple(item.value for item in RootInstalledQualificationSuite))
    args = parser.parse_args(arguments)
    if args.action == RootSetupAction.QUALIFY.value:
        if (args.suite is None or len(arguments) != 3
                or arguments[0] != RootSetupAction.QUALIFY.value
                or arguments[1] != "--suite"):
            parser.error("use exactly: qualify --suite <fixed-suite-id>")
    elif args.suite is not None or arguments != [args.action]:
        parser.error("lifecycle actions accept no additional arguments")
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        if args.action == RootSetupAction.QUALIFY.value:
            print("Qualification requires the root controlling terminal.", file=sys.stderr)
            return 4
        result = _result(RootSetupAction(args.action), RootSetupState.PENDING, "admission",
                         "Root setup requires its controlling terminal for local operator intake.")
    elif args.action == RootSetupAction.QUALIFY.value:
        return _run_installed_qualification(args.suite)
    else:
        try:
            result = run_root_setup_action(args.action)
        except RuntimeError as exc:
            result = _result(RootSetupAction(args.action), RootSetupState.PENDING,
                             "admission", _safe_reason(exc))
        except EOFError:
            result = _result(RootSetupAction(args.action), RootSetupState.PENDING,
                             "admission", "Root terminal input ended before source selection completed.")
        except ValueError as exc:
            result = _result(RootSetupAction(args.action), RootSetupState.FAILED,
                             "admission", _safe_reason(exc))
    print(result.message, file=sys.stderr)
    if result.state is RootSetupState.PENDING and result.resume_command:
        print(f"Resume with: {result.resume_command}", file=sys.stderr)
    return result.exit_code


def _run_installed_qualification(suite_id: str) -> int:
    """Dispatch one source-owned qualification recipe through the installed actor."""
    try:
        selected_suite = RootInstalledQualificationSuite(suite_id)
    except (TypeError, ValueError):
        print("Qualification suite is outside the fixed installed suite catalog.", file=sys.stderr)
        return 1
    try:
        _require_root_linux()
    except RuntimeError:
        print("Qualification is incomplete: a current Linux root actor is required.", file=sys.stderr)
        return 4
    try:
        from .authority.installed_qualification import (
            RootInstalledQualificationResult,
            run_selected_installed_qualification,
        )
    except ImportError:
        print("Qualification is incomplete: the verified installed dispatcher is unavailable.",
              file=sys.stderr)
        return 4
    try:
        result = run_selected_installed_qualification(selected_suite.value)
    except Exception as exc:
        # The dispatcher owns detailed typed diagnostics. Never print exception
        # contents, which could contain paths, source data, or credentials.
        print(f"Qualification is incomplete ({type(exc).__name__}).", file=sys.stderr)
        return 4
    if (type(result) is not RootInstalledQualificationResult
            or getattr(result, "schema", None) != 1
            or getattr(result, "suite_id", None) != selected_suite.value
            or getattr(result, "status", None) not in {"passed", "failed", "incomplete"}):
        print("Qualification is incomplete: installed dispatcher returned an invalid result.",
              file=sys.stderr)
        return 4
    status = result.status
    evidence = getattr(result, "evidence_sha256", None)
    if status == "passed" and (not isinstance(evidence, str)
                               or not re.fullmatch(r"[0-9a-f]{64}", evidence)):
        print("Qualification is incomplete: passed result has no valid evidence digest.",
              file=sys.stderr)
        return 4
    print(f"Installed qualification {selected_suite.value}: {status}.", file=sys.stderr)
    return {"passed": 0, "failed": 1, "incomplete": 4}[status]


def launcher_status() -> LauncherStatus:
    """Return only current-process evidence; do not expose root file metadata.

    The unprivileged lifecycle CLI cannot attest the protected release receipt
    or selected launcher. It therefore receives an explicit unverified state
    and no privileged command to display.
    """
    if os.getuid() != 0 or os.geteuid() != 0 or not sys.platform.startswith("linux"):
        return _launcher_status_required()
    try:
        if verify_installed_launcher():
            # The actor alone says nothing about a prepared or active setup
            # generation. Until a typed durable status receipt is connected,
            # keep presentation at the reviewed non-authorizing state.
            return _launcher_status_required(
                message="The root launcher is verified; setup state still requires a durable lifecycle receipt."
            )
    except (OSError, RuntimeError, ValueError):
        pass
    return _launcher_status_required()


def _launcher_status_required(*, message: str =
                              "The installed launcher has not been verified by its root actor.") -> LauncherStatus:
    return LauncherStatus(1, "root-setup-required", None, False, "",
                          "ROOT_ATTESTATION_REQUIRED", message)


def _capture_root_tty_proof() -> _RootTTYProof:
    if not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0:
        raise RuntimeError("root TTY proof requires the Linux root setup process")
    stdin_fd = os.dup(0)
    try:
        if not os.isatty(stdin_fd) or not os.isatty(2):
            raise RuntimeError("root candidate selection requires a controlling TTY")
        terminal = os.fstat(stdin_fd)
        stderr_terminal = os.fstat(2)
        if (not stat.S_ISCHR(terminal.st_mode) or not stat.S_ISCHR(stderr_terminal.st_mode)
                or (terminal.st_dev, terminal.st_ino, terminal.st_rdev)
                != (stderr_terminal.st_dev, stderr_terminal.st_ino, stderr_terminal.st_rdev)):
            raise RuntimeError("root candidate selection must use one controlling terminal")
        process_group_id = os.getpgrp()
        if os.tcgetpgrp(stdin_fd) != process_group_id:
            raise RuntimeError("root candidate selection is not from the foreground terminal group")
        pid = os.getpid()
        opener = getattr(os, "pidfd_open", None)
        if opener is None:
            raise RuntimeError("root candidate selection requires a kernel process identity handle")
        pidfd = opener(pid, 0)
        now = time.monotonic()
        return _RootTTYProof(
            stdin_fd=stdin_fd,
            pidfd=pidfd,
            controller_pid=pid,
            controller_start_ticks=_process_start_ticks(pid),
            controller_uid=os.getuid(),
            controller_gid=os.getgid(),
            session_id=os.getsid(0),
            process_group_id=process_group_id,
            tty_device=terminal.st_dev,
            tty_inode=terminal.st_ino,
            tty_rdevice=terminal.st_rdev,
            issued_monotonic=now,
            expires_monotonic=now + 60.0,
        )
    except BaseException:
        os.close(stdin_fd)
        raise


def _verify_root_tty_proof(proof: _RootTTYProof) -> None:
    if (not sys.platform.startswith("linux") or os.getuid() != 0 or os.geteuid() != 0
            or proof.controller_pid != os.getpid()
            or proof.controller_uid != os.getuid() or proof.controller_gid != os.getgid()
            or proof.session_id != os.getsid(0) or proof.process_group_id != os.getpgrp()
            or time.monotonic() >= proof.expires_monotonic
            or proof.expires_monotonic - proof.issued_monotonic > 60.0
            or proof.controller_start_ticks != _process_start_ticks(proof.controller_pid)):
        raise RuntimeError("root TTY candidate selection is stale or belongs to another controller")
    try:
        os.fstat(proof.pidfd)
        terminal = os.fstat(proof.stdin_fd)
        if (not os.isatty(proof.stdin_fd) or not stat.S_ISCHR(terminal.st_mode)
                or (terminal.st_dev, terminal.st_ino, terminal.st_rdev)
                != (proof.tty_device, proof.tty_inode, proof.tty_rdevice)
                or os.tcgetpgrp(proof.stdin_fd) != proof.process_group_id):
            raise RuntimeError("root controlling terminal changed after candidate selection")
    except OSError:
        raise RuntimeError("root controlling terminal proof is no longer available") from None


def _process_start_ticks(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "rb") as source:
            raw = source.read(4096)
        close = raw.rfind(b")")
        fields = raw[close + 2:].split()
        if close < 0 or len(fields) <= 19:
            raise ValueError
        return int(fields[19])
    except (OSError, ValueError, IndexError):
        raise RuntimeError("root process start identity is unavailable") from None


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
        (RootSetupState.PENDING, "publication"): "PUBLICATION_UNAVAILABLE",
        (RootSetupState.PENDING, "health"): "HEALTH_UNAVAILABLE",
    }.get((state, phase), "SETUP_PENDING")
    resume = action if state is RootSetupState.PENDING and resume_allowed else None
    return RootSetupResult(action, state, phase, message,
                           f"sudo -- hermes-installer-root-setup {action.value}" if resume else "", code,
                           blocker, resume, session_id, transaction_ref, generation_ref,
                           receipt_refs)


def _report_ref(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


def _verify_native_output_receipts(receipts: object, *, session: object,
                                   prepared_generation_id: str) -> tuple[object, ...]:
    """Require the assembler's complete fixed output-role closure."""
    from .authority.native_output_receipts import RuntimeArtifactReceipt

    required = {
        "native-compiled-closure", "native-entrypoint-manifest",
        "native-action-resolver", "native-boundary-overlay", "native-candidate-index",
    }
    if not isinstance(receipts, tuple) or len(receipts) != len(required):
        raise RuntimeError("native assembler did not return its complete five-role receipt closure")
    authorization = getattr(session, "_authorization", None)
    session_handle = getattr(session, "_handle", None)
    if (not isinstance(getattr(authorization, "transaction_handle", None), str)
            or not isinstance(getattr(authorization, "plan_digest", None), str)
            or not isinstance(getattr(session_handle, "session_id", None), str)):
        raise RuntimeError("native output receipts cannot be joined to current setup custody")
    if (any(type(item) is not RuntimeArtifactReceipt for item in receipts)
            or {item.artifact_role for item in receipts} != required
            or len({item.receipt_id for item in receipts}) != len(required)
            or any(item.setup_session_id != session_handle.session_id
                   or item.transaction_handle != authorization.transaction_handle
                   or item.plan_digest != authorization.plan_digest
                   or item.prepared_generation_id != prepared_generation_id
                   for item in receipts)):
        raise RuntimeError("native assembler receipt roles are missing, duplicated, or untyped")
    return receipts


__all__ = ["LauncherStatus", "RootBootstrapCandidateSelectionRegistry", "RootSetupAction",
           "RootSetupExplicitChoices", "RootSetupResult", "RootSetupState",
           "VerifiedRootBootstrapCandidateSelection",
           "launcher_status", "main", "run_root_setup_action", "verify_installed_launcher"]
