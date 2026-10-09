"""Installer lifecycle orchestration for secure Cloudflare enrollment.

This module joins the setup-only credential references, the installer journal,
and the ownership-aware Cloudflare adapter. It deliberately keeps account
secrets in memory only and never marks the public route ready while the origin
or protected tunnel-token sink is unavailable.
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..credentials import CredentialError
from ..setup_wizard import CloudflareDesktopAdapter
from ..state import Journal
from .cloudflare import CloudflareClient, CloudflareError
from .cloudflare_setup import PreparedAccessResources, RemoteCloudflareProvisioner, RemoteConflict
from .config import RemoteConfigError, collect_remote_setup
from .journal import dump as dump_remote_journal
from .journal import load as load_remote_journal
from .lifecycle import RemoteJournal


@dataclass(frozen=True, slots=True)
class RemoteEnrollmentResult:
    """Secret-free result for lifecycle CLI rendering and exit-code selection."""

    state: str
    access_state: str
    policy_read_state: str
    route_state: str
    phase: str
    message: str
    next_steps: tuple[str, ...] = ()
    resource_ids: Mapping[str, str] = field(default_factory=dict)
    component_installable: bool = False

    def __post_init__(self) -> None:
        if self.state not in {"ready", "pending", "failed"}:
            raise ValueError("remote enrollment state must be ready, pending, or failed")
        if self.access_state not in {"pending", "ready", "failed"}:
            raise ValueError("remote access state must be pending, ready, or failed")
        if self.policy_read_state not in {"pending", "verified", "failed"}:
            raise ValueError("remote policy-read state must be pending, verified, or failed")
        if self.route_state not in {"pending", "active", "failed"}:
            raise ValueError("remote route state must be pending, active, or failed")
        if self.route_state != "active" and self.state == "ready":
            raise ValueError("remote enrollment cannot be ready before route activation")
        if self.component_installable and self.policy_read_state != "verified":
            raise ValueError("remote component is installable only after exact policy-read verification")


def _config_mapping(config: Mapping[str, Any] | Any) -> dict[str, Any]:
    if isinstance(config, Mapping):
        return dict(config)
    remote = getattr(config, "remote_desktop", None)
    if isinstance(remote, Mapping):
        return {"remote_desktop": dict(remote)}
    raise TypeError("remote enrollment requires a validated installer configuration")


def _operation_key(hostname: str) -> str:
    digest = hashlib.sha256(hostname.casefold().encode("utf-8")).hexdigest()
    return "installer:remote-desktop:" + digest[:32]


def _resource_ids(remote: RemoteJournal) -> dict[str, str]:
    return {
        kind: value.resource_id
        for kind, value in remote.resources.items()
        if kind in {"identity_provider", "access_app", "access_policy", "tunnel", "dns"}
    }


def _safe_setup_error(exc: Exception) -> str:
    """Return only known-redacted adapter errors; never display arbitrary exceptions."""
    if isinstance(exc, RemoteConflict):
        return "Cloudflare reports a hostname or installer-resource ownership conflict. Existing resources were preserved."
    if isinstance(exc, CredentialError):
        return "A referenced Cloudflare credential is unavailable or cannot be read safely."
    if isinstance(exc, RemoteConfigError):
        return str(exc)
    if isinstance(exc, CloudflareError):
        return str(exc)
    return "Cloudflare enrollment did not complete; secret values and provider diagnostics were suppressed."


def run_remote_desktop_enrollment(
    config: Mapping[str, Any] | Any,
    journal: Journal,
    *,
    client_factory: Callable[[str], Any] | None = None,
    activate_route: bool = False,
    origin_ready: Callable[[], bool] | None = None,
    runtime_token_writer: Callable[[str], Any] | None = None,
    resume_command: str = "hermes-installer setup",
) -> RemoteEnrollmentResult:
    """Stage owned Access resources, prove read authority, and optionally activate.

    `journal` must be the caller's active private installer Journal. The caller
    already holds the installer process lock; this function intentionally does
    not acquire another lock. `runtime_token_writer` must be an enrolled
    protected host sink. It is required before any tunnel/DNS activation and is
    never constructed by this module.

    The default path stages only Cloudflare Access resources and performs the
    exact app/policy/OTP reads with the separate policy token. A verified policy
    is necessary for component installation but does not claim that the public
    route is active.
    """
    data = _config_mapping(config)
    remote_config = data.get("remote_desktop", {})
    if not isinstance(remote_config, Mapping):
        return RemoteEnrollmentResult(
            "failed", "failed", "pending", "pending", "empty",
            "remote_desktop configuration must be an object.",
            (f"Correct the installer configuration and run {resume_command}.",),
        )
    remote_config = dict(remote_config)
    hostname = remote_config.get("hostname")
    setup_ref = remote_config.get("management_token_ref")
    if not isinstance(hostname, str) or not hostname.strip():
        return RemoteEnrollmentResult(
            "pending", "pending", "pending", "pending", "empty",
            "No remote hostname was selected; no Cloudflare resources were changed.",
            (f"Select a hostname and run {resume_command}.",),
        )
    if not isinstance(setup_ref, str) or not setup_ref:
        return RemoteEnrollmentResult(
            "pending", "pending", "pending", "pending", "empty",
            "The scoped Cloudflare setup credential is not configured.",
            (f"Store a scoped setup credential securely and run {resume_command}.",),
        )

    factory = client_factory or CloudflareClient
    adapter = CloudflareDesktopAdapter(client_factory=factory)
    try:
        # This resolves only the explicit credential reference and performs
        # read-only active-zone / Access-organization discovery.
        setup = collect_remote_setup(interactive=False, config=remote_config,
                                     client_factory=factory)
    except (CredentialError, RemoteConfigError, CloudflareError, OSError, ValueError) as exc:
        return RemoteEnrollmentResult(
            "pending", "pending", "pending", "pending", "credentials_validated",
            _safe_setup_error(exc),
            (f"Correct the selected zone or secure credential reference, then run {resume_command}.",),
        )
    except Exception as exc:  # fail closed while suppressing third-party diagnostics
        return RemoteEnrollmentResult(
            "pending", "pending", "pending", "pending", "credentials_validated",
            _safe_setup_error(exc),
            (f"Check Cloudflare connectivity and run {resume_command}.",),
        )

    hostname = setup.hostname
    operation = _operation_key(hostname)
    prior = journal.operation(operation)
    payload = prior.get("payload") if isinstance(prior, Mapping) else None
    saved_remote = payload.get("remote_journal") if isinstance(payload, Mapping) else None
    try:
        if prior is None:
            operation_id = uuid.uuid4().hex
            remote_journal = load_remote_journal(None, operation_id=operation_id, hostname=hostname)
            # Write identity before any account mutation so a crash can only
            # leave resources owned by a durable operation marker.
            journal.checkpoint(operation, "in_progress", {"remote_journal": dump_remote_journal(remote_journal)})
        else:
            if not isinstance(saved_remote, Mapping):
                raise ValueError("remote operation has no recoverable ownership journal")
            operation_id = saved_remote.get("operation_id")
            if not isinstance(operation_id, str) or not operation_id:
                raise ValueError("remote operation has an invalid ownership identity")
            remote_journal = load_remote_journal(saved_remote, operation_id=operation_id, hostname=hostname)
    except (TypeError, ValueError, KeyError):
        return RemoteEnrollmentResult(
            "failed", "failed", "pending", "pending", "empty",
            "The saved Cloudflare ownership journal is invalid; no account changes were attempted.",
            ("Preserve the installer state for review before starting a new remote setup operation.",),
        )

    def save_remote(value: RemoteJournal, status: str = "in_progress") -> None:
        journal.checkpoint(operation, status, {"remote_journal": dump_remote_journal(value)})

    # Build a Cloudflare API client from the setup token already resolved by
    # collect_remote_setup. The object remains ephemeral and is never returned.
    setup_client = factory(setup.management_token)
    read_ref = remote_config.get("policy_read_token_ref")
    def policy_read_check(value: RemoteJournal) -> bool:
        if not isinstance(read_ref, str) or not read_ref:
            return False
        adapter.verify_owned_policy_read(read_ref, setup, value)
        return True

    policy_check = policy_read_check if isinstance(read_ref, str) and read_ref else None
    provisioner = RemoteCloudflareProvisioner(
        setup_client,
        setup,
        remote_journal,
        checkpoint=lambda value: save_remote(value),
        origin_ready=origin_ready or (lambda: False),
        policy_read_check=policy_check,
        gateway_port=8765,
    )
    try:
        provisioner.prepare_access_resources()
    except RemoteConflict as exc:
        save_remote(remote_journal, "failed")
        return RemoteEnrollmentResult(
            "failed", "failed", "pending", "pending", remote_journal.phase.value,
            _safe_setup_error(exc),
            ("Resolve the conflict using the exact installer ownership record, then resume; unowned resources will not be changed.",),
            _resource_ids(remote_journal),
        )
    except Exception as exc:
        save_remote(remote_journal, "pending")
        return RemoteEnrollmentResult(
            "pending", "pending", "pending", "pending", remote_journal.phase.value,
            _safe_setup_error(exc),
            (f"Keep the checkpointed Access resources and run {resume_command} to resume.",),
            _resource_ids(remote_journal),
        )

    if not isinstance(read_ref, str) or not read_ref:
        remote_journal.error_code = "POLICY_READ_PENDING"
        save_remote(remote_journal, "pending")
        return RemoteEnrollmentResult(
            "pending", "ready", "pending", "pending", remote_journal.phase.value,
            "Installer-owned Access app, email policy, and OTP identity provider are checkpointed; the separate read-only policy credential is still required.",
            (f"Store a distinct minimum-read Cloudflare credential and run {resume_command}.",),
            _resource_ids(remote_journal),
        )

    try:
        adapter.verify_owned_policy_read(read_ref, setup, remote_journal)
    except Exception as exc:
        remote_journal.error_code = "POLICY_READ_PENDING"
        save_remote(remote_journal, "pending")
        return RemoteEnrollmentResult(
            "pending", "ready", "pending", "pending", remote_journal.phase.value,
            "The separate token did not pass reads for the exact journal-owned Access app, policy, and OTP identity provider. " + _safe_setup_error(exc),
            (f"Check the separate minimum-read token and run {resume_command}; owned Access resources are preserved.",),
            _resource_ids(remote_journal),
        )

    remote_journal.completed.add("policy_read_verified")
    remote_journal.error_code = None
    save_remote(remote_journal, "policy_read_verified")
    if not activate_route:
        save_remote(remote_journal, "pending")
        return RemoteEnrollmentResult(
            "pending", "ready", "verified", "pending", remote_journal.phase.value,
            "Cloudflare Access setup and exact policy-read verification passed; the public route remains inactive until the protected local origin is ready.",
            (f"Install and verify the protected local Desktop gateway, then run {resume_command} to activate the route.",),
            _resource_ids(remote_journal), True,
        )

    if origin_ready is None or runtime_token_writer is None:
        save_remote(remote_journal, "pending")
        missing = []
        if origin_ready is None:
            missing.append("a real protected-origin readiness check")
        if runtime_token_writer is None:
            missing.append("an enrolled protected tunnel-token sink")
        return RemoteEnrollmentResult(
            "pending", "ready", "verified", "pending", remote_journal.phase.value,
            "Route activation is blocked until " + " and ".join(missing) + ".",
            (f"Complete those protected host integrations and run {resume_command}.",),
            _resource_ids(remote_journal), True,
        )

    # RemoteCloudflareProvisioner owns the external API ordering and must store
    # the tunnel token through the supplied host sink before it writes DNS.
    try:
        activate = getattr(provisioner, "provision_protected", None)
        if not callable(activate):
            raise RuntimeError("protected tunnel-token gate is not available")
        provisioned = activate(runtime_token_writer=runtime_token_writer)
        if provisioned is None or not getattr(provisioned, "tunnel_id", None):
            raise RuntimeError("route activation did not return a verified owned tunnel result")
        save_remote(remote_journal, "active")
        return RemoteEnrollmentResult(
            "ready", "ready", "verified", "active", remote_journal.phase.value,
            "Owned Access resources, exact policy reads, protected tunnel-token storage, and the route are verified.",
            (), _resource_ids(remote_journal), True,
        )
    except RemoteConflict as exc:
        save_remote(remote_journal, "failed")
        return RemoteEnrollmentResult(
            "failed", "ready", "verified", "failed", remote_journal.phase.value,
            _safe_setup_error(exc),
            (f"Resolve only the owned-resource conflict and run {resume_command}.",),
            _resource_ids(remote_journal), True,
        )
    except Exception as exc:
        save_remote(remote_journal, "pending")
        return RemoteEnrollmentResult(
            "pending", "ready", "verified", "pending", remote_journal.phase.value,
            _safe_setup_error(exc),
            (f"Check the protected token sink and local origin, then run {resume_command}; no token is included in state or output.",),
            _resource_ids(remote_journal), True,
        )
