"""Root-side assembly and listener for the protected authority daemon.

The installed root service supplies trusted, root-validated enrollment objects
and fixed handler adapters. This module owns signing-key loading, handler
registration checks and per-profile Unix socket startup; workers never load the
protected config or key.
"""
from __future__ import annotations

import os
import signal
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from .service import (AuthorityPolicy, AuthorityService, ChildDelegationRule,
                      EffectHandler, EffectRule, PrincipalBinding)
from .types import AuthorityDenied

DEFAULT_SOCKET_DIR = Path("/run/hermes-installer/authority")


def build_authority_service(*, signing_key_path: Path, key_id: str,
                            bindings_by_uid: Mapping[int, PrincipalBinding],
                            rules: Mapping[tuple[str, str], EffectRule],
                            handlers: Mapping[tuple[str, str], EffectHandler],
                            policy: AuthorityPolicy,
                            process_profiles: Mapping[str, Any] | None = None,
                            process_handler_options: Mapping[str, Any] | None = None,
                            profile_generations: Mapping[str, str] | None = None,
                            background_consent_active: Any | None = None,
                            delegations: Mapping[str, ChildDelegationRule] | None = None) -> AuthorityService:
    """Build the root service from already validated protected enrollments.

    `process_profiles`, policy, rules and handler adapters must be created by
    the root-owned enrollment loader. This function does not accept paths or
    factories from a worker or from environment variables.
    """
    registered = dict(handlers)
    if process_profiles:
        from hermes_installer.managed_process_custodian import build_managed_process_handlers
        for key, handler in build_managed_process_handlers(
                process_profiles, **dict(process_handler_options or {})).items():
            if key in registered:
                raise AuthorityDenied("authority.configuration", "duplicate fixed effect handler registration")
            registered[key] = handler
    return AuthorityService.from_key_file(
        signing_key_path, key_id=key_id, bindings_by_uid=bindings_by_uid,
        rules=rules, handlers=registered, policy=policy,
        profile_generations=profile_generations,
        background_consent_active=background_consent_active,
        delegations=delegations,
    )


def build_enrolled_authority_service(*, process_handler_options: Mapping[str, Any] | None = None,
                                    provider_admission: Any | None = None,
                                    mcp_transport_factory: Any | None = None,
                                    background_consent_active: Any | None = None) -> tuple[AuthorityService, Any]:
    """Load only root-protected enrollment and assemble installed fixed verbs.

    Adapter implementations are statically imported from their reviewed
    packages; optional external account/service adapters are omitted until a
    concrete root-owned eligibility source is enrolled. No worker-selected
    module name, path, URL, credential, or factory is loaded from JSON.
    """
    if os.geteuid() != 0:
        raise AuthorityDenied("authority.privilege", "authority enrollment must be loaded by root")
    from .enrollment import (
        ARTIFACT_CATALOG_PATH, AUTHORITY_KEY_PATH, RootCredentialVault,
        load_artifact_catalog, load_protected_enrollment,
    )
    vault = RootCredentialVault()
    enrollment = load_protected_enrollment(vault=vault)
    handlers: dict[tuple[str, str], EffectHandler] = {}
    artifact_catalog = load_artifact_catalog(enrollment) if ARTIFACT_CATALOG_PATH.exists() else None
    effective_process_options = dict(process_handler_options or {})
    if artifact_catalog is not None:
        resolver = lambda store_id, sha256: artifact_catalog.resolve_store_id(
            store_id, enrollment.artifact_staging_directory, expected_uid=0)
        if "artifact_resolver" in effective_process_options:
            raise AuthorityDenied("authority.configuration", "process artifact resolver is fixed by protected catalog")
        effective_process_options["artifact_resolver"] = resolver

    if enrollment.process_profiles:
        from hermes_installer.managed_process_custodian import build_managed_process_handlers
        handlers.update(build_managed_process_handlers(
            enrollment.process_profiles, **effective_process_options))

    if ARTIFACT_CATALOG_PATH.exists():
        from hermes_installer.artifacts import build_artifact_handlers
        handlers.update(build_artifact_handlers(artifact_catalog, enrollment.artifact_staging_directory,
                                               expected_uid=0))

    # These integrations are composed only when their actual protected
    # eligibility/transport implementations have been supplied by the root
    # service package. Catalog presence alone is never treated as consent.
    if enrollment.provider_enrollments and provider_admission is not None:
        from hermes_installer.provider_effect_handlers import ProviderEnrollment, build_provider_handlers
        typed: dict[tuple[str, str], Any] = {}
        for record in enrollment.provider_enrollments.values():
            fields = dict(record)
            fields.pop("id", None)
            fields["models"] = frozenset(fields["models"])
            fields["allowed_sensitivities"] = frozenset(fields["allowed_sensitivities"])
            route = ProviderEnrollment(**fields)
            typed[(route.target, route.recipient)] = route
        handlers.update(build_provider_handlers(enrollments=typed, admission=provider_admission,
                                                vault=vault))

    if enrollment.mcp_services and enrollment.mcp_http_bindings:
        # The enrolled transport owns endpoint resolution and TLS. This fixed
        # factory accepts only root-loaded service/binding records and never a
        # worker-selected endpoint, argv, credential, or adapter import path.
        from hermes_installer.mcp.broker import ProtectedMCPService
        from hermes_installer.mcp.enrolled_transport import build_enrolled_mcp_handlers
        services = {}
        for service_id, raw in enrollment.mcp_services.items():
            fields = {key: value for key, value in raw.items() if key != "id"}
            fields["allowed_tools"] = frozenset(fields["allowed_tools"])
            fields["selection_arguments"] = {
                tool: tuple(arguments) for tool, arguments in fields["selection_arguments"].items()
            }
            services[service_id] = ProtectedMCPService(service_id=service_id, **fields)
        handlers.update(build_enrolled_mcp_handlers(services, enrollment.mcp_http_bindings))

    service = build_authority_service(
        signing_key_path=AUTHORITY_KEY_PATH, key_id=enrollment.key_id,
        bindings_by_uid=enrollment.bindings_by_uid, rules=enrollment.rules,
        handlers=handlers, policy=enrollment.policy,
        delegations=enrollment.delegations,
        profile_generations={profile_id: profile.generation
                             for profile_id, profile in enrollment.process_profiles.items()},
        background_consent_active=background_consent_active,
    )
    if enrollment.memory_providers:
        from hermes_installer.memory.broker import MemoryTarget, build_memory_handlers, build_memory_runtime
        targets = {}
        for raw in enrollment.memory_providers.values():
            target = MemoryTarget(**{key: value for key, value in raw.items() if key != "id"})
            targets[(target.profile_id, target.namespace_id, target.provider)] = target
        runtime = build_memory_runtime(
            targets, service, root_data_dir=Path("/var/lib/hermes-installer/memory"), vault=vault)
        service.memory_owner_state = runtime["owner_state"]
        active_lookup = runtime["consent_active"]
        if callable(active_lookup):
            service.background_consent_active = active_lookup
        memory_handlers = build_memory_handlers(
            targets=runtime["targets"], owner_state=runtime["owner_state"], queue=runtime["queue"],
            ipc=runtime["ipc"], engines=runtime["engines"], eligibility=runtime["eligibility"],
            maximum_timeout=runtime["maximum_timeout"],
        )
        enrolled_operations = {(rule.operation, rule.target) for rule in enrollment.rules.values()}
        for key, handler in memory_handlers.items():
            if key not in enrolled_operations or key in service.handlers:
                raise AuthorityDenied("authority.configuration", "memory handler lacks a unique protected effect rule")
            service.handlers[key] = handler
    return service, enrollment


def serve_authority(service: AuthorityService, *, socket_gid_by_uid: Mapping[int, int],
                    stop_event: threading.Event,
                    socket_dir: Path = DEFAULT_SOCKET_DIR,
                    max_clients_per_uid: int = 32) -> None:
    """Run one root-owned socket per enrolled UID, gated by each primary GID."""
    if os.geteuid() != 0:
        raise AuthorityDenied("authority.privilege", "authority daemon must run as root")
    if not socket_dir.is_absolute() or socket_dir != DEFAULT_SOCKET_DIR:
        raise AuthorityDenied("authority.socket", "authority socket directory is fixed")
    info = socket_dir.lstat()
    if (stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o711):
        raise AuthorityDenied("authority.socket", "per-UID socket directory custody is invalid")
    enrolled_uids = set(service.bindings_by_uid)
    if set(socket_gid_by_uid) != enrolled_uids:
        raise AuthorityDenied("authority.socket", "socket GID map must exactly match enrolled UIDs")
    gids = list(socket_gid_by_uid.values())
    if (any(type(gid) is not int or gid <= 0 for gid in gids)
            or len(set(gids)) != len(gids)):
        raise AuthorityDenied("authority.socket", "each profile needs a unique protected primary GID")
    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def run_one(uid: int, gid: int) -> None:
        try:
            service.serve_unix(socket_dir / f"{uid}.sock", socket_gid=gid,
                               stop_event=stop_event, expected_uid=0,
                               max_clients=max_clients_per_uid)
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            stop_event.set()

    threads = [threading.Thread(target=run_one, args=(uid, gid),
                                name=f"authority-uid-{uid}", daemon=False)
               for uid, gid in sorted(socket_gid_by_uid.items())]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    if failures:
        raise AuthorityDenied("authority.listener", "protected authority listener exited") from failures[0]


def main() -> int:
    """System-service entry point; does not mutate installation state."""
    service, enrollment = build_enrolled_authority_service()
    process_profiles = enrollment.process_profiles
    socket_gid_by_uid: dict[int, int] = {}
    for uid, binding in enrollment.bindings_by_uid.items():
        profile = process_profiles.get(binding.profile_id)
        if profile is None or profile.owner_uid != uid:
            raise AuthorityDenied("authority.socket", "every socket peer must map to a root-enrolled worker profile")
        socket_gid_by_uid[uid] = profile.owner_gid
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_event.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop_event.set())
    serve_authority(service, socket_gid_by_uid=socket_gid_by_uid, stop_event=stop_event)
    return 0
