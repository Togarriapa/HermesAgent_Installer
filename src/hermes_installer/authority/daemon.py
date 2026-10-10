"""Root-side assembly and listener for the protected authority daemon.

The installed root service supplies trusted, root-validated enrollment objects
and fixed handler adapters. This module owns signing-key loading, handler
registration checks and per-profile Unix socket startup; workers never load the
protected config or key.
"""
from __future__ import annotations

import os
import inspect
import signal
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from .service import (AuthorityPolicy, AuthorityService, ChildDelegationRule,
                      EffectHandler, EffectRule, PrincipalBinding)
from .types import AuthorityDenied
from .native_worker_endpoint_custody import RootPreparedAuthorityEndpointCustodian

DEFAULT_SOCKET_DIR = Path("/run/hermes-installer/authority")


def build_authority_service(*, signing_key_path: Path, key_id: str,
                            bindings_by_uid: Mapping[int, PrincipalBinding],
                            rules: Mapping[tuple[str, str, str], EffectRule],
                            handlers: Mapping[tuple[str, str], EffectHandler],
                            policy: AuthorityPolicy,
                            process_profiles: Mapping[str, Any] | None = None,
                            process_handler_options: Mapping[str, Any] | None = None,
                            profile_generations: Mapping[str, str] | None = None,
                            background_consent_active: Any | None = None,
                            delegations: Mapping[str, ChildDelegationRule] | None = None,
                            process_effect_handler: Any | None = None,
                            register_process_handlers: bool = True,
                            selected_operation_resolver: Any | None = None,
                            remote_session_authority: Any | None = None,
                            source_receipt_delivery: Any | None = None,
                            source_observer_registry: Any | None = None,
                            native_runtime_observer: Any | None = None,
                            native_invocation_registry: Any | None = None,
                            service_generation_digest: str | None = None) -> AuthorityService:
    """Build the root service from already validated protected enrollments.

    `process_profiles`, policy, rules and handler adapters must be created by
    the root-owned enrollment loader. This function does not accept paths or
    factories from a worker or from environment variables.
    """
    registered = dict(handlers)
    manager = process_effect_handler
    if process_profiles and manager is None:
        from hermes_installer.managed_process_custodian import create_managed_process_handler
        manager = create_managed_process_handler(process_profiles, **dict(process_handler_options or {}))
    if manager is not None and register_process_handlers:
        for key, handler in manager.handlers().items():
            if key in registered:
                raise AuthorityDenied("authority.configuration", "duplicate fixed effect handler registration")
            registered[key] = handler
    return AuthorityService.from_key_file(
        signing_key_path, key_id=key_id, bindings_by_uid=bindings_by_uid,
        rules=rules, handlers=registered, policy=policy,
        profile_generations=profile_generations,
        background_consent_active=background_consent_active,
        delegations=delegations,
        process_effect_handler=manager,
        selected_operation_resolver=selected_operation_resolver,
        remote_session_authority=remote_session_authority,
        source_receipt_delivery=source_receipt_delivery,
        source_observer_registry=source_observer_registry,
        native_runtime_observer=native_runtime_observer,
        native_invocation_registry=native_invocation_registry,
        service_generation_digest=service_generation_digest,
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
    service_ref: dict[str, AuthorityService] = {}
    def authorization_check(context: Any, authorization: Any, *, operation: str,
                            request_digest: str, retry_index: int = 0) -> bool:
        active = service_ref.get("service")
        if active is None:
            raise AuthorityDenied("authority.starting", "authority service is not ready")
        return active.revalidate_effect(context, authorization, operation=operation,
                                        request_digest=request_digest, retry_index=retry_index)
    artifact_catalog = load_artifact_catalog(enrollment) if ARTIFACT_CATALOG_PATH.exists() else None
    effective_process_options = dict(process_handler_options or {})
    if artifact_catalog is not None:
        resolver = lambda store_id, sha256: artifact_catalog.resolve_store_id(
            store_id, enrollment.artifact_staging_directory, expected_uid=0)
        if "artifact_resolver" in effective_process_options:
            raise AuthorityDenied("authority.configuration", "process artifact resolver is fixed by protected catalog")
        effective_process_options["artifact_resolver"] = resolver

    process_manager = None
    runtime_bindings = None
    if artifact_catalog is not None and enrollment.service_records:
        from .runtime_bindings import build_root_runtime_bindings
        runtime_bindings = build_root_runtime_bindings(
            enrollment, vault=vault, artifact_catalog=artifact_catalog,
            authorization_check=authorization_check,
            process_handler_options=effective_process_options, expected_uid=0,
        )
        process_manager = runtime_bindings.process_manager
        handlers.update(runtime_bindings.effect_handlers)

    if runtime_bindings is None and ARTIFACT_CATALOG_PATH.exists():
        from hermes_installer.artifacts import build_artifact_handlers
        # Older broker revisions lack an effect-time authorization callback.
        # Do not silently register those handlers: cancellation during a body
        # read is too late to prevent an outbound connection after revocation.
        if "authorization_check" in inspect.signature(build_artifact_handlers).parameters:
            handlers.update(build_artifact_handlers(
                artifact_catalog, enrollment.artifact_staging_directory,
                expected_uid=0, authorization_check=authorization_check))

    # These integrations are composed only when their actual protected
    # eligibility/transport implementations have been supplied by the root
    # service package. Catalog presence alone is never treated as consent.
    typed_providers: dict[tuple[str, str], Any] = {}
    provider_normalization_policies: dict[tuple[str, str], Mapping[str, object]] = {}
    for bridge in enrollment.native_bridges.values():
        record = {
            "id": bridge.normalization_policy_id,
            "revision": bridge.normalization_policy_revision,
            "route_schema_id": bridge.route_schema_id,
            "output_limit_mode": bridge.output_limit_mode,
            "output_limit_ceiling": bridge.output_limit_ceiling,
            "canonicalizer_artifact_id": bridge.canonicalizer_artifact_id,
            "canonicalizer_sha256": bridge.canonicalizer_sha256,
            "normalization_policy_sha256": bridge.normalization_policy_sha256,
        }
        route_key = (bridge.target, bridge.recipient)
        previous = provider_normalization_policies.setdefault(route_key, record)
        if dict(previous) != record:
            raise AuthorityDenied("enrollment.native_bridge", "provider route has conflicting normalization policies")
    if enrollment.provider_enrollments:
        from hermes_installer.provider_effect_handlers import ProviderEnrollment, build_provider_handlers
        for record in enrollment.provider_enrollments.values():
            fields = dict(record)
            fields.pop("id", None)
            fields["models"] = frozenset(fields["models"])
            fields["allowed_sensitivities"] = frozenset(fields["allowed_sensitivities"])
            route = ProviderEnrollment(**fields)
            typed_providers[(route.target, route.recipient)] = route
        if provider_admission is not None:
            handlers.update(build_provider_handlers(enrollments=typed_providers, admission=provider_admission,
                                                    vault=vault,
                                                    normalization_policies=provider_normalization_policies))

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
        process_effect_handler=process_manager,
        register_process_handlers=runtime_bindings is None,
        selected_operation_resolver=(runtime_bindings.resolve_selected_operation
                                     if runtime_bindings is not None else None),
        service_generation_digest=enrollment.protected_enrollment_digest,
    )
    if runtime_bindings is not None:
        service.attach_root_runtime_bindings(runtime_bindings)
    service_ref["service"] = service
    authority_runtime = None
    if runtime_bindings is not None and artifact_catalog is not None:
        from .runtime_composition import compose_root_authority_runtime
        authority_runtime = compose_root_authority_runtime(
            service=service, enrollment=enrollment, bindings=runtime_bindings,
            artifact_catalog=artifact_catalog, vault=vault,
        )
    service.root_authority_runtime = authority_runtime
    if authority_runtime is not None:
        authority_runtime = _finalize_active_setup_choice_registry(
            service=service, enrollment=enrollment, bindings=runtime_bindings,
            runtime=authority_runtime,
        )
        service.root_authority_runtime = authority_runtime
        authority_runtime = _finalize_active_memory_lifecycle(
            service=service, enrollment=enrollment, bindings=runtime_bindings,
            runtime=authority_runtime,
        )
        service.root_authority_runtime = authority_runtime
    # The listener cannot accept effects until both post-compose finalization
    # phases above have returned. Memory lifecycle evidence is deliberately
    # composed only after the durable setup-choice registry is attached.
    return service, enrollment


def _finalize_active_setup_choice_registry(*, service: AuthorityService,
                                           enrollment: Any, bindings: Any,
                                           runtime: Any) -> Any:
    """Complete the durable-choice graph after its signer runtime is active.

    The authority signer deliberately requires ``service.root_authority_runtime``
    to already be the fully composed object. This is therefore a second,
    one-time composition phase before the daemon returns the service to its
    listener. Missing release/publication/journal evidence leaves choice-based
    routes unavailable; a partial attachment is a startup error.
    """
    from dataclasses import replace
    from .runtime_composition import RootAuthorityRuntime, _AUTHORITY_JOURNAL_ROOT_ID

    if (type(runtime) is not RootAuthorityRuntime or runtime.service is not service
            or runtime.bindings is not bindings or bindings is not service.root_runtime_bindings):
        raise AuthorityDenied("setup.choice", "active setup-choice composition has no exact root runtime")
    if getattr(bindings, "root_setup_choice_registry", None) is not None:
        raise AuthorityDenied("setup.choice", "durable setup-choice registry was already attached")

    release = runtime.controller_release_receipt
    actor = runtime.controller_actor_observation
    if release is None or actor is None:
        try:
            from .installer_release import InstalledRootReleaseVerifier
            release, actor = InstalledRootReleaseVerifier.from_current_root_process()
            runtime = replace(runtime, controller_release_receipt=release,
                              controller_actor_observation=actor)
            service.root_authority_runtime = runtime
        except Exception as exc:
            return replace(
                runtime,
                consent_unavailable_reason=(
                    f"active setup-choice registry lacks the installed release/actor proof ({type(exc).__name__})"
                ),
            )

    registry = None
    try:
        from .root_setup_choices import RootSetupChoiceRegistry
        from .setup_policy_publication import PolicyPublicationReceiptResolver

        if (enrollment.protected_enrollment_digest != bindings.service_generation_digest
                or enrollment.protected_enrollment_digest != service.service_generation_digest):
            raise AuthorityDenied("setup.choice", "active enrollment digest changed during finalization")
        publication = PolicyPublicationReceiptResolver.resolve_current()
        journal = bindings.resolve_root_journal(
            _AUTHORITY_JOURNAL_ROOT_ID,
            expected_active_generation_digest=enrollment.protected_enrollment_digest,
        )
        registry = RootSetupChoiceRegistry.from_root_runtime(
            release, publication, service, journal,
        )
        bindings.attach_root_setup_choice_registry(registry, service)
        from .root_runtime_foreground_tty import RootRuntimeForegroundTTYObserver
        foreground_tty = RootRuntimeForegroundTTYObserver.from_root_runtime(
            verified_installer_release=release,
            current_installed_actor_verifier=actor,
            active_bindings=bindings,
            root_journal=journal,
        )
        registry.attach_foreground_tty_observer(foreground_tty)
        runtime = replace(runtime, root_setup_choice_registry=registry,
                          consent_unavailable_reason=None)
        service.root_authority_runtime = runtime
        service.active_network_generation_owner = None
        service.active_network_generation_unavailable_reason = None
        try:
            from .local_resource_effects import RootActiveLocalOwnerPrincipalRegistry
            local_owner_principal = RootActiveLocalOwnerPrincipalRegistry.from_root_runtime(runtime)
            from .local_resource_effects import RootActiveOwnerOverlayRegistry
            owner_overlay_registry = RootActiveOwnerOverlayRegistry.from_root_runtime(
                runtime, local_owner_principal,
            )
            runtime = replace(
                runtime, active_local_owner_principal_registry=local_owner_principal,
                active_owner_overlay_registry=owner_overlay_registry,
                local_owner_overlay_unavailable_reason=None,
            )
            service.attach_active_owner_overlay_registry(owner_overlay_registry)
        except Exception as exc:
            # Local-owner resources are independent of Authentik. An absent
            # or stale local adoption disables only that exact feature lane.
            runtime = replace(
                runtime, active_local_owner_principal_registry=None,
                active_owner_overlay_registry=None,
                local_owner_overlay_unavailable_reason=(
                    f"active local-owner principal registry is unavailable ({type(exc).__name__})"
                ),
            )
        service.root_authority_runtime = runtime
        # Network authority is independently current after setup has expired.
        # Keep it unavailable if the exact post-setup runtime/source custody
        # cannot be composed; no setup session or policy-property text is used
        # as a substitute.
        try:
            from .active_network_generation import RootActiveNetworkGenerationOwner
            # The service pointer is the canonical identity checked by the
            # owner. Do not replace the runtime after owner construction.
            service.root_authority_runtime = runtime
            owner = RootActiveNetworkGenerationOwner.from_root_runtime(runtime)
            service.active_network_generation_owner = owner
            service.active_network_generation_unavailable_reason = None
        except Exception as exc:
            service.active_network_generation_owner = None
            service.active_network_generation_unavailable_reason = (
                f"active worker network generation owner is unavailable ({type(exc).__name__})"
            )
        return runtime
    except Exception as exc:
        if (registry is not None
                or getattr(bindings, "root_setup_choice_registry", None) is not None
                or getattr(service, "_root_setup_choice_registry", None) is not None):
            raise AuthorityDenied(
                "setup.choice", "durable setup-choice attachment was partial; restart the root service",
            ) from None
        return replace(
            runtime,
            consent_unavailable_reason=(
                f"durable active setup-choice registry is unavailable ({type(exc).__name__})"
            ),
        )


def _finalize_active_memory_lifecycle(*, service: AuthorityService,
                                      enrollment: Any, bindings: Any,
                                      runtime: Any) -> Any:
    """Compose memory lifecycle once, after durable choices are attached.

    This phase deliberately reuses the exact memory runtime and network lease
    resolver created by core composition. It does not rebuild services,
    listeners, or providers, and does not substitute capture consent for the
    explicit adopted service-enable choice.
    """
    from dataclasses import replace
    from .runtime_composition import RootAuthorityRuntime

    if type(runtime) is not RootAuthorityRuntime or runtime.service is not service or runtime.bindings is not bindings:
        raise AuthorityDenied("memory.lifecycle", "post-choice lifecycle composition lacks the exact active runtime")
    if not enrollment.memory_enrollments:
        return runtime
    choices = runtime.root_setup_choice_registry
    if (choices is None or bindings.root_setup_choice_registry is not choices
            or getattr(service, "_root_setup_choice_registry", None) is not choices):
        return replace(
            runtime,
            memory_lifecycle_unavailable_reason="durable adopted memory service-enable choice is unavailable",
        )

    memory_runtime = runtime.memory_runtime
    network_resolver = None
    if isinstance(memory_runtime, Mapping):
        connector = memory_runtime.get("namespace_connector")
        network_resolver = getattr(connector, "private_network_lease_resolver", None)
    try:
        from .memory_runtime_composition import compose_root_memory_runtime
        composed = compose_root_memory_runtime(
            bindings=bindings, enrollment=enrollment,
            memory_runtime=memory_runtime, service=service,
            root_setup_choice_registry=choices,
            vault=runtime.vault,
            network_lease_resolver=network_resolver,
            monotonic=service.monotonic,
        )
        return replace(
            runtime,
            memory_runtime_composition=composed,
            memory_lifecycle_unavailable_reason=composed.unavailable_reason,
        )
    except Exception as exc:
        return replace(
            runtime,
            memory_lifecycle_unavailable_reason=(
                f"post-choice root memory lifecycle composition rejected ({type(exc).__name__})"
            ),
        )


def serve_authority(service: AuthorityService, *, socket_gid_by_uid: Mapping[int, int],
                    stop_event: threading.Event,
                    socket_dir: Path = DEFAULT_SOCKET_DIR,
                    max_clients_per_uid: int = 32,
                    adopted_listener_by_uid: Mapping[int, socket.socket] | None = None) -> None:
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
    adopted = dict(adopted_listener_by_uid or {})
    if not adopted:
        raise AuthorityDenied("authority.activation", "authority effects require an acknowledged transferred listener")
    if set(adopted) != enrolled_uids or len(enrolled_uids) != 1:
        raise AuthorityDenied("authority.socket", "supervised adoption must cover the exact singleton enrolled profile")
    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def prune_root_observers() -> None:
        while not stop_event.wait(1.0):
            runtime = getattr(service, "root_authority_runtime", None)
            prune = getattr(runtime, "prune", None)
            if callable(prune):
                try:
                    prune()
                except BaseException as exc:
                    with failure_lock:
                        failures.append(exc)
                    stop_event.set()
                    return

    def run_one(uid: int, gid: int) -> None:
        try:
            service.serve_unix_from_owned_listener(adopted[uid], stop_event=stop_event,
                                                   max_clients=max_clients_per_uid)
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            stop_event.set()

    def run_resource_scheduler() -> None:
        runtime = getattr(service, "root_authority_runtime", None)
        scheduler = getattr(runtime, "resource_scheduler", None)
        if scheduler is None:
            return
        try:
            scheduler.run(stop_event)
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            stop_event.set()

    threads = [threading.Thread(target=run_one, args=(uid, gid),
                                name=f"authority-uid-{uid}", daemon=False)
               for uid, gid in sorted(socket_gid_by_uid.items())]
    pruner = threading.Thread(target=prune_root_observers,
                              name="authority-observer-prune", daemon=False)
    scheduler_thread = threading.Thread(target=run_resource_scheduler,
                                         name="authority-resource-scheduler", daemon=False)
    pruner.start()
    scheduler_thread.start()
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    stop_event.set()
    pruner.join()
    scheduler_thread.join()
    if failures:
        raise AuthorityDenied("authority.listener", "protected authority listener exited") from failures[0]


def main() -> int:
    """The direct console entry point is deliberately unavailable without adoption."""
    raise AuthorityDenied("authority.activation", "authority effects require the fixed supervised adoption action")


def main_adopt(activation_id: str) -> int:
    """Fixed installed-unit action which serves only the acknowledged transferred listener."""
    # The installed root actor snapshots its finite module closure.  Load the
    # complete native launch verifier before that observation, never on the
    # first post-capture worker request.
    from .native_worker_launch import preload_native_worker_launch_closure
    preload_native_worker_launch_closure()
    service, enrollment = build_enrolled_authority_service()
    runtime = getattr(service, "root_authority_runtime", None)
    process_manager = getattr(runtime, "process_manager", None)
    process_profiles = (process_manager.profiles if process_manager is not None
                        else enrollment.process_profiles)
    socket_gid_by_uid: dict[int, int] = {}
    for uid, binding in enrollment.bindings_by_uid.items():
        profile = process_profiles.get(binding.profile_id)
        if profile is None or profile.owner_uid != uid:
            raise AuthorityDenied("authority.socket", "every socket peer must map to a root-enrolled worker profile")
        socket_gid_by_uid[uid] = profile.owner_gid
    from .installer_release import InstalledRootReleaseVerifier
    from .listener_activation import RootAuthorityListenerActivationReceiver
    held_release, actor = InstalledRootReleaseVerifier.from_current_root_process()
    receiver = RootAuthorityListenerActivationReceiver.from_current_installed_daemon(
        runtime, activation_id, held_release, actor, service=service, enrollment=enrollment)
    listener: socket.socket | None = None
    active_listener: Any = None
    stop_event = threading.Event()
    signal.signal(signal.SIGTERM, lambda _signum, _frame: stop_event.set())
    signal.signal(signal.SIGINT, lambda _signum, _frame: stop_event.set())
    try:
        listener, active_listener = receiver.receive_listener()
        # The v191 health intent and its completion share the protected
        # authority journal with the setup transaction.  The /run activation
        # record remains transport/currentness evidence only.
        from .listener_activation import RootSetupHealthIntentJournal
        root_journal = runtime.bindings.resolve_root_journal(
            "installer-authority-journal-v1",
            expected_active_generation_digest=runtime.enrollment.protected_enrollment_digest,
        )
        health_journal = RootSetupHealthIntentJournal.from_root_journal(
            root_journal, activation_id, receiver=receiver,
            active_receipt=receiver.current_active_receipt(),
        )
        receiver.attach_health_intent_journal(health_journal)
        service.root_authority_listener_activation_receiver = receiver
        service.root_setup_health_intent_journal = health_journal
        if process_manager is not None:
            # This owner binds fresh active PM/source projections and the
            # receiver's retained adopted FD. Failure leaves the native worker
            # unavailable; the generic process path denies that profile.
            from .native_worker_launch import NativeHermesWorkerLaunchUnavailable
            try:
                process_manager.bind_native_worker_launch_owner(
                    runtime, receiver, active_listener)
            except NativeHermesWorkerLaunchUnavailable:
                pass
        socket_path = listener.getsockname()
        if (not isinstance(socket_path, str)
                or socket_path != str(DEFAULT_SOCKET_DIR / f"{next(iter(socket_gid_by_uid))}.sock")):
            raise AuthorityDenied("authority.activation", "acknowledged listener path differs from the selected enrolled UID")
        serve_authority(service, socket_gid_by_uid=socket_gid_by_uid, stop_event=stop_event,
                        adopted_listener_by_uid={next(iter(socket_gid_by_uid)): listener})
    finally:
        stop_event.set()
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
            # Remove only the exact socket leaf named by the adopted journal;
            # a pathname replacement is preserved for recovery/inspection.
            try:
                info = Path(socket_path).lstat()
                if (stat.S_ISSOCK(info.st_mode) and info.st_uid == 0
                        and info.st_gid == enrollment.process_profiles[
                            next(iter(enrollment.bindings_by_uid.values())).profile_id].owner_gid
                        and (info.st_dev, info.st_ino) == (
                            active_listener.socket_device, active_listener.socket_inode)):
                    Path(socket_path).unlink()
            except (OSError, KeyError, StopIteration):
                pass
        owner = getattr(receiver, "_owner", None)
        close_owner = getattr(owner, "close", None)
        if callable(close_owner):
            close_owner()
        close_receiver = getattr(receiver, "close", None)
        if callable(close_receiver):
            close_receiver()
        authority_runtime = getattr(service, "root_authority_runtime", None)
        close_runtime = getattr(authority_runtime, "close", None)
        if callable(close_runtime):
            close_runtime()
        if runtime is not None:
            connector = getattr(runtime, "service_connector", None)
            shutdown = getattr(connector, "shutdown", None)
            if callable(shutdown):
                shutdown()
        remote_authority = getattr(service, "remote_session_authority", None)
        stop_watchdog = getattr(remote_authority, "stop_watchdog", None)
        if callable(stop_watchdog):
            stop_watchdog()
        actor.close()
        held_release.close()
    return 0
