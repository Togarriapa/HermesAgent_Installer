"""Root-side assembly and listener for the protected authority daemon.

The installed root service supplies trusted, root-validated enrollment objects
and fixed handler adapters. This module owns signing-key loading, handler
registration checks and per-profile Unix socket startup; workers never load the
protected config or key.
"""
from __future__ import annotations

import os
import stat
import threading
from pathlib import Path
from typing import Any, Callable, Mapping

from .service import AuthorityPolicy, AuthorityService, EffectHandler, EffectRule, PrincipalBinding
from .types import AuthorityDenied

DEFAULT_SOCKET_DIR = Path("/run/hermes-installer/authority")


def build_authority_service(*, signing_key_path: Path, key_id: str,
                            bindings_by_uid: Mapping[int, PrincipalBinding],
                            rules: Mapping[tuple[str, str], EffectRule],
                            handlers: Mapping[tuple[str, str], EffectHandler],
                            policy: AuthorityPolicy,
                            process_profiles: Mapping[str, Any] | None = None,
                            process_handler_options: Mapping[str, Any] | None = None) -> AuthorityService:
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
    )


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
