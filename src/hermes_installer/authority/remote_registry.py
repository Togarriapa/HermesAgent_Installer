"""Root router for multiple protected HI13 enrollment rows.

Each ``RemoteSessionAuthority`` owns its own verifier, policy epoch and
connector binding. This registry selects an authority by the protected
hostname on admission, then routes every later opaque handle to the exact
authority that minted it. It never interprets or trusts a caller identity.
"""
from __future__ import annotations

import threading
from typing import Any, Mapping

from .remote_sessions import RemoteAdmissionRequest, RemoteSessionAuthority
from .types import AuthorityDenied


class RemoteSessionAuthorityRegistry:
    """One daemon-facing HI13 service assembled from active root enrollments."""

    def __init__(self, authorities: Mapping[str, RemoteSessionAuthority]):
        if not isinstance(authorities, Mapping) or len(authorities) > 128:
            raise ValueError("protected remote authority map is invalid")
        by_hostname: dict[str, RemoteSessionAuthority] = {}
        for enrollment_id, authority in authorities.items():
            if (not isinstance(enrollment_id, str) or not enrollment_id
                    or not isinstance(authority, RemoteSessionAuthority)
                    or authority.enrollment.enrollment_id != enrollment_id):
                raise ValueError("remote authority map does not match protected enrollment IDs")
            hostname = authority.enrollment.hostname.casefold()
            if hostname in by_hostname:
                raise ValueError("active remote enrollment hostnames are ambiguous")
            by_hostname[hostname] = authority
        self._by_hostname = by_hostname
        self._by_id = dict(authorities)
        self._handles: dict[str, RemoteSessionAuthority] = {}
        self._lock = threading.RLock()

    def admit_remote_session(self, access_jwt: bytes, request: RemoteAdmissionRequest,
                             *, peer_uid: int, peer_pid: int, peer_pidfd: int) -> Any:
        if not isinstance(request, RemoteAdmissionRequest):
            raise AuthorityDenied("remote.request", "typed root admission request is required")
        authority = self._by_hostname.get(request.hostname.casefold())
        if authority is None:
            raise AuthorityDenied("remote.route", "remote hostname is not enrolled")
        response = authority.admit_remote_session(
            access_jwt, request, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        handle = str(response.remote_session_handle)
        with self._lock:
            if handle in self._handles:
                authority.close_remote_session(handle, peer_uid=peer_uid,
                                               peer_pid=peer_pid, peer_pidfd=peer_pidfd)
                raise AuthorityDenied("remote.handle", "root generated a duplicate session handle")
            self._handles[handle] = authority
        return response

    def _for_handle(self, handle: str) -> RemoteSessionAuthority:
        with self._lock:
            authority = self._handles.get(handle)
        if authority is None:
            raise AuthorityDenied("remote.handle", "remote session is unavailable")
        return authority

    def challenge_remote_session(self, remote_session_handle: str, *,
                                 peer_uid: int, peer_pid: int, peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).challenge_remote_session(
            remote_session_handle, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def renew_remote_session(self, remote_session_handle: str, access_jwt: bytes,
                             renewal_nonce: str, *, peer_uid: int, peer_pid: int,
                             peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).renew_remote_session(
            remote_session_handle, access_jwt, renewal_nonce,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def close_remote_session(self, remote_session_handle: str, *,
                             peer_uid: int, peer_pid: int, peer_pidfd: int) -> Any:
        authority = self._for_handle(remote_session_handle)
        response = authority.close_remote_session(
            remote_session_handle, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)
        with self._lock:
            self._handles.pop(remote_session_handle, None)
        return response

    def open_remote_connector(self, remote_session_handle: str, *,
                              peer_uid: int, peer_pid: int, peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).open_remote_connector(
            remote_session_handle, peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def read_remote_connector(self, remote_session_handle: str, connector_handle: str,
                              sequence: int, maximum_bytes: int, *, peer_uid: int,
                              peer_pid: int, peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).read_remote_connector(
            remote_session_handle, connector_handle, sequence, maximum_bytes,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def write_remote_connector(self, remote_session_handle: str, connector_handle: str,
                               sequence: int, data_bytes: bytes, *, peer_uid: int,
                               peer_pid: int, peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).write_remote_connector(
            remote_session_handle, connector_handle, sequence, data_bytes,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def close_remote_connector(self, remote_session_handle: str, connector_handle: str, *,
                               peer_uid: int, peer_pid: int, peer_pidfd: int) -> Any:
        return self._for_handle(remote_session_handle).close_remote_connector(
            remote_session_handle, connector_handle,
            peer_uid=peer_uid, peer_pid=peer_pid, peer_pidfd=peer_pidfd)

    def stop_watchdog(self) -> None:
        for authority in self._by_id.values():
            authority.stop_watchdog()

