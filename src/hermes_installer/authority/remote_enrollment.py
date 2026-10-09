"""Strict parser and join checks for active HI13 remote-session enrollment.

Rows come only from the digest-verified active ``service_generations`` catalog.
This module does not read worker configuration, credentials, or account state.
It joins those rows to root-loaded principals and process profiles before an
authority or connector can be assembled.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

from .remote_sessions import RemotePrincipalBinding, RemoteSessionEnrollment
from .types import AuthorityDenied

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,128}\Z")
_REMOTE_FIELDS = frozenset({
    "id", "gateway_profile_id", "gateway_role_artifact_id", "gateway_role_sha256",
    "native_desktop_profile_id", "native_generation", "connector_target_id",
    "approved_asset_routes", "approved_websocket_route", "expected_hostname",
    "expected_origin", "jwt_issuer", "jwt_audience", "jwks_origin",
    "jwt_algorithm_allowlist", "allowed_email_reference_id",
    "policy_verifier_enrollment_id", "policy_config_digest",
    "maximum_lease_seconds", "watchdog_interval_seconds", "policy_revision",
    "principal_bindings_by_subject", "access_policy_binding", "tunnel_runtime_binding",
})
_ACCESS_FIELDS = frozenset({
    "verifier_enrollment_id", "account_id", "application_id", "policy_id",
    "otp_identity_provider_id", "otp_provider_type", "verifier_config_digest",
    "read_credential_reference_id",
})
_TUNNEL_FIELDS = frozenset({
    "tunnel_enrollment_id", "tunnel_id", "cloudflared_profile_id",
    "tunnel_token_reference_id", "token_sink_id", "origin_readiness_policy_id",
})


def _deny(reason: str) -> AuthorityDenied:
    return AuthorityDenied("remote.enrollment", reason)


def _exact(value: Any, fields: frozenset[str], name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != fields:
        raise _deny(f"protected {name} fields are invalid")
    return value


def _id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise _deny(f"protected {name} is invalid")
    return value


def _digest(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise _deny(f"protected {name} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class RemoteAccessPolicyBinding:
    verifier_enrollment_id: str
    account_id: str
    application_id: str
    policy_id: str
    otp_identity_provider_id: str
    otp_provider_type: str
    verifier_config_digest: str
    read_credential_reference_id: str

    def __post_init__(self) -> None:
        if (not all(_ID.fullmatch(x) for x in (
                self.verifier_enrollment_id, self.account_id, self.application_id,
                self.policy_id, self.otp_identity_provider_id))
                or self.otp_provider_type != "onetimepin"
                or not _DIGEST.fullmatch(self.verifier_config_digest)
                or not _ID.fullmatch(self.read_credential_reference_id)):
            raise ValueError("protected Access policy binding is malformed")


@dataclass(frozen=True, slots=True)
class RemoteTunnelRuntimeBinding:
    tunnel_enrollment_id: str
    tunnel_id: str
    cloudflared_profile_id: str
    tunnel_token_reference_id: str
    token_sink_id: str
    origin_readiness_policy_id: str

    def __post_init__(self) -> None:
        if not all(_ID.fullmatch(x) for x in (
                self.tunnel_enrollment_id, self.tunnel_id, self.cloudflared_profile_id,
                self.tunnel_token_reference_id, self.token_sink_id,
                self.origin_readiness_policy_id)):
            raise ValueError("protected tunnel runtime binding is malformed")


@dataclass(frozen=True, slots=True)
class EnrolledRemoteSession:
    """One active HI13 row plus its already-validated service joins."""

    session: RemoteSessionEnrollment
    access_policy: RemoteAccessPolicyBinding
    tunnel_runtime: RemoteTunnelRuntimeBinding


def parse_remote_session_enrollments(
    records: tuple[Mapping[str, Any], ...] | list[Mapping[str, Any]], *,
    principal_bindings: Mapping[str, Mapping[str, str]],
    process_profiles: Mapping[str, Any],
) -> Mapping[str, EnrolledRemoteSession]:
    """Validate active records against root principal and managed-process joins.

    ``principal_bindings`` is derived by the protected enrollment loader from
    its Authentik principal identities and UID/profile bindings. The caller
    must not supply this mapping from a worker/configuration channel.
    """
    if (not isinstance(records, (tuple, list)) or len(records) > 128
            or not isinstance(principal_bindings, Mapping)
            or not isinstance(process_profiles, Mapping)):
        raise _deny("active HI13 enrollment catalog is malformed")
    by_subject: dict[str, Mapping[str, str]] = {}
    profile_generations: dict[str, str] = {}
    profiles_by_id: dict[str, Any] = {}
    for profile_id, profile in process_profiles.items():
        if (not isinstance(profile_id, str) or not _ID.fullmatch(profile_id)
                or getattr(profile, "profile_id", None) != profile_id
                or not isinstance(getattr(profile, "generation", None), str)
                or not _ID.fullmatch(profile.generation)):
            raise _deny("active managed-process profile catalog is malformed")
        profiles_by_id[profile_id] = profile
        profile_generations[profile_id] = profile.generation
    for subject, raw in principal_bindings.items():
        if (not isinstance(subject, str) or not 1 <= len(subject) <= 256
                or not isinstance(raw, Mapping)
                or set(raw) != {"principal_id", "profile_id", "email"}):
            raise _deny("protected remote principal mapping is malformed")
        principal_id = _id(raw["principal_id"], "remote principal ID")
        profile_id = _id(raw["profile_id"], "remote principal profile ID")
        email = raw["email"]
        if (not isinstance(email, str) or email != email.casefold()
                or not re.fullmatch(r"[^@\s]{1,64}@[^@\s.]+(?:\.[^@\s.]+)+", email)
                or profile_id not in profiles_by_id):
            raise _deny("protected remote principal identity or profile join is invalid")
        by_subject[subject] = MappingProxyType({
            "principal_id": principal_id, "profile_id": profile_id, "email": email,
        })
    if (not by_subject or len({v["email"] for v in by_subject.values()}) != len(by_subject)
            or len({v["profile_id"] for v in by_subject.values()}) != len(by_subject)):
        raise _deny("remote subject, email, and profile mapping is ambiguous")

    result: dict[str, EnrolledRemoteSession] = {}
    for raw in records:
        row = _exact(raw, _REMOTE_FIELDS, "remote session enrollment")
        enrollment_id = _id(row["id"], "remote enrollment ID")
        if enrollment_id in result:
            raise _deny("remote enrollment IDs are duplicated")
        gateway_profile_id = _id(row["gateway_profile_id"], "gateway profile ID")
        native_profile_id = _id(row["native_desktop_profile_id"], "native Desktop profile ID")
        gateway = profiles_by_id.get(gateway_profile_id)
        desktop = profiles_by_id.get(native_profile_id)
        if gateway is None or desktop is None:
            raise _deny("gateway or Desktop profile is absent from active process custody")
        gateway_generation = _id(gateway.generation, "gateway generation")
        native_generation = _id(row["native_generation"], "native Desktop generation")
        if desktop.generation != native_generation:
            raise _deny("native Desktop generation differs from active process custody")
        gateway_role_artifact_id = _id(row["gateway_role_artifact_id"], "gateway role artifact ID")
        gateway_role_sha256 = _digest(row["gateway_role_sha256"], "gateway role digest")
        role_hashes = getattr(gateway, "process_role_artifact_hashes", None) or {}
        if role_hashes.get(gateway_role_artifact_id) != gateway_role_sha256:
            raise _deny("gateway role artifact does not match the active pinned process recipe")
        if row["connector_target_id"] != "xpra-native":
            raise _deny("remote connector target is not the fixed native Xpra target")
        asset_routes = row["approved_asset_routes"]
        websocket_route = row["approved_websocket_route"]
        if (not isinstance(asset_routes, list) or not asset_routes
                or len(asset_routes) != len(set(asset_routes))
                or any(route != "xpra-http" for route in asset_routes)
                or websocket_route != "xpra-websocket"):
            raise _deny("remote connector routes differ from the fixed Xpra protocol routes")

        policy_map: dict[str, RemotePrincipalBinding] = {}
        raw_mapping = row["principal_bindings_by_subject"]
        if not isinstance(raw_mapping, Mapping) or set(raw_mapping) != set(by_subject):
            raise _deny("remote principal mapping is not the exact protected principal set")
        for subject, value in raw_mapping.items():
            selected = _exact(value, frozenset({"principal_id", "profile_id", "email"}), "remote subject mapping")
            expected = by_subject[subject]
            if any(selected[key] != expected[key] for key in expected):
                raise _deny("remote subject mapping differs from Authentik principal/profile enrollment")
            profile_id = expected["profile_id"]
            policy_map[subject] = RemotePrincipalBinding(
                subject, expected["email"], expected["principal_id"], profile_id,
                profile_generations[profile_id])

        access_raw = _exact(row["access_policy_binding"], _ACCESS_FIELDS, "Access policy binding")
        access = RemoteAccessPolicyBinding(**dict(access_raw))
        if (access.verifier_enrollment_id != row["policy_verifier_enrollment_id"]
                or access.verifier_config_digest != row["policy_config_digest"]):
            raise _deny("remote Access policy/verifier references do not match the selected binding")
        _id(row["allowed_email_reference_id"], "allowed email reference ID")
        _id(access.read_credential_reference_id, "separate policy-read credential reference ID")

        tunnel_raw = _exact(row["tunnel_runtime_binding"], _TUNNEL_FIELDS, "tunnel runtime binding")
        tunnel = RemoteTunnelRuntimeBinding(**dict(tunnel_raw))
        if len({gateway_profile_id, native_profile_id, tunnel.cloudflared_profile_id}) != 3:
            raise _deny("gateway, Desktop and cloudflared must use distinct enrolled profiles")
        cloudflared = profiles_by_id.get(tunnel.cloudflared_profile_id)
        if cloudflared is None or cloudflared.owner_uid <= 0:
            raise _deny("tunnel runtime profile is absent from active custody")

        try:
            session = RemoteSessionEnrollment(
                enrollment_id=enrollment_id,
                hostname=row["expected_hostname"], expected_origin=row["expected_origin"],
                jwt_issuer=row["jwt_issuer"], jwt_audience=row["jwt_audience"],
                jwks_origin=row["jwks_origin"],
                jwt_algorithm_allowlist=tuple(row["jwt_algorithm_allowlist"]),
                allowed_email_reference_id=row["allowed_email_reference_id"],
                policy_verifier_enrollment_id=row["policy_verifier_enrollment_id"],
                profile_id=next(iter(policy_map.values())).profile_id,
                gateway_profile_id=gateway_profile_id,
                gateway_role_artifact_id=gateway_role_artifact_id,
                gateway_role_sha256=gateway_role_sha256,
                gateway_generation=gateway_generation,
                native_desktop_profile_id=native_profile_id,
                native_generation=native_generation, desktop_generation=native_generation,
                connector_target_id="xpra-native", approved_asset_routes=tuple(asset_routes),
                websocket_route_id="xpra-websocket", policy_revision=row["policy_revision"],
                policy_config_digest=row["policy_config_digest"],
                principal_bindings_by_subject=policy_map,
                maximum_lease_seconds=row["maximum_lease_seconds"],
                watchdog_interval_seconds=row["watchdog_interval_seconds"],
            )
        except (TypeError, ValueError, KeyError):
            raise _deny("remote session enrollment failed strict validation") from None
        result[enrollment_id] = EnrolledRemoteSession(session, access, tunnel)
    return MappingProxyType(result)
