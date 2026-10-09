"""IDs-only selected-profile writer for disabled native MCP metadata.

The root/setup factory pairs this writer with a sealed installation binding.
Callers can select only an enrolled service generation and profile; they never
provide HERMES_HOME, config paths, MCP server mappings, endpoint strings, or
ownership fingerprints.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Callable, Mapping, Sequence

from hermes_installer.mcp.enrolled_transport import ProtectedMCPHTTPBinding
from hermes_installer.mcp.hermes_config import (
    HermesMCPConfigError,
    write_selected_profile_mcp_config,
)
from hermes_installer.mcp.native_dispatch import NativeMCPRegistrationIndex


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z", re.ASCII)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SERVER_NAME = re.compile(r"[a-z][a-z0-9_-]{0,62}\Z", re.ASCII)
_FACTORY_TOKEN = object()


class NativeMCPConfigUnavailable(PermissionError):
    """The selected native MCP config lacks an exact protected join."""


@dataclass(frozen=True, slots=True)
class NativeMCPConfigReceipt:
    enrollment_id: str
    service_generation_digest: str
    profile_id: str
    config_sha256: str
    server_count: int
    status: str = "materialized_disabled_pending_native_dispatch"


@dataclass(frozen=True, slots=True)
class _SelectedProfileTarget:
    """Private path-bearing result from the sealed installation resolver."""

    profile_id: str
    hermes_home: Any
    owner_uid: int


@dataclass(frozen=True, slots=True)
class RootSelectedMCPConfigInputs:
    """One exact root-selected config join from the current protected snapshot."""

    enrollment_id: str
    service_generation_digest: str
    profile_id: str
    registration_index: NativeMCPRegistrationIndex
    services: Mapping[str, Any]
    current_mcp_generations: Mapping[str, str]
    http_bindings: Mapping[str, ProtectedMCPHTTPBinding]


class RootSelectedNativeMCPConfigWriter:
    """Factory-sealed, path-private selected profile config operation.

    The callbacks are installed by root/setup composition from the selected
    installation binding, active protected MCP snapshot and lifecycle journal.
    This object exposes one public operation with opaque selectors only.
    """

    __slots__ = ("_target_for_ids", "_selection_for_ids", "_owners_for_ids",
                 "_commit_owners", "_owner_uid", "_sealed")

    def __init__(self, token: object, *,
                 target_for_ids: Callable[[str, str, str], _SelectedProfileTarget],
                 selection_for_ids: Callable[[str, str, str], RootSelectedMCPConfigInputs],
                 owners_for_ids: Callable[[str, str, str], Mapping[str, str]],
                 commit_owners: Callable[[str, str, str, Mapping[str, str], str], None],
                 expected_owner_uid: int) -> None:
        if token is not _FACTORY_TOKEN:
            raise TypeError("selected MCP config writer must be created by the trusted installer factory")
        if (not all(callable(item) for item in (target_for_ids, selection_for_ids,
                                                owners_for_ids, commit_owners))
                or type(expected_owner_uid) is not int or expected_owner_uid <= 0):
            raise TypeError("selected MCP config writer factory inputs are invalid")
        self._target_for_ids = target_for_ids
        self._selection_for_ids = selection_for_ids
        self._owners_for_ids = owners_for_ids
        self._commit_owners = commit_owners
        self._owner_uid = expected_owner_uid
        self._sealed = True

    @classmethod
    def _from_root_factory(cls, *, target_for_ids, selection_for_ids,
                           owners_for_ids, commit_owners,
                           expected_owner_uid: int) -> "RootSelectedNativeMCPConfigWriter":
        """Private constructor for the setup/root runtime composition factory."""
        return cls(
            _FACTORY_TOKEN, target_for_ids=target_for_ids,
            selection_for_ids=selection_for_ids, owners_for_ids=owners_for_ids,
            commit_owners=commit_owners, expected_owner_uid=expected_owner_uid,
        )

    def write_selected_mcp_config(self, enrollment_id: str,
                                  service_generation_digest: str,
                                  resource_profile_id: str) -> NativeMCPConfigReceipt:
        """Merge selected HTTP metadata; direct Hermes transport stays disabled."""
        for label, value in (("MCP enrollment", enrollment_id),
                             ("service generation", service_generation_digest),
                             ("profile", resource_profile_id)):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise NativeMCPConfigUnavailable(f"selected {label} selector is invalid")
        if not _SHA256.fullmatch(service_generation_digest):
            raise NativeMCPConfigUnavailable("selected service generation digest is invalid")
        try:
            target = self._target_for_ids(enrollment_id, service_generation_digest, resource_profile_id)
            selection = self._selection_for_ids(enrollment_id, service_generation_digest, resource_profile_id)
            owners = self._owners_for_ids(enrollment_id, service_generation_digest, resource_profile_id)
        except Exception:
            raise NativeMCPConfigUnavailable("selected native MCP installation or enrollment is unavailable") from None
        if (type(target) is not _SelectedProfileTarget
                or target.profile_id != resource_profile_id
                or target.owner_uid != self._owner_uid
                or type(selection) is not RootSelectedMCPConfigInputs
                or selection.enrollment_id != enrollment_id
                or selection.service_generation_digest != service_generation_digest
                or selection.profile_id != resource_profile_id
                or not isinstance(selection.registration_index, NativeMCPRegistrationIndex)
                or not isinstance(owners, Mapping)):
            raise NativeMCPConfigUnavailable("selected MCP config joins are stale or incomplete")
        proposed = _disabled_entries(selection)
        if not proposed:
            raise NativeMCPConfigUnavailable(
                "selected MCP config has no eligible protected HTTP service; stdio remains pending its managed lease"
            )
        target_path = target.hermes_home / "profiles" / resource_profile_id / "config.yaml"
        try:
            next_owners, digest = write_selected_profile_mcp_config(
                hermes_home=target.hermes_home, config_path=target_path,
                proposed=proposed, owned_fingerprints=owners,
                expected_owner_uid=self._owner_uid,
                commit_ownership=lambda fingerprint_map, payload_digest: self._commit_owners(
                    enrollment_id, service_generation_digest, resource_profile_id,
                    MappingProxyType(dict(fingerprint_map)), payload_digest,
                ),
            )
        except (HermesMCPConfigError, OSError, TypeError, ValueError):
            raise NativeMCPConfigUnavailable("selected native MCP config was not committed") from None
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise NativeMCPConfigUnavailable("selected native MCP config digest is unavailable")
        return NativeMCPConfigReceipt(
            enrollment_id=enrollment_id,
            service_generation_digest=service_generation_digest,
            profile_id=resource_profile_id,
            config_sha256=digest,
            server_count=len(next_owners),
        )


def _disabled_entries(selection: RootSelectedMCPConfigInputs) -> Mapping[str, Mapping[str, Any]]:
    index = selection.registration_index
    services = selection.services
    generations = selection.current_mcp_generations
    bindings = selection.http_bindings
    if (not isinstance(services, Mapping) or not isinstance(generations, Mapping)
            or not isinstance(bindings, Mapping)):
        raise NativeMCPConfigUnavailable("protected MCP config catalogs are invalid")
    grouped: dict[str, dict[str, Any]] = {}
    for row in index.bindings:
        # The index itself is already scoped to this exact root-selected
        # profile/package/service generation. MCP enrollment IDs are distinct
        # connector identities and are never equated with the installation ID.
        if generations.get(row.mcp_enrollment_id) != row.mcp_generation:
            raise NativeMCPConfigUnavailable("MCP config row references a stale service generation")
        service = services.get(row.mcp_enrollment_id)
        if not isinstance(service, Mapping):
            from hermes_installer.mcp.broker import ProtectedMCPService
            if type(service) is not ProtectedMCPService:
                raise NativeMCPConfigUnavailable("selected MCP server has no protected service record")
            service_id = service.service_id
            channel = service.channel
            binding_id = service.transport_binding_id
            revision = service.reviewed_revision
            allowed = service.allowed_tools
        else:
            service_id = service.get("id", service.get("service_id"))
            channel = service.get("channel")
            binding_id = service.get("transport_binding_id")
            revision = service.get("reviewed_revision")
            allowed = service.get("allowed_tools")
        if (service_id != row.mcp_enrollment_id or not isinstance(allowed, (tuple, list, set, frozenset))
                or row.mcp_tool_name not in allowed
                or row.effect_operation != ("mcp.request" if channel == "http" else "mcp.stdio")):
            raise NativeMCPConfigUnavailable("selected MCP row differs from its protected service policy")
        # There is no safe worker stdio config command. The root proxy still
        # handles that enrolled channel separately if a managed lease exists.
        if channel != "http":
            continue
        http = bindings.get(binding_id)
        if (type(http) is not ProtectedMCPHTTPBinding
                or http.binding_id != binding_id or http.service_id != service_id
                or http.reviewed_revision != revision):
            raise NativeMCPConfigUnavailable("selected MCP HTTP config has no exact endpoint binding")
        if not _SERVER_NAME.fullmatch(row.native_server_name):
            raise NativeMCPConfigUnavailable("selected native MCP server name is invalid")
        existing = grouped.get(row.native_server_name)
        if existing is None:
            grouped[row.native_server_name] = {
                "url": http.endpoint,
                "enabled": False,
                "timeout": 9,
                "connect_timeout": 9,
                "tools": {"include": [row.mcp_tool_name]},
            }
        else:
            if existing["url"] != http.endpoint:
                raise NativeMCPConfigUnavailable("native MCP server name joins conflicting protected endpoints")
            if row.mcp_tool_name not in existing["tools"]["include"]:
                existing["tools"]["include"].append(row.mcp_tool_name)
    return MappingProxyType({
        name: MappingProxyType({**entry, "tools": MappingProxyType({
            "include": tuple(sorted(entry["tools"]["include"])),
        })})
        for name, entry in sorted(grouped.items())
    })
