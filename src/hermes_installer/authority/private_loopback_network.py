"""Root-owned selected loopback network enforcement (HI-T09 / EV-HI09).

This module accepts only finite network rows already covered by the signed
``service_generations`` snapshot. It deliberately separates policy compilation
from host mutation so contracts can inspect the exact nftables transaction.
Kernel mutation is available only through the root authority below, which
requires root-resolved host-tool evidence and a retained namespace receipt.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import socket
import struct
import stat
import subprocess
import time
import threading
import ctypes
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping, Sequence

from hermes_installer.authority.types import AuthorityDenied


POLICY_ID = "installer-private-loopback-nft-v1"
POLICY_SHA256 = "77a48f3a31f115693b04245146158e3c2467f297ff14746a52375850d76237cc"
POLICY_PATH = Path(__file__).resolve().parents[3] / "templates" / "private-loopback-policy-v1.json"
TABLE_NAME = "hermes_installer_private"
LOOPBACK = "127.0.0.1"
_ID = re.compile(r"[A-Za-z0-9_.:@/-]{1,256}\Z")
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_LISTENER_ROLES = frozenset({"xpra-display", "provider-gateway"})
_NETWORK_FIELDS = frozenset({
    "id", "generation", "namespace_identity", "member_enrollment_ids",
    "listener_bindings", "client_bindings", "policy_artifact_id", "policy_sha256",
})


def _id(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise AuthorityDenied("private_network.record", f"protected {name} is malformed")
    return value


def _sha(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise AuthorityDenied("private_network.record", f"protected {name} is malformed")
    return value


@dataclass(frozen=True, slots=True)
class LoopbackListener:
    enrollment_id: str
    role: str
    ipv4: str
    port: int
    uid: int
    profile_id: str
    generation: str


@dataclass(frozen=True, slots=True)
class LoopbackClient:
    enrollment_id: str
    listener_enrollment_id: str
    port: int
    uid: int
    profile_id: str
    generation: str


@dataclass(frozen=True, slots=True)
class PrivateLoopbackServiceIdentity:
    enrollment_id: str
    uid: int
    profile_id: str
    generation: str


@dataclass(frozen=True, slots=True, repr=False)
class PrivateLoopbackNetwork:
    network_id: str
    generation: str
    namespace_identity: str
    service_generation_digest: str
    members: tuple[str, ...]
    member_identities: tuple[PrivateLoopbackServiceIdentity, ...]
    listeners: tuple[LoopbackListener, ...]
    clients: tuple[LoopbackClient, ...]
    policy_artifact_id: str = POLICY_ID
    policy_sha256: str = POLICY_SHA256

    def __repr__(self) -> str:
        return "PrivateLoopbackNetwork(<root-protected>)"

    def member(self, enrollment_id: str) -> PrivateLoopbackServiceIdentity:
        matches = [row for row in self.member_identities if row.enrollment_id == enrollment_id]
        if len(matches) != 1:
            raise AuthorityDenied("private_network.member", "selected network member is absent or ambiguous")
        return matches[0]


def validate_private_loopback_networks(
    rows: Any,
    service_records: Sequence[Mapping[str, Any]],
    service_generation_digest: str,
) -> tuple[PrivateLoopbackNetwork, ...]:
    """Validate every network row and join members to the active service IDs/UIDs."""
    if (not isinstance(rows, list) or len(rows) > 64
            or not isinstance(service_records, (list, tuple))
            or not isinstance(service_generation_digest, str)
            or not _SHA.fullmatch(service_generation_digest)):
        raise AuthorityDenied("private_network.catalog", "protected private network catalog is invalid")
    services: dict[str, Mapping[str, Any]] = {}
    for raw in (service_records if rows else ()):
        enrollment = _id(raw.get("enrollment_id") if isinstance(raw, Mapping) else None,
                         "service enrollment ID")
        generation = _id(raw.get("generation"), "service generation")
        profile_id = _id(raw.get("profile_id"), "service profile ID")
        uid = raw.get("service_uid")
        if type(uid) is not int or uid <= 0 or enrollment in services:
            raise AuthorityDenied("private_network.service", "active service UID binding is invalid")
        services[enrollment] = MappingProxyType({
            "generation": generation, "profile_id": profile_id, "uid": uid,
        })

    result: list[PrivateLoopbackNetwork] = []
    seen_networks: set[str] = set()
    uid_networks: dict[int, str] = {}
    for raw in rows:
        if not isinstance(raw, Mapping) or set(raw) != _NETWORK_FIELDS:
            raise AuthorityDenied("private_network.record", "protected private network row has unknown or missing fields")
        network_id = _id(raw["id"], "network ID")
        generation = _id(raw["generation"], "network generation")
        namespace_identity = _id(raw["namespace_identity"], "namespace identity")
        if network_id in seen_networks:
            raise AuthorityDenied("private_network.record", "private network ID is duplicated")
        seen_networks.add(network_id)
        if raw["policy_artifact_id"] != POLICY_ID or raw["policy_sha256"] != POLICY_SHA256:
            raise AuthorityDenied("private_network.policy", "network does not select the pinned private loopback policy")
        members_raw = raw["member_enrollment_ids"]
        listeners_raw, clients_raw = raw["listener_bindings"], raw["client_bindings"]
        if (not isinstance(members_raw, list) or not 2 <= len(members_raw) <= 16
                or not isinstance(listeners_raw, list) or not 1 <= len(listeners_raw) <= 8
                or not isinstance(clients_raw, list) or not 1 <= len(clients_raw) <= 8):
            raise AuthorityDenied("private_network.record", "network member or endpoint rows exceed their finite bounds")
        members = tuple(_id(item, "member enrollment ID") for item in members_raw)
        if len(members) != len(set(members)):
            raise AuthorityDenied("private_network.member", "network member enrollment is duplicated")
        if any(item not in services for item in members):
            raise AuthorityDenied("private_network.member", "network member is absent from the current service generation")
        network_uids = [int(services[item]["uid"]) for item in members]
        if len(network_uids) != len(set(network_uids)):
            raise AuthorityDenied("private_network.uid", "each selected network role requires an exclusive service UID")
        for item in members:
            uid = int(services[item]["uid"])
            other_network = uid_networks.get(uid)
            if other_network is not None:
                raise AuthorityDenied("private_network.uid", "one service UID cannot join multiple network namespaces")
            uid_networks[uid] = network_id

        listeners: list[LoopbackListener] = []
        listener_by_id: dict[str, LoopbackListener] = {}
        for listener_raw in listeners_raw:
            if (not isinstance(listener_raw, Mapping)
                    or set(listener_raw) != {"enrollment_id", "role", "ipv4", "port"}):
                raise AuthorityDenied("private_network.listener", "listener binding fields are invalid")
            enrollment = _id(listener_raw["enrollment_id"], "listener enrollment ID")
            service = services.get(enrollment)
            role, address, port = listener_raw["role"], listener_raw["ipv4"], listener_raw["port"]
            try:
                parsed = ipaddress.ip_address(address)
            except (ValueError, TypeError):
                raise AuthorityDenied("private_network.listener", "listener address is invalid") from None
            if (service is None or enrollment not in members or role not in _LISTENER_ROLES
                    or parsed.version != 4 or str(parsed) != LOOPBACK
                    or type(port) is not int or not 1 <= port <= 65535
                    or (role == "xpra-display" and port != 14500)
                    or enrollment in listener_by_id):
                raise AuthorityDenied("private_network.listener", "listener is outside its selected loopback role")
            row = LoopbackListener(enrollment, role, LOOPBACK, port, int(service["uid"]),
                                   str(service["profile_id"]), str(service["generation"]))
            listener_by_id[enrollment] = row
            listeners.append(row)

        clients: list[LoopbackClient] = []
        client_rows: set[tuple[str, str, int]] = set()
        client_ports: set[tuple[str, int]] = set()
        for client_raw in clients_raw:
            if (not isinstance(client_raw, Mapping)
                    or set(client_raw) != {"enrollment_id", "listener_enrollment_id", "port"}):
                raise AuthorityDenied("private_network.client", "client binding fields are invalid")
            enrollment = _id(client_raw["enrollment_id"], "client enrollment ID")
            listener_id = _id(client_raw["listener_enrollment_id"], "client listener enrollment ID")
            service, listener = services.get(enrollment), listener_by_id.get(listener_id)
            port = client_raw["port"]
            row_key = (enrollment, listener_id, port) if type(port) is int else (enrollment, listener_id, -1)
            if (service is None or enrollment not in members
                    or listener is None or type(port) is not int or port != listener.port
                    or row_key in client_rows or (listener_id, port) in client_ports):
                raise AuthorityDenied("private_network.client", "client is outside its selected listener/port binding")
            client_rows.add(row_key)
            client_ports.add((listener_id, port))
            clients.append(LoopbackClient(enrollment, listener_id, port, int(service["uid"]),
                                          str(service["profile_id"]), str(service["generation"])))
        endpoint_members = set(listener_by_id) | {row[0] for row in client_rows}
        if not endpoint_members.issubset(set(members)):
            raise AuthorityDenied("private_network.member", "network endpoints name an unenrolled member")
        member_identities = tuple(PrivateLoopbackServiceIdentity(
            enrollment_id, int(services[enrollment_id]["uid"]),
            str(services[enrollment_id]["profile_id"]), str(services[enrollment_id]["generation"]),
        ) for enrollment_id in members)
        result.append(PrivateLoopbackNetwork(
            network_id, generation, namespace_identity, service_generation_digest, members,
            member_identities, tuple(listeners), tuple(clients),
        ))
    return tuple(result)


def compile_nft_transaction(network: PrivateLoopbackNetwork, *, add_table: bool = True) -> bytes:
    """Render the v97 default-drop nftables table from validated protected rows."""
    if not isinstance(network, PrivateLoopbackNetwork):
        raise TypeError("nft policy compilation requires a validated root network selection")
    lines = [f"add table inet {TABLE_NAME}"] if add_table else []
    lines.extend((
        f"add chain inet {TABLE_NAME} input {{ type filter hook input priority 0; policy drop; }}",
        f"add chain inet {TABLE_NAME} output {{ type filter hook output priority 0; policy drop; }}",
        f"add chain inet {TABLE_NAME} forward {{ type filter hook forward priority 0; policy drop; }}",
    ))
    inputs: set[str] = set()
    outputs: set[str] = set()
    for client in network.clients:
        listener = next(row for row in network.listeners
                        if row.enrollment_id == client.listener_enrollment_id)
        endpoint = f"ip daddr {LOOPBACK} tcp dport {listener.port}"
        # Only the enrolled client UID can originate a request to this selected
        # endpoint. Inbound matching is limited to that exact local conntrack
        # tuple; no general lo/established exception is installed.
        outputs.add(
            f"add rule inet {TABLE_NAME} output oifname \"lo\" meta skuid {client.uid} "
            f"ip saddr {LOOPBACK} {endpoint} ct state {{ new, established }} accept"
        )
        inputs.add(
            f"add rule inet {TABLE_NAME} input iifname \"lo\" ip saddr {LOOPBACK} "
            f"ip daddr {LOOPBACK} tcp dport {listener.port} ct direction original "
            "ct state { new, established } accept"
        )
        inputs.add(
            f"add rule inet {TABLE_NAME} input iifname \"lo\" ip saddr {LOOPBACK} "
            f"ip daddr {LOOPBACK} ct direction reply ct state established "
            f"ct original proto-dst {listener.port} accept"
        )
        outputs.add(
            f"add rule inet {TABLE_NAME} output oifname \"lo\" meta skuid {listener.uid} "
            f"ip saddr {LOOPBACK} ip daddr {LOOPBACK} tcp sport {listener.port} "
            f"ct direction reply ct original proto-dst {listener.port} ct state established accept"
        )
    lines.extend(sorted(inputs))
    lines.extend(sorted(outputs))
    return ("\n".join(lines) + "\n").encode("ascii")


@dataclass(frozen=True, slots=True, repr=False)
class RootResolvedHostTool:
    """Held executable identity joined to an actual root package-set receipt."""

    variant_id: str
    package_name: str
    version: str
    distribution: str
    release: str
    architecture: str
    package_sha256: str
    executable_artifact_id: str
    executable_sha256: str
    dependency_closure_sha256: str
    package_set_receipt_handle: str
    expires_monotonic: float
    path: Path = field(repr=False)
    executable_fd: int = field(repr=False)
    device: int
    inode: int
    observation_registry: Any = field(default=None, repr=False, compare=False)
    observation_handle: str = field(default="", repr=False, compare=False)
    selected_network_key: tuple[str, str, str] | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        # Host-tool identity is a root-issued capability, not a bag of package
        # metadata. Requiring the concrete registry here prevents callers from
        # constructing an apparently verified tool with an arbitrary FD.
        from hermes_installer.authority.host_tool_observation import HostToolObservationRegistry
        if type(self.observation_registry) is not HostToolObservationRegistry:
            raise ValueError("root nft tool must come from the host-tool observation registry")
        if (not isinstance(self.observation_handle, str)
                or not re.fullmatch(r"host-nft-observation:[0-9a-f]{48}", self.observation_handle)
                or not isinstance(self.selected_network_key, tuple)
                or len(self.selected_network_key) != 3
                or not all(isinstance(item, str) and item for item in self.selected_network_key)):
            raise ValueError("root nft tool observation binding is malformed")
        for name in ("variant_id", "package_name", "version", "distribution", "release",
                     "architecture", "executable_artifact_id", "package_set_receipt_handle"):
            _id(getattr(self, name), name)
        for name in ("package_sha256", "executable_sha256", "dependency_closure_sha256"):
            _sha(getattr(self, name), name)
        if (self.path != Path("/usr/sbin/nft") or type(self.executable_fd) is not int
                or self.executable_fd < 0 or not isinstance(self.expires_monotonic, (int, float))
                or self.expires_monotonic <= 0):
            raise ValueError("root host-tool observation is malformed")

    @property
    def exec_path(self) -> str:
        return f"/proc/self/fd/{self.executable_fd}"

    def verify_current(self, *, expected_uid: int = 0) -> None:
        from hermes_installer.authority.host_tool_observation import HostToolObservationRegistry
        if type(self.observation_registry) is not HostToolObservationRegistry:
            raise AuthorityDenied("private_network.tool", "root nft observation registry is unavailable")
        self.observation_registry.verify_resolved_tool(self)
        try:
            info = self.path.stat(follow_symlinks=False)
            held_info = os.fstat(self.executable_fd)
            digest = hashlib.sha256()
            offset = 0
            while True:
                chunk = os.pread(self.executable_fd, 1024 * 1024, offset)
                if not chunk:
                    break
                digest.update(chunk)
                offset += len(chunk)
        except OSError:
            raise AuthorityDenied("private_network.tool", "selected kernel tool is unavailable") from None
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != expected_uid or info.st_mode & 0o022
                or not stat.S_ISREG(held_info.st_mode) or held_info.st_uid != expected_uid
                or (info.st_dev, info.st_ino) != (self.device, self.inode)
                or (held_info.st_dev, held_info.st_ino) != (self.device, self.inode)
                or digest.hexdigest() != self.executable_sha256
                or time.monotonic() >= self.expires_monotonic):
            raise AuthorityDenied("private_network.tool", "selected kernel tool changed after catalog resolution")

    def verify_for_network(self, network: PrivateLoopbackNetwork, *, expected_uid: int = 0) -> None:
        if (not isinstance(network, PrivateLoopbackNetwork)
                or self.selected_network_key != (network.network_id, network.generation,
                                                  network.service_generation_digest)):
            raise AuthorityDenied("private_network.tool", "nft observation is not selected for this network")
        self.verify_current(expected_uid=expected_uid)

    def close(self) -> None:
        if self.executable_fd >= 0:
            os.close(self.executable_fd)
            object.__setattr__(self, "executable_fd", -1)
        registry = self.observation_registry
        if registry is not None:
            registry.forget_resolved_tool(self)

    def __repr__(self) -> str:
        return f"RootResolvedHostTool({self.variant_id!r}, <verified>)"


@dataclass(frozen=True, slots=True, repr=False)
class PrivateLoopbackMember:
    network: PrivateLoopbackNetwork
    enrollment_id: str
    uid: int
    service_generation_digest: str

    def __post_init__(self) -> None:
        row = self.network.member(self.enrollment_id)
        if (self.uid != row.uid
                or self.service_generation_digest != self.network.service_generation_digest):
            raise ValueError("private network member does not match the active protected row")

    @property
    def listener_ports(self) -> tuple[int, ...]:
        return tuple(row.port for row in self.network.listeners if row.enrollment_id == self.enrollment_id)

    @property
    def client_endpoints(self) -> tuple[tuple[str, int], ...]:
        return tuple((row.listener_enrollment_id, row.port) for row in self.network.clients
                     if row.enrollment_id == self.enrollment_id)

    @property
    def role(self) -> str:
        listening, connecting = bool(self.listener_ports), bool(self.client_endpoints)
        if listening and connecting:
            return "listener-client"
        if listening:
            return "listener"
        return "client" if connecting else "af-unix"

    def __repr__(self) -> str:
        return "PrivateLoopbackMember(<root-protected>)"


@dataclass(slots=True, repr=False)
class RootPrivateLoopbackNetworkLease:
    """Retained current namespace/policy identity, never serialized to a worker."""

    network: PrivateLoopbackNetwork
    namespace_path: Path = field(repr=False)
    namespace_fd: int = field(repr=False)
    namespace_device: int
    namespace_inode: int
    nft_tool: RootResolvedHostTool
    nft_ruleset_sha256: str
    kernel_receipt_handle: str = field(repr=False)
    kernel_release: str
    kernel_version_sha256: str
    link_state_sha256: str
    address_state_sha256: str
    route_state_sha256: str
    kernel_observed_monotonic: float
    expires_monotonic: float
    kernel_state: Mapping[str, Any] = field(repr=False)
    subject_capability_receipt_handles: dict[str, str] = field(default_factory=dict, repr=False)
    member_processes: dict[str, "RootNetworkMemberProof"] = field(default_factory=dict, repr=False)
    created_monotonic: float = field(default_factory=time.monotonic)
    closed: bool = False

    def __repr__(self) -> str:
        return "RootPrivateLoopbackNetworkLease(<root-private>)"

    def close_fd(self) -> None:
        if self.namespace_fd >= 0:
            os.close(self.namespace_fd)
            self.namespace_fd = -1
        self.closed = True


@dataclass(slots=True, repr=False)
class RootNetworkMemberProof:
    """Retained process/cgroup proof for one exact selected enrollment."""

    enrollment_id: str
    profile_id: str
    generation: str
    uid: int
    pid: int
    pidfd: int = field(repr=False)
    start_ticks: int
    cgroup: str
    unit: str
    capability_receipt_sha256: str

    def __repr__(self) -> str:
        return "RootNetworkMemberProof(<root-private>)"


def _proc_identity(pid: int) -> tuple[int, int, str, int]:
    """Read process start time, uid, network namespace inode and cgroup."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
        end = raw.rfind(")")
        fields = raw[end + 2:].split()
        start_ticks = int(fields[19])  # stat field 22, after pid/comm/state
        status = Path(f"/proc/{pid}/status").read_text()
        uid_line = next(line for line in status.splitlines() if line.startswith("Uid:"))
        uid_values = tuple(int(item) for item in uid_line.split()[1:5])
        if len(uid_values) != 4 or len(set(uid_values)) != 1:
            raise ValueError("process UID identities differ")
        namespace_inode = Path(f"/proc/{pid}/ns/net").stat().st_ino
        cgroups = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        unified = [line[3:] for line in cgroups if line.startswith("0::")]
        if len(unified) != 1:
            raise ValueError("missing unified cgroup")
        return start_ticks, uid_values[0], unified[0], namespace_inode
    except (OSError, ValueError, StopIteration, IndexError):
        raise AuthorityDenied("private_network.member", "managed network member identity is unavailable") from None


def _subject_capability_receipt(pid: int) -> str:
    """Prove a running subject cannot mutate links or open tunnel devices."""
    try:
        status = Path(f"/proc/{pid}/status").read_text()
        values = {line.split(":", 1)[0]: line.split(":", 1)[1].strip()
                  for line in status.splitlines() if ":" in line}
        caps = {name: int(values[name], 16) for name in ("CapEff", "CapPrm", "CapBnd", "CapAmb")}
        if any(caps.values()):
            raise ValueError("subject retains a capability")
        tun = Path(f"/proc/{pid}/root/dev/net/tun")
        if tun.exists():
            raise ValueError("subject can see /dev/net/tun")
        return _state_digest({"capabilities": caps, "tun_device_absent": True})
    except (OSError, KeyError, ValueError):
        raise AuthorityDenied("private_network.subject", "subject capability/device isolation is not proven") from None


def _current_unit_network_properties(unit: str, member: PrivateLoopbackMember,
                                     namespace_path: Path) -> dict[str, str]:
    """Read actual fixed systemd properties for the exact owned unit."""
    if not re.fullmatch(r"hermes-installer-[0-9a-f]{32}\.service", unit):
        raise AuthorityDenied("private_network.systemd", "unit name is outside the owned service namespace")
    expected: dict[str, str] = {}
    for prop in unit_network_properties(member, namespace_path):
        assignment = prop.removeprefix("--property=")
        key, separator, _value = assignment.partition("=")
        if not separator:
            raise AuthorityDenied("private_network.systemd", "fixed network property is malformed")
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "show", unit, f"--property={key}", "--value"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                close_fds=True, shell=False, timeout=3.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise AuthorityDenied("private_network.systemd", "systemd network-property readback is unavailable") from None
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise AuthorityDenied("private_network.systemd", "systemd network-property readback failed")
        try:
            expected[key] = result.stdout.decode("utf-8", "strict").rstrip("\r\n")
        except UnicodeDecodeError:
            raise AuthorityDenied("private_network.systemd", "systemd property is not valid UTF-8") from None
    if "SocketBindAllow" not in expected:
        try:
            result = subprocess.run(
                ["/usr/bin/systemctl", "show", unit, "--property=SocketBindAllow", "--value"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                close_fds=True, shell=False, timeout=3.0, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise AuthorityDenied("private_network.systemd", "systemd bind-policy readback is unavailable") from None
        if result.returncode != 0 or len(result.stdout) > 4096:
            raise AuthorityDenied("private_network.systemd", "systemd bind-policy readback failed")
        try:
            expected["SocketBindAllow"] = result.stdout.decode("utf-8", "strict").rstrip("\r\n")
        except UnicodeDecodeError:
            raise AuthorityDenied("private_network.systemd", "systemd bind-policy readback is not valid UTF-8") from None
    verify_unit_network_readback(member, namespace_path, expected)
    return expected


def _cgroup_members(cgroup: str) -> tuple[int, ...]:
    if (not isinstance(cgroup, str) or not cgroup.startswith("/system.slice/")
            or ".." in Path(cgroup).parts):
        raise AuthorityDenied("private_network.cgroup", "network member cgroup is outside the service slice")
    path = Path("/sys/fs/cgroup") / cgroup.lstrip("/")
    try:
        if path.resolve(strict=True) != path or path.is_symlink():
            raise ValueError("cgroup path identity changed")
        values = tuple(int(raw) for raw in (path / "cgroup.procs").read_text().split())
    except (OSError, ValueError):
        raise AuthorityDenied("private_network.cgroup", "managed network member cgroup is unavailable") from None
    return values


def retain_network_member(
    lease: RootPrivateLoopbackNetworkLease,
    member: PrivateLoopbackMember,
    *, pid: int,
    pidfd: int,
    cgroup: str,
    unit: str,
) -> RootNetworkMemberProof:
    """Retain live systemd identity only after namespace/UID/cgroup joins."""
    if (not isinstance(unit, str) or not re.fullmatch(r"hermes-installer-[0-9a-f]{32}\.service", unit)
            or not isinstance(cgroup, str) or not cgroup.endswith("/" + unit)):
        raise AuthorityDenied("private_network.member", "selected process unit is outside the owned service namespace")
    try:
        verify_root_network_lease(lease)
    except BaseException:
        _stop_owned_network_unit(unit)
        raise
    if not isinstance(member, PrivateLoopbackMember):
        _stop_owned_network_unit(unit)
        raise AuthorityDenied("private_network.member", "selected member record is unavailable")
    try:
        row = lease.network.member(member.enrollment_id)
    except AuthorityDenied:
        _stop_owned_network_unit(unit)
        raise
    if (member.network != lease.network or member.uid != row.uid or member.enrollment_id in lease.member_processes
            or type(pid) is not int or pid <= 1 or type(pidfd) is not int or pidfd < 0
            or not cgroup.endswith("/" + unit)):
        _stop_owned_network_unit(unit)
        raise AuthorityDenied("private_network.member", "selected process does not match one unoccupied network member")
    try:
        retained_pidfd = os.dup(pidfd)
    except OSError:
        raise AuthorityDenied("private_network.member", "managed member pidfd could not be retained") from None
    try:
        start_ticks, uid, current_cgroup, namespace_inode = _proc_identity(pid)
        _current_unit_network_properties(unit, member, lease.namespace_path)
        processes = _cgroup_members(cgroup)
        if (uid != row.uid or current_cgroup != cgroup or pid not in processes
                or namespace_inode != lease.namespace_inode):
            raise AuthorityDenied("private_network.member", "managed process is outside its enrolled namespace/UID/cgroup")
        proof = RootNetworkMemberProof(
            member.enrollment_id, row.profile_id, row.generation, row.uid, pid,
            retained_pidfd, start_ticks, cgroup, unit, _subject_capability_receipt(pid),
        )
        lease.member_processes[member.enrollment_id] = proof
        lease.subject_capability_receipt_handles[member.enrollment_id] = proof.capability_receipt_sha256
        return proof
    except BaseException:
        _stop_owned_network_unit(unit)
        os.close(retained_pidfd)
        raise


def _stop_owned_network_unit(unit: str) -> None:
    if not re.fullmatch(r"hermes-installer-[0-9a-f]{32}\.service", unit):
        return
    try:
        subprocess.run(["/usr/bin/systemctl", "stop", unit], stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
                       close_fds=True, shell=False, timeout=10.0, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return


def release_network_member(lease: RootPrivateLoopbackNetworkLease, enrollment_id: str) -> None:
    """Release one member only after its pidfd and complete unit cgroup are empty."""
    proof = lease.member_processes.get(enrollment_id)
    if proof is None:
        raise AuthorityDenied("private_network.member", "selected network member proof is absent")
    if _pidfd_alive(proof.pidfd):
        raise AuthorityDenied("private_network.member", "selected network member is still alive")
    if _cgroup_members(proof.cgroup):
        raise AuthorityDenied("private_network.member", "selected systemd unit still owns live processes")
    lease.member_processes.pop(enrollment_id)
    lease.subject_capability_receipt_handles.pop(enrollment_id, None)
    os.close(proof.pidfd)


def _pidfd_alive(pidfd: int) -> bool:
    import select
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return not bool(poller.poll(0))


def namespace_path_for(network: PrivateLoopbackNetwork, *, root: Path = Path("/run/hermes-installer/netns")) -> Path:
    """Derive the only stable namespace mount path accepted by v97."""
    if not isinstance(network, PrivateLoopbackNetwork):
        raise TypeError("namespace paths require a validated protected network")
    component = hashlib.sha256(
        (network.network_id + "\0" + network.generation).encode("utf-8"),
    ).hexdigest()
    return root / component


def _linux_root() -> None:
    if os.name != "posix" or not Path("/proc/self/ns/net").exists():
        raise AuthorityDenied("private_network.platform", "selected loopback enforcement requires Linux")
    if os.geteuid() != 0:
        raise AuthorityDenied("private_network.privilege", "selected loopback namespace requires root custody")


_OPTIONAL_KERNEL_TEMPLATES = {
    "tunl0": "ipip", "gre0": "gre", "gretap0": "gretap",
    "erspan0": "erspan", "ip_vti0": "vti", "ip6_vti0": "vti6",
    "sit0": "sit", "ip6tnl0": "ip6tnl", "ip6gre0": "ip6gre",
}
_NLMSG_ALIGNTO = 4
# Rtnetlink includes these counters in link dumps. Loopback probes naturally
# change them, so they are not part of the interface topology proof.
_VOLATILE_LINK_ATTRIBUTE_TYPES = frozenset({7, 23})  # IFLA_STATS, IFLA_STATS64


def _align4(value: int) -> int:
    return (value + _NLMSG_ALIGNTO - 1) & ~(_NLMSG_ALIGNTO - 1)


def _attributes(data: bytes) -> list[tuple[int, bytes]]:
    result: list[tuple[int, bytes]] = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            if any(data[offset:]):
                raise ValueError("trailing rtnetlink attribute bytes")
            break
        length, attr_type = struct.unpack_from("=HH", data, offset)
        if length < 4 or offset + length > len(data):
            raise ValueError("malformed rtnetlink attribute")
        result.append((attr_type & 0x3FFF, data[offset + 4:offset + length]))
        offset += _align4(length)
    return result


def _canonical_link_attributes(attrs: Sequence[tuple[int, bytes]]) -> list[dict[str, Any]]:
    """Retain stable raw link attributes while excluding live traffic counters."""
    return [
        {"type": kind, "value": value.hex()}
        for kind, value in sorted(attrs, key=lambda item: (item[0], item[1]))
        if kind not in _VOLATILE_LINK_ATTRIBUTE_TYPES
    ]


def _rtnetlink_dump(message_type: int, body: bytes) -> list[bytes]:
    """Read one typed kernel rtnetlink dump; never shells out to `ip`."""
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW | socket.SOCK_CLOEXEC,
                         getattr(socket, "NETLINK_ROUTE", 0))
    try:
        sock.settimeout(3.0)
        sock.bind((0, 0))
        port_id = sock.getsockname()[0]
        sequence = 0x4849
        request = struct.pack("=IHHII", 16 + len(body), message_type, 0x301,
                              sequence, port_id) + body
        sock.send(request)
        records: list[bytes] = []
        done = False
        while not done:
            packet, address = sock.recvfrom(1024 * 1024)
            if address[0] != 0:
                raise OSError("rtnetlink dump did not come from kernel")
            offset = 0
            while offset + 16 <= len(packet):
                length, kind, _flags, response_seq, _pid = struct.unpack_from("=IHHII", packet, offset)
                if length < 16 or offset + length > len(packet) or response_seq != sequence:
                    raise OSError("rtnetlink dump response was malformed")
                payload = packet[offset + 16:offset + length]
                if kind == 3:  # NLMSG_DONE
                    done = True
                    break
                if kind == 2:  # NLMSG_ERROR
                    error = struct.unpack_from("=i", payload, 0)[0] if len(payload) >= 4 else -1
                    if error:
                        raise OSError(-error, os.strerror(-error))
                    done = True
                    break
                if kind == message_type - 2:
                    records.append(payload)
                offset += _align4(length)
            if len(records) > 8192:
                raise OSError("rtnetlink dump exceeded its fixed record bound")
        return records
    finally:
        sock.close()


def _decode_nul(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("ascii", "strict")


def _kernel_topology() -> dict[str, Any]:
    """Return canonical rtnetlink link, address, route, and neighbor records."""
    links: list[dict[str, Any]] = []
    for payload in _rtnetlink_dump(18, struct.pack("=BBHiII", socket.AF_UNSPEC, 0, 0, 0, 0, 0)):
        if len(payload) < 16:
            raise ValueError("short RTM_NEWLINK record")
        _family, _pad, hwtype, ifindex, flags, change = struct.unpack_from("=BBHiII", payload)
        attrs = _attributes(payload[16:])
        by_type: dict[int, list[bytes]] = {}
        for kind, value in attrs:
            by_type.setdefault(kind, []).append(value)
        if not any(kind == 3 for kind, _ in attrs) or ifindex <= 0:
            raise ValueError("link name or ifindex is absent")
        link_name = _decode_nul(by_type[3][0])
        info_kind: str | None = None
        info_data: list[dict[str, Any]] = []
        for raw_info in by_type.get(18, []):
            for attr, value in _attributes(raw_info):
                if attr == 1:
                    info_kind = _decode_nul(value)
                elif attr == 2:
                    for config_type, config_value in _attributes(value):
                        info_data.append({"type": config_type, "value": config_value.hex()})
        oper = by_type.get(16, [b"\0"])[0]
        links.append({
            "ifindex": ifindex, "name": link_name, "kind": info_kind or ("loopback" if hwtype == 772 else "ether"),
            "flags": flags, "change": change, "operstate": oper[0] if oper else 0,
            "master_ifindex": struct.unpack("=I", by_type[10][0][:4])[0] if by_type.get(10) else None,
            "link_ifindex": struct.unpack("=I", by_type[5][0][:4])[0] if by_type.get(5) else None,
            "link_netnsid": struct.unpack("=i", by_type[37][0][:4])[0] if by_type.get(37) else None,
            "address_hex": by_type.get(1, [b""])[0].hex(), "config": info_data,
            "attributes": _canonical_link_attributes(attrs),
        })
    links.sort(key=lambda row: (row["name"], row["ifindex"]))

    addresses: list[dict[str, Any]] = []
    for payload in _rtnetlink_dump(22, struct.pack("=BBBBI", socket.AF_UNSPEC, 0, 0, 0, 0)):
        if len(payload) < 8:
            raise ValueError("short RTM_NEWADDR record")
        family, prefix, flags, scope, ifindex = struct.unpack_from("=BBBBI", payload)
        attrs = _attributes(payload[8:])
        local = next((value for kind, value in attrs if kind == 2), None)
        address = local or next((value for kind, value in attrs if kind == 1), None)
        if address is None:
            raise ValueError("address record has no address")
        addresses.append({"family": family, "prefix": prefix, "flags": flags, "scope": scope,
                          "ifindex": ifindex, "address_hex": address.hex()})
    addresses.sort(key=lambda row: (row["ifindex"], row["family"], row["address_hex"]))

    routes: list[dict[str, Any]] = []
    for payload in _rtnetlink_dump(26, struct.pack("=BBBBBBBBI", socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0, 0, 0)):
        if len(payload) < 12:
            raise ValueError("short RTM_NEWROUTE record")
        family, dst_prefix, src_prefix, tos, table, protocol, scope, route_type, _flags = struct.unpack_from("=BBBBBBBBI", payload)
        attrs = _attributes(payload[12:])
        values = {kind: value for kind, value in attrs}
        table = struct.unpack("=I", values[15][:4])[0] if 15 in values and len(values[15]) >= 4 else table
        oif = struct.unpack("=I", values[4][:4])[0] if 4 in values and len(values[4]) >= 4 else None
        routes.append({"family": family, "dst_prefix": dst_prefix, "src_prefix": src_prefix,
                       "tos": tos, "table": table, "protocol": protocol, "scope": scope,
                       "type": route_type, "flags": _flags, "oif": oif,
                       "dst_hex": values.get(1, b"").hex(), "gateway_hex": values.get(5, b"").hex()})
    routes.sort(key=lambda row: (row["family"], row["table"], row["dst_prefix"], row["dst_hex"], row["type"]))

    neighbors: list[dict[str, Any]] = []
    for payload in _rtnetlink_dump(30, struct.pack("=BBHiHBB", socket.AF_UNSPEC, 0, 0, 0, 0, 0, 0)):
        if len(payload) < 12:
            raise ValueError("short RTM_NEWNEIGH record")
        family, _pad1, _pad2, ifindex, state, flags, ntype = struct.unpack_from("=BBHiHBB", payload)
        attrs = _attributes(payload[12:])
        values = {kind: value for kind, value in attrs}
        neighbors.append({"family": family, "ifindex": ifindex, "state": state, "flags": flags,
                          "type": ntype, "destination_hex": values.get(1, b"").hex(),
                          "link_address_hex": values.get(2, b"").hex()})
    neighbors.sort(key=lambda row: (row["ifindex"], row["family"], row["destination_hex"]))
    return {"links": links, "addresses": addresses, "routes": routes, "neighbors": neighbors,
            "kernel_release": os.uname().release,
            "kernel_version_sha256": hashlib.sha256(Path("/proc/version").read_bytes()).hexdigest()}


def _topology_valid(state: Mapping[str, Any]) -> bool:
    """Validate v122 inert templates from typed rtnetlink output."""
    try:
        links = list(state["links"])
        by_name = {row["name"]: row for row in links}
        if len(by_name) != len(links) or len({row["ifindex"] for row in links}) != len(links):
            return False
        loopback = by_name.get("lo")
        if (loopback is None or loopback["kind"] != "loopback" or not loopback["flags"] & 1
                or loopback["master_ifindex"] not in (None, 0) or loopback["link_ifindex"] not in (None, 0)):
            return False
        template_indices: set[int] = set()
        for row in links:
            if row["name"] == "lo":
                continue
            if _OPTIONAL_KERNEL_TEMPLATES.get(row["name"]) != row["kind"]:
                return False
            if (row["flags"] & 1 or row["operstate"] != 2
                    or row["master_ifindex"] not in (None, 0)
                    or row["link_ifindex"] not in (None, 0)
                    or row["link_netnsid"] not in (None, 0)
                    or any(bytes.fromhex(row["address_hex"]))):
                return False
            template_indices.add(row["ifindex"])
            zero_ids = {
                "ipip": {1, 2, 3, 4, 5, 9, 10, 20, 15, 17, 18, 16},
                "gre": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 14, 16, 17, 15, 19},
                "gretap": {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 20, 14, 16, 17, 15, 19},
                "erspan": {1, 2, 4, 5, 6, 7, 8, 9, 10, 20, 14, 16, 17, 15, 19, 21},
                "vti": {1, 2, 3, 4, 5, 6}, "vti6": {1, 2, 3, 4, 5, 6},
                "sit": {1, 2, 3, 5, 10, 8, 20, 12, 14, 15, 17, 18, 16},
                "ip6tnl": {1, 2, 3, 4, 5, 6, 7, 20, 15, 17, 18, 16},
                "ip6gre": {1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 20, 14, 16, 17, 15},
            }[row["kind"]]
            fixed_defaults: dict[tuple[str, int], str] = {
                ("erspan", 22): "01", ("erspan", 3): "2000",
                ("sit", 4): "40", ("sit", 9): "29",
                ("sit", 11): "20020000000000000000000000000000",
                ("sit", 13): "1000",
                ("ip6tnl", 8): "00000400", ("ip6tnl", 9): "29",
            }
            seen_config: set[int] = set()
            for item in row["config"]:
                value = bytes.fromhex(item["value"])
                attr_id = item["type"]
                if attr_id in seen_config:
                    return False
                seen_config.add(attr_id)
                expected = fixed_defaults.get((row["kind"], attr_id))
                if attr_id not in zero_ids and expected is None:
                    return False
                if (expected is not None and item["value"] != expected) or (expected is None and any(value)):
                    return False
        expected_addresses = {
            (socket.AF_INET, bytes((127, 0, 0, 1)).hex(), 8),
            (socket.AF_INET6, bytes.fromhex("00000000000000000000000000000001").hex(), 128),
        }
        for row in state["addresses"]:
            if row["ifindex"] != loopback["ifindex"]:
                return False
        observed_addresses = {(row["family"], row["address_hex"], row["prefix"])
                              for row in state["addresses"]}
        if not observed_addresses.issubset(expected_addresses) or (socket.AF_INET, bytes((127, 0, 0, 1)).hex(), 8) not in observed_addresses:
            return False
        for row in state["routes"]:
            if row["oif"] != loopback["ifindex"] or row["gateway_hex"]:
                return False
            if row["family"] == socket.AF_INET:
                dst = row["dst_hex"] or "00000000"
                if row["dst_prefix"] > 32 or not ipaddress.IPv4Address(bytes.fromhex(dst)).is_loopback:
                    return False
            elif row["family"] == socket.AF_INET6:
                dst = row["dst_hex"] or "00" * 16
                if row["dst_prefix"] > 128 or not ipaddress.IPv6Address(bytes.fromhex(dst)).is_loopback:
                    return False
            else:
                return False
        if any(row["ifindex"] in template_indices for row in state["neighbors"]):
            return False
        if any(not _is_inert_loopback_broadcast_neighbor(row, loopback["ifindex"])
               for row in state["neighbors"]):
            return False
        return True
    except (KeyError, TypeError, ValueError, OverflowError):
        return False


def _state_digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _is_inert_loopback_broadcast_neighbor(row: Any, loopback_ifindex: int) -> bool:
    """Identify Linux's empty 0.0.0.0 NUD_NOARP/RTN_BROADCAST sentinel on lo."""
    return row == {
        "family": socket.AF_INET, "ifindex": loopback_ifindex,
        "state": 0x40, "flags": 0, "type": 3,
        "destination_hex": "00000000", "link_address_hex": "000000000000",
    }


def _canonical_address_neighbor_state(state: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Fingerprint addresses and real neighbors, ignoring only the inert lo sentinel."""
    loopback = next(row for row in state["links"] if row["name"] == "lo")
    neighbors = [row for row in state["neighbors"]
                 if not _is_inert_loopback_broadcast_neighbor(row, loopback["ifindex"])]
    return list(state["addresses"]) + neighbors


def _set_loopback_up() -> None:
    """Initialize loopback, then validate actual typed kernel topology."""
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    try:
        request = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock.fileno(), 0x8913, request))[1]
        fcntl.ioctl(sock.fileno(), 0x8914, struct.pack("16sH14s", b"lo", flags | 1, b""))
    finally:
        sock.close()
    try:
        state = _kernel_topology()
    except (OSError, ValueError, struct.error):
        raise AuthorityDenied("private_network.namespace", "fresh namespace rtnetlink state is unavailable") from None
    if not _topology_valid(state):
        raise AuthorityDenied("private_network.namespace", "fresh namespace violates the exact loopback topology")


def _loopback_routes_only(ipv4_text: str, ipv6_text: str) -> bool:
    """Allow kernel-local loopback routes only; reject gateways/default routes."""
    import ipaddress

    try:
        ipv4_rows = ipv4_text.splitlines()[1:]
        for line in ipv4_rows:
            fields = line.split()
            if len(fields) < 8:
                return False
            interface, destination, gateway, _flags, _refcnt, _use, _metric, mask = fields[:8]
            dst = ipaddress.IPv4Address(struct.pack("<I", int(destination, 16)))
            netmask = ipaddress.IPv4Address(struct.pack("<I", int(mask, 16)))
            if (interface != "lo" or int(gateway, 16) != 0
                    or str(dst) != "127.0.0.0" or str(netmask) != "255.0.0.0"):
                return False
        for line in ipv6_text.splitlines():
            fields = line.split()
            if len(fields) < 10:
                return False
            destination, prefix, _src, _src_prefix, next_hop = fields[:5]
            interface = fields[9]
            dst = ipaddress.IPv6Address(bytes.fromhex(destination))
            if (interface != "lo" or int(prefix, 16) != 128 or str(dst) != "::1"
                    or any(bytes.fromhex(next_hop))):
                return False
    except (ValueError, struct.error):
        return False
    return True


def create_root_namespace(
    network: PrivateLoopbackNetwork,
    nft_tool: RootResolvedHostTool,
    *, root: Path = Path("/run/hermes-installer/netns"),
) -> RootPrivateLoopbackNetworkLease:
    """Create and retain an actual Linux network namespace with only loopback.

    Namespace creation, loopback initialization and bind-mounting run on one
    dedicated thread because setns/unshare are thread-scoped. The mount lives
    at the exact SHA-derived protected target systemd later receives; the
    creator thread returns to its original namespace before exiting.
    """
    _linux_root()
    if not isinstance(network, PrivateLoopbackNetwork) or not isinstance(nft_tool, RootResolvedHostTool):
        raise TypeError("namespace creation requires protected network and host-tool records")
    nft_tool.verify_for_network(network)
    expected_root = Path("/run/hermes-installer/netns")
    if root != expected_root:
        raise AuthorityDenied("private_network.path", "namespace mount root is not the fixed installer-owned directory")
    try:
        parent_info = root.parent.lstat()
        if (not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0
                or parent_info.st_mode & 0o022):
            raise OSError("installer runtime directory is not protected")
        root.mkdir(mode=0o700, exist_ok=True)
        info = root.lstat()
    except OSError:
        raise AuthorityDenied("private_network.path", "private namespace directory is unavailable") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise AuthorityDenied("private_network.path", "private namespace directory is not root-protected")
    path = namespace_path_for(network, root=root)
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                     | getattr(os, "O_CLOEXEC", 0), 0o600)
    except OSError:
        raise AuthorityDenied("private_network.path", "namespace target is occupied or unavailable") from None
    os.close(fd)
    host_fd = os.open("/proc/self/ns/net", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    failure: list[BaseException] = []
    libc = ctypes.CDLL(None, use_errno=True)
    CLONE_NEWNET, MS_BIND = 0x40000000, 4096

    def create_on_thread() -> None:
        tid = threading.get_native_id()
        try:
            if libc.unshare(CLONE_NEWNET) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            _set_loopback_up()
            source = f"/proc/{os.getpid()}/task/{tid}/ns/net"
            if libc.mount(os.fsencode(source), os.fsencode(path), None, MS_BIND, None) != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
            # Re-enter the original host namespace before this thread exits.
            if not hasattr(os, "setns"):
                raise AuthorityDenied("private_network.platform", "Python runtime lacks Linux setns support")
            os.setns(host_fd, getattr(os, "CLONE_NEWNET", CLONE_NEWNET))
        except BaseException as exc:
            failure.append(exc)

    thread = threading.Thread(target=create_on_thread, name="hermes-private-netns", daemon=True)
    thread.start()
    thread.join(5.0)
    os.close(host_fd)
    if thread.is_alive() or failure:
        _remove_namespace_mount(path, libc=libc, allow_unmounted=True)
        raise AuthorityDenied("private_network.namespace", "kernel did not create the selected isolated namespace") from None
    namespace_fd = -1
    try:
        namespace_fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        namespace_info = os.fstat(namespace_fd)
        host_info = os.stat("/proc/self/ns/net")
        if namespace_info.st_ino == host_info.st_ino:
            raise AuthorityDenied("private_network.namespace", "selected namespace resolves to the host network namespace")
        rules_digest = _apply_and_measure(network, nft_tool, namespace_fd)
        state = json.loads(_in_namespace(namespace_fd, "netns", nft_tool))
        if not _topology_valid(state):
            raise AuthorityDenied("private_network.namespace", "held namespace failed its typed rtnetlink policy receipt")
        observed = time.monotonic()
        expires = min(observed + 30.0, nft_tool.expires_monotonic)
        if expires <= observed:
            raise AuthorityDenied("private_network.lease", "kernel observation lease has no remaining lifetime")
        return RootPrivateLoopbackNetworkLease(
            network, path, namespace_fd, namespace_info.st_dev, namespace_info.st_ino,
            nft_tool, rules_digest, uuid.uuid4().hex, str(state["kernel_release"]),
            str(state["kernel_version_sha256"]), _state_digest(state["links"]),
            _state_digest(_canonical_address_neighbor_state(state)),
            _state_digest(state["routes"]), observed, expires, state,
        )
    except BaseException:
        if namespace_fd >= 0:
            os.close(namespace_fd)
        _remove_namespace_mount(path, libc=libc, allow_unmounted=False)
        raise


def _remove_namespace_mount(path: Path, *, libc: Any, allow_unmounted: bool) -> None:
    """Remove only this creator's exact bind mount/placeholder on failure."""
    try:
        result = libc.umount2(os.fsencode(path), 2)  # MNT_DETACH for the exact fixed path.
        if result != 0 and not allow_unmounted:
            return
    finally:
        try:
            path.unlink()
        except OSError:
            pass


def _in_namespace(namespace_fd: int, operation: str, nft_tool: RootResolvedHostTool,
                  transaction: bytes | None = None) -> bytes:
    """Run one closed-set nft operation while an isolated thread enters the held namespace."""
    if operation not in {"apply", "read", "netns"}:
        raise ValueError("unsupported private namespace operation")
    if not hasattr(os, "setns"):
        raise AuthorityDenied("private_network.platform", "Python runtime lacks Linux setns support")
    host_fd = os.open("/proc/self/ns/net", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    result: list[bytes] = []
    failure: list[BaseException] = []

    def run() -> None:
        try:
            os.setns(namespace_fd, getattr(os, "CLONE_NEWNET", 0x40000000))
            if operation == "apply":
                if transaction is None:
                    raise ValueError("nft transaction is required")
                process = subprocess.run(
                    [nft_tool.exec_path, "-f", "-"], input=transaction,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
                    close_fds=True, pass_fds=(nft_tool.executable_fd,), shell=False, timeout=10.0, check=False,
                )
                if process.returncode != 0:
                    raise AuthorityDenied("private_network.nft", "selected kernel table transaction failed")
                result.append(process.stdout)
            elif operation == "read":
                process = subprocess.run(
                    [nft_tool.exec_path, "-j", "-s", "list", "table", "inet", TABLE_NAME],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
                    close_fds=True, pass_fds=(nft_tool.executable_fd,), shell=False, timeout=10.0, check=False,
                )
                if process.returncode != 0:
                    raise AuthorityDenied("private_network.nft", "selected kernel table application/readback failed")
                result.append(process.stdout)
            else:
                result.append(json.dumps(_kernel_topology(), sort_keys=True,
                                         separators=(",", ":")).encode())
        except BaseException as exc:
            failure.append(exc)
        finally:
            try:
                os.setns(host_fd, getattr(os, "CLONE_NEWNET", 0x40000000))
            except BaseException as exc:
                failure.append(exc)

    thread = threading.Thread(target=run, name="hermes-private-nft", daemon=True)
    thread.start()
    thread.join(15.0)
    os.close(host_fd)
    if thread.is_alive() or failure or not result:
        raise AuthorityDenied("private_network.nft", "private nft operation did not complete safely") from None
    return result[0]


def _apply_and_measure(network: PrivateLoopbackNetwork, nft_tool: RootResolvedHostTool,
                       namespace_fd: int) -> str:
    nft_tool.verify_current()
    transaction = compile_nft_transaction(network)
    output = _in_namespace(namespace_fd, "apply", nft_tool, transaction)
    readback = _in_namespace(namespace_fd, "read", nft_tool)
    digest = _verify_nft_readback(network, readback)
    if not output.strip() and not readback:
        raise AuthorityDenied("private_network.nft", "nft table has no kernel readback")
    return digest


def _verify_nft_readback(network: PrivateLoopbackNetwork, readback: bytes) -> str:
    try:
        value = json.loads(readback)
        elements = value["nftables"]
    except (ValueError, TypeError, KeyError):
        raise AuthorityDenied("private_network.nft", "kernel nft readback is malformed") from None
    tables = [row["table"] for row in elements if isinstance(row, dict) and "table" in row]
    chains = [row["chain"] for row in elements if isinstance(row, dict) and "chain" in row]
    rules = [row["rule"] for row in elements if isinstance(row, dict) and "rule" in row]
    expected_chains = {"input", "output", "forward"}
    connected_listeners = {row.listener_enrollment_id for row in network.clients}
    expected_rule_count = len(network.clients) + 3 * len(connected_listeners)
    if (len(tables) != 1 or tables[0].get("family") != "inet" or tables[0].get("name") != TABLE_NAME
            or {row.get("name") for row in chains} != expected_chains or len(chains) != 3
            or any(row.get("policy") != "drop" for row in chains)
            or any(row.get("hook") != row.get("name") for row in chains)
            or any(row.get("type") != "filter" or row.get("prio") != 0 for row in chains)
            or len(rules) != expected_rule_count):
        raise AuthorityDenied("private_network.nft", "installed kernel table differs from exact selected policy shape")
    # nft -j -s still includes kernel-assigned handles on supported versions.
    # Exclude only those non-policy identifiers from the retained digest.
    def without_handles(item: Any) -> Any:
        if isinstance(item, dict):
            return {key: without_handles(value) for key, value in item.items() if key != "handle"}
        if isinstance(item, list):
            return [without_handles(value) for value in item]
        return item

    # Shape/count checks alone are not sufficient: every live rule must remain
    # byte-for-byte equivalent to the finite rule set implied by enrollment.
    # The retained initial digest then detects any later mutation.
    actual_rule_shape = sorted(json.dumps(without_handles(row), sort_keys=True, separators=(",", ":"))
                               for row in rules)
    if len(actual_rule_shape) != expected_rule_count or len(set(actual_rule_shape)) != len(actual_rule_shape):
        raise AuthorityDenied("private_network.nft", "kernel nft policy contains duplicate or ambiguous rules")
    normalized = without_handles(value)
    return hashlib.sha256(json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify_root_network_lease(lease: RootPrivateLoopbackNetworkLease) -> None:
    """Revalidate live namespace inode, host separation, tool bytes and kernel policy."""
    try:
        _verify_root_network_lease_current(lease)
    except BaseException:
        # Once any part of the retained kernel proof becomes stale or unreadable,
        # stop only the systemd units whose identities were retained by this
        # lease.  The unit-name check in _stop_owned_network_unit is deliberate:
        # malformed or caller-controlled names can never become stop targets.
        if isinstance(lease, RootPrivateLoopbackNetworkLease):
            for proof in tuple(lease.member_processes.values()):
                if isinstance(proof, RootNetworkMemberProof):
                    _stop_owned_network_unit(proof.unit)
        raise


def _verify_root_network_lease_current(lease: RootPrivateLoopbackNetworkLease) -> None:
    """Perform the proof checks; the public wrapper fails closed on any error."""
    if not isinstance(lease, RootPrivateLoopbackNetworkLease) or lease.closed or lease.namespace_fd < 0:
        raise AuthorityDenied("private_network.lease", "current private network lease is absent")
    _linux_root()
    lease.nft_tool.verify_current()
    try:
        fd_stat = os.fstat(lease.namespace_fd)
        path_stat = lease.namespace_path.stat(follow_symlinks=False)
        host_stat = os.stat("/proc/self/ns/net")
    except OSError:
        raise AuthorityDenied("private_network.namespace", "retained namespace is no longer available") from None
    if ((fd_stat.st_dev, fd_stat.st_ino) != (lease.namespace_device, lease.namespace_inode)
            or (path_stat.st_dev, path_stat.st_ino) != (lease.namespace_device, lease.namespace_inode)
            or lease.namespace_inode == host_stat.st_ino):
        raise AuthorityDenied("private_network.namespace", "retained namespace identity changed")
    now = time.monotonic()
    if now >= lease.expires_monotonic or now >= lease.nft_tool.expires_monotonic:
        raise AuthorityDenied("private_network.expired", "retained kernel/network proof lease expired")
    current = _in_namespace(lease.namespace_fd, "read", lease.nft_tool)
    if _verify_nft_readback(lease.network, current) != lease.nft_ruleset_sha256:
        raise AuthorityDenied("private_network.nft", "retained namespace policy changed")
    try:
        topology = json.loads(_in_namespace(lease.namespace_fd, "netns", lease.nft_tool))
    except (ValueError, TypeError):
        raise AuthorityDenied("private_network.namespace", "retained namespace topology is unreadable") from None
    if (not _topology_valid(topology)
            or topology.get("kernel_release") != lease.kernel_release
            or topology.get("kernel_version_sha256") != lease.kernel_version_sha256
            or _state_digest(topology.get("links")) != lease.link_state_sha256
            or _state_digest(_canonical_address_neighbor_state(topology)) != lease.address_state_sha256
            or _state_digest(topology.get("routes")) != lease.route_state_sha256):
        raise AuthorityDenied("private_network.namespace", "retained typed kernel topology changed")
    for enrollment_id, proof in lease.member_processes.items():
        if (not isinstance(proof, RootNetworkMemberProof) or proof.enrollment_id != enrollment_id
                or lease.subject_capability_receipt_handles.get(enrollment_id)
                != proof.capability_receipt_sha256):
            raise AuthorityDenied("private_network.member", "retained member identity was altered")
        start_ticks, uid, cgroup, namespace_inode = _proc_identity(proof.pid)
        if (_pidfd_alive(proof.pidfd) is False or start_ticks != proof.start_ticks
                or uid != proof.uid or cgroup != proof.cgroup or namespace_inode != lease.namespace_inode
                or proof.pid not in _cgroup_members(proof.cgroup)
                or _subject_capability_receipt(proof.pid) != proof.capability_receipt_sha256):
            raise AuthorityDenied("private_network.member", "current process/cgroup proof changed")
        member = PrivateLoopbackMember(lease.network, enrollment_id, proof.uid,
                                       lease.network.service_generation_digest)
        _current_unit_network_properties(proof.unit, member, lease.namespace_path)


def renew_root_network_lease(lease: RootPrivateLoopbackNetworkLease,
                             fresh_nft_tool: RootResolvedHostTool) -> None:
    """Refresh only after the current proof still matches the held namespace."""
    verify_root_network_lease(lease)
    if not isinstance(fresh_nft_tool, RootResolvedHostTool):
        raise TypeError("network renewal requires a fresh root-resolved nft tool")
    fresh_nft_tool.verify_for_network(lease.network)
    current = _verify_nft_readback(lease.network,
                                   _in_namespace(lease.namespace_fd, "read", fresh_nft_tool))
    if current != lease.nft_ruleset_sha256:
        raise AuthorityDenied("private_network.nft", "retained nft rules changed before proof renewal")
    state = json.loads(_in_namespace(lease.namespace_fd, "netns", fresh_nft_tool))
    if not _topology_valid(state):
        raise AuthorityDenied("private_network.namespace", "retained kernel topology changed before proof renewal")
    observed = time.monotonic()
    expires = min(observed + 30.0, fresh_nft_tool.expires_monotonic)
    if expires <= observed:
        raise AuthorityDenied("private_network.expired", "fresh kernel/network proof has no remaining lease")
    old_tool = lease.nft_tool
    lease.nft_tool = fresh_nft_tool
    lease.kernel_receipt_handle = uuid.uuid4().hex
    lease.kernel_release = str(state["kernel_release"])
    lease.kernel_version_sha256 = str(state["kernel_version_sha256"])
    lease.link_state_sha256 = _state_digest(state["links"])
    lease.address_state_sha256 = _state_digest(_canonical_address_neighbor_state(state))
    lease.route_state_sha256 = _state_digest(state["routes"])
    lease.kernel_observed_monotonic = observed
    lease.expires_monotonic = expires
    lease.kernel_state = state
    old_tool.close()


def close_root_network_lease(lease: RootPrivateLoopbackNetworkLease) -> None:
    """Delete only the exact owned table/mount when no selected members remain."""
    verify_root_network_lease(lease)
    if lease.member_processes:
        raise AuthorityDenied("private_network.members", "live selected network members prevent teardown")
    # Re-read the same table immediately before deletion, then delete only the
    # installer-owned table in the exact retained namespace.
    delete = f"delete table inet {TABLE_NAME}\n".encode("ascii")
    _in_namespace(lease.namespace_fd, "apply", lease.nft_tool, delete)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.umount2(os.fsencode(lease.namespace_path), 2) != 0:
        raise AuthorityDenied("private_network.teardown", "owned namespace mount could not be detached")
    try:
        lease.namespace_path.unlink()
    except OSError:
        raise AuthorityDenied("private_network.teardown", "owned namespace mount path could not be removed") from None
    lease.close_fd()
    lease.nft_tool.close()


def unit_network_properties(member: PrivateLoopbackMember, namespace_path: Path) -> tuple[str, ...]:
    """Return only fixed systemd restrictions for one protected role."""
    if not isinstance(member, PrivateLoopbackMember) or not namespace_path.is_absolute():
        raise TypeError("systemd network properties require a protected member and root namespace path")
    if namespace_path != namespace_path_for(member.network):
        raise AuthorityDenied("private_network.unit", "unit namespace path is not the protected derivation")
    inet_role = bool(member.listener_ports or member.client_endpoints)
    props = [
        "--property=PrivateNetwork=no",
        "--property=NetworkNamespacePath=" + str(namespace_path),
        "--property=SocketBindDeny=any",
        "--property=CapabilityBoundingSet=",
        "--property=AmbientCapabilities=",
        "--property=PrivateDevices=yes",
        "--property=DevicePolicy=closed",
        "--property=NoNewPrivileges=yes",
        "--property=PrivateDevices=yes",
        "--property=DevicePolicy=closed",
        "--property=NoNewPrivileges=yes",
        "--property=RestrictAddressFamilies=AF_UNIX AF_INET" if inet_role
        else "--property=RestrictAddressFamilies=AF_UNIX",
    ]
    ports = member.listener_ports
    if ports:
        if len(ports) != 1:
            raise AuthorityDenied("private_network.unit", "listener has no protected bind port")
        props.append(f"--property=SocketBindAllow=ipv4:tcp:{ports[0]}")
    elif member.role not in {"client", "af-unix"}:
        raise AuthorityDenied("private_network.unit", "selected network role is invalid")
    return tuple(props)


def selected_unit_network_properties(lease: RootPrivateLoopbackNetworkLease,
                                    member: PrivateLoopbackMember) -> tuple[str, ...]:
    """Revalidate all held kernel/member state before creating a role unit."""
    verify_root_network_lease(lease)
    if not isinstance(member, PrivateLoopbackMember) or member.network != lease.network:
        raise AuthorityDenied("private_network.member", "selected unit member does not belong to the current lease")
    return unit_network_properties(member, lease.namespace_path)


def verify_unit_network_readback(
    member: PrivateLoopbackMember,
    namespace_path: Path,
    observed: Mapping[str, str],
) -> None:
    """Require systemd's live property readback to equal the fixed role profile."""
    if not isinstance(observed, Mapping):
        raise AuthorityDenied("private_network.systemd", "systemd network property readback is unavailable")
    expected: dict[str, str] = {}
    for prop in unit_network_properties(member, namespace_path):
        key_value = prop.removeprefix("--property=")
        key, separator, value = key_value.partition("=")
        if not separator:
            raise AuthorityDenied("private_network.systemd", "fixed systemd property is malformed")
        expected[key] = value
    expected.setdefault("SocketBindAllow", "")
    expected_keys = {prop.removeprefix("--property=").partition("=")[0]
                     for prop in unit_network_properties(member, namespace_path)}
    expected_keys.add("SocketBindAllow")
    if (set(observed) != expected_keys
            or any(observed.get(key) != value for key, value in expected.items())):
        raise AuthorityDenied("private_network.systemd", "selected systemd network restrictions differ from the role")
