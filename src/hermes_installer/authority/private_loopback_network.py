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
        if self.observation_registry is not None:
            self.observation_registry.revalidate_current(self.observation_handle, self.selected_network_key)

    def close(self) -> None:
        if self.executable_fd >= 0:
            os.close(self.executable_fd)
            object.__setattr__(self, "executable_fd", -1)

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
    verify_root_network_lease(lease)
    row = lease.network.member(member.enrollment_id)
    if (member.network != lease.network or member.uid != row.uid or member.enrollment_id in lease.member_processes
            or type(pid) is not int or pid <= 1 or type(pidfd) is not int or pidfd < 0
            or not isinstance(unit, str) or not re.fullmatch(r"hermes-installer-[0-9a-f]{32}\.service", unit)
            or not cgroup.endswith("/" + unit)):
        raise AuthorityDenied("private_network.member", "selected process does not match one unoccupied network member")
    try:
        retained_pidfd = os.dup(pidfd)
    except OSError:
        raise AuthorityDenied("private_network.member", "managed member pidfd could not be retained") from None
    try:
        start_ticks, uid, current_cgroup, namespace_inode = _proc_identity(pid)
        processes = _cgroup_members(cgroup)
        if (uid != row.uid or current_cgroup != cgroup or pid not in processes
                or namespace_inode != lease.namespace_inode):
            raise AuthorityDenied("private_network.member", "managed process is outside its enrolled namespace/UID/cgroup")
        proof = RootNetworkMemberProof(
            member.enrollment_id, row.profile_id, row.generation, row.uid, pid,
            retained_pidfd, start_ticks, cgroup, unit,
        )
        lease.member_processes[member.enrollment_id] = proof
        return proof
    except BaseException:
        os.close(retained_pidfd)
        raise


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


def _set_loopback_up() -> None:
    """Initialize the sole interface in the current network namespace."""
    import fcntl

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM | socket.SOCK_CLOEXEC)
    try:
        request = struct.pack("16sH14s", b"lo", 0, b"")
        flags = struct.unpack("16sH14s", fcntl.ioctl(sock.fileno(), 0x8913, request))[1]
        fcntl.ioctl(sock.fileno(), 0x8914, struct.pack("16sH14s", b"lo", flags | 1, b""))
    finally:
        sock.close()
    if socket.if_nameindex() != [(1, "lo")]:
        raise AuthorityDenied("private_network.namespace", "new namespace has an unexpected interface")
    if not _loopback_routes_only(Path("/proc/self/net/route").read_text(),
                                 Path("/proc/self/net/ipv6_route").read_text()):
        raise AuthorityDenied("private_network.namespace", "new namespace unexpectedly has IPv4 routes")


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
    if (nft_tool.observation_registry is not None
            and nft_tool.selected_network_key != (network.network_id, network.generation,
                network.service_generation_digest)):
        raise AuthorityDenied("private_network.tool", "verified nft observation belongs to another selected network")
    nft_tool.verify_current()
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
    try:
        namespace_fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        namespace_info = os.fstat(namespace_fd)
        host_info = os.stat("/proc/self/ns/net")
        if namespace_info.st_ino == host_info.st_ino:
            raise AuthorityDenied("private_network.namespace", "selected namespace resolves to the host network namespace")
        rules_digest = _apply_and_measure(network, nft_tool, namespace_fd)
        return RootPrivateLoopbackNetworkLease(
            network, path, namespace_fd, namespace_info.st_dev, namespace_info.st_ino,
            nft_tool, rules_digest,
        )
    except BaseException:
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
                names = [name for _index, name in socket.if_nameindex()]
                routes = Path("/proc/self/net/route").read_text()
                ipv6_routes = Path("/proc/self/net/ipv6_route").read_text()
                result.append(json.dumps({"interfaces": names, "routes": routes,
                                          "ipv6_routes": ipv6_routes}, sort_keys=True).encode())
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
    current = _in_namespace(lease.namespace_fd, "read", lease.nft_tool)
    if _verify_nft_readback(lease.network, current) != lease.nft_ruleset_sha256:
        raise AuthorityDenied("private_network.nft", "retained namespace policy changed")
    try:
        topology = json.loads(_in_namespace(lease.namespace_fd, "netns", lease.nft_tool))
    except (ValueError, TypeError):
        raise AuthorityDenied("private_network.namespace", "retained namespace topology is unreadable") from None
    if (topology.get("interfaces") != ["lo"]
            or not _loopback_routes_only(topology.get("routes", ""),
                                         topology.get("ipv6_routes", ""))):
        raise AuthorityDenied("private_network.namespace", "retained namespace gained an interface or route")
    for enrollment_id, proof in lease.member_processes.items():
        if not isinstance(proof, RootNetworkMemberProof) or proof.enrollment_id != enrollment_id:
            raise AuthorityDenied("private_network.member", "retained member identity was altered")
        start_ticks, uid, cgroup, namespace_inode = _proc_identity(proof.pid)
        if (_pidfd_alive(proof.pidfd) is False or start_ticks != proof.start_ticks
                or uid != proof.uid or cgroup != proof.cgroup or namespace_inode != lease.namespace_inode
                or proof.pid not in _cgroup_members(proof.cgroup)):
            raise AuthorityDenied("private_network.member", "current process/cgroup proof changed")


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
    if any(observed.get(key) != value for key, value in expected.items()):
        raise AuthorityDenied("private_network.systemd", "selected systemd network restrictions differ from the role")
