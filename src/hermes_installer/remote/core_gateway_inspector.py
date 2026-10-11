"""Read-only root witness for the fixed core-mode Gateway and backend."""
from __future__ import annotations

import asyncio
import hashlib
import json
import math
import os
import re
import secrets
import select
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import threading
import time
import pwd
import selectors
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .jarvis_mission_executor import MissionBinding

# Startup readiness and the native observer both bind to this exact closed
# mission-turn contract; old six-field schema-1 rows are not upgraded by parsing.
MISSION_BINDING_SCHEMA = 2

from .core_gateway import (
    CORE_CONFIG, CORE_GATEWAY_UNIT, CORE_GATEWAY_UNIT_PATH, CORE_HOST, CORE_INGRESS_SOCKET,
    CORE_INSPECTOR_SOCKET, CORE_PORT, CORE_SERVICE_UNIT, GATEWAY_ARGV, GATEWAY_EXECUTABLE,
    CoreGatewayConfig, CoreGatewayDenied,
)

TUNNEL_UNIT = "hermes-jarvis-mvp-tunnel.service"
TUNNEL_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-mvp-tunnel.service")
TUNNEL_EXECUTABLE = Path("/usr/bin/cloudflared")
TUNNEL_ARGV = ("/usr/bin/cloudflared", "--no-autoupdate", "tunnel", "run", "--token-file",
               "/run/credentials/hermes-jarvis-mvp-tunnel.service/tunnel-token")
CORE_UNIT_PATH = Path("/etc/systemd/system/hermes-jarvis-core.service")
CORE_LAUNCHER = Path("/usr/local/libexec/hermes-jarvis-core-launcher")
CORE_PYTHON_LINK = Path("/home/admin/HermesInstaller/data/installs/dbd62d2bc9a23cac/environments/2be4b41371094d1c9745c2cfbd0f3fe0/venv/bin/python")
CORE_PYTHON_REAL = Path("/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3.14")
CORE_PYTHON_LINK_TARGET = "/home/admin/HermesInstaller/data/tools/python-3.14.7+20260901-linux-arm64/bin/python3"
CORE_ARGV_TAIL = ("-P", "-m", "hermes_cli.main", "serve", "--isolated", "--host",
                  CORE_HOST, "--port", str(CORE_PORT))
CORE_TOKEN_SOURCE = Path("/etc/hermes-installer/jarvis-core/session-token")
CORE_ADMIN_HOME = Path("/home/admin")
CORE_HERMES_HOME = CORE_ADMIN_HOME / ".hermes"
CORE_USER_CONFIG = CORE_HERMES_HOME / "config.yaml"
MAX_CORE_USER_CONFIG_BYTES = 512 * 1024
CORE_SOURCE = Path("/home/admin/HermesInstaller/data/generations/hermes-agent-7085fbf77532")
CORE_SOURCE_REVISION = "7085fbf7753266fc4943c55ac04926186bc90005"
CORE_SOURCE_FILES = {
    "pm/lock.json": "49b79259220160f147255078a19af541a5f328d3871c8041cc1eb909d19eb549",
    "uv.lock": "2bc4db483e9cba927cd7147f9ccbb09635f85bb3f1f36d6e9d51d06b65d1c67e",
    "pyproject.toml": "cadde2f6a92574d292103f43abf66408b1d841cd9ea332ca7f3e3dfc5dcc87fd",
    "hermes_cli/web_server.py": "839ee3fa8d9548c9e1875ffe1321e287eda37c3577e607dcd93288621b0403a4",
    "tui_gateway/ws.py": "1cecdb714a0abc1edf8fc0ec2d00edc1dc042f0da37baaefb8ba20ce3edeae63",
}
# This additional source is used only for native tool-configuration observation.
# Keeping it separate preserves the deployed core-source generation receipt.
CORE_NATIVE_TOOL_SOURCE_FILES = {
    "tui_gateway/methods_tools.py": "afedca2ea72e8f8751cf7736283ae8d786305a1b1e309bdf05ea52ec4bd89c11",
}
# The core imports the fixed native observer and Resources handler from the
# active, root-owned installer generation. Keep these pins separate from the
# official Hermes source-generation receipt above.
CORE_NATIVE_ADAPTER_SOURCE = Path(__file__).resolve(strict=True).parents[2]
CORE_NATIVE_ADAPTER_SOURCE_FILES = {
    "hermes_installer/__init__.py": "61ac3dfa3bd8505d5296065d597b9b76c4a42c1f17c706c2d67f4fee2b193242",
    "hermes_installer/remote/__init__.py": "bf7dbd677d6dd4384a02211039002f760821748b33f3f66ee425d9633b5005a4",
    "hermes_installer/remote/core_native_observer.py": "05b78faeb738b6c7f64e9969f59a24e561725b0cfcffa27eb197da65dd768e54",
    "hermes_installer/remote/native_child_adapter.py": "5bf912a83bb011a0af55f0157204dd8a7ea7f00834bf4635de0de530e84ea365",
    "hermes_installer/remote/jarvis_master_planning.py": "88a1192fbf6a55b680a80192ed312428346484054df324270626bd8bb927b239",
    "hermes_installer/remote/native_plugin_bootstrap.py": "e39c230582bb1e99e67986001c5fe2d3c7baa581266786e264ee0da508d1fe66",
    "hermes_installer/remote/jarvis_mission_executor.py": "80c1b89e5dbd93fb54d7ec04cde5818a1ed89a187746d40621cfb040e55beee1",
    "hermes_installer/components/__init__.py": "eb02d685a1fb560210c2915296f7553e279e100b511d6b63892d3e877ccd7e7b",
    "hermes_installer/components/resources_internal_dispatch.py": "2c6cbda366df596fc1160f7fd6607e48fdee8ad29840f3d6bb9cd6858c2a668b",
    "hermes_installer/components/resources_active_profile_source.py": "408ac8e98609b5beab00b048ec28f5e3c6c7e01868295148e334c68542d077dc",
    "hermes_installer/components/resources_native_plugin_bundle/plugin.yaml": "d0b3b422c29190826eea55d6f96bb81593956210a36c600541085612a06f27be",
    "hermes_installer/components/resources_native_plugin_bundle/__init__.py": "a3afaa7c211ddd9d2e6c7c939af5f2e64a2355bf6cd8f57909dbe29d68849e77",
    "hermes_installer/native_invocations.py": "16878d0b5416a763743ca9fa8b1714db93e5c9b063d3f71880ca429ebf16dc63",
    "hermes_installer/remote/jarvis_final_effects.py": "fdfadff944797345c9f6bf6fc91b42ed05f0d2ad99ae383f86dd6553e3fc4583",
}
CORE_NATIVE_PLUGIN_STAGED_FILES = {
    "plugin.yaml": "d0b3b422c29190826eea55d6f96bb81593956210a36c600541085612a06f27be",
    "__init__.py": "a3afaa7c211ddd9d2e6c7c939af5f2e64a2355bf6cd8f57909dbe29d68849e77",
}
CORE_NATIVE_PLUGIN_ID = "hermes-installer-resources-delegation"
CORE_PYVENV_CFG_SHA256 = "d982d4b71a70c99f49afef3c0b2cf683c2f053a802da8885d366657b9565f1ad"
CORE_PYTHON_SHA256 = "566f5e480aa1adccd3214f6251f50cab08daf768158d778fd9a73d19ab1fe001"
CORE_WORKSPACE = Path("/home/admin/.hermes/workspaces/jarvis-core")
CORE_NATIVE_OBSERVER_DIRECTORY = Path("/run/hermes-jarvis-native-observer")
CORE_NATIVE_OBSERVER_SOCKET = CORE_NATIVE_OBSERVER_DIRECTORY / "native-observer.sock"
CORE_PATH = "/home/admin/.hermes/bin:/home/admin/.local/bin:/usr/local/bin:/usr/bin:/bin"
CORE_CREDENTIALS_DIRECTORY = "/run/credentials/hermes-jarvis-core.service"
MAX_REQUEST = 1024
MAX_RESPONSE = 4096
MAX_FINAL_EFFECT_RESPONSE = 64 * 1024
MAX_MASTER_PLAN_RESPONSE = 32 * 1024
MAX_NATIVE_ACTIVITY_RESPONSE = 128 * 1024
MAX_SKILL_LEARNING_REQUEST_BYTES = 20 * 1024
MAX_SKILL_LEARNING_RESPONSE_BYTES = 700 * 1024
MAX_OWNER_TURN_REQUEST_BYTES = 24 * 1024
MAX_SKILL_LEARNING_DIFF_BYTES = 256 * 1024
MAX_OWNER_TURN_SECONDS = 600.0
NATIVE_SKILL_LEARNING_SHA256 = "83c3c9fe8147612ab9e4f31d2c4951015626170091042a782fee0f001de8005b"
NATIVE_SKILL_LEARNING_SIZE = 24_429
MAX_OUTPUT = 16_384
MAX_HASH_FILE_BYTES = 512 * 1024 * 1024
MAX_PROOF_SECONDS = 5.0
IPC_TIMEOUT = 2.0
_PROOF_SEAL = object()
_OVERVIEW_PROOF_SEAL = object()
_SKILL_LEARNING_PROOF_SEAL = object()
_NATIVE_CUSTODY_SEAL = object()
_OWNER_TURN_SEAL = object()
_NATIVE_TOOL_CONFIGURATION_SEAL = object()
_RESOURCES_DELEGATE_NAME = "resources_delegate"
_RESOURCES_DELEGATE_TOOLSET = "resources_internal"
_RESOURCES_DELEGATE_SCHEMA_SHA256 = "9325cea421e122395475b0ba0d0517cb4aa4c16c3d4a14c5145f9fcc3f957f33"
_RESOURCES_DISPATCH_SOURCE_SHA256 = "050afe835279e022ba3e4ec479f597692f5bdc88f7488eb630863d08a6b8cf9c"
_SERVER_SLOTS = threading.BoundedSemaphore(16)
_MAX_RETAINED_INGRESS_ISSUES = 128
_RETAINED_INGRESS_ISSUES: dict[tuple[int, str, str, str], "_RetainedIngressIssue"] = {}
_RETAINED_INGRESS_LOCK = threading.RLock()
_LEARNING_JWKS_CACHE: Any = None
_LEARNING_JWKS_LOCK = threading.Lock()
_CORE_NATIVE_CUSTODY: Any = None
_CORE_NATIVE_REGISTRY: Any = None
_CORE_NATIVE_REGISTRY_TYPE: Any = None
_CORE_NATIVE_STOP: threading.Event | None = None
_CORE_NATIVE_THREAD: threading.Thread | None = None
_CORE_NATIVE_INIT_STOP: threading.Event | None = None
_CORE_NATIVE_INIT_THREAD: threading.Thread | None = None
_OBSERVATION_FIELDS = (
    "schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
    "peer_pid", "peer_uid", "peer_gid", "peer_start_ticks", "tunnel_invocation_id",
    "tunnel_unit_sha256", "tunnel_executable_sha256", "origin_socket_device",
    "origin_socket_inode", "gateway_unit_sha256", "core_unit_sha256",
    "core_invocation_id", "core_pid", "core_start_ticks", "core_listener_inode",
    "core_source_generation",
    "core_generation", "config_sha256",
)
_OWNER_TURN_FIELDS = (
    "schema", "owner_turn_handle", "owner_subject_sha256", "token_fingerprint_sha256",
    "jwt_expires_monotonic", "ingress_issued_monotonic", "ingress_expires_monotonic",
    "accepted_monotonic", "expires_monotonic", "ingress_nonce", "ingress_proof_sha256",
    "peer_gateway_pid", "peer_gateway_uid", "peer_gateway_gid", "peer_gateway_start_ticks",
    "gateway_invocation_id", "tunnel_invocation_id", "core_generation", "core_pid",
    "core_uid", "core_gid", "core_start_ticks", "core_invocation_id", "core_listener_inode",
    "core_source_generation", "core_unit_sha256", "core_executable_sha256",
    "session_id", "conversation_id", "gateway_turn_id", "prompt_sha256", "mission_binding",
    "planning_context",
)


@dataclass(frozen=True, slots=True)
class PlanningContext:
    """Closed server-provided correlation for a same-owner-turn Jarvis plan.

    This DTO carries no authority by itself. The root inspector reconstructs the
    mission, catalog and current-master values from its own fixed stores both when
    it is prepared and when the owner turn is registered.
    """

    schema: int
    mission_id: str
    revision: int
    goal_sha256: str
    catalog_sha256: str
    planner_prompt_sha256: str
    master_source_generation_sha256: str
    master_source_manifest_sha256: str
    master_prompt_sha256: str
    source_profile_id: str = "hermes"

    def to_wire(self) -> dict[str, Any]:
        return {
            "schema": self.schema, "mission_id": self.mission_id,
            "revision": self.revision, "goal_sha256": self.goal_sha256,
            "catalog_sha256": self.catalog_sha256,
            "planner_prompt_sha256": self.planner_prompt_sha256,
            "master_source_generation_sha256": self.master_source_generation_sha256,
            "master_source_manifest_sha256": self.master_source_manifest_sha256,
            "master_prompt_sha256": self.master_prompt_sha256,
            "source_profile_id": self.source_profile_id,
        }

    @classmethod
    def from_wire(cls, value: Any) -> "PlanningContext":
        fields = {"schema", "mission_id", "revision", "goal_sha256", "catalog_sha256",
                  "planner_prompt_sha256", "master_source_generation_sha256",
                  "master_source_manifest_sha256", "master_prompt_sha256", "source_profile_id"}
        if type(value) is not dict or set(value) != fields:
            raise CoreInspectionDenied("planning context fields differ")
        try:
            result = cls(**value)
        except Exception:
            raise CoreInspectionDenied("planning context is malformed") from None
        if (type(result.schema) is not int or result.schema != 1
                or not isinstance(result.mission_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", result.mission_id) is None
                or type(result.revision) is not int or result.revision < 1
                or any(not _is_hash(getattr(result, name)) for name in (
                    "goal_sha256", "catalog_sha256", "planner_prompt_sha256",
                    "master_source_generation_sha256", "master_source_manifest_sha256",
                    "master_prompt_sha256"))
                or result.source_profile_id != "hermes"):
            raise CoreInspectionDenied("planning context is malformed")
        return result


_MASTER_PLAN_DATA_SEAL = object()


@dataclass(frozen=True, slots=True)
class RootVerifiedJarvisMasterPlanData:
    """Current root-readback of durable plan DATA, never itself a dispatch permit."""

    schema: int
    mission_id: str
    revision: int
    owner_subject_sha256: str
    goal_sha256: str
    plan_json: str
    plan_sha256: str
    response_sha256: str
    gateway_turn_id: str
    owner_turn_handle: str
    core_generation: str
    core_source_generation: str
    catalog_sha256: str
    planner_prompt_sha256: str
    master_source_generation_sha256: str
    master_source_manifest_sha256: str
    master_prompt_sha256: str
    source_profile_id: str
    selected_source_ids: tuple[str, ...]
    execution_mode: str
    _seal: object = field(repr=False, compare=False)

    def is_root_verified_data(self) -> bool:
        try:
            if (type(self) is not RootVerifiedJarvisMasterPlanData
                    or self._seal is not _MASTER_PLAN_DATA_SEAL
                    or type(self.schema) is not int or self.schema != 1
                    or type(self.revision) is not int or self.revision < 1):
                return False
            plan = json.loads(self.plan_json, object_pairs_hook=_unique_pairs)
            return bool(re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.mission_id)
                and all(_is_hash(getattr(self, name)) for name in (
                    "owner_subject_sha256", "goal_sha256", "plan_sha256", "response_sha256",
                    "core_generation", "core_source_generation", "catalog_sha256",
                    "planner_prompt_sha256", "master_source_generation_sha256",
                    "master_source_manifest_sha256", "master_prompt_sha256"))
                and isinstance(self.plan_json, str) and 2 <= len(self.plan_json.encode("utf-8")) <= 16_384
                and isinstance(self.gateway_turn_id, str)
                and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", self.gateway_turn_id)
                and isinstance(self.owner_turn_handle, str)
                and re.fullmatch(r"[0-9a-f]{32}", self.owner_turn_handle)
                and self.execution_mode in {"oneshot", "kanban"}
                and self.source_profile_id == "hermes"
                and isinstance(self.selected_source_ids, tuple)
                and len(self.selected_source_ids) <= 16
                and len(set(self.selected_source_ids)) == len(self.selected_source_ids)
                and hashlib.sha256(_canonical_json({"execution_mode": self.execution_mode,
                    "selected_source_ids": list(self.selected_source_ids), "plan": plan})).hexdigest()
                    == self.plan_sha256)
        except Exception:
            return False

    def to_wire(self) -> dict[str, Any]:
        if not self.is_root_verified_data():
            raise CoreGatewayDenied("root plan data is unavailable")
        return {name: getattr(self, name) for name in (
            "schema", "mission_id", "revision", "owner_subject_sha256", "goal_sha256",
            "plan_json", "plan_sha256", "response_sha256", "gateway_turn_id",
            "owner_turn_handle", "core_generation", "core_source_generation",
            "catalog_sha256", "planner_prompt_sha256", "master_source_generation_sha256",
            "master_source_manifest_sha256", "master_prompt_sha256", "source_profile_id",
            "execution_mode")} | {"selected_source_ids": list(self.selected_source_ids)}


def _planning_context_wire(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if type(value) is not PlanningContext:
        raise CoreInspectionDenied("planning context is not a typed value")
    return PlanningContext.from_wire(value.to_wire()).to_wire()
class CoreInspectionDenied(PermissionError):
    pass


def _observation_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-ingress-v1\0" + canonical).hexdigest()


@dataclass(frozen=True, slots=True)
class _RetainedIngressIssue:
    """One-use root memory of an actual ingress proof issuance."""

    caller_pid: int
    caller_start_ticks: str
    nonce: str
    proof_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    peer: tuple[int, int, int]
    socket_identity: tuple[int, int]
    core_generation: str
    config_sha256: str
    boot_id: str


def _retain_ingress_issue(*, caller_pid: int, caller_start_ticks: str,
                          proof: dict[str, Any]) -> None:
    now = time.monotonic()
    key = (caller_pid, caller_start_ticks, proof["nonce"], proof["proof_sha256"])
    retained = _RetainedIngressIssue(
        caller_pid, caller_start_ticks, proof["nonce"], proof["proof_sha256"],
        proof["issued_monotonic"], proof["expires_monotonic"],
        (proof["peer_pid"], proof["peer_uid"], proof["peer_gid"]),
        (proof["origin_socket_device"], proof["origin_socket_inode"]),
        proof["core_generation"], proof["config_sha256"], proof["boot_id"],
    )
    with _RETAINED_INGRESS_LOCK:
        for old_key, old in tuple(_RETAINED_INGRESS_ISSUES.items()):
            if old.expires_monotonic <= now:
                _RETAINED_INGRESS_ISSUES.pop(old_key, None)
        if len(_RETAINED_INGRESS_ISSUES) >= _MAX_RETAINED_INGRESS_ISSUES:
            raise CoreInspectionDenied("one-use ingress proof capacity is full")
        if key in _RETAINED_INGRESS_ISSUES:
            raise CoreInspectionDenied("one-use ingress proof was already retained")
        _RETAINED_INGRESS_ISSUES[key] = retained


def _consume_ingress_issue(*, caller_pid: int, caller_start_ticks: str,
                           nonce: str, proof_sha256: str,
                           peer: tuple[int, int, int], core_generation: str,
                           config: CoreGatewayConfig) -> _RetainedIngressIssue:
    now = time.monotonic()
    key = (caller_pid, caller_start_ticks, nonce, proof_sha256)
    with _RETAINED_INGRESS_LOCK:
        for old_key, old in tuple(_RETAINED_INGRESS_ISSUES.items()):
            if old.expires_monotonic <= now:
                _RETAINED_INGRESS_ISSUES.pop(old_key, None)
        retained = _RETAINED_INGRESS_ISSUES.pop(key, None)
    if (retained is None or retained.caller_pid != caller_pid
            or retained.caller_start_ticks != caller_start_ticks
            or retained.peer != peer or retained.core_generation != core_generation
            or retained.config_sha256 != config.config_sha256
            or retained.boot_id != config.boot_id
            or retained.issued_monotonic >= now
            or not retained.issued_monotonic < retained.expires_monotonic <=
                retained.issued_monotonic + MAX_PROOF_SECONDS
            or now >= retained.expires_monotonic):
        raise CoreInspectionDenied("original ingress proof is unavailable or expired")
    return retained


def _learning_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False, ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(b"hermes-jarvis-skill-learning-v1\0" + canonical).hexdigest()


def _owner_turn_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("utf-8")
    return hashlib.sha256(b"hermes-jarvis-owner-turn-v1\0" + canonical).hexdigest()


def _mission_binding_wire(value: Any) -> dict[str, Any] | None:
    """Return only the exact mission DTO shape; arbitrary request mappings are never authority."""
    if value is None:
        return None
    try:
        from .jarvis_mission_executor import MissionBinding
        if type(value) is not MissionBinding:
            raise ValueError
        wire = value.to_wire()
        fields = {"schema", "mission_id", "revision", "plan_sha256", "task_sha256",
                  "source_profile_id", "execution_mode", "autonomy_mode", "selected_source_ids",
                  "scope_sha256", "authorization_sha256"}
        source_ids = wire.get("selected_source_ids") if type(wire) is dict else None
        if (type(wire) is not dict
                or set(wire) != fields
                or type(wire.get("schema")) is not int or wire["schema"] != MISSION_BINDING_SCHEMA
                or wire.get("source_profile_id") != "hermes"
                or type(wire.get("revision")) is not int or wire["revision"] < 1
                or not isinstance(wire.get("mission_id"), str)
                or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", wire["mission_id"]) is None
                or not _is_hash(wire.get("plan_sha256"))
                or not _is_hash(wire.get("task_sha256"))
                or wire.get("execution_mode") not in {"oneshot", "kanban"}
                or wire.get("autonomy_mode") not in {"approval_required", "fully_autonomous"}
                or not isinstance(source_ids, list) or not 1 <= len(source_ids) <= 12
                or any(not isinstance(item, str)
                       or re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,95}", item) is None for item in source_ids)
                or len(set(source_ids)) != len(source_ids)
                or "orchestrator" not in source_ids
                or not _is_hash(wire.get("scope_sha256"))
                or (wire.get("autonomy_mode") == "approval_required"
                    and wire.get("authorization_sha256") is not None)
                or (wire.get("autonomy_mode") == "fully_autonomous"
                    and not _is_hash(wire.get("authorization_sha256")))):
            raise ValueError
        decoded = MissionBinding.from_wire(wire)
        if type(decoded) is not MissionBinding or decoded != value:
            raise ValueError
        return wire
    except Exception:
        raise CoreInspectionDenied("mission binding is not a verified typed value") from None


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8", errors="strict")


def _read_root_planning_catalog(core_source_generation: str) -> tuple[dict[str, Any], str]:
    """Rebuild the mission catalog from the current Resources CAS and pinned inventory."""
    if not _is_hash(core_source_generation):
        raise CoreInspectionDenied("current Resources generation is unavailable")
    from hermes_installer.components.resources_active_profile_source import _read_catalog
    snapshot = _read_catalog(core_source_generation)
    if snapshot is None or not isinstance(snapshot.get("sources"), dict):
        raise CoreInspectionDenied("current Resources catalog is unavailable")
    inventory_path = CORE_NATIVE_ADAPTER_SOURCE / "hermes_installer/remote/jarvis_capability_inventory.json"
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    expected_digest = "16ba9ef9b5a5a727cbfa29a43f12862e3aca6deb1a57cab52f9d7d9b96610860"
    if _protected_file_sha(inventory_path, deadline=deadline) != expected_digest:
        raise CoreInspectionDenied("pinned Resources source inventory changed")
    fd = os.open(inventory_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or info.st_size > 512 * 1024):
            raise CoreInspectionDenied("pinned Resources inventory custody differs")
        raw = bytearray()
        while len(raw) <= 512 * 1024:
            block = os.read(fd, min(8192, 512 * 1024 + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
        after = os.fstat(fd)
        named = os.stat(inventory_path, follow_symlinks=False)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
            item.st_gid, item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if (signature(info) != signature(after) or signature(info) != signature(named)
                or hashlib.sha256(raw).hexdigest() != expected_digest):
            raise CoreInspectionDenied("pinned Resources inventory changed while reading")
    finally:
        os.close(fd)
    try:
        inventory = json.loads(bytes(raw).decode("utf-8", errors="strict"),
                               object_pairs_hook=_unique_pairs)
    except Exception:
        raise CoreInspectionDenied("pinned Resources inventory is malformed") from None
    if (type(inventory) is not dict or set(inventory) != {"readiness", "source", "items"}
            or inventory.get("readiness") != "pending"
            or inventory.get("source") != {
                "kind": "offline-bundle", "catalogVersion": "2.3.1",
                "revision": "113f42d33be9e0c8f0f47f5ca998e687323dec83"}
            or type(inventory.get("items")) is not list or len(inventory["items"]) != 692):
        raise CoreInspectionDenied("pinned Resources inventory schema differs")
    profile_ids = set(snapshot["sources"])
    profiles: dict[str, str] = {}
    sources: dict[str, dict[str, str]] = {}
    seen: set[tuple[str, str]] = set()
    previous: tuple[str, str] | None = None
    for item in inventory["items"]:
        if (type(item) is not dict
                or set(item) not in ({"id", "kind", "name", "summary", "state", "readiness"},
                    {"id", "kind", "name", "summary", "state", "readiness", "displayName"})
                or item.get("kind") not in {"profiles", "bundles", "skills", "plugins", "mcps", "channels", "crons", "webhooks"}
                or item.get("state") != "bundled" or item.get("readiness") != "pending"
                or not all(isinstance(item.get(key), str) for key in ("id", "name", "summary"))
                or len(item["id"]) > 120 or len(item["name"]) > 120 or len(item["summary"]) > 240
                or ("displayName" in item and (not isinstance(item["displayName"], str)
                                                or len(item["displayName"]) > 120))):
            raise CoreInspectionDenied("pinned Resources inventory item differs")
        identity = (item["kind"], item["id"])
        if identity in seen or (previous is not None and identity <= previous):
            raise CoreInspectionDenied("pinned Resources inventory ordering differs")
        seen.add(identity)
        previous = identity
        if item["kind"] not in {"profiles", "bundles"}:
            continue
        label = item.get("displayName") or item["name"]
        if not isinstance(label, str) or not label or len(label) > 120:
            raise CoreInspectionDenied("pinned Resources label is invalid")
        # Match the exact, bounded projection used by jarvis_missions._verified_team_catalog.
        label = " ".join("".join(ch for ch in label if ch >= " " and ch != "\x7f").split())[:120]
        if not label:
            raise CoreInspectionDenied("pinned Resources label is empty")
        sources[item["id"]] = {"label": label, "kind": item["kind"]}
        if item["kind"] == "profiles":
            profiles[item["id"]] = label
    if set(profiles) != profile_ids:
        raise CoreInspectionDenied("pinned profile catalog differs from the Resources CAS")
    catalog = {
        "profiles": dict(sorted(profiles.items())),
        "sources": dict(sorted(sources.items())),
        "source": {"revision": inventory["source"]["revision"],
                   "catalog_version": inventory["source"]["catalogVersion"],
                   "package_sha256": expected_digest},
    }
    digest = hashlib.sha256(_canonical_json({"schema": 1, **catalog})).hexdigest()
    # The CAS source bytes are independently rechecked after projecting its IDs.
    if _read_catalog(core_source_generation) is None or time.monotonic() >= deadline:
        raise CoreInspectionDenied("Resources catalog changed during projection")
    return catalog, digest


def _mission_store_identity(config: CoreGatewayConfig, path: Path, *,
                            include_sidecars: bool = True) -> tuple[Any, ...]:
    """Validate the fixed gateway-owned SQLite store and return stable file identity.

    The store is intentionally owned by the gateway UID (normally 996), not root.
    Root reads it only after this narrow owner/mode/path check; database rows remain
    untrusted and are independently joined to root observations before use.
    """
    expected = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
    if path != expected:
        raise CoreInspectionDenied("mission ledger path differs")
    for ancestor in (Path("/"), Path("/var"), Path("/var/lib")):
        item = os.lstat(ancestor)
        if (not stat.S_ISDIR(item.st_mode) or item.st_uid != 0
                or stat.S_IMODE(item.st_mode) & 0o022):
            raise CoreInspectionDenied("mission ledger ancestor custody differs")
    parent = os.lstat(path.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != config.gateway_uid
            or stat.S_IMODE(parent.st_mode) & 0o077):
        raise CoreInspectionDenied("mission ledger custody differs")
    directory_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                           | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    file_fds: list[int] = []
    try:
        parent_fd_info = os.fstat(directory_fd)
        if (parent_fd_info.st_dev, parent_fd_info.st_ino, parent_fd_info.st_uid) != (
                parent.st_dev, parent.st_ino, parent.st_uid):
            raise CoreInspectionDenied("mission ledger parent changed")
        info = os.stat(path.name, dir_fd=directory_fd, follow_symlinks=False)
        db_fd = os.open(path.name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
        file_fds.append(db_fd)
        opened = os.fstat(db_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != config.gateway_uid
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) & 0o077
                or (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_nlink)
                    != (info.st_dev, info.st_ino, info.st_uid, info.st_nlink)):
            raise CoreInspectionDenied("mission ledger custody differs")
        sidecars: list[tuple[Any, ...]] = []
        for suffix in ("-wal", "-shm", "-journal"):
            candidate_name = path.name + suffix
            try:
                item = os.stat(candidate_name, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                sidecars.append((suffix, None))
                continue
            if (not stat.S_ISREG(item.st_mode) or item.st_uid != config.gateway_uid
                    or item.st_nlink != 1 or stat.S_IMODE(item.st_mode) & 0o077):
                raise CoreInspectionDenied("mission ledger sidecar custody differs")
            side_fd = os.open(candidate_name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                              | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
            file_fds.append(side_fd)
            opened = os.fstat(side_fd)
            if (opened.st_dev, opened.st_ino, opened.st_uid, opened.st_nlink) != (
                    item.st_dev, item.st_ino, item.st_uid, item.st_nlink):
                raise CoreInspectionDenied("mission ledger sidecar changed")
            sidecars.append((suffix, item.st_dev, item.st_ino, item.st_uid, item.st_mode,
                             item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns))
        identity = (parent.st_dev, parent.st_ino, parent.st_uid, parent.st_mode,
                    info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink)
        return identity + (tuple(sidecars),) if include_sidecars else identity
    finally:
        for descriptor in file_fds:
            os.close(descriptor)
        os.close(directory_fd)


def _mission_binding_from_wire(value: Any) -> Any:
    if value is None:
        return None
    fields = {"schema", "mission_id", "revision", "plan_sha256", "task_sha256",
              "source_profile_id", "execution_mode", "autonomy_mode", "selected_source_ids",
              "scope_sha256", "authorization_sha256"}
    if type(value) is not dict or set(value) != fields:
        raise CoreInspectionDenied("mission binding wire shape is invalid")
    try:
        from .jarvis_mission_executor import MissionBinding
        binding = MissionBinding.from_wire(value)
        if type(binding) is not MissionBinding or _mission_binding_wire(binding) != value:
            raise ValueError
        return binding
    except Exception:
        raise CoreInspectionDenied("mission binding wire value is invalid") from None


def _resolve_spent_mission_binding(value: Any, *, owner_subject_sha256: str,
                                   gateway_turn_id: str, core_generation: str,
                                   core_source_generation: str, deadline: float) -> Any:
    """Re-read the exact spent approval before root seals its mission correlation."""
    wire = _mission_binding_wire(value)
    if wire is None:
        return None
    if time.monotonic() >= deadline:
        raise CoreInspectionDenied("mission binding expired")
    try:
        from .jarvis_chat import CHAT_STORE_PATH
        from .jarvis_mission_executor import (
            MissionBinding, MissionLedgerReader, resolve_spent_mission_binding,
        )
        if CHAT_STORE_PATH != Path("/var/lib/hermes-jarvis-chat/chat.sqlite3"):
            raise ValueError
        binding = MissionBinding.from_wire(wire)
        store = MissionLedgerReader(path=CHAT_STORE_PATH)
        persisted = resolve_spent_mission_binding(store, binding,
            gateway_turn_id=gateway_turn_id, owner_subject_sha256=owner_subject_sha256,
            core_generation=core_generation, core_source_generation=core_source_generation)
        if (type(binding) is not MissionBinding or persisted is not True
                or time.monotonic() >= deadline):
            raise ValueError
        return binding
    except Exception:
        raise CoreInspectionDenied("spent mission binding is unavailable or changed") from None


def _verify_planning_context(context: Any, *, owner_subject_sha256: str,
                             core_generation: str, core_source_generation: str,
                             prompt_sha256: str, mission_id: str | None = None,
                             revision: int | None = None, gateway_turn_id: str | None = None,
                             conversation_id: str | None = None, session_id: str | None = None,
                             config: CoreGatewayConfig, custody: Any,
                             preparing: bool) -> PlanningContext:
    """Rebuild mission/catalog/master facts from root custody and the fixed read-only DB."""
    dto = context if type(context) is PlanningContext else PlanningContext.from_wire(context)
    if (dto.source_profile_id != "hermes" or dto.mission_id != mission_id
            or dto.revision != revision or dto.planner_prompt_sha256 != prompt_sha256
            or not _is_hash(owner_subject_sha256) or not _is_hash(core_generation)
            or not _is_hash(core_source_generation)):
        raise CoreInspectionDenied("planning context does not match its owner turn")
    if (type(custody) is not CoreNativeObserverCustody
            or custody.core_generation != core_generation
            or custody.core_source_generation != core_source_generation):
        raise CoreInspectionDenied("planning context core custody changed")
    try:
        proof_deadline = time.monotonic() + MAX_PROOF_SECONDS
        from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
        from hermes_installer.remote.jarvis_mission_executor import (
            MissionLedgerReader, mission_goal_arguments_sha256,
        )
        from hermes_installer.remote.jarvis_master_planning import (
            build_jarvis_mission_master_plan_prompt, mission_catalog_sha256,
        )
        from hermes_installer.components.resources_active_profile_source import (
            RootVerifiedJarvisMasterSource,
        )
        expected_path = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        if CHAT_STORE_PATH != expected_path:
            raise ValueError
        ledger_identity = _mission_store_identity(config, expected_path)
        current_source = RootVerifiedJarvisMasterSource.current_master_source(custody, config)
        if (type(current_source) is not RootVerifiedJarvisMasterSource
                or current_source.profile_id != "hermes"
                or current_source.native_profile_key != "default"
                or current_source.display_name != "Jarvis"
                or current_source.is_current_sealed(custody, now=time.monotonic()) is not True
                or current_source.core_generation != core_generation
                or current_source.core_source_generation != core_source_generation):
            raise ValueError
        catalog, catalog_sha = _read_root_planning_catalog(core_source_generation)
        with MissionLedgerReader(path=expected_path)._connect() as db:
            mission_columns = {row[1] for row in db.execute("PRAGMA table_info(jarvis_missions)")}
            required_mission = {"id", "owner", "revision", "title", "brief", "team_ids", "status",
                                "execution_mode", "master_plan_sha256"}
            if not required_mission.issubset(mission_columns):
                raise ValueError
            mission = db.execute(
                "SELECT id,owner,revision,title,brief,team_ids,status,execution_mode,master_plan_sha256 "
                "FROM jarvis_missions WHERE id=? AND owner=? AND revision=?",
                (dto.mission_id, owner_subject_sha256, dto.revision)).fetchone()
            if (mission is None or mission["status"] != "draft"
                    or mission["execution_mode"] != "pending"
                    or mission["master_plan_sha256"] is not None
                    or not isinstance(mission["title"], str) or not 1 <= len(mission["title"]) <= 120
                    or not isinstance(mission["brief"], str) or not 1 <= len(mission["brief"]) <= 8000):
                raise ValueError
            expected_goal = mission_goal_arguments_sha256(mission["brief"])
            exact_catalog_sha = mission_catalog_sha256(catalog)
            prompt = build_jarvis_mission_master_plan_prompt(mission, catalog)
            expected_prompt_sha = hashlib.sha256(prompt.encode("utf-8", errors="strict")).hexdigest()
            if (dto.goal_sha256 != expected_goal or dto.catalog_sha256 != catalog_sha
                    or exact_catalog_sha != catalog_sha
                    or dto.planner_prompt_sha256 != expected_prompt_sha
                    or dto.master_source_generation_sha256 != current_source.generation_sha256
                    or dto.master_source_manifest_sha256 != current_source.source_member_manifest_sha256
                    or dto.master_prompt_sha256 != current_source.effective_prompt_sha256
                    or hashlib.sha256(prompt.encode("utf-8", errors="strict")).hexdigest()
                        != dto.planner_prompt_sha256):
                raise ValueError
            columns = {row[1] for row in db.execute(
                "PRAGMA table_info(jarvis_mission_planning_turns)")}
            required_planning = {"id", "owner", "mission_id", "revision", "task_sha256",
                "catalog_sha256", "source_binding", "planner_prompt_sha256", "gateway_turn_id",
                "conversation_id", "status", "master_source_generation_sha256",
                "master_source_manifest_sha256", "master_prompt_sha256"}
            if not required_planning.issubset(columns):
                raise ValueError
            planning = db.execute(
                "SELECT id,owner,mission_id,revision,task_sha256,catalog_sha256,source_binding,"
                "planner_prompt_sha256,gateway_turn_id,conversation_id,status,"
                "master_source_generation_sha256,master_source_manifest_sha256,master_prompt_sha256 "
                "FROM jarvis_mission_planning_turns WHERE owner=? AND mission_id=? AND revision=?",
                (owner_subject_sha256, dto.mission_id, dto.revision)).fetchone()
            if planning is None:
                raise ValueError
            try:
                source_binding = json.loads(planning["source_binding"],
                                            object_pairs_hook=_unique_pairs)
            except Exception:
                raise ValueError from None
            if (type(source_binding) is not dict
                    or set(source_binding) != {"core_generation", "core_source_generation"}
                    or source_binding != {"core_generation": core_generation,
                                          "core_source_generation": core_source_generation}
                    or planning["task_sha256"] != expected_goal
                    or planning["catalog_sha256"] != catalog_sha
                    or planning["planner_prompt_sha256"] != expected_prompt_sha
                    or planning["master_source_generation_sha256"] != current_source.generation_sha256
                    or planning["master_source_manifest_sha256"] != current_source.source_member_manifest_sha256
                    or planning["master_prompt_sha256"] != current_source.effective_prompt_sha256):
                raise ValueError
            if preparing:
                if planning["status"] != "reserved" or planning["gateway_turn_id"] not in (None, ""):
                    raise ValueError
            else:
                if (planning["status"] != "queued"
                        or planning["gateway_turn_id"] != gateway_turn_id
                        or planning["conversation_id"] != conversation_id
                        or not isinstance(gateway_turn_id, str)
                        or not isinstance(session_id, str)):
                    raise ValueError
                turn = db.execute(
                    "SELECT owner,conversation_id,status,runtime_session_id,core_generation "
                    "FROM turns WHERE id=?", (gateway_turn_id,)).fetchone()
                if (turn is None or turn["owner"] != owner_subject_sha256
                        or turn["conversation_id"] != conversation_id
                        or turn["status"] not in {"queued", "running"}
                        or turn["runtime_session_id"] != session_id
                    or turn["core_generation"] != core_generation):
                    raise ValueError
        if _mission_store_identity(config, expected_path) != ledger_identity:
            raise ValueError
        if (time.monotonic() >= proof_deadline
                or current_source.is_current_sealed(custody, now=time.monotonic()) is not True
                or _read_root_planning_catalog(core_source_generation)[1] != catalog_sha):
            raise ValueError
        return dto
    except CoreInspectionDenied:
        raise
    except Exception:
        raise CoreInspectionDenied("root mission planning context is unavailable or changed") from None


def _prepare_planning_context(*, owner_subject_sha256: str, mission_id: str,
                              revision: int, planner_prompt_sha256: str,
                              core_generation: str, core_source_generation: str,
                              config: CoreGatewayConfig, custody: Any) -> PlanningContext:
    """Build a planning DTO only from a root-owned reserved mission row and live sources."""
    if (not _is_hash(owner_subject_sha256) or type(revision) is not int or revision < 1
            or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", mission_id or "") is None
            or not _is_hash(planner_prompt_sha256)):
        raise CoreInspectionDenied("planning request identity is invalid")
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    try:
        from hermes_installer.remote.jarvis_chat import CHAT_STORE_PATH
        from hermes_installer.remote.jarvis_mission_executor import (
            MissionLedgerReader, mission_goal_arguments_sha256,
        )
        from hermes_installer.remote.jarvis_master_planning import (
            build_jarvis_mission_master_plan_prompt, mission_catalog_sha256,
        )
        from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        expected_path = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        if CHAT_STORE_PATH != expected_path:
            raise ValueError
        ledger_identity = _mission_store_identity(config, expected_path)
        master = RootVerifiedJarvisMasterSource.current_master_source(custody, config)
        if (type(master) is not RootVerifiedJarvisMasterSource
                or master.profile_id != "hermes" or master.display_name != "Jarvis"
                or master.is_current_sealed(custody, now=time.monotonic()) is not True):
            raise ValueError
        catalog, catalog_sha = _read_root_planning_catalog(core_source_generation)
        with MissionLedgerReader(path=expected_path)._connect() as db:
            row = db.execute(
                "SELECT id,owner,revision,title,brief,team_ids,status,execution_mode,master_plan_sha256 "
                "FROM jarvis_missions WHERE id=? AND owner=? AND revision=?",
                (mission_id, owner_subject_sha256, revision)).fetchone()
            if (row is None or row["status"] != "draft" or row["execution_mode"] != "pending"
                    or row["master_plan_sha256"] is not None
                    or not isinstance(row["title"], str) or not row["title"]
                    or not isinstance(row["brief"], str) or not row["brief"]):
                raise ValueError
            reserved = db.execute(
                "SELECT task_sha256,catalog_sha256,source_binding,planner_prompt_sha256,status,gateway_turn_id,"
                "master_source_generation_sha256,master_source_manifest_sha256,master_prompt_sha256 "
                "FROM jarvis_mission_planning_turns WHERE owner=? AND mission_id=? AND revision=?",
                (owner_subject_sha256, mission_id, revision)).fetchone()
            if reserved is None or reserved["status"] != "reserved" or reserved["gateway_turn_id"] not in (None, ""):
                raise ValueError
            prompt = build_jarvis_mission_master_plan_prompt(row, catalog)
            prompt_sha = hashlib.sha256(prompt.encode("utf-8", errors="strict")).hexdigest()
            if mission_catalog_sha256(catalog) != catalog_sha:
                raise ValueError
            source_binding = json.loads(reserved["source_binding"], object_pairs_hook=_unique_pairs)
            goal_sha = mission_goal_arguments_sha256(row["brief"])
            if (prompt_sha != planner_prompt_sha256 or reserved["task_sha256"] != goal_sha
                    or reserved["catalog_sha256"] != catalog_sha
                    or reserved["planner_prompt_sha256"] != prompt_sha
                    or reserved["master_source_generation_sha256"] != master.generation_sha256
                    or reserved["master_source_manifest_sha256"] != master.source_member_manifest_sha256
                    or reserved["master_prompt_sha256"] != master.effective_prompt_sha256
                    or source_binding != {"core_generation": core_generation,
                                          "core_source_generation": core_source_generation}
                    or hashlib.sha256(prompt.encode("utf-8", errors="strict")).hexdigest() != prompt_sha):
                raise ValueError
        if _mission_store_identity(config, expected_path) != ledger_identity:
            raise ValueError
        if (time.monotonic() >= deadline
                or master.is_current_sealed(custody, now=time.monotonic()) is not True
                or _read_root_planning_catalog(core_source_generation)[1] != catalog_sha):
            raise ValueError
        return PlanningContext(1, mission_id, revision, goal_sha, catalog_sha, prompt_sha,
            master.generation_sha256, master.source_member_manifest_sha256,
            master.effective_prompt_sha256, "hermes")
    except CoreInspectionDenied:
        raise
    except Exception:
        raise CoreInspectionDenied("root planning context could not be prepared") from None


def _valid_learning_candidates(candidates: Any, readiness: str) -> bool:
    if readiness not in {"read-only-native-review", "partial", "unavailable"}:
        return False
    if not isinstance(candidates, list) or len(candidates) > 64:
        return False
    candidate_fields = {"opaque_id", "revision_sha256", "action", "created_at", "skill_label",
                        "summary", "diff_text", "diff_sha256", "truncated", "state"}
    total = 0
    seen: set[str] = set()
    for item in candidates:
        if type(item) is not dict or set(item) != candidate_fields:
            return False
        if (not isinstance(item.get("opaque_id"), str)
                or re.fullmatch(r"[0-9a-f]{24}", item["opaque_id"]) is None
                or item["opaque_id"] in seen):
            return False
        seen.add(item["opaque_id"])
        action = item.get("action")
        if (not _is_hash(item.get("revision_sha256"))
                or not isinstance(action, str)
                or action not in {"create", "edit", "patch", "write_file",
                                  "remove_file", "delete", "batch"}
                or (item.get("created_at") is not None and
                    (isinstance(item["created_at"], bool)
                     or not isinstance(item["created_at"], (int, float))
                     or not math.isfinite(item["created_at"])))
                or not isinstance(item.get("skill_label"), str) or len(item["skill_label"]) > 120
                or not isinstance(item.get("summary"), str) or len(item["summary"]) > 240
                or not isinstance(item.get("diff_text"), str)
                or not _is_hash(item.get("diff_sha256"))
                or type(item.get("truncated")) is not bool
                or item.get("state") != "pending-review"):
            return False
        raw = item["diff_text"].encode("utf-8", "strict")
        total += len(raw)
        if total > MAX_SKILL_LEARNING_DIFF_BYTES:
            return False
        if not item["truncated"] and hashlib.sha256(raw).hexdigest() != item["diff_sha256"]:
            return False
    return readiness != "unavailable" or not candidates


def _valid_learning_reasons(value: Any) -> bool:
    allowed = {"pending_directory_unavailable", "pending_member_invalid", "pending_limit_exceeded",
               "pending_record_skipped", "pending_record_invalid", "native_diff_unavailable",
               "diff_limit_reached", "pending_custody_changed"}
    return (isinstance(value, list) and len(value) <= 16
            and all(isinstance(item, str) and item in allowed for item in value)
            and len(set(value)) == len(value))


def _learning_jwks(config: CoreGatewayConfig, *, deadline: float) -> Any:
    global _LEARNING_JWKS_CACHE
    from .jwks import JWKSCache
    remaining = deadline - time.monotonic()
    if remaining <= 0.1:
        raise TimeoutError
    with _LEARNING_JWKS_LOCK:
        cache = _LEARNING_JWKS_CACHE
        if cache is None or cache.issuer != config.issuer:
            cache = JWKSCache(config.issuer, ttl_seconds=30,
                              timeout_seconds=min(3.0, max(0.1, remaining)))
            _LEARNING_JWKS_CACHE = cache
        return cache


def _run_native_skill_learning_probe(*, deadline: float) -> dict[str, Any]:
    helper = Path(__file__).resolve().with_name("native_skill_learning_probe.py")
    for parent in helper.parents:
        directory = os.lstat(parent)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or stat.S_IMODE(directory.st_mode) & 0o022):
            raise ValueError("fixed native review source path custody differs")
        if parent == parent.parent:
            break
    info = os.lstat(helper)
    if (not stat.S_ISREG(info.st_mode) or info.st_size != NATIVE_SKILL_LEARNING_SIZE
            or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) & 0o022
            or _protected_file_sha(helper, owner_uid=0, deadline=deadline)
                != NATIVE_SKILL_LEARNING_SHA256):
        raise ValueError("fixed native review helper custody differs")
    script = (
        "import runpy,sys;"
        f"sys.path.insert(0,{str(CORE_SOURCE)!r});"
        f"p={str(helper)!r};"
        "runpy.run_path(p)['main']()"
    )
    account = pwd.getpwnam("admin")
    python_info = os.lstat(CORE_PYTHON_LINK)
    if (account.pw_uid != 1000 or account.pw_gid != 1000
            or not stat.S_ISLNK(python_info.st_mode)
            or os.readlink(CORE_PYTHON_LINK) != CORE_PYTHON_LINK_TARGET):
        raise ValueError("fixed native review runtime custody differs")
    remaining = deadline - time.monotonic()
    if remaining <= 0.1:
        raise TimeoutError
    environment = {
        "HOME": str(CORE_ADMIN_HOME), "HERMES_HOME": str(CORE_HERMES_HOME),
        "PATH": CORE_PATH, "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "HERMES_DISABLE_LAZY_INSTALLS": "1", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    }
    process = subprocess.Popen(
        (str(CORE_PYTHON_LINK), "-I", "-B", "-c", script), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
        cwd=str(CORE_SOURCE), env=environment, user=account.pw_uid, group=account.pw_gid,
        extra_groups=(), umask=0o077, start_new_session=True,
    )
    assert process.stdout is not None
    os.set_blocking(process.stdout.fileno(), False)
    output = bytearray()
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            for key, _mask in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 32 * 1024)
                if chunk:
                    output.extend(chunk)
                    if len(output) > 640 * 1024:
                        raise ValueError("native review output exceeded bound")
                else:
                    selector.unregister(key.fileobj)
            if process.poll() is not None and not selector.get_map():
                break
        if process.wait(timeout=max(0.05, deadline-time.monotonic())) != 0:
            raise ValueError("native review helper failed")
    except Exception:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            try:
                process.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        raise
    finally:
        selector.close()
        process.stdout.close()
    raw = bytes(output)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise ValueError("native review helper output framing differs")
    result = json.loads(raw[:-1].decode("utf-8", "strict"), object_pairs_hook=_unique_pairs)
    expected = {"schema", "state", "candidates", "pending_reasons", "candidate_count", "diff_bytes"}
    if (type(result) is not dict or set(result) != expected or type(result.get("schema")) is not int
            or result["schema"] != 1 or result.get("state") not in {"read-only-native-review", "partial"}
            or not _valid_learning_reasons(result.get("pending_reasons"))):
        raise ValueError("native review helper schema differs")
    if (not _valid_learning_candidates(result.get("candidates"), result["state"])
            or type(result.get("candidate_count")) is not int
            or result["candidate_count"] != len(result["candidates"])
            or type(result.get("diff_bytes")) is not int
            or result["diff_bytes"] != sum(len(item["diff_text"].encode("utf-8"))
                                           for item in result["candidates"])):
        raise ValueError("native review helper content differs")
    return result


def observe_skill_learning(config: CoreGatewayConfig, *, request: dict[str, Any],
                           caller_pid: int, caller_uid: int, caller_gid: int,
                           peer_pid: int, peer_uid: int, peer_gid: int) -> dict[str, Any]:
    required = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
                "core_generation", "ingress_nonce", "ingress_proof_sha256"}
    if (type(request) is not dict or set(request) != required or type(request.get("schema")) is not int
            or request["schema"] != 1 or request.get("op") != "observe-skill-learning"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or not all(type(value) is int for value in (peer_pid, peer_uid, peer_gid))
            or not isinstance(request.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None
            or not isinstance(request.get("ingress_nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["ingress_nonce"]) is None
            or not _is_hash(request.get("ingress_proof_sha256"))
            or not _is_hash(request.get("core_generation"))
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384
            or not request["access_jwt"].isascii()):
        raise CoreInspectionDenied("native review request is invalid")
    caller_start = _proc_start_ticks(caller_pid)
    retained = _consume_ingress_issue(caller_pid=caller_pid,
        caller_start_ticks=caller_start, nonce=request["ingress_nonce"],
        proof_sha256=request["ingress_proof_sha256"],
        peer=(peer_pid, peer_uid, peer_gid), core_generation=request["core_generation"],
        config=config)
    deadline = retained.expires_monotonic
    # Rejoin SO_PEERCRED to the fixed gateway unit/source before validating the
    # forwarded owner assertion or reading native pending content.
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if (current["proof_sha256"] != retained.proof_sha256
            or current["core_generation"] != retained.core_generation
            or current["boot_id"] != retained.boot_id
            or current["config_sha256"] != retained.config_sha256
            or time.monotonic() >= deadline):
        raise CoreInspectionDenied("native review ingress changed")
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)),
        deadline_monotonic=deadline)
    if time.monotonic() >= deadline:
        raise CoreInspectionDenied("native review ingress expired")
    native = _run_native_skill_learning_probe(deadline=deadline)
    final = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if (final["proof_sha256"] != retained.proof_sha256 or time.monotonic() >= deadline
            or principal.email.casefold() not in config.allowed_emails):
        raise CoreInspectionDenied("native review proof expired or changed")
    issued = retained.issued_monotonic
    jwt_deadline = time.monotonic() + max(0.0, principal.expires_at-time.time())
    expiry = min(deadline, jwt_deadline, issued + MAX_PROOF_SECONDS)
    body = {
        "schema": 1, "nonce": request["nonce"], "boot_id": retained.boot_id,
        "issued_monotonic": issued, "expires_monotonic": expiry,
        "config_sha256": retained.config_sha256, "core_generation": retained.core_generation,
        "ingress_nonce": retained.nonce, "ingress_proof_sha256": retained.proof_sha256,
        "readiness": native["state"], "pending_reasons": native["pending_reasons"],
        "candidates": native["candidates"],
    }
    body["proof_sha256"] = _learning_digest(body)
    return body


def observe_owner_turn(config: CoreGatewayConfig, *, request: dict[str, Any],
                       caller_pid: int, caller_uid: int, caller_gid: int,
                       peer_pid: int, peer_uid: int, peer_gid: int,
                       registry: Any) -> dict[str, Any]:
    """Validate a fresh Access-backed turn ingress and register it in root memory."""
    required = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
                "core_generation", "ingress_nonce", "ingress_proof_sha256", "session_id",
                "conversation_id", "gateway_turn_id", "prompt_sha256"}
    if (type(request) is not dict or not required.issubset(request)
            or set(request) - required - {"mission_binding", "planning_context"}
                or set(request) - required not in (
                    set(), {"mission_binding"}, {"planning_context"},
                    {"mission_binding", "planning_context"})
            or type(request.get("schema")) is not int
            or request["schema"] != 1 or request.get("op") != "observe-owner-turn"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or not all(type(value) is int for value in (peer_pid, peer_uid, peer_gid))
            or not isinstance(request.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None
            or not isinstance(request.get("ingress_nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["ingress_nonce"]) is None
            or not _is_hash(request.get("ingress_proof_sha256"))
            or not _is_hash(request.get("core_generation"))
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384 or not request["access_jwt"].isascii()
            or not _is_hash(request.get("prompt_sha256"))
            or not isinstance(request.get("session_id"), str)
            or not 1 <= len(request["session_id"]) <= 512
            or not request["session_id"].isascii()
            or any(ord(char) < 0x20 for char in request["session_id"])
            or any(not isinstance(request.get(key), str)
                   or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", request[key]) is None
                   for key in ("conversation_id", "gateway_turn_id"))):
        raise CoreInspectionDenied("owner turn request is invalid")
    if (registry is None or registry is not _CORE_NATIVE_REGISTRY
            or _CORE_NATIVE_REGISTRY_TYPE is None or type(registry) is not _CORE_NATIVE_REGISTRY_TYPE):
        raise CoreInspectionDenied("native owner registry is unavailable")
    caller_start = _proc_start_ticks(caller_pid)
    retained = _consume_ingress_issue(caller_pid=caller_pid,
        caller_start_ticks=caller_start, nonce=request["ingress_nonce"],
        proof_sha256=request["ingress_proof_sha256"],
        peer=(peer_pid, peer_uid, peer_gid), core_generation=request["core_generation"],
        config=config)
    deadline = retained.expires_monotonic
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if (current["proof_sha256"] != retained.proof_sha256
            or current["core_generation"] != retained.core_generation
            or current["boot_id"] != retained.boot_id
            or current["config_sha256"] != retained.config_sha256
            or time.monotonic() >= deadline):
        raise CoreInspectionDenied("owner turn ingress changed")
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)),
        deadline_monotonic=deadline)
    if (time.monotonic() >= deadline
            or principal.email.casefold() not in config.allowed_emails):
        raise CoreInspectionDenied("owner turn ingress expired")
    custody = _CORE_NATIVE_CUSTODY
    if type(custody) is not CoreNativeObserverCustody:
        raise CoreInspectionDenied("current native observer custody is unavailable")
    mission_binding = _resolve_spent_mission_binding(
        _mission_binding_from_wire(request.get("mission_binding")),
        owner_subject_sha256=hashlib.sha256(principal.subject.encode("utf-8")).hexdigest(),
        gateway_turn_id=request["gateway_turn_id"],
        core_generation=retained.core_generation,
        core_source_generation=current["core_source_generation"], deadline=deadline)
    planning_context = None
    if "planning_context" in request:
        if mission_binding is not None:
            raise CoreInspectionDenied("mission execution and planning context cannot be combined")
        planning_context_wire = PlanningContext.from_wire(request["planning_context"])
        planning_context = _verify_planning_context(
            request["planning_context"],
            owner_subject_sha256=hashlib.sha256(principal.subject.encode("utf-8")).hexdigest(),
            core_generation=retained.core_generation,
            core_source_generation=current["core_source_generation"],
            prompt_sha256=request["prompt_sha256"],
            mission_id=planning_context_wire.mission_id,
            revision=planning_context_wire.revision,
            gateway_turn_id=request["gateway_turn_id"],
            conversation_id=request["conversation_id"], session_id=request["session_id"],
            config=config, custody=custody, preparing=False)
    final = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if (final["proof_sha256"] != retained.proof_sha256
            or final["core_generation"] != retained.core_generation
            or final["boot_id"] != retained.boot_id
            or final["config_sha256"] != retained.config_sha256
            or time.monotonic() >= deadline):
        raise CoreInspectionDenied("owner turn custody changed")
    if (type(custody) is not CoreNativeObserverCustody
            or custody._seal is not _NATIVE_CUSTODY_SEAL
            or final["core_generation"] != custody.core_generation
            or final["core_pid"] != custody.core_pid
            or final["core_start_ticks"] != custody.core_start_ticks
            or final["core_invocation_id"] != custody.core_invocation_id
            or final["core_listener_inode"] != custody.core_listener_inode
            or final["core_source_generation"] != custody.core_source_generation):
        raise CoreInspectionDenied("current native core custody is unavailable")
    gateway_pidfd, gateway_start, gateway_invocation = _check_unit_process(
        config, unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
    try:
        if gateway_start != retained.caller_start_ticks:
            raise CoreInspectionDenied("gateway process changed during owner turn registration")
    finally:
        os.close(gateway_pidfd)
    pidfd = os.dup(custody._core_pidfd)
    accepted_at = time.monotonic()
    jwt_expiry = accepted_at + max(0.0, principal.expires_at - time.time())
    owner_expiry = min(jwt_expiry, retained.issued_monotonic + MAX_OWNER_TURN_SECONDS)
    if (accepted_at >= deadline or accepted_at >= owner_expiry
            or not secrets.compare_digest(
                hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest(),
                principal.token_fingerprint)):
        os.close(pidfd)
        raise CoreInspectionDenied("owner turn registration expired")
    claims = {
        "schema": 1, "owner_turn_handle": secrets.token_hex(16),
        "owner_subject_sha256": hashlib.sha256(principal.subject.encode("utf-8")).hexdigest(),
        "token_fingerprint_sha256": hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest(),
        "jwt_expires_monotonic": jwt_expiry,
        "ingress_issued_monotonic": retained.issued_monotonic,
        "ingress_expires_monotonic": retained.expires_monotonic,
        "accepted_monotonic": accepted_at, "expires_monotonic": owner_expiry,
        "ingress_nonce": retained.nonce, "ingress_proof_sha256": retained.proof_sha256,
        "peer_gateway_pid": caller_pid, "peer_gateway_uid": caller_uid,
        "peer_gateway_gid": caller_gid, "peer_gateway_start_ticks": gateway_start,
        "gateway_invocation_id": gateway_invocation,
        "tunnel_invocation_id": final["tunnel_invocation_id"],
        "core_generation": final["core_generation"], "core_pid": custody.core_pid,
        "core_uid": custody.core_uid, "core_gid": custody.core_gid,
        "core_start_ticks": custody.core_start_ticks,
        "core_invocation_id": custody.core_invocation_id,
        "core_listener_inode": custody.core_listener_inode,
        "core_source_generation": custody.core_source_generation,
        "core_unit_sha256": custody.core_unit_sha256,
        "core_executable_sha256": custody.core_executable_sha256,
        "session_id": request["session_id"], "conversation_id": request["conversation_id"],
        "gateway_turn_id": request["gateway_turn_id"], "prompt_sha256": request["prompt_sha256"],
        "mission_binding": mission_binding, "planning_context": planning_context,
    }
    digest_claims = dict(claims)
    digest_claims["mission_binding"] = _mission_binding_wire(mission_binding)
    digest_claims["planning_context"] = _planning_context_wire(planning_context)
    observation = CoreVerifiedOwnerTurnObservation(
        **claims, proof_sha256=_owner_turn_digest(digest_claims), _core_pidfd=pidfd,
        _seal=_OWNER_TURN_SEAL)
    if (observation.verify_current(config, custody=custody, now=accepted_at) is not True
            or time.monotonic() >= deadline):
        os.close(pidfd)
        raise CoreInspectionDenied("owner turn proof changed during registration")
    try:
        handle = registry.register_owner_turn(observation)
    except Exception:
        os.close(pidfd)
        raise CoreInspectionDenied("owner turn registration failed") from None
    policy = None
    try:
        tool_configuration = observe_current_native_tool_configuration(
            config, custody=custody, owner_turn=observation)
        candidate_policy = registry.enroll_current_orchestrator_policy(observation, tool_configuration)
        from .core_native_observer import RootSelectedOrchestratorDelegationPolicy
        if (type(candidate_policy) is RootSelectedOrchestratorDelegationPolicy
                and registry.is_current_orchestrator_policy(candidate_policy, observation) is True):
            policy = candidate_policy
    except Exception:
        # Policy/source enrollment is an optional native capability. The root
        # owner-turn identity remains usable for ordinary chat; all native
        # action operations independently fail closed without a policy.
        policy = None
    try:
        post = observe_current_ingress(config, nonce=retained.nonce,
            caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
            peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
            _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
        custody_current = custody.verify_current(
            config, observation, custody.core_pid, custody.core_uid, custody.core_gid)
    except Exception:
        try:
            registry.revoke_owner_turn(observation.owner_turn_handle)
        except Exception:
            pass
        raise CoreInspectionDenied("owner turn custody changed after registration") from None
    if (not isinstance(handle, str) or handle != observation.owner_turn_handle
            or post["proof_sha256"] != retained.proof_sha256
            or post["core_generation"] != retained.core_generation
            or post["config_sha256"] != retained.config_sha256
            or time.monotonic() >= deadline
            or custody_current is not True):
        # A typed registry owns the descriptor after successful registration. Revoke the
        # record synchronously if its claimed handle is not the root-generated one.
        try:
            registry.revoke_owner_turn(observation.owner_turn_handle)
        except Exception:
            pass
        raise CoreInspectionDenied("owner turn registration result is invalid")
    return {"schema": 1, "nonce": request["nonce"], "owner_turn_handle": handle}


def prepare_master_planning_context(config: CoreGatewayConfig, *, request: dict[str, Any],
                                   caller_pid: int, caller_uid: int, caller_gid: int,
                                   peer_pid: int, peer_uid: int, peer_gid: int,
                                   custody: Any) -> dict[str, Any]:
    """Root-authenticate the request and derive a context for an already reserved plan row."""
    fields = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
              "core_generation", "ingress_nonce", "ingress_proof_sha256", "mission_id",
              "revision", "planner_prompt_sha256"}
    if (type(request) is not dict or set(request) != fields or request.get("schema") != 1
            or request.get("op") != "prepare-master-planning-context"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or (not isinstance(request.get("nonce"), str)
                or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None)
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384
            or not request["access_jwt"].isascii()
            or not _is_hash(request.get("core_generation"))
            or not isinstance(request.get("ingress_nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["ingress_nonce"]) is None
            or not _is_hash(request.get("ingress_proof_sha256"))
            or not _is_hash(request.get("planner_prompt_sha256"))
            or type(request.get("revision")) is not int):
        raise CoreInspectionDenied("planning context request is invalid")
    caller_start = _proc_start_ticks(caller_pid)
    key = (caller_pid, caller_start, request["ingress_nonce"], request["ingress_proof_sha256"])
    with _RETAINED_INGRESS_LOCK:
        retained = _RETAINED_INGRESS_ISSUES.get(key)
    if (retained is None or retained.peer != (peer_pid, peer_uid, peer_gid)
            or retained.core_generation != request["core_generation"]
            or retained.config_sha256 != config.config_sha256
            or time.monotonic() >= retained.expires_monotonic):
        raise CoreInspectionDenied("planning ingress is stale")
    deadline = retained.expires_monotonic
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)),
        deadline_monotonic=deadline)
    if (principal.email.casefold() not in config.allowed_emails
            or current["proof_sha256"] != retained.proof_sha256
            or current["core_generation"] != retained.core_generation
            or current["core_source_generation"] != custody.core_source_generation
            or time.monotonic() >= deadline
            or hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest()
                != principal.token_fingerprint):
        raise CoreInspectionDenied("planning ingress identity changed")
    context = _prepare_planning_context(
        owner_subject_sha256=hashlib.sha256(principal.subject.encode("utf-8")).hexdigest(),
        mission_id=request["mission_id"], revision=request["revision"],
        planner_prompt_sha256=request["planner_prompt_sha256"],
        core_generation=retained.core_generation,
        core_source_generation=current["core_source_generation"],
        config=config, custody=custody)
    final = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    if final["proof_sha256"] != retained.proof_sha256 or time.monotonic() >= deadline:
        raise CoreInspectionDenied("planning ingress changed during preparation")
    return {"schema": 1, "nonce": request["nonce"], "ok": True,
            "planning_context": context.to_wire()}


def observe_read_master_plan(config: CoreGatewayConfig, *, request: dict[str, Any],
                             caller_pid: int, caller_uid: int, caller_gid: int,
                             peer_pid: int, peer_uid: int, peer_gid: int,
                             custody: Any, registry: Any) -> dict[str, Any]:
    """Read a durable plan only after fresh Access, owner, turn, CAS and master joins."""
    required = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
                "core_generation", "ingress_nonce", "ingress_proof_sha256", "mission_id", "revision"}
    if (type(request) is not dict or set(request) != required or request.get("schema") != 1
            or request.get("op") != "read-master-plan"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or not isinstance(request.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384
            or not request["access_jwt"].isascii()
            or not _is_hash(request.get("core_generation"))
            or not isinstance(request.get("ingress_nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["ingress_nonce"]) is None
            or not _is_hash(request.get("ingress_proof_sha256"))
            or type(request.get("revision")) is not int or request["revision"] < 1
            or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", request.get("mission_id", "")) is None):
        raise CoreInspectionDenied("master plan read request is invalid")
    caller_start = _proc_start_ticks(caller_pid)
    issue_key = (caller_pid, caller_start, request["ingress_nonce"], request["ingress_proof_sha256"])
    with _RETAINED_INGRESS_LOCK:
        retained = _RETAINED_INGRESS_ISSUES.get(issue_key)
    if (retained is None or retained.peer != (peer_pid, peer_uid, peer_gid)
            or retained.core_generation != request["core_generation"]
            or retained.config_sha256 != config.config_sha256
            or time.monotonic() >= retained.expires_monotonic):
        raise CoreInspectionDenied("master plan ingress is stale")
    deadline = retained.expires_monotonic
    ingress = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)), deadline_monotonic=deadline)
    owner_hash = hashlib.sha256(principal.subject.encode("utf-8")).hexdigest()
    if (principal.email.casefold() not in config.allowed_emails
            or hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest()
                != principal.token_fingerprint
            or ingress["proof_sha256"] != retained.proof_sha256
            or ingress["core_source_generation"] != custody.core_source_generation
            or ingress["core_generation"] != custody.core_generation):
        raise CoreInspectionDenied("master plan owner ingress changed")
    try:
        from hermes_installer.components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        from hermes_installer.remote.jarvis_mission_executor import mission_goal_arguments_sha256
        from hermes_installer.remote.core_native_observer import RootObservedMasterPlanRecord
        path = Path("/var/lib/hermes-jarvis-chat/chat.sqlite3")
        ledger_identity = _mission_store_identity(config, path)
        if (registry is None or not callable(getattr(registry, "read_master_plan_record", None))):
            raise ValueError
        master = RootVerifiedJarvisMasterSource.current_master_source(custody, config)
        if (type(master) is not RootVerifiedJarvisMasterSource
                or master.is_current_sealed(custody, now=time.monotonic()) is not True):
            raise ValueError
        catalog, catalog_sha = _read_root_planning_catalog(custody.core_source_generation)
        observed = registry.read_master_plan_record(
            owner_subject_sha256=owner_hash, mission_id=request["mission_id"],
            revision=request["revision"])
        if (type(observed) is not RootObservedMasterPlanRecord
                or observed.is_root_observed() is not True
                or observed.owner_subject_sha256 != owner_hash
                or observed.mission_id != request["mission_id"]
                or observed.revision != request["revision"]
                or observed.owner_turn_handle == ""
                or observed.core_generation != custody.core_generation
                or observed.core_source_generation != custody.core_source_generation):
            raise ValueError
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=1) as db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA query_only=ON")
            mission = db.execute(
                "SELECT * FROM jarvis_missions WHERE id=? AND owner=? AND revision=?",
                (request["mission_id"], owner_hash, request["revision"])).fetchone()
            planning = db.execute(
                "SELECT * FROM jarvis_mission_planning_turns WHERE owner=? AND mission_id=? AND revision=?",
                (owner_hash, request["mission_id"], request["revision"])).fetchone()
            if mission is None or planning is None:
                raise ValueError
            plan = json.loads(mission["master_plan_json"], object_pairs_hook=_unique_pairs)
            selected = json.loads(mission["selected_source_ids"], object_pairs_hook=_unique_pairs)
            source_binding = json.loads(planning["source_binding"], object_pairs_hook=_unique_pairs)
            turn = db.execute("SELECT owner,conversation_id,status,runtime_session_id,core_generation "
                              "FROM turns WHERE id=?", (mission["master_plan_gateway_turn_id"],)).fetchone()
            if (mission["status"] != "draft" or mission["execution_mode"] not in {"oneshot", "kanban"}
                    or not _is_hash(mission["master_plan_sha256"])
                    or not _is_hash(mission["master_plan_response_sha256"])
                    or not isinstance(selected, list) or len(selected) > 12
                    or len(set(selected)) != len(selected)
                    or any(not isinstance(item, str) or item not in catalog["profiles"] for item in selected)
                    or (not selected and mission["execution_mode"] != "oneshot")
                    or planning["status"] != "completed" or turn is None
                    or planning["gateway_turn_id"] != mission["master_plan_gateway_turn_id"]
                    or planning["conversation_id"] != turn["conversation_id"]
                    or planning["task_sha256"] != mission_goal_arguments_sha256(mission["brief"])
                    or planning["catalog_sha256"] != catalog_sha
                    or planning["status"] != "completed"
                    or source_binding != {"core_generation": custody.core_generation,
                                          "core_source_generation": custody.core_source_generation}
                    or planning["master_source_generation_sha256"] != master.generation_sha256
                    or planning["master_source_manifest_sha256"] != master.source_member_manifest_sha256
                    or planning["master_prompt_sha256"] != master.effective_prompt_sha256
                    or planning["master_source_generation_sha256"] != observed.master_source_generation_sha256
                    or planning["master_source_manifest_sha256"] != observed.master_source_manifest_sha256
                    or planning["master_prompt_sha256"] != observed.master_prompt_sha256
                    or planning["gateway_turn_id"] != observed.gateway_turn_id
                    or planning["conversation_id"] != observed.conversation_id
                    or mission["master_plan_owner_turn_handle"] != observed.owner_turn_handle
                    or mission["master_plan_gateway_turn_id"] != observed.gateway_turn_id
                    or mission["master_plan_core_generation"] != observed.core_generation
                    or mission["master_plan_core_source_generation"] != observed.core_source_generation
                    or mission["master_plan_sha256"] != observed.plan_sha256
                    or mission["master_plan_response_sha256"] != observed.response_sha256
                    or mission["master_plan_json"] != observed.plan_json
                    or planning["task_sha256"] != observed.goal_sha256
                    or planning["catalog_sha256"] != observed.catalog_sha256
                    or planning["planner_prompt_sha256"] != observed.planner_prompt_sha256
                    or selected != list(observed.selected_source_ids)
                    or mission["execution_mode"] != observed.execution_mode
                    or mission["master_plan_catalog_sha256"] != planning["catalog_sha256"]
                    or mission["master_plan_planner_prompt_sha256"] != planning["planner_prompt_sha256"]
                    or mission["master_plan_source_generation_sha256"] != master.generation_sha256
                    or mission["master_plan_source_manifest_sha256"] != master.source_member_manifest_sha256
                    or mission["master_plan_master_prompt_sha256"] != master.effective_prompt_sha256
                    or turn["owner"] != owner_hash or turn["status"] != "completed"
                    or turn["runtime_session_id"] != observed.session_id
                    or turn["conversation_id"] != observed.conversation_id
                    or turn["core_generation"] != custody.core_generation):
                raise ValueError
            full_digest = hashlib.sha256(_canonical_json({"execution_mode": mission["execution_mode"],
                "selected_source_ids": selected, "plan": plan})).hexdigest()
            if full_digest != mission["master_plan_sha256"]:
                raise ValueError
            row = {
                "schema": 1, "mission_id": mission["id"], "revision": mission["revision"],
                "owner_subject_sha256": owner_hash,
                "goal_sha256": planning["task_sha256"],
                "plan_json": _canonical_json(plan).decode("utf-8"),
                "plan_sha256": mission["master_plan_sha256"],
                "response_sha256": mission["master_plan_response_sha256"],
                "gateway_turn_id": mission["master_plan_gateway_turn_id"],
                "owner_turn_handle": mission["master_plan_owner_turn_handle"],
                "core_generation": mission["master_plan_core_generation"],
                "core_source_generation": mission["master_plan_core_source_generation"],
                "catalog_sha256": planning["catalog_sha256"],
                "planner_prompt_sha256": planning["planner_prompt_sha256"],
                "master_source_generation_sha256": master.generation_sha256,
                "master_source_manifest_sha256": master.source_member_manifest_sha256,
                "master_prompt_sha256": master.effective_prompt_sha256,
                "source_profile_id": "hermes", "selected_source_ids": selected,
                "execution_mode": mission["execution_mode"],
            }
        if _mission_store_identity(config, path) != ledger_identity:
            raise ValueError
        if (time.monotonic() >= deadline or master.is_current_sealed(custody, now=time.monotonic()) is not True
                or _read_root_planning_catalog(custody.core_source_generation)[1] != catalog_sha):
            raise ValueError
    except Exception:
        raise CoreInspectionDenied("durable master plan is unavailable or stale") from None
    return {"schema": 1, "nonce": request["nonce"], "ok": True, "plan_data": row}


def observe_read_native_activity(config: CoreGatewayConfig, *, request: dict[str, Any],
                                 caller_pid: int, caller_uid: int, caller_gid: int,
                                 peer_pid: int, peer_uid: int, peer_gid: int,
                                 custody: Any, registry: Any) -> dict[str, Any]:
    """Return real native-child callbacks after a fresh owner JWT/ingress join."""
    required = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
                "core_generation", "ingress_nonce", "ingress_proof_sha256"}
    if (type(request) is not dict or set(request) != required or request.get("schema") != 1
            or request.get("op") != "read-native-activity"
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or re.fullmatch(r"[0-9a-f]{64}", request.get("nonce", "")) is None
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384
            or not request["access_jwt"].isascii()
            or not _is_hash(request.get("core_generation"))
            or re.fullmatch(r"[0-9a-f]{64}", request.get("ingress_nonce", "")) is None
            or not _is_hash(request.get("ingress_proof_sha256"))):
        raise CoreInspectionDenied("native activity read request is invalid")
    caller_start = _proc_start_ticks(caller_pid)
    issue_key = (caller_pid, caller_start, request["ingress_nonce"],
                 request["ingress_proof_sha256"])
    with _RETAINED_INGRESS_LOCK:
        retained = _RETAINED_INGRESS_ISSUES.get(issue_key)
    if (retained is None or retained.peer != (peer_pid, peer_uid, peer_gid)
            or retained.core_generation != request["core_generation"]
            or retained.config_sha256 != config.config_sha256
            or time.monotonic() >= retained.expires_monotonic):
        raise CoreInspectionDenied("native activity ingress is stale")
    deadline = retained.expires_monotonic
    ingress = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)), deadline_monotonic=deadline)
    owner_hash = hashlib.sha256(principal.subject.encode("utf-8")).hexdigest()
    if (principal.email.casefold() not in config.allowed_emails
            or hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest()
                != principal.token_fingerprint
            or ingress["proof_sha256"] != retained.proof_sha256
            or ingress["core_source_generation"] != custody.core_source_generation
            or ingress["core_generation"] != custody.core_generation
            or registry is not _CORE_NATIVE_REGISTRY
            or _CORE_NATIVE_REGISTRY_TYPE is None
            or type(registry) is not _CORE_NATIVE_REGISTRY_TYPE
            or not callable(getattr(registry, "read_native_activity", None))):
        raise CoreInspectionDenied("native activity owner ingress changed")
    try:
        activity = registry.read_native_activity(owner_subject_sha256=owner_hash,
            core_generation=custody.core_generation,
            core_source_generation=custody.core_source_generation)
        final = observe_current_ingress(config, nonce=retained.nonce,
            caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
            peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
            _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
        if (final["proof_sha256"] != retained.proof_sha256 or time.monotonic() >= deadline
                or type(activity) is not dict or set(activity) != {
                    "schema", "observed_at", "window_seconds", "coverage", "instances", "relations"}
                or activity.get("schema") != 1
                or not isinstance(activity.get("instances"), list)
                or len(activity["instances"]) > 100
                or sum(len(item.get("events", [])) for item in activity["instances"]
                       if isinstance(item, dict)) > 200
                or activity.get("relations") != []):
            raise ValueError
    except Exception:
        raise CoreInspectionDenied("current native activity is unavailable") from None
    return {"schema": 1, "nonce": request["nonce"], "ok": True, "activity": activity}


def observe_final_effect_request(config: CoreGatewayConfig, *, request: dict[str, Any],
                                 caller_pid: int, caller_uid: int, caller_gid: int,
                                 peer_pid: int, peer_uid: int, peer_gid: int,
                                 registry: Any) -> dict[str, Any]:
    """Root-authenticate a fresh BFF request before listing or deciding one review."""
    op = request.get("op") if isinstance(request, dict) else None
    base = {"schema", "op", "nonce", "peer_pid", "peer_uid", "peer_gid", "access_jwt",
            "core_generation", "ingress_nonce", "ingress_proof_sha256", "owner_turn_handle"}
    expected = (base if op == "list-final-effects" else
                base | {"pending_id", "review_sha256", "decision", "idempotency_key"}
                if op == "decide-final-effect" else set())
    if (not expected or type(request) is not dict or set(request) != expected
            or type(request.get("schema")) is not int or request["schema"] != 1
            or type(request.get("nonce")) is not str
            or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None
            or (request.get("peer_pid"), request.get("peer_uid"), request.get("peer_gid"))
                != (peer_pid, peer_uid, peer_gid)
            or not all(type(value) is int for value in (peer_pid, peer_uid, peer_gid))
            or not isinstance(request.get("access_jwt"), str)
            or not 1 <= len(request["access_jwt"]) <= 16_384
            or not request["access_jwt"].isascii()
            or not _is_hash(request.get("core_generation"))
            or not isinstance(request.get("ingress_nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["ingress_nonce"]) is None
            or not _is_hash(request.get("ingress_proof_sha256"))
            or not isinstance(request.get("owner_turn_handle"), str)
            or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", request["owner_turn_handle"]) is None):
        raise CoreInspectionDenied("final-effect review request is invalid")
    if (registry is None or registry is not _CORE_NATIVE_REGISTRY
            or _CORE_NATIVE_REGISTRY_TYPE is None or type(registry) is not _CORE_NATIVE_REGISTRY_TYPE):
        raise CoreInspectionDenied("root final-effect observer is unavailable")
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    caller_start = _proc_start_ticks(caller_pid)
    retained = _consume_ingress_issue(caller_pid=caller_pid, caller_start_ticks=caller_start,
        nonce=request["ingress_nonce"], proof_sha256=request["ingress_proof_sha256"],
        peer=(peer_pid, peer_uid, peer_gid), core_generation=request["core_generation"], config=config)
    deadline = min(deadline, retained.expires_monotonic)
    current = observe_current_ingress(config, nonce=retained.nonce,
        caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
        peer_pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid,
        _issued=retained.issued_monotonic, _deadline=deadline, _retain_issuance=False)
    gateway_pidfd, gateway_start, _gateway_invocation = _check_unit_process(
        config, unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
    try:
        if (gateway_start != retained.caller_start_ticks
                or current["proof_sha256"] != retained.proof_sha256
                or current["core_generation"] != retained.core_generation
                or time.monotonic() >= deadline):
            raise CoreInspectionDenied("final-effect review ingress changed")
    finally:
        os.close(gateway_pidfd)
    from .gateway import validate_access_jwt
    principal = validate_access_jwt(request["access_jwt"],
        policy=config.policy(_learning_jwks(config, deadline=deadline)), deadline_monotonic=deadline)
    subject_sha256 = hashlib.sha256(principal.subject.encode("utf-8", errors="strict")).hexdigest()
    if (principal.email.casefold() not in config.allowed_emails
            or not secrets.compare_digest(
                hashlib.sha256(request["access_jwt"].encode("ascii")).hexdigest(),
                principal.token_fingerprint)
            or time.monotonic() >= min(deadline, principal.expires_at - time.time() + time.monotonic())):
        raise CoreInspectionDenied("final-effect review owner is unavailable")
    gateway_peer = (caller_pid, caller_uid, caller_gid)
    if op == "list-final-effects":
        reviews = registry.list_final_effects_for_owner(
            request["owner_turn_handle"], subject_sha256, gateway_peer)
        body = [{"pending_id": item.pending_id, "review_sha256": item.review_sha256,
                 "tool_name": item.tool_name, "preview_json": item.preview_json,
                 "status": item.status, "expires_monotonic": item.expires_monotonic}
                for item in reviews]
        result = {"schema": 1, "nonce": request["nonce"], "ok": True, "reviews": body}
    else:
        status = registry.decide_final_effect_for_owner(
            request["owner_turn_handle"], subject_sha256, gateway_peer,
            pending_id=request["pending_id"], review_sha256=request["review_sha256"],
            decision=request["decision"], idempotency_key=request["idempotency_key"])
        if status not in {"approved", "denied"}:
            raise CoreInspectionDenied("final-effect review decision is unavailable")
        result = {"schema": 1, "nonce": request["nonce"], "ok": True, "status": status}
    if time.monotonic() >= deadline:
        raise CoreInspectionDenied("final-effect review expired")
    return result


def observe_native_mission_preflight(config: CoreGatewayConfig, *, request: dict[str, Any],
                                     caller_pid: int, caller_uid: int, caller_gid: int,
                                     registry: Any) -> dict[str, Any]:
    """Re-read one exact spent mission row from the fixed gateway process."""
    fields = {"schema", "op", "nonce", "gateway_turn_id", "owner_subject_sha256", "mission_binding"}
    if (type(request) is not dict or set(request) != fields
            or type(request.get("schema")) is not int or request["schema"] != 1
            or request.get("op") != "preflight-native-mission"
            or not isinstance(request.get("nonce"), str)
            or re.fullmatch(r"[0-9a-f]{64}", request["nonce"]) is None
            or not isinstance(request.get("gateway_turn_id"), str)
            or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", request["gateway_turn_id"]) is None
            or not _is_hash(request.get("owner_subject_sha256"))):
        raise CoreInspectionDenied("mission preflight request is invalid")
    if (registry is None or registry is not _CORE_NATIVE_REGISTRY
            or _CORE_NATIVE_REGISTRY_TYPE is None or type(registry) is not _CORE_NATIVE_REGISTRY_TYPE):
        raise CoreInspectionDenied("root mission observer is unavailable")
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    gateway_pidfd, gateway_start, _invocation = _check_unit_process(
        config, unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
    custody = None
    try:
        if caller_uid != config.gateway_uid or time.monotonic() >= deadline:
            raise CoreInspectionDenied("mission preflight caller is not the current gateway")
        custody = capture_current_core_native_custody(config)
        if (custody.core_generation != _CORE_NATIVE_CUSTODY.core_generation
                or custody.core_source_generation != _CORE_NATIVE_CUSTODY.core_source_generation
                or custody.core_pid != _CORE_NATIVE_CUSTODY.core_pid
                or custody.core_start_ticks != _CORE_NATIVE_CUSTODY.core_start_ticks):
            raise CoreInspectionDenied("mission preflight core custody changed")
        result = registry.preflight_native_mission(
            _mission_binding_from_wire(request["mission_binding"]),
            owner_subject_sha256=request["owner_subject_sha256"],
            gateway_turn_id=request["gateway_turn_id"])
        if result is not True or time.monotonic() >= deadline:
            raise CoreInspectionDenied("spent mission preflight is unavailable")
    finally:
        os.close(gateway_pidfd)
        if custody is not None:
            os.close(custody._core_pidfd)
    return {"schema": 1, "nonce": request["nonce"], "ok": True}


def _overview_digest(values: dict[str, Any]) -> str:
    canonical = json.dumps(values, sort_keys=True, separators=(",", ":"),
                           allow_nan=False).encode("ascii")
    return hashlib.sha256(b"hermes-jarvis-core-overview-v1\0" + canonical).hexdigest()


def _deny():
    raise CoreInspectionDenied("fixed core ingress observation denied")


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _read_exact(conn: socket.socket, size: int, deadline: float) -> bytes:
    result = bytearray()
    while len(result) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        conn.settimeout(remaining)
        chunk = conn.recv(size - len(result))
        if not chunk:
            raise OSError("short IPC frame")
        result.extend(chunk)
    return bytes(result)


def _run_fixed(argv: tuple[str, ...], *, deadline: float, maximum: int) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=remaining, check=False, close_fds=True,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"})
    if result.returncode != 0 or len(result.stdout) > maximum:
        raise ValueError("fixed observation command failed")
    return result.stdout


def _unit_properties(unit: str, *, deadline: float) -> dict[str, str]:
    allowed = {CORE_GATEWAY_UNIT, CORE_SERVICE_UNIT, TUNNEL_UNIT}
    if unit not in allowed:
        raise ValueError("unknown fixed unit")
    raw = _run_fixed(("/usr/bin/systemctl", "show", unit, "--no-pager",
        "--property=LoadState", "--property=ActiveState", "--property=SubState",
        "--property=MainPID", "--property=ControlGroup", "--property=FragmentPath",
        "--property=User", "--property=Group", "--property=DynamicUser",
        "--property=SupplementaryGroups", "--property=DropInPaths",
        "--property=InvocationID"), deadline=deadline, maximum=8192)
    props = {}
    for line in raw.decode("utf-8", "strict").splitlines():
        if "=" not in line:
            raise ValueError("malformed systemd output")
        key, value = line.split("=", 1)
        if key in props:
            raise ValueError("duplicate systemd property")
        props[key] = value
    if (props.get("LoadState") != "loaded" or props.get("ActiveState") != "active"
            or props.get("SubState") != "running" or props.get("DropInPaths") != ""
            or not re.fullmatch(r"[0-9a-fA-F-]{32,36}", props.get("InvocationID", ""))):
        _deny()
    return props


def _protected_file_sha(path: Path, *, owner_uid: int = 0, owner_gid: int | None = None,
                        exact_mode: int | None = None, deadline: float | None = None,
                        allow_owner_group_write: bool = False) -> str:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                 getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != owner_uid
                or (owner_gid is not None and info.st_gid != owner_gid)
                or (stat.S_IMODE(info.st_mode) & 0o002)
                or (not allow_owner_group_write and stat.S_IMODE(info.st_mode) & 0o020)
                or info.st_nlink != 1
                or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)
                or info.st_size > MAX_HASH_FILE_BYTES):
            raise ValueError("fixed file is not immutable root custody")
        digest = hashlib.sha256()
        while True:
            if deadline is not None and time.monotonic() >= deadline:
                raise TimeoutError("fixed file hash deadline expired")
            block = os.read(fd, 8192)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        signature = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_uid,
                                  item.st_gid, item.st_nlink, item.st_size,
                                  item.st_mtime_ns, item.st_ctime_ns)
        if (signature(after) != signature(info) or signature(named) != signature(info)
                or (deadline is not None and time.monotonic() >= deadline)):
            raise ValueError("fixed file changed while hashing")
        return digest.hexdigest()
    finally:
        os.close(fd)


def _read_proc_environment(pid: int, *, deadline: float) -> dict[bytes, bytes]:
    env_fd = os.open(f"/proc/{pid}/environ", os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
    try:
        environment = bytearray()
        while len(environment) <= 1024 * 1024:
            if time.monotonic() >= deadline:
                raise TimeoutError("core environment deadline expired")
            block = os.read(env_fd, min(16_384, 1024 * 1024 + 1 - len(environment)))
            if not block:
                break
            environment.extend(block)
    finally:
        os.close(env_fd)
    if len(environment) > 1024 * 1024:
        _deny()
    result: dict[bytes, bytes] = {}
    # Convert the bounded mutable read buffer before splitting: bytearray keys are
    # unhashable and must never escape into the exact environment validator.
    for entry in bytes(environment).split(b"\0"):
        if not entry:
            continue
        key, sep, value = entry.partition(b"=")
        if not sep or key in result:
            _deny()
        result[key] = value
    return result


def _validate_core_process_environment(environment: dict[bytes, bytes], secret: bytes) -> None:
    token = environment.get(b"HERMES_DASHBOARD_SESSION_TOKEN")
    expected = {
        b"HOME": b"/home/admin",
        b"HERMES_HOME": b"/home/admin/.hermes",
        b"PATH": CORE_PATH.encode("ascii"),
        b"HERMES_DISABLE_LAZY_INSTALLS": b"1",
        b"PYTHONNOUSERSITE": b"1",
        b"PYTHONDONTWRITEBYTECODE": b"1",
        b"PYTHONPATH": _core_pythonpath().encode("ascii"),
        b"CREDENTIALS_DIRECTORY": CORE_CREDENTIALS_DIRECTORY.encode("ascii"),
    }
    if (any(environment.get(key) != value for key, value in expected.items())
            or any(key in environment for key in (b"PYTHONHOME", b"PYTHONUSERBASE",
                                                   b"PYTHONSTARTUP", b"VIRTUAL_ENV"))
            or token is None or not secrets.compare_digest(token, secret)):
        _deny()


def _current_core_credential(pid: int, config: CoreGatewayConfig, *, deadline: float) -> None:
    """Join the protected backend token source to the live process privately."""
    parent = os.lstat(CORE_TOKEN_SOURCE.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0
            or parent.st_gid != config.gateway_gid or stat.S_IMODE(parent.st_mode) != 0o750):
        _deny()
    fd = os.open(CORE_TOKEN_SOURCE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0))
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o640
                or info.st_nlink != 1 or not 32 <= info.st_size <= 4097):
            _deny()
        secret = bytearray()
        while len(secret) <= 4097:
            if time.monotonic() >= deadline:
                raise TimeoutError("core credential deadline expired")
            block = os.read(fd, min(1024, 4098 - len(secret)))
            if not block:
                break
            secret.extend(block)
        after = os.fstat(fd)
        if ((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size,
                    after.st_mtime_ns, after.st_ctime_ns)):
            _deny()
        if secret.endswith(b"\n"):
            secret = secret[:-1]
        if (not 32 <= len(secret) <= 4096
                or any(byte < 0x21 or byte > 0x7e for byte in secret)):
            _deny()
    finally:
        os.close(fd)
    # The value is neither returned, hashed into a public proof, nor logged.
    environment: dict[bytes, bytes] = {}
    try:
        environment = _read_proc_environment(pid, deadline=deadline)
        _validate_core_process_environment(environment, secret)
    finally:
        environment.clear()
        for index in range(len(secret)):
            secret[index] = 0


def _run_source_git(args: tuple[str, ...], *, deadline: float, maximum: int) -> bytes:
    argv = ("/usr/bin/git", "--no-optional-locks", "-c", f"safe.directory={CORE_SOURCE}",
            "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
            "-C", str(CORE_SOURCE), *args)
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, close_fds=True,
        env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C",
             "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"})
    assert proc.stdout is not None
    output = bytearray()
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                proc.kill()
                _deny()
            events = poller.poll(max(1, min(50, int(remaining * 1000))))
            if not events:
                if proc.poll() is not None:
                    break
                continue
            try:
                block = os.read(fd, min(4096, maximum + 1 - len(output)))
            except BlockingIOError:
                continue
            if not block:
                break
            output.extend(block)
            if len(output) > maximum:
                proc.kill()
                _deny()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or proc.wait(timeout=remaining) != 0:
            _deny()
        return bytes(output)
    finally:
        if proc.poll() is None:
            proc.kill()
            try:
                proc.wait(timeout=0.5)
            except subprocess.TimeoutExpired:
                pass
        proc.stdout.close()


def _root_immutable_directory(path: Path) -> None:
    """Require every fixed adapter path component to be a real root directory."""
    absolute = Path(os.path.abspath(path))
    fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in absolute.parts[1:]:
            child = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0), dir_fd=fd)
            info = os.fstat(child)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) & 0o022):
                os.close(child)
                _deny()
            os.close(fd)
            fd = child
    finally:
        os.close(fd)


def _current_native_adapter_generation(*, deadline: float) -> str:
    """Verify the immutable installer adapter closure used by the live core."""
    try:
        declared_file = Path(__file__).absolute()
        resolved_file = Path(__file__).resolve(strict=True)
        source = CORE_NATIVE_ADAPTER_SOURCE
        if (declared_file != resolved_file or not source.is_absolute()
                or source != resolved_file.parents[2]
                or source != CORE_NATIVE_ADAPTER_SOURCE):
            _deny()
        _root_immutable_directory(source)
        values: dict[str, str] = {}
        for relative, expected in CORE_NATIVE_ADAPTER_SOURCE_FILES.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("native adapter source proof deadline expired")
            path = source / relative
            _root_immutable_directory(path.parent)
            actual = _protected_file_sha(path, owner_uid=0, deadline=deadline)
            if actual != expected:
                _deny()
            values[relative] = actual
        canonical = json.dumps({"adapter_source": str(source), "files": values},
                               sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(
            b"hermes-jarvis-native-adapter-source-v1\0" + canonical).hexdigest()
    except Exception:
        _deny()


def _core_pythonpath() -> str:
    """The sole allowed import path: pinned Hermes followed by installer adapter."""
    return f"{CORE_SOURCE}:{CORE_NATIVE_ADAPTER_SOURCE}"


def verify_staged_native_resources_plugin(*, deadline: float) -> str:
    """Root-read back the fixed staged plugin bytes before native owner admission.

    This proves the copied bundle matches the immutable installer package. It
    does not prove activation or registration; the native live ToolEntry receipt
    and observed provider request remain separate required evidence.
    """
    if os.geteuid() != 0 or time.monotonic() >= deadline:
        _deny()
    source_generation = _current_native_adapter_generation(deadline=deadline)
    account = pwd.getpwnam("admin")
    if account.pw_uid != 1000 or account.pw_gid != 1000 or account.pw_dir != str(CORE_ADMIN_HOME):
        _deny()
    directory_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                           | getattr(os, "O_NOFOLLOW", 0))
    try:
        expectations = (
            ("home", 0, 0, None),
            ("admin", account.pw_uid, account.pw_gid, None),
            (".hermes", account.pw_uid, account.pw_gid, 0o700),
            ("plugins", account.pw_uid, account.pw_gid, None),
            (CORE_NATIVE_PLUGIN_ID, 0, 0, 0o555),
        )
        for component, owner, group, exact_mode in expectations:
            child_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                               | getattr(os, "O_NOFOLLOW", 0), dir_fd=directory_fd)
            info = os.fstat(child_fd)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_gid != group
                    or stat.S_IMODE(info.st_mode) & 0o022
                    or (exact_mode is not None and stat.S_IMODE(info.st_mode) != exact_mode)):
                os.close(child_fd)
                _deny()
            os.close(directory_fd)
            directory_fd = child_fd
        if set(os.listdir(directory_fd)) != set(CORE_NATIVE_PLUGIN_STAGED_FILES):
            _deny()
        values: dict[str, str] = {}
        for name, expected in CORE_NATIVE_PLUGIN_STAGED_FILES.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("staged native plugin proof deadline expired")
            fd = os.open(name, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0), dir_fd=directory_fd)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_gid != 0
                        or stat.S_IMODE(before.st_mode) != 0o444 or before.st_nlink != 1
                        or before.st_size > 64 * 1024):
                    _deny()
                content = bytearray()
                while len(content) <= 64 * 1024:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("staged native plugin proof deadline expired")
                    chunk = os.read(fd, min(8192, 64 * 1024 + 1 - len(content)))
                    if not chunk:
                        break
                    content.extend(chunk)
                after = os.fstat(fd)
                named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                signature = lambda value: (value.st_dev, value.st_ino, value.st_mode,
                    value.st_uid, value.st_gid, value.st_nlink, value.st_size,
                    value.st_mtime_ns, value.st_ctime_ns)
                if (len(content) != before.st_size or len(content) > 64 * 1024
                        or signature(before) != signature(after)
                        or signature(before) != signature(named)):
                    _deny()
                data = bytes(content)
            finally:
                os.close(fd)
            actual = hashlib.sha256(data).hexdigest()
            if actual != expected:
                _deny()
            values[name] = actual
        if time.monotonic() >= deadline or _current_native_adapter_generation(deadline=deadline) != source_generation:
            _deny()
        canonical = json.dumps({"adapter_generation": source_generation, "bundle": values},
                               sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(
            b"hermes-jarvis-native-plugin-staged-v1\0" + canonical).hexdigest()
    except Exception:
        _deny()
    finally:
        os.close(directory_fd)


def _current_core_source(config: CoreGatewayConfig, *, deadline: float) -> str:
    """Validate the exact selected official source/runtime closure without exporting paths."""
    try:
        info = os.lstat(CORE_SOURCE)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != config.core_uid
                or info.st_gid != config.core_gid or stat.S_IMODE(info.st_mode) & 0o002):
            _deny()
        git_info = os.lstat(CORE_SOURCE / ".git")
        if (not stat.S_ISDIR(git_info.st_mode) or git_info.st_uid != config.core_uid
                or git_info.st_gid != config.core_gid or stat.S_IMODE(git_info.st_mode) & 0o002):
            _deny()
        head = _run_source_git(("rev-parse", "--verify", "HEAD"), deadline=deadline, maximum=128)
        if head.strip().decode("ascii", "strict") != CORE_SOURCE_REVISION:
            _deny()
        dirty = _run_source_git(("status", "--porcelain=v1", "--untracked-files=all",
                                 "--ignore-submodules=none"), deadline=deadline, maximum=8192)
        if dirty:
            _deny()
        digests: list[str] = []
        for relative, expected in CORE_SOURCE_FILES.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("source file proof deadline expired")
            actual = _protected_file_sha(CORE_SOURCE / relative, owner_uid=config.core_uid,
                owner_gid=config.core_gid, exact_mode=0o664, deadline=deadline,
                allow_owner_group_write=True)
            if actual != expected:
                _deny()
            digests.append(actual)
        pyvenv = config.core_python.parent.parent / "pyvenv.cfg"
        actual_pyvenv = _protected_file_sha(pyvenv, owner_uid=config.core_uid,
            owner_gid=config.core_gid, deadline=deadline, allow_owner_group_write=True)
        if actual_pyvenv != CORE_PYVENV_CFG_SHA256 or config.core_python_sha256 != CORE_PYTHON_SHA256:
            _deny()
        closure = {"source_revision": CORE_SOURCE_REVISION,
                   "files": dict(zip(CORE_SOURCE_FILES, digests)),
                   "pyvenv_cfg_sha256": actual_pyvenv,
                   "python_sha256": CORE_PYTHON_SHA256}
        canonical = json.dumps(closure, sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(b"hermes-jarvis-core-source-generation-v1\0" + canonical).hexdigest()
    except Exception:
        _deny()


def _current_native_tool_source(config: CoreGatewayConfig, *, deadline: float) -> str:
    """Verify only the additional pinned source used by the native tool policy reader."""
    try:
        values: dict[str, str] = {}
        for relative, expected in CORE_NATIVE_TOOL_SOURCE_FILES.items():
            if time.monotonic() >= deadline:
                raise TimeoutError("native source proof deadline expired")
            actual = _protected_file_sha(CORE_SOURCE / relative, owner_uid=config.core_uid,
                owner_gid=config.core_gid, exact_mode=0o664, deadline=deadline,
                allow_owner_group_write=True)
            if actual != expected:
                _deny()
            values[relative] = actual
        canonical = json.dumps({"source_revision": CORE_SOURCE_REVISION, "files": values},
                               sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha256(b"hermes-jarvis-native-tool-source-v1\0" + canonical).hexdigest()
    except Exception:
        _deny()


def _proc_start_ticks(pid: int) -> str:
    raw = Path(f"/proc/{pid}/stat").read_text()
    close = raw.rfind(")")
    fields = raw[close + 2:].split()
    if close < 0 or len(fields) <= 19 or not fields[19].isdecimal():
        raise ValueError("invalid process stat")
    return fields[19]


def _process(pid: int, *, uid: int, gid: int, argv: tuple[str, ...], executable: Path,
             executable_sha256: str, cgroup: str, deadline: float,
             supplementary_gid: int | None = None,
             executable_owner_uid: int = 0, executable_owner_gid: int | None = None,
             executable_mode: int | None = None) -> tuple[int, str]:
    if pid <= 1 or time.monotonic() >= deadline or not hasattr(os, "pidfd_open"):
        _deny()
    pidfd = os.pidfd_open(pid, 0)
    try:
        start = _proc_start_ticks(pid)
        status = Path(f"/proc/{pid}/status").read_text()
        fields = {}
        for line in status.splitlines():
            key, sep, value = line.partition(":")
            if sep:
                fields[key] = value.strip().split()
        actual_uid = fields.get("Uid", [])
        actual_gid = fields.get("Gid", [])
        groups = fields.get("Groups", [])
        if (len(actual_uid) < 2 or len(actual_gid) < 2 or int(actual_uid[1]) != uid
                or int(actual_gid[1]) != gid
                or (supplementary_gid is not None and str(supplementary_gid) not in groups)):
            _deny()
        raw_argv = Path(f"/proc/{pid}/cmdline").read_bytes()
        actual_argv = tuple(item.decode("utf-8", "strict") for item in raw_argv.rstrip(b"\0").split(b"\0"))
        actual_executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
        actual_cgroup = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
        if (actual_argv != argv or actual_executable != executable
                or f"0::{cgroup}" not in actual_cgroup
                or _protected_file_sha(actual_executable, owner_uid=executable_owner_uid,
                    owner_gid=executable_owner_gid, exact_mode=executable_mode,
                    deadline=deadline) != executable_sha256
                or _proc_start_ticks(pid) != start):
            _deny()
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poll.poll(0):
            _deny()
        return pidfd, start
    except Exception:
        os.close(pidfd)
        raise


def _check_unit_process(config: CoreGatewayConfig, *, unit: str, pid: int, deadline: float,
                        peer_uid: int | None = None, peer_gid: int | None = None):
    props = _unit_properties(unit, deadline=deadline)
    main_pid = int(props.get("MainPID", "0"))
    if main_pid != pid or props.get("ControlGroup") != f"/system.slice/{unit}":
        _deny()
    if unit == CORE_GATEWAY_UNIT:
        path, expected_hash = CORE_GATEWAY_UNIT_PATH, config.gateway_unit_sha256
        exe, exe_hash, argv = GATEWAY_EXECUTABLE, config.gateway_python_sha256, (
            GATEWAY_ARGV[0], *GATEWAY_ARGV[1:])
        uid, gid, supplementary = config.gateway_uid, config.gateway_gid, None
        executable_owner = (0, None, None)
        if props.get("FragmentPath") != str(path) or props.get("User") != str(uid) or props.get("Group") != str(gid):
            _deny()
    elif unit == CORE_SERVICE_UNIT:
        path, expected_hash = CORE_UNIT_PATH, config.core_unit_sha256
        launcher_hash = _protected_file_sha(CORE_LAUNCHER, deadline=deadline)
        if launcher_hash != config.core_launcher_sha256:
            _deny()
        try:
            executable = config.core_python.resolve(strict=True)
        except OSError:
            _deny()
        if (config.core_python != CORE_PYTHON_LINK or executable != CORE_PYTHON_REAL
                or os.readlink(config.core_python) != CORE_PYTHON_LINK_TARGET):
            _deny()
        exe, exe_hash = executable, config.core_python_sha256
        argv = (str(config.core_python), *CORE_ARGV_TAIL)
        uid, gid, supplementary = config.core_uid, config.core_gid, None
        executable_owner = (config.core_uid, config.core_gid, 0o755)
        if (props.get("FragmentPath") != str(path) or props.get("User") != "admin"
                or props.get("Group") != str(config.core_gid)):
            _deny()
    elif unit == TUNNEL_UNIT:
        path, expected_hash = TUNNEL_UNIT_PATH, config.tunnel_unit_sha256
        exe, exe_hash, argv = TUNNEL_EXECUTABLE, config.cloudflared_binary_sha256, TUNNEL_ARGV
        uid, gid, supplementary = peer_uid, peer_gid, config.gateway_gid
        executable_owner = (0, None, None)
        if (props.get("FragmentPath") != str(path) or props.get("DynamicUser") != "yes"
                or props.get("SupplementaryGroups") != str(config.gateway_gid)):
            _deny()
    else:
        _deny()
    if _protected_file_sha(path, deadline=deadline) != expected_hash:
        _deny()
    try:
        pidfd, start = _process(main_pid, uid=uid, gid=gid, argv=argv, executable=exe,
            executable_sha256=exe_hash, cgroup=props["ControlGroup"], deadline=deadline,
            supplementary_gid=supplementary, executable_owner_uid=executable_owner[0],
            executable_owner_gid=executable_owner[1], executable_mode=executable_owner[2])
        return pidfd, start, props["InvocationID"]
    except Exception:
        raise


def capture_current_core_native_custody(config: CoreGatewayConfig) -> CoreNativeObserverCustody:
    """Capture the fixed, active core process for the private native observer socket."""
    if os.geteuid() != 0 or type(config) is not CoreGatewayConfig:
        raise CoreInspectionDenied("root core custody is required")
    account = pwd.getpwnam("admin")
    if (account.pw_uid != config.core_uid or account.pw_gid != config.core_gid
            or account.pw_dir != str(CORE_ADMIN_HOME)):
        raise CoreInspectionDenied("fixed core identity differs")
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    _config_current(config)
    props = _unit_properties(CORE_SERVICE_UNIT, deadline=deadline)
    try:
        core_pid = int(props.get("MainPID", "0"))
    except ValueError:
        _deny()
    pidfd, start, invocation = _check_unit_process(
        config, unit=CORE_SERVICE_UNIT, pid=core_pid, deadline=deadline)
    try:
        _current_core_credential(core_pid, config, deadline=deadline)
        source_generation = _current_core_source(config, deadline=deadline)
        if Path(f"/proc/{core_pid}/cwd").resolve(strict=True) != CORE_WORKSPACE:
            _deny()
        listener_inode = _core_listener_inode(core_pid)
        generation_payload = (f"{invocation}\0{core_pid}\0{start}\0{listener_inode}\0"
                              f"{source_generation}").encode("ascii")
        core_generation = hashlib.sha256(
            b"hermes-jarvis-core-generation-v1\0" + generation_payload).hexdigest()
        if (time.monotonic() >= deadline or _boot_id() != config.boot_id
                or _proc_start_ticks(core_pid) != start
                or int(_unit_properties(CORE_SERVICE_UNIT, deadline=deadline).get("MainPID", "0")) != core_pid
                or _core_listener_inode(core_pid) != listener_inode):
            _deny()
        custody = CoreNativeObserverCustody(
            core_pid=core_pid, core_uid=config.core_uid, core_gid=config.core_gid,
            core_start_ticks=start, core_generation=core_generation,
            core_invocation_id=invocation, core_listener_inode=listener_inode,
            core_source_generation=source_generation, core_unit_sha256=config.core_unit_sha256,
            core_executable_sha256=config.core_python_sha256,
            boot_id=config.boot_id,
            config_sha256=config.config_sha256, _core_pidfd=pidfd, _seal=_NATIVE_CUSTODY_SEAL)
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            _deny()
        return custody
    except Exception:
        os.close(pidfd)
        raise


def _start_optional_core_native_observer(config: CoreGatewayConfig,
                                         stop: threading.Event | None = None) -> bool:
    """Start the separate admin-readable observer only with verified current source custody."""
    global _CORE_NATIVE_CUSTODY, _CORE_NATIVE_REGISTRY, _CORE_NATIVE_REGISTRY_TYPE
    global _CORE_NATIVE_STOP, _CORE_NATIVE_THREAD
    custody = None
    registry = None
    worker = None
    stop = stop or threading.Event()
    try:
        if stop.is_set():
            return False
        from ..components.resources_active_profile_source import RootVerifiedJarvisMasterSource
        from .core_native_observer import RootCoreNativeObservationRegistry, serve_core_native_observer
        custody = capture_current_core_native_custody(config)
        if stop.is_set():
            raise CoreInspectionDenied("optional native observer startup was cancelled")
        try:
            source = RootVerifiedJarvisMasterSource.current_master_source(custody, config=config)
        except Exception:
            source = None
        if (source is not None and (type(source) is not RootVerifiedJarvisMasterSource
                or source.profile_id != "hermes" or source.native_profile_key != "default"
                or source.display_name != "Jarvis"
                or source.is_current_sealed(custody=custody, now=time.monotonic()) is not True)):
            source = None
        registry = RootCoreNativeObservationRegistry.from_current_core_custody(
            custody, selected_profile_source=source, config=config)
        if type(registry) is not RootCoreNativeObservationRegistry:
            raise CoreInspectionDenied("native observation registry is unavailable")
        if stop.is_set():
            raise CoreInspectionDenied("optional native observer startup was cancelled")
        worker = threading.Thread(target=serve_core_native_observer,
            kwargs={"registry": registry, "socket_path": CORE_NATIVE_OBSERVER_SOCKET,
                    "admin_gid": 1000, "stop_event": stop}, daemon=True,
            name="jarvis-native-observer")
        worker.start()
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and not stop.is_set():
            if not worker.is_alive():
                raise CoreInspectionDenied("native observer listener did not start")
            try:
                parent = os.lstat(CORE_NATIVE_OBSERVER_DIRECTORY)
                listener = os.lstat(CORE_NATIVE_OBSERVER_SOCKET)
                if (stat.S_ISDIR(parent.st_mode) and parent.st_uid == 0 and parent.st_gid == 1000
                        and stat.S_IMODE(parent.st_mode) == 0o750
                        and stat.S_ISSOCK(listener.st_mode) and listener.st_uid == 0
                        and listener.st_gid == 1000 and stat.S_IMODE(listener.st_mode) == 0o660):
                    if (source is not None and source.is_current_sealed(
                            custody=custody, now=time.monotonic()) is not True):
                        source = None
                    if stop.is_set():
                        raise CoreInspectionDenied("optional native observer startup was cancelled")
                    _CORE_NATIVE_CUSTODY = custody
                    _CORE_NATIVE_REGISTRY = registry
                    _CORE_NATIVE_REGISTRY_TYPE = RootCoreNativeObservationRegistry
                    _CORE_NATIVE_STOP = stop
                    _CORE_NATIVE_THREAD = worker
                    return True
            except FileNotFoundError:
                pass
            time.sleep(0.02)
        raise CoreInspectionDenied("native observer listener is unavailable")
    except Exception:
        stop.set()
        if worker is not None and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        if registry is not None:
            try:
                registry.close()
            except Exception:
                pass
        if custody is not None:
            try:
                os.close(custody._core_pidfd)
            except OSError:
                pass
        return False


def _stop_optional_core_native_observer() -> None:
    global _CORE_NATIVE_CUSTODY, _CORE_NATIVE_REGISTRY, _CORE_NATIVE_REGISTRY_TYPE
    global _CORE_NATIVE_STOP, _CORE_NATIVE_THREAD
    global _CORE_NATIVE_INIT_STOP, _CORE_NATIVE_INIT_THREAD
    init_stop, init_thread = _CORE_NATIVE_INIT_STOP, _CORE_NATIVE_INIT_THREAD
    _CORE_NATIVE_INIT_STOP = None
    _CORE_NATIVE_INIT_THREAD = None
    if init_stop is not None:
        init_stop.set()
    if init_thread is not None and init_thread is not threading.current_thread():
        init_thread.join(timeout=1.0)
    stop, worker, registry, custody = (
        _CORE_NATIVE_STOP, _CORE_NATIVE_THREAD, _CORE_NATIVE_REGISTRY, _CORE_NATIVE_CUSTODY)
    _CORE_NATIVE_STOP = None
    _CORE_NATIVE_THREAD = None
    _CORE_NATIVE_REGISTRY = None
    _CORE_NATIVE_REGISTRY_TYPE = None
    _CORE_NATIVE_CUSTODY = None
    if stop is not None:
        stop.set()
    if worker is not None and worker is not threading.current_thread():
        worker.join(timeout=1.0)
    if registry is not None:
        try:
            registry.close()
        except Exception:
            pass
    if custody is not None:
        try:
            os.close(custody._core_pidfd)
        except OSError:
            pass


def _socket_identity(path: Path, config: CoreGatewayConfig) -> tuple[int, int]:
    if path != CORE_INGRESS_SOCKET:
        _deny()
    parent_fd = os.open("/", os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0))
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                              | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
            info = os.fstat(next_fd)
            target = component == path.parent.name
            if (not stat.S_ISDIR(info.st_mode)
                    or (target and (info.st_uid != config.gateway_uid or info.st_gid != config.gateway_gid
                                    or stat.S_IMODE(info.st_mode) != 0o750))
                    or (not target and (info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022))):
                os.close(next_fd)
                _deny()
            os.close(parent_fd)
            parent_fd = next_fd
        fd = os.open(path.name, os.O_PATH | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != config.gateway_uid
                    or info.st_gid != config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
                _deny()
            return info.st_dev, info.st_ino
        finally:
            os.close(fd)
    finally:
        os.close(parent_fd)


def _core_listener_inode(pid: int) -> int:
    target = f"{CORE_PORT:04X}"
    inodes = set()
    for line in Path("/proc/net/tcp").read_text().splitlines()[1:]:
        parts = line.split()
        if len(parts) > 9 and parts[1] == f"0100007F:{target}" and parts[3] == "0A":
            inodes.add(parts[9])
    if len(inodes) != 1:
        _deny()
    for fd in Path(f"/proc/{pid}/fd").iterdir():
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", link)
        if match and match.group(1) in inodes:
            return int(match.group(1))
    _deny()


def _boot_id() -> str:
    value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if not re.fullmatch(r"[0-9a-f-]{36}", value):
        _deny()
    return value


def _config_current(config: CoreGatewayConfig) -> CoreGatewayConfig:
    if type(config) is not CoreGatewayConfig:
        _deny()
    current = CoreGatewayConfig.load(expected_owner_uid=0)
    if current.config_sha256 != config.config_sha256 or current.boot_id != config.boot_id:
        _deny()
    return current


def observe_current_ingress(config: CoreGatewayConfig, *, nonce: str, caller_pid: int,
                            caller_uid: int, caller_gid: int, peer_pid: int,
                            peer_uid: int, peer_gid: int, _issued: float | None = None,
                            _deadline: float | None = None,
                            _projection_factory: Any = None,
                            _retain_issuance: bool = True) -> dict[str, Any]:
    issued = time.monotonic() if _issued is None else _issued
    deadline = issued + MAX_PROOF_SECONDS if _deadline is None else _deadline
    pidfds = []
    try:
        if (os.geteuid() != 0 or not re.fullmatch(r"[0-9a-f]{64}", nonce)
                or (caller_uid, caller_gid) != (config.gateway_uid, config.gateway_gid)
                or _boot_id() != config.boot_id):
            _deny()
        _config_current(config)
        origin = _socket_identity(config.ingress_socket, config)
        gateway_pidfd, gateway_start, _gw_invocation = _check_unit_process(config,
            unit=CORE_GATEWAY_UNIT, pid=caller_pid, deadline=deadline)
        pidfds.append(gateway_pidfd)
        tunnel_pidfd, tunnel_start, tunnel_invocation = _check_unit_process(config,
            unit=TUNNEL_UNIT, pid=peer_pid, peer_uid=peer_uid, peer_gid=peer_gid, deadline=deadline)
        pidfds.append(tunnel_pidfd)
        core_props = _unit_properties(CORE_SERVICE_UNIT, deadline=deadline)
        core_pid = int(core_props.get("MainPID", "0"))
        core_pidfd, core_start, core_invocation = _check_unit_process(config,
            unit=CORE_SERVICE_UNIT, pid=core_pid, deadline=deadline)
        pidfds.append(core_pidfd)
        _current_core_credential(core_pid, config, deadline=deadline)
        source_generation = _current_core_source(config, deadline=deadline)
        if Path(f"/proc/{core_pid}/cwd").resolve(strict=True) != CORE_WORKSPACE:
            _deny()
        listener_inode = _core_listener_inode(core_pid)
        generation_payload = (f"{core_invocation}\0{core_pid}\0{core_start}\0{listener_inode}\0"
                              f"{source_generation}").encode("ascii")
        core_generation = hashlib.sha256(b"hermes-jarvis-core-generation-v1\0" + generation_payload).hexdigest()
        if _projection_factory is not None:
            _projection_factory(source_generation)
            if time.monotonic() >= deadline:
                _deny()
        if (time.monotonic() >= deadline or _boot_id() != config.boot_id
                or _socket_identity(config.ingress_socket, config) != origin
                or _core_listener_inode(core_pid) != listener_inode
                or _current_core_source(config, deadline=deadline) != source_generation
                or _config_current(config).config_sha256 != config.config_sha256):
            _deny()
        for pidfd, pid, start_ticks in (
                (gateway_pidfd, caller_pid, gateway_start),
                (tunnel_pidfd, peer_pid, tunnel_start),
                (core_pidfd, core_pid, core_start)):
            poller = select.poll()
            poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if poller.poll(0) or _proc_start_ticks(pid) != start_ticks:
                _deny()
        body: dict[str, Any] = {
            "schema": 1, "nonce": nonce, "boot_id": config.boot_id,
            "issued_monotonic": issued, "expires_monotonic": issued + MAX_PROOF_SECONDS,
            "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid,
            "peer_start_ticks": tunnel_start, "tunnel_invocation_id": tunnel_invocation,
            "tunnel_unit_sha256": config.tunnel_unit_sha256,
            "tunnel_executable_sha256": config.cloudflared_binary_sha256,
            "origin_socket_device": origin[0], "origin_socket_inode": origin[1],
            "gateway_unit_sha256": config.gateway_unit_sha256,
            "core_unit_sha256": config.core_unit_sha256,
            "core_invocation_id": core_invocation, "core_pid": core_pid,
            "core_start_ticks": core_start, "core_listener_inode": listener_inode,
            "core_source_generation": source_generation,
            "core_generation": core_generation, "config_sha256": config.config_sha256,
        }
        body["proof_sha256"] = _observation_digest(body)
        if _retain_issuance:
            _retain_ingress_issue(caller_pid=caller_pid,
                                  caller_start_ticks=gateway_start, proof=body)
        return body
    finally:
        for pidfd in pidfds:
            try:
                os.close(pidfd)
            except OSError:
                pass


_OVERVIEW_PROJECTION_FIELDS = {
    "core_version", "provider", "model", "account_state", "resources_state",
    "resource_counts", "resources_revision", "artifact_sha256",
    "discovery_observed_at_utc", "active_prompt_matches_bundled_primary",
}


def _core_overview_projection(source_generation: str,
                              config_digest_holder: dict[str, str | None] | None = None) -> dict[str, Any]:
    from ..core_runtime import COMMIT, read_current_resources_discovery
    projection = read_current_resources_discovery(core_source_generation=source_generation)
    provider, model, digest = _fixed_model_config_projection()
    if config_digest_holder is not None:
        config_digest_holder["digest"] = digest
    # These are safe configured labels from the fixed private config only. They
    # do not establish authentication, provider reachability, or per-turn routing.
    projection.update({"core_version": COMMIT[:12], "provider": provider, "model": model,
                       "account_state": "unknown"})
    if not _valid_overview_projection(projection):
        _deny()
    return projection


def _fixed_model_config_bytes() -> bytes | None:
    """Read the fixed owner config under root custody without exposing raw YAML."""
    from ..core_runtime import _projection_file
    account = pwd.getpwnam("admin")
    home = os.lstat(CORE_ADMIN_HOME)
    private_home = os.lstat(CORE_HERMES_HOME)
    if (not stat.S_ISDIR(home.st_mode) or home.st_uid != account.pw_uid
            or stat.S_IMODE(home.st_mode) & 0o022
            or not stat.S_ISDIR(private_home.st_mode) or private_home.st_uid != account.pw_uid
            or private_home.st_gid != account.pw_gid or stat.S_IMODE(private_home.st_mode) != 0o700):
        raise CoreInspectionDenied("fixed model configuration custody differs")
    return _projection_file(CORE_USER_CONFIG, owner=account.pw_uid, group=account.pw_gid,
                            mode=0o600, maximum=MAX_CORE_USER_CONFIG_BYTES)


def _parse_native_inheritance_config(raw: bytes) -> tuple[tuple[str, ...], str]:
    """Read only the explicit configured parent toolset maximum from protected bytes."""
    import yaml
    from yaml.constructor import ConstructorError

    class UniqueSafeLoader(yaml.SafeLoader):
        def compose_node(self, parent, index):
            if self.check_event(yaml.AliasEvent):
                raise ConstructorError(None, None, "YAML aliases are not accepted",
                                       self.peek_event().start_mark)
            return super().compose_node(parent, index)

    def construct_mapping(loader, node, deep=False):
        mapping = {}
        for key_node, value_node in node.value:
            key = loader.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in mapping:
                raise ConstructorError("while constructing a mapping", node.start_mark,
                                       "duplicate or non-string configuration key", key_node.start_mark)
            mapping[key] = loader.construct_object(value_node, deep=deep)
        return mapping

    UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                                     construct_mapping)
    document = yaml.load(raw, Loader=UniqueSafeLoader)
    if not isinstance(document, dict):
        raise CoreInspectionDenied("fixed native configuration is unavailable")
    # Require an explicit non-empty configured selection. The root treats this as an
    # upper bound only; live native blocked/disabled/platform filters remain authoritative.
    platform_toolsets = document.get("platform_toolsets")
    cli_selection = platform_toolsets.get("cli") if isinstance(platform_toolsets, dict) else None
    if (not isinstance(cli_selection, list) or not cli_selection or len(cli_selection) > 256
            or any(not isinstance(item, str) or not item or len(item) > 96
                   or not item.isascii() or any(ord(char) < 0x20 for char in item)
                   for item in cli_selection)):
        raise CoreInspectionDenied("explicit parent tool selection is unavailable")
    if len(set(cli_selection)) != len(cli_selection):
        raise CoreInspectionDenied("explicit parent tool selection is ambiguous")
    return tuple(sorted(cli_selection)), hashlib.sha256(raw).hexdigest()


def _read_session_tool_configuration(
        session_id: str, *, selected_toolsets: tuple[str, ...], deadline: float) -> tuple[str, ...]:
    """Build a configured maximum from protected selections and current toolset metadata.

    The RPC's `enabled` field omits disabled and platform-gated filtering, so it is
    validated as metadata but never used as an effective dispatch allowlist.
    """
    if (not isinstance(session_id, str) or not session_id.isascii()
            or not 1 <= len(session_id) <= 512
            or any(ord(char) < 0x20 for char in session_id)):
        raise CoreInspectionDenied("current parent session is unavailable")
    if (not isinstance(selected_toolsets, tuple) or not selected_toolsets
            or tuple(sorted(set(selected_toolsets))) != selected_toolsets):
        raise CoreInspectionDenied("configured parent tool maximum is unavailable")
    if time.monotonic() >= deadline - 1.0:
        raise CoreInspectionDenied("current parent tool inventory exceeded its deadline")
    from .core_client import CoreRpcClient

    async def read():
        remaining = deadline - time.monotonic()
        if remaining < 1.0:
            raise CoreInspectionDenied("current parent tool inventory exceeded its deadline")
        client = CoreRpcClient(timeout_seconds=min(2.0, remaining),
                               token_owner_uid=0, token_group_gid=981)
        # Fixed source-audited method and exact session-only parameters. The method
        # name is never received from the caller or forwarded from a browser.
        return await client._rpc("tools.list", {"session_id": session_id})

    try:
        result = asyncio.run(read())
    except Exception:
        raise CoreInspectionDenied("current parent tool inventory is unavailable") from None
    if type(result) is not dict or set(result) != {"toolsets"}:
        raise CoreInspectionDenied("current parent tool inventory has an unknown schema")
    rows = result.get("toolsets")
    if not isinstance(rows, list) or not 1 <= len(rows) <= 256:
        raise CoreInspectionDenied("current parent tool inventory is empty or ambiguous")
    seen_toolsets: set[str] = set()
    matched_toolsets: set[str] = set()
    all_tools: set[str] = set()
    total = 0
    for row in rows:
        if (type(row) is not dict or set(row) != {"name", "description", "tool_count", "enabled", "tools"}
                or not isinstance(row.get("name"), str) or not row["name"].isascii()
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", row["name"]) is None
                or not isinstance(row.get("description"), str) or len(row["description"]) > 2048
                or any(ord(char) < 0x20 and char not in "\t\n" for char in row["description"])
                or type(row.get("tool_count")) is not int or not 0 <= row["tool_count"] <= 10_000
                or type(row.get("enabled")) is not bool
                or not isinstance(row.get("tools"), list) or len(row["tools"]) > 512
                or row["tool_count"] != len(row["tools"])):
            raise CoreInspectionDenied("current parent tool inventory contains an invalid row")
        toolset_name = row["name"]
        if toolset_name in seen_toolsets:
            raise CoreInspectionDenied("current parent tool inventory contains duplicate toolsets")
        seen_toolsets.add(toolset_name)
        row_tools: set[str] = set()
        for tool in row["tools"]:
            if (not isinstance(tool, str) or not tool.isascii()
                    or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", tool) is None
                    or tool in row_tools):
                raise CoreInspectionDenied("current parent tool inventory contains an invalid tool")
            row_tools.add(tool)
        total += len(row_tools)
        if total > 2048:
            raise CoreInspectionDenied("current parent tool inventory exceeded its bound")
        if toolset_name in selected_toolsets:
            matched_toolsets.add(toolset_name)
            all_tools.update(row_tools)
    if matched_toolsets != set(selected_toolsets) or not all_tools:
        raise CoreInspectionDenied("selected configured tool metadata is incomplete")
    return tuple(sorted(all_tools))


def _fixed_model_config_projection() -> tuple[str | None, str | None, str | None]:
    try:
        raw = _fixed_model_config_bytes()
    except FileNotFoundError:
        return None, None, None
    except Exception:
        # A present but unsafe config is an unknown value, never a public read path.
        return None, None, None
    digest = hashlib.sha256(raw).hexdigest()
    try:
        import yaml
        from yaml.constructor import ConstructorError

        class UniqueSafeLoader(yaml.SafeLoader):
            def compose_node(self, parent, index):
                if self.check_event(yaml.AliasEvent):
                    raise ConstructorError(None, None, "YAML aliases are not accepted",
                                           self.peek_event().start_mark)
                return super().compose_node(parent, index)

        def construct_mapping(loader, node, deep=False):
            mapping = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                if key in mapping:
                    raise ConstructorError("while constructing a mapping", node.start_mark,
                                           "duplicate configuration key", key_node.start_mark)
                mapping[key] = loader.construct_object(value_node, deep=deep)
            return mapping

        UniqueSafeLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
                                         construct_mapping)
        document = yaml.load(raw, Loader=UniqueSafeLoader)
        if not isinstance(document, dict):
            return None, None, digest
        model_config = document.get("model")
        if isinstance(model_config, dict):
            model_value = model_config.get("default", model_config.get("name", ""))
            provider_value = model_config.get("provider", "")
        elif isinstance(model_config, str) and model_config:
            model_value, provider_value = model_config, ""
        else:
            model_value, provider_value = "", ""
        return (_safe_config_label(provider_value, provider=True),
                _safe_config_label(model_value, provider=False), digest)
    except Exception:
        return None, None, digest


def _safe_config_label(value: Any, *, provider: bool) -> str | None:
    maximum = 80 if provider else 160
    pattern = (r"[A-Za-z0-9][A-Za-z0-9._+-]{0,79}" if provider
               else r"[A-Za-z0-9][A-Za-z0-9 ._:/+-]{0,159}")
    if not isinstance(value, str) or not value or len(value) > maximum:
        return None
    if not provider and ("://" in value or "\\" in value or value.endswith("/")
                         or "//" in value):
        return None
    return value if re.fullmatch(pattern, value) else None


def _current_fixed_model_config_digest() -> str | None:
    try:
        raw = _fixed_model_config_bytes()
    except Exception:
        return None
    return hashlib.sha256(raw).hexdigest()


def _valid_overview_projection(projection: Any) -> bool:
    if type(projection) is not dict or set(projection) != _OVERVIEW_PROJECTION_FIELDS:
        return False
    if (projection.get("core_version") != CORE_SOURCE_REVISION[:12]
            or projection.get("account_state") not in {"unknown", "configured"}
            or projection.get("resources_state") not in {"pending", "discovered", "stale"}):
        return False
    if (projection.get("provider") is not None
            and _safe_config_label(projection["provider"], provider=True) != projection["provider"]):
        return False
    if (projection.get("model") is not None
            and _safe_config_label(projection["model"], provider=False) != projection["model"]):
        return False
    if projection["resources_state"] != "discovered":
        return all(projection[key] is None for key in (
            "resource_counts", "resources_revision", "artifact_sha256",
            "discovery_observed_at_utc", "active_prompt_matches_bundled_primary"))
    counts = projection.get("resource_counts")
    if (not isinstance(counts, dict) or set(counts) != {
            "native_skills", "internal_profiles", "source_profiles_preserved",
            "other_declarations_preserved"}
            or any(type(value) is not int or value < 0 or value > 10000
                   for value in counts.values())):
        return False
    revision = projection.get("resources_revision")
    observed = projection.get("discovery_observed_at_utc")
    if (not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            or not _is_hash(projection.get("artifact_sha256"))
            or type(projection.get("active_prompt_matches_bundled_primary")) is not bool
            or not isinstance(observed, str)
            or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", observed) is None):
        return False
    try:
        parsed = datetime.fromisoformat(observed.replace("Z", "+00:00"))
        return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(parsed)
    except (TypeError, ValueError):
        return False


def observe_current_core_overview(config: CoreGatewayConfig, *, nonce: str,
                                  caller_pid: int, caller_uid: int, caller_gid: int,
                                  peer_pid: int, peer_uid: int, peer_gid: int,
                                  issued: float, deadline: float) -> dict[str, Any]:
    projection_holder: dict[str, Any] = {}
    config_digest_holder: dict[str, str | None] = {}

    def project(source_generation: str) -> None:
        projection_holder.update(_core_overview_projection(source_generation, config_digest_holder))

    ingress = observe_current_ingress(config, nonce=nonce, caller_pid=caller_pid,
        caller_uid=caller_uid, caller_gid=caller_gid, peer_pid=peer_pid,
        peer_uid=peer_uid, peer_gid=peer_gid, _issued=issued, _deadline=deadline,
        _projection_factory=project)
    if set(projection_holder) != _OVERVIEW_PROJECTION_FIELDS:
        _deny()
    captured_config_digest = config_digest_holder.get("digest")
    if (captured_config_digest is not None
            and _current_fixed_model_config_digest() != captured_config_digest):
        _deny()
    body = {
        "schema": 1, "nonce": nonce, "boot_id": ingress["boot_id"],
        "issued_monotonic": issued, "expires_monotonic": min(issued + MAX_PROOF_SECONDS, deadline),
        "config_sha256": ingress["config_sha256"],
        "core_generation": ingress["core_generation"],
        "core_source_generation": ingress["core_source_generation"],
        "projection": projection_holder,
    }
    if time.monotonic() >= body["expires_monotonic"]:
        _deny()
    body["proof_sha256"] = _overview_digest(body)
    return body


@dataclass(frozen=True, slots=True)
class CoreVerifiedOverviewObservation:
    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    config_sha256: str
    core_generation: str
    core_source_generation: str
    projection: dict[str, Any]
    proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, peer_pid: int,
                       peer_uid: int, peer_gid: int,
                       accepted_ingress: Any,
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            claims = {name: getattr(self, name) for name in (
                "schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
                "config_sha256", "core_generation", "core_source_generation", "projection")}
            projection = self.projection
            if (self._seal is not _OVERVIEW_PROOF_SEAL or not _valid_overview_projection(projection)
                    or type(self.schema) is not int or self.schema != 1
                    or not re.fullmatch(r"[0-9a-f]{64}", self.nonce)
                    or self.boot_id != config.boot_id or self.config_sha256 != config.config_sha256
                    or type(projection) is not dict or set(projection) != _OVERVIEW_PROJECTION_FIELDS
                    or projection.get("account_state") not in {"unknown", "configured"}
                    or projection.get("resources_state") not in {"pending", "discovered", "stale"}
                    or projection.get("core_version") != CORE_SOURCE_REVISION[:12]
                    or (projection.get("provider") is not None and
                        _safe_config_label(projection["provider"], provider=True) != projection["provider"])
                    or (projection.get("model") is not None and
                        _safe_config_label(projection["model"], provider=False) != projection["model"])
                    or (projection.get("resources_revision") is not None and
                        re.fullmatch(r"[0-9a-f]{40}", projection["resources_revision"]) is None)
                    or (projection.get("artifact_sha256") is not None
                        and not _is_hash(projection.get("artifact_sha256")))
                    or (projection.get("active_prompt_matches_bundled_primary") is not None
                        and type(projection.get("active_prompt_matches_bundled_primary")) is not bool)
                    or (projection.get("discovery_observed_at_utc") is not None
                        and (not isinstance(projection.get("discovery_observed_at_utc"), str)
                             or re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
                                             projection["discovery_observed_at_utc"]) is None))
                    or (projection.get("resource_counts") is not None and
                        (not isinstance(projection.get("resource_counts"), dict)
                         or set(projection["resource_counts"]) != {
                             "native_skills", "internal_profiles", "source_profiles_preserved",
                             "other_declarations_preserved"}
                         or any(type(value) is not int or value < 0 or value > 10000
                                for value in projection["resource_counts"].values())))
                    or any(isinstance(value, bool) or not isinstance(value, (int, float))
                           or not math.isfinite(value) for value in
                           (self.issued_monotonic, self.expires_monotonic, current))
                    or not self.issued_monotonic <= current < self.expires_monotonic
                    or not self.issued_monotonic < self.expires_monotonic <= self.issued_monotonic + MAX_PROOF_SECONDS
                    or not _is_hash(self.config_sha256) or not _is_hash(self.core_generation)
                    or not _is_hash(self.core_source_generation) or _overview_digest(claims) != self.proof_sha256):
                return False
            from .core_gateway import CoreAcceptedIngressObservation
            return bool(type(accepted_ingress) is CoreAcceptedIngressObservation
                        and accepted_ingress.verify_current(config, now=current)
                        and (accepted_ingress.peer_pid, accepted_ingress.peer_uid, accepted_ingress.peer_gid)
                            == (peer_pid, peer_uid, peer_gid)
                        and accepted_ingress.core_generation == self.core_generation
                        and accepted_ingress.root_observation.core_source_generation == self.core_source_generation
                        and accepted_ingress.root_observation.boot_id == self.boot_id
                        and accepted_ingress._config_sha256 == self.config_sha256
                        and time.monotonic() < min(accepted_ingress.expires_monotonic, self.expires_monotonic))
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class CoreVerifiedSkillLearningObservation:
    """Sealed, read-only pending skill-review snapshot for one accepted owner request."""

    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    config_sha256: str
    core_generation: str
    ingress_nonce: str
    ingress_proof_sha256: str
    readiness: str
    pending_reasons: tuple[str, ...]
    candidates: tuple[dict[str, Any], ...]
    proof_sha256: str
    _access_fingerprint: str = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, peer_pid: int,
                       peer_uid: int, peer_gid: int, accepted_ingress: Any,
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            from .core_gateway import CoreAcceptedIngressObservation
            claims = {
                "schema": self.schema, "nonce": self.nonce, "boot_id": self.boot_id,
                "issued_monotonic": self.issued_monotonic, "expires_monotonic": self.expires_monotonic,
                "config_sha256": self.config_sha256, "core_generation": self.core_generation,
                "ingress_nonce": self.ingress_nonce,
                "ingress_proof_sha256": self.ingress_proof_sha256,
                "readiness": self.readiness, "pending_reasons": list(self.pending_reasons),
                "candidates": list(self.candidates),
            }
            accepted_root = accepted_ingress.root_observation
            return bool(
                self._seal is _SKILL_LEARNING_PROOF_SEAL
                and type(self.schema) is int and self.schema == 1
                and re.fullmatch(r"[0-9a-f]{64}", self.nonce)
                and self.boot_id == config.boot_id
                and self.config_sha256 == config.config_sha256
                and self.core_generation == accepted_ingress.core_generation
                and self.ingress_nonce == accepted_root.nonce
                and self.ingress_proof_sha256 == accepted_root.proof_sha256
                and self._access_fingerprint == accepted_ingress.principal.token_fingerprint
                and isinstance(self.readiness, str)
                and self.readiness in {"read-only-native-review", "partial", "unavailable"}
                and _valid_learning_reasons(list(self.pending_reasons))
                and _valid_learning_candidates(list(self.candidates), self.readiness)
                and _is_hash(self.proof_sha256)
                and _learning_digest(claims) == self.proof_sha256
                and all(not isinstance(value, bool) and isinstance(value, (int, float))
                        and math.isfinite(value) for value in
                        (self.issued_monotonic, self.expires_monotonic, current))
                and self.issued_monotonic == accepted_root.issued_monotonic
                and self.issued_monotonic <= current < self.expires_monotonic
                and self.issued_monotonic < self.expires_monotonic <= accepted_root.expires_monotonic
                and self.expires_monotonic <= accepted_ingress.expires_monotonic
                and type(accepted_ingress) is CoreAcceptedIngressObservation
                and accepted_ingress.verify_current(config, now=current)
                and (accepted_ingress.peer_pid, accepted_ingress.peer_uid, accepted_ingress.peer_gid)
                    == (peer_pid, peer_uid, peer_gid)
            )
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class CoreVerifiedIngressObservation:
    schema: int
    nonce: str
    boot_id: str
    issued_monotonic: float
    expires_monotonic: float
    peer_pid: int
    peer_uid: int
    peer_gid: int
    peer_start_ticks: str
    tunnel_invocation_id: str
    tunnel_unit_sha256: str
    tunnel_executable_sha256: str
    origin_socket_device: int
    origin_socket_inode: int
    gateway_unit_sha256: str
    core_unit_sha256: str
    core_invocation_id: str
    core_pid: int
    core_start_ticks: str
    core_listener_inode: int
    core_source_generation: str
    core_generation: str
    config_sha256: str
    proof_sha256: str
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, peer_pid: int, peer_uid: int,
                       peer_gid: int, listener_identity: tuple[int, int],
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            claims = {name: getattr(self, name) for name in _OBSERVATION_FIELDS}
            return bool(self._seal is _PROOF_SEAL and type(self.schema) is int and self.schema == 1
                and re.fullmatch(r"[0-9a-f]{64}", self.nonce)
                and self.boot_id == config.boot_id == _boot_id()
                and self.config_sha256 == config.config_sha256
                and self.gateway_unit_sha256 == config.gateway_unit_sha256
                and self.core_unit_sha256 == config.core_unit_sha256
                and self.tunnel_unit_sha256 == config.tunnel_unit_sha256
                and self.tunnel_executable_sha256 == config.cloudflared_binary_sha256
                and (self.peer_pid, self.peer_uid, self.peer_gid) == (peer_pid, peer_uid, peer_gid)
                and (self.origin_socket_device, self.origin_socket_inode) == listener_identity
                and type(current) in (int, float) and self.issued_monotonic <= current < self.expires_monotonic
                and self.issued_monotonic < self.expires_monotonic <=
                    self.issued_monotonic + MAX_PROOF_SECONDS
                and self.peer_start_ticks.isdecimal() and self.core_start_ticks.isdecimal()
                and _is_hash(self.core_source_generation)
                and self.core_generation == hashlib.sha256(
                    b"hermes-jarvis-core-generation-v1\0" +
                    f"{self.core_invocation_id}\0{self.core_pid}\0{self.core_start_ticks}\0{self.core_listener_inode}\0{self.core_source_generation}".encode("ascii")
                ).hexdigest()
                and _observation_digest(claims) == self.proof_sha256
                and all(_is_hash(value) for value in (self.tunnel_unit_sha256,
                    self.tunnel_executable_sha256, self.gateway_unit_sha256, self.core_unit_sha256,
                    self.core_source_generation, self.config_sha256, self.proof_sha256)))
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class CoreNativeObserverCustody:
    """Root-held PIDFD and fixed service facts for the current native observer peer."""

    core_pid: int
    core_uid: int
    core_gid: int
    core_start_ticks: str
    core_generation: str
    core_invocation_id: str
    core_listener_inode: int
    core_source_generation: str
    core_unit_sha256: str
    core_executable_sha256: str
    boot_id: str
    config_sha256: str
    _core_pidfd: int = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, accepted_ingress: Any,
                       peer_pid: int, peer_uid: int, peer_gid: int) -> bool:
        now = time.monotonic()
        try:
            if (self._seal is not _NATIVE_CUSTODY_SEAL
                    or type(accepted_ingress) is not CoreVerifiedOwnerTurnObservation
                    or not accepted_ingress.verify_current(config, custody=self, now=now)
                    or (peer_pid, peer_uid, peer_gid) != (self.core_pid, self.core_uid, self.core_gid)
                    or self.config_sha256 != config.config_sha256
                    or self.boot_id != config.boot_id or _boot_id() != config.boot_id
                    or self.core_unit_sha256 != config.core_unit_sha256
                    or self.core_executable_sha256 != config.core_python_sha256
                    or self.core_uid != config.core_uid or self.core_gid != config.core_gid):
                return False
            held = select.poll()
            held.register(self._core_pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
            if held.poll(0) or _proc_start_ticks(self.core_pid) != self.core_start_ticks:
                return False
            deadline = min(now + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
            props = _unit_properties(CORE_SERVICE_UNIT, deadline=deadline)
            if (int(props.get("MainPID", "0")) != self.core_pid
                    or props.get("InvocationID") != self.core_invocation_id):
                return False
            pidfd, start, invocation = _check_unit_process(
                config, unit=CORE_SERVICE_UNIT, pid=self.core_pid, deadline=deadline)
            try:
                if start != self.core_start_ticks or invocation != self.core_invocation_id:
                    return False
            finally:
                os.close(pidfd)
            if (_core_listener_inode(self.core_pid) != self.core_listener_inode
                    or _current_core_source(config, deadline=deadline) != self.core_source_generation
                    or Path(f"/proc/{self.core_pid}/cwd").resolve(strict=True) != CORE_WORKSPACE):
                return False
            _current_core_credential(self.core_pid, config, deadline=deadline)
            return time.monotonic() < min(deadline, accepted_ingress.expires_monotonic)
        except Exception:
            return False

    def verify_peer(self, config: CoreGatewayConfig, accepted_ingress: Any,
                    connection: socket.socket) -> bool:
        try:
            if not hasattr(socket, "SO_PEERCRED"):
                return False
            pid, uid, gid = struct.unpack(
                "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            return self.verify_current(config, accepted_ingress, pid, uid, gid)
        except Exception:
            return False


@dataclass(frozen=True, slots=True)
class CoreVerifiedOwnerTurnObservation:
    """Root-sealed registration of one accepted user turn; prompt text is never retained."""

    schema: int
    owner_turn_handle: str
    owner_subject_sha256: str
    token_fingerprint_sha256: str
    jwt_expires_monotonic: float
    ingress_issued_monotonic: float
    ingress_expires_monotonic: float
    accepted_monotonic: float
    expires_monotonic: float
    ingress_nonce: str
    ingress_proof_sha256: str
    peer_gateway_pid: int
    peer_gateway_uid: int
    peer_gateway_gid: int
    peer_gateway_start_ticks: str
    gateway_invocation_id: str
    tunnel_invocation_id: str
    core_generation: str
    core_pid: int
    core_uid: int
    core_gid: int
    core_start_ticks: str
    core_invocation_id: str
    core_listener_inode: int
    core_source_generation: str
    core_unit_sha256: str
    core_executable_sha256: str
    session_id: str
    conversation_id: str
    gateway_turn_id: str
    prompt_sha256: str
    mission_binding: MissionBinding | None
    planning_context: PlanningContext | None
    _core_pidfd: int = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def verify_current(self, config: CoreGatewayConfig, *, custody: CoreNativeObserverCustody,
                       now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            claims = {name: getattr(self, name) for name in _OWNER_TURN_FIELDS}
            claims["mission_binding"] = _mission_binding_wire(self.mission_binding)
            claims["planning_context"] = _planning_context_wire(self.planning_context)
            issued = self.ingress_issued_monotonic
            return bool(
                self._seal is _OWNER_TURN_SEAL and type(self.schema) is int and self.schema == 1
                and type(custody) is CoreNativeObserverCustody
                and custody._seal is _NATIVE_CUSTODY_SEAL
                and all(_is_hash(value) for value in (
                    self.owner_subject_sha256, self.token_fingerprint_sha256,
                    self.ingress_proof_sha256, self.core_generation, self.core_source_generation,
                    self.core_unit_sha256, self.core_executable_sha256, self.prompt_sha256))
                and re.fullmatch(r"[0-9a-f]{32}", self.owner_turn_handle) is not None
                and re.fullmatch(r"[0-9a-f]{64}", self.ingress_nonce) is not None
                and all(type(value) is int and value > 1 for value in
                        (self.peer_gateway_pid, self.core_pid))
                and all(type(value) is int and value >= 0 for value in
                        (self.peer_gateway_uid, self.peer_gateway_gid, self.core_uid, self.core_gid,
                         self.core_listener_inode))
                and self.peer_gateway_start_ticks.isdecimal() and self.core_start_ticks.isdecimal()
                and all(re.fullmatch(r"[0-9a-fA-F-]{32,36}", value) for value in
                        (self.gateway_invocation_id, self.tunnel_invocation_id,
                         self.core_invocation_id))
                and self.core_pid == custody.core_pid and self.core_uid == custody.core_uid
                and self.core_gid == custody.core_gid and self.core_start_ticks == custody.core_start_ticks
                and self.core_generation == custody.core_generation
                and self.core_invocation_id == custody.core_invocation_id
                and self.core_listener_inode == custody.core_listener_inode
                and self.core_source_generation == custody.core_source_generation
                and self.core_unit_sha256 == custody.core_unit_sha256
                and self.core_executable_sha256 == custody.core_executable_sha256
                and isinstance(self.session_id, str) and 1 <= len(self.session_id) <= 512
                and self.session_id.isascii()
                and not any(ord(char) < 0x20 for char in self.session_id)
                and all(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_-]{24,64}", value)
                        for value in (self.conversation_id, self.gateway_turn_id))
                and self.ingress_issued_monotonic < self.ingress_expires_monotonic
                and self.ingress_expires_monotonic <= issued + MAX_PROOF_SECONDS
                and self.accepted_monotonic >= issued
                and self.accepted_monotonic < self.ingress_expires_monotonic
                and self.accepted_monotonic < self.expires_monotonic
                and (self.planning_context is None or (
                    type(self.planning_context) is PlanningContext
                    and self.mission_binding is None
                    and self.prompt_sha256 == self.planning_context.planner_prompt_sha256))
                and all(type(value) in (int, float) and math.isfinite(value) for value in
                        (self.jwt_expires_monotonic, self.ingress_issued_monotonic,
                         self.ingress_expires_monotonic, self.accepted_monotonic,
                         self.expires_monotonic, current))
                and self.accepted_monotonic <= current < self.expires_monotonic
                and self.expires_monotonic <= min(
                    self.jwt_expires_monotonic, issued + MAX_OWNER_TURN_SECONDS)
                and self.peer_gateway_uid == config.gateway_uid
                and self.core_uid == config.core_uid and self.core_gid == config.core_gid
                and self.core_unit_sha256 == config.core_unit_sha256
                and self.core_executable_sha256 == config.core_python_sha256
                and custody.boot_id == config.boot_id and custody.config_sha256 == config.config_sha256
                and _owner_turn_digest(claims) == self.proof_sha256
            )
        except Exception:
            return False

    def is_current_sealed(self, config: CoreGatewayConfig, *,
                          custody: CoreNativeObserverCustody,
                          now: float | None = None) -> bool:
        return bool(type(self) is CoreVerifiedOwnerTurnObservation
                    and self._seal is _OWNER_TURN_SEAL
                    and self.verify_current(config, custody=custody, now=now))

    proof_sha256: str


def _current_resources_delegate_registration(*, deadline: float) -> dict[str, str]:
    """Join the sealed plugin descriptor to the exact root-installed handler source bytes."""
    from .core_native_observer import (
        CoreNativeResourcesDelegateRegistration,
        current_resources_delegate_registration,
    )
    registration = current_resources_delegate_registration()
    if (type(registration) is not CoreNativeResourcesDelegateRegistration
            or registration.schema != 1
            or registration.name != _RESOURCES_DELEGATE_NAME
            or registration.toolset != _RESOURCES_DELEGATE_TOOLSET
            or registration.package_relative_path != "components/resources_internal_dispatch.py"
            or registration.schema_sha256 != _RESOURCES_DELEGATE_SCHEMA_SHA256):
        raise CoreInspectionDenied("fixed Resources delegate registration is unavailable")
    inspector_path = Path(__file__).resolve(strict=True)
    package_root = inspector_path.parents[1]
    if package_root.name != "hermes_installer":
        raise CoreInspectionDenied("installed package root is unavailable")
    current = package_root
    while True:
        info = os.lstat(current)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise CoreInspectionDenied("installed package path custody differs")
        if current == current.parent:
            break
        current = current.parent
    member = package_root / "components" / "resources_internal_dispatch.py"
    source_sha256 = _protected_file_sha(member, owner_uid=0, deadline=deadline)
    if (source_sha256 != _RESOURCES_DISPATCH_SOURCE_SHA256
            or registration.source_sha256 != source_sha256):
        raise CoreInspectionDenied("Resources delegate source bytes are not the reviewed member")
    return {
        "resources_delegate_name": registration.name,
        "resources_delegate_toolset": registration.toolset,
        "resources_delegate_schema_sha256": registration.schema_sha256,
        "resources_delegate_source_sha256": source_sha256,
    }


@dataclass(frozen=True, slots=True)
class CoreVerifiedNativeToolConfiguration:
    """Root-sealed configured maximum and registered Resources wrapper provenance."""

    schema: int
    core_generation: str
    core_source_generation: str
    owner_subject_sha256: str
    tool_configuration_sha256: str
    configured_parent_tool_names: tuple[str, ...]
    resources_delegate_name: str
    resources_delegate_toolset: str
    resources_delegate_schema_sha256: str
    resources_delegate_source_sha256: str
    issued_monotonic: float
    expires_monotonic: float
    _config: CoreGatewayConfig = field(repr=False, compare=False)
    _seal: object = field(repr=False, compare=False)

    def is_current_sealed(self, *, custody: CoreNativeObserverCustody,
                          owner_turn: CoreVerifiedOwnerTurnObservation,
                          now: float | None = None) -> bool:
        current = time.monotonic() if now is None else now
        try:
            if (type(self) is not CoreVerifiedNativeToolConfiguration
                    or self._seal is not _NATIVE_TOOL_CONFIGURATION_SEAL
                    or type(custody) is not CoreNativeObserverCustody
                    or custody._seal is not _NATIVE_CUSTODY_SEAL
                    or type(owner_turn) is not CoreVerifiedOwnerTurnObservation
                    or type(self._config) is not CoreGatewayConfig
                    or not owner_turn.verify_current(
                        self._config, custody=custody, now=current)
                    or type(self.schema) is not int or self.schema != 1
                    or self.core_generation != owner_turn.core_generation
                    or self.core_source_generation != owner_turn.core_source_generation
                    or self.owner_subject_sha256 != owner_turn.owner_subject_sha256
                    or not _is_hash(self.tool_configuration_sha256)
                    or not isinstance(self.configured_parent_tool_names, tuple)
                    or not self.configured_parent_tool_names
                    or tuple(sorted(set(self.configured_parent_tool_names))) != self.configured_parent_tool_names
                    or any(not isinstance(name, str) or not name.isascii()
                           or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,127}", name) is None
                           for name in self.configured_parent_tool_names)
                    or self.resources_delegate_name != _RESOURCES_DELEGATE_NAME
                    or self.resources_delegate_toolset != _RESOURCES_DELEGATE_TOOLSET
                    or self.resources_delegate_name not in self.configured_parent_tool_names
                    or not _is_hash(self.resources_delegate_schema_sha256)
                    or not _is_hash(self.resources_delegate_source_sha256)
                    or any(type(value) not in (int, float) or not math.isfinite(value)
                           for value in (self.issued_monotonic, self.expires_monotonic, current))
                    or not owner_turn.accepted_monotonic <= self.issued_monotonic < self.expires_monotonic
                    or self.expires_monotonic > owner_turn.expires_monotonic
                    or not self.issued_monotonic <= current < self.expires_monotonic):
                return False
            config = self._config
            if custody.verify_current(config, owner_turn, custody.core_pid,
                                      custody.core_uid, custody.core_gid) is not True:
                return False
            fresh = _read_native_tool_configuration_claims(config, custody, owner_turn)
            if time.monotonic() >= min(owner_turn.expires_monotonic, self.expires_monotonic):
                return False
            return (fresh["tool_configuration_sha256"] == self.tool_configuration_sha256
                    and fresh["configured_parent_tool_names"] == self.configured_parent_tool_names
                    and fresh["resources_delegate_name"] == self.resources_delegate_name
                    and fresh["resources_delegate_toolset"] == self.resources_delegate_toolset
                    and fresh["resources_delegate_schema_sha256"] == self.resources_delegate_schema_sha256
                    and fresh["resources_delegate_source_sha256"] == self.resources_delegate_source_sha256
                    and custody.verify_current(config, owner_turn, custody.core_pid,
                                              custody.core_uid, custody.core_gid) is True)
        except Exception:
            return False


def _read_native_tool_configuration_claims(
        config: CoreGatewayConfig, custody: CoreNativeObserverCustody,
        owner_turn: CoreVerifiedOwnerTurnObservation) -> dict[str, Any]:
    """Re-read protected selections, registered wrapper source, and current tool metadata."""
    if (type(config) is not CoreGatewayConfig
            or type(custody) is not CoreNativeObserverCustody
            or type(owner_turn) is not CoreVerifiedOwnerTurnObservation
            or custody.verify_current(config, owner_turn, custody.core_pid,
                                      custody.core_uid, custody.core_gid) is not True):
        raise CoreInspectionDenied("current native tool configuration custody is unavailable")
    deadline = min(time.monotonic() + MAX_PROOF_SECONDS, owner_turn.expires_monotonic)
    native_source_digest = _current_native_tool_source(config, deadline=deadline)
    delegate_registration = _current_resources_delegate_registration(deadline=deadline)
    raw = _fixed_model_config_bytes()
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_CORE_USER_CONFIG_BYTES:
        raise CoreInspectionDenied("fixed native tool configuration is unavailable")
    selected_toolsets, config_digest = _parse_native_inheritance_config(raw)
    names = _read_session_tool_configuration(owner_turn.session_id,
        selected_toolsets=selected_toolsets, deadline=deadline)
    names = tuple(sorted(set(names) | {_RESOURCES_DELEGATE_NAME}))
    if time.monotonic() >= deadline:
        raise CoreInspectionDenied("current native tool configuration expired")
    current_raw = _fixed_model_config_bytes()
    current_native_source_digest = _current_native_tool_source(config, deadline=deadline)
    current_delegate_registration = _current_resources_delegate_registration(deadline=deadline)
    if (current_native_source_digest != native_source_digest
            or current_delegate_registration != delegate_registration
            or not isinstance(current_raw, bytes)
            or not secrets.compare_digest(hashlib.sha256(current_raw).hexdigest(), config_digest)):
        raise CoreInspectionDenied("fixed native tool configuration changed")
    if custody.verify_current(config, owner_turn, custody.core_pid,
                              custody.core_uid, custody.core_gid) is not True:
        raise CoreInspectionDenied("current native core custody changed")
    values = {
        "schema": 1,
        "core_generation": owner_turn.core_generation,
        "core_source_generation": owner_turn.core_source_generation,
        "owner_subject_sha256": owner_turn.owner_subject_sha256,
        "session_id": owner_turn.session_id,
        "fixed_config_sha256": config_digest,
        "native_tool_source_sha256": native_source_digest,
        "selected_parent_toolsets": list(selected_toolsets),
        "configured_parent_tool_names": list(names),
        **delegate_registration,
    }
    digest = hashlib.sha256(b"hermes-jarvis-native-tool-configuration-v1\0" +
        json.dumps(values, sort_keys=True, separators=(",", ":"), allow_nan=False)
        .encode("ascii")).hexdigest()
    return {
        "tool_configuration_sha256": digest,
        "configured_parent_tool_names": names,
        **delegate_registration,
    }


def observe_current_native_tool_configuration(
        config: CoreGatewayConfig, *, custody: CoreNativeObserverCustody,
        owner_turn: CoreVerifiedOwnerTurnObservation) -> CoreVerifiedNativeToolConfiguration:
    """Issue the fixed current tool policy only from protected config and exact live-session readback."""
    try:
        now = time.monotonic()
        claims = _read_native_tool_configuration_claims(config, custody, owner_turn)
        expires = min(owner_turn.expires_monotonic, now + MAX_OWNER_TURN_SECONDS)
        observation = CoreVerifiedNativeToolConfiguration(
            schema=1, core_generation=owner_turn.core_generation,
            core_source_generation=owner_turn.core_source_generation,
            owner_subject_sha256=owner_turn.owner_subject_sha256,
            tool_configuration_sha256=claims["tool_configuration_sha256"],
            configured_parent_tool_names=claims["configured_parent_tool_names"],
            resources_delegate_name=claims["resources_delegate_name"],
            resources_delegate_toolset=claims["resources_delegate_toolset"],
            resources_delegate_schema_sha256=claims["resources_delegate_schema_sha256"],
            resources_delegate_source_sha256=claims["resources_delegate_source_sha256"],
            issued_monotonic=now, expires_monotonic=expires,
            _config=config, _seal=_NATIVE_TOOL_CONFIGURATION_SEAL)
        if expires <= now:
            raise CoreInspectionDenied("native tool configuration expired before enrollment")
        return observation
    except CoreInspectionDenied:
        raise
    except Exception:
        raise CoreInspectionDenied("current native tool configuration is unavailable") from None




def _read_frame(conn: socket.socket, deadline: float, maximum: int, *,
                encoding: str = "ascii") -> dict[str, Any]:
    size = struct.unpack("!I", _read_exact(conn, 4, deadline))[0]
    if not 2 <= size <= maximum:
        raise ValueError("IPC message exceeded bound")
    value = json.loads(_read_exact(conn, size, deadline).decode(encoding), object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("IPC frame is not an object")
    return value


def _serve_connection(conn: socket.socket, config: CoreGatewayConfig) -> None:
    try:
        issued = time.monotonic()
        deadline = issued + MAX_PROOF_SECONDS
        conn.settimeout(MAX_PROOF_SECONDS)
        if not hasattr(socket, "SO_PEERCRED"):
            return
        caller_pid, caller_uid, caller_gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if caller_uid != config.gateway_uid or caller_pid <= 1:
            return
        request = _read_frame(conn, deadline, MAX_OWNER_TURN_REQUEST_BYTES)
        if request.get("op") == "observe-skill-learning":
            result = observe_skill_learning(config, request=request, caller_pid=caller_pid,
                caller_uid=caller_uid, caller_gid=caller_gid, peer_pid=request.get("peer_pid"),
                peer_uid=request.get("peer_uid"), peer_gid=request.get("peer_gid"))
            maximum = MAX_SKILL_LEARNING_RESPONSE_BYTES
        elif request.get("op") == "observe-owner-turn":
            result = observe_owner_turn(config, request=request, caller_pid=caller_pid,
                caller_uid=caller_uid, caller_gid=caller_gid, peer_pid=request.get("peer_pid"),
                peer_uid=request.get("peer_uid"), peer_gid=request.get("peer_gid"),
                registry=_CORE_NATIVE_REGISTRY)
            maximum = MAX_RESPONSE
        elif request.get("op") == "prepare-master-planning-context":
            result = prepare_master_planning_context(config, request=request,
                caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                peer_pid=request.get("peer_pid"), peer_uid=request.get("peer_uid"),
                peer_gid=request.get("peer_gid"), custody=_CORE_NATIVE_CUSTODY)
            maximum = MAX_RESPONSE
        elif request.get("op") == "read-master-plan":
            result = observe_read_master_plan(config, request=request,
                caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                peer_pid=request.get("peer_pid"), peer_uid=request.get("peer_uid"),
                peer_gid=request.get("peer_gid"), custody=_CORE_NATIVE_CUSTODY,
                registry=_CORE_NATIVE_REGISTRY)
            maximum = MAX_MASTER_PLAN_RESPONSE
        elif request.get("op") == "read-native-activity":
            result = observe_read_native_activity(config, request=request,
                caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                peer_pid=request.get("peer_pid"), peer_uid=request.get("peer_uid"),
                peer_gid=request.get("peer_gid"), custody=_CORE_NATIVE_CUSTODY,
                registry=_CORE_NATIVE_REGISTRY)
            maximum = MAX_NATIVE_ACTIVITY_RESPONSE
        elif request.get("op") in {"list-final-effects", "decide-final-effect"}:
            result = observe_final_effect_request(config, request=request, caller_pid=caller_pid,
                caller_uid=caller_uid, caller_gid=caller_gid, peer_pid=request.get("peer_pid"),
                peer_uid=request.get("peer_uid"), peer_gid=request.get("peer_gid"),
                registry=_CORE_NATIVE_REGISTRY)
            maximum = MAX_FINAL_EFFECT_RESPONSE
        elif request.get("op") == "preflight-native-mission":
            result = observe_native_mission_preflight(config, request=request,
                caller_pid=caller_pid, caller_uid=caller_uid, caller_gid=caller_gid,
                registry=_CORE_NATIVE_REGISTRY)
            maximum = MAX_RESPONSE
        else:
            if set(request) != {"op", "nonce", "peer_pid", "peer_uid", "peer_gid"}:
                return
            arguments = {"nonce": request["nonce"], "caller_pid": caller_pid,
                "caller_uid": caller_uid, "caller_gid": caller_gid, "peer_pid": request["peer_pid"],
                "peer_uid": request["peer_uid"], "peer_gid": request["peer_gid"]}
            maximum = MAX_RESPONSE
            if request.get("op") == "observe-ingress":
                result = observe_current_ingress(config, **arguments)
            elif request.get("op") == "observe-core-overview":
                result = observe_current_core_overview(config, **arguments, issued=issued, deadline=deadline)
            else:
                return
        raw = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False,
                         ensure_ascii=False).encode("utf-8")
        if len(raw) > maximum or time.monotonic() >= deadline:
            return
        conn.sendall(struct.pack("!I", len(raw)) + raw)
    except Exception:
        return
    finally:
        _SERVER_SLOTS.release()
        conn.close()


def serve_inspection_socket(config: CoreGatewayConfig) -> None:
    if os.geteuid() != 0 or type(config) is not CoreGatewayConfig:
        raise CoreInspectionDenied("core inspector must run as root")
    if CORE_INSPECTOR_SOCKET.exists() or CORE_INSPECTOR_SOCKET.is_symlink():
        raise CoreInspectionDenied("fixed core inspector socket is occupied")
    parent = os.lstat(CORE_INSPECTOR_SOCKET.parent)
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != config.gateway_gid
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise CoreInspectionDenied("fixed core inspector directory custody differs")
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    identity = None
    stopping = False
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    try:
        for sig in previous:
            signal.signal(sig, stop)
        server.bind(str(CORE_INSPECTOR_SOCKET))
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        identity = (info.st_dev, info.st_ino)
        os.chown(CORE_INSPECTOR_SOCKET, 0, config.gateway_gid)
        os.chmod(CORE_INSPECTOR_SOCKET, 0o660)
        server.listen(16)
        server.settimeout(0.5)
        # Optional profile/source projection may take longer than the regular
        # inspector's ingress deadline. Keep the core observation socket serving
        # while that separately bounded feature initializes.
        global _CORE_NATIVE_INIT_STOP, _CORE_NATIVE_INIT_THREAD
        init_stop = threading.Event()
        init_thread = threading.Thread(target=_start_optional_core_native_observer,
            args=(config, init_stop), daemon=True, name="jarvis-native-observer-init")
        _CORE_NATIVE_INIT_STOP = init_stop
        _CORE_NATIVE_INIT_THREAD = init_thread
        init_thread.start()
        while not stopping:
            try:
                conn, _ = server.accept()
            except TimeoutError:
                continue
            if not _SERVER_SLOTS.acquire(blocking=False):
                conn.close()
                continue
            try:
                worker = threading.Thread(target=_serve_connection, args=(conn, config), daemon=True)
                worker.start()
            except Exception:
                _SERVER_SLOTS.release()
                conn.close()
                raise
    finally:
        _stop_optional_core_native_observer()
        server.close()
        for sig, prior in previous.items():
            signal.signal(sig, prior)
        try:
            info = os.lstat(CORE_INSPECTOR_SOCKET)
            if identity == (info.st_dev, info.st_ino) and stat.S_ISSOCK(info.st_mode):
                CORE_INSPECTOR_SOCKET.unlink()
        except OSError:
            pass


def verify_current_ingress(config: CoreGatewayConfig, *, peer_pid: int,
                           peer_uid: int, peer_gid: int) -> CoreVerifiedIngressObservation:
    from .core_gateway import _log_ingress_denial, _read_config_current
    _read_config_current(config)
    nonce = os.urandom(32).hex()
    deadline = time.monotonic() + IPC_TIMEOUT
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        _log_ingress_denial("root_ipc_socket", CoreGatewayDenied())
        raise CoreGatewayDenied("root core inspector socket is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(IPC_TIMEOUT)
    try:
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {"op": "observe-ingress", "nonce": nonce,
                "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid}
        raw_request = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw_request) > MAX_REQUEST:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw_request)) + raw_request)
        result = _read_frame(conn, deadline, MAX_RESPONSE)
    except Exception as error:
        _log_ingress_denial("root_ipc_exchange", error)
        raise CoreGatewayDenied("root core ingress proof is unavailable") from None
    finally:
        conn.close()
    fields = {field.name for field in CoreVerifiedIngressObservation.__dataclass_fields__.values()
              if not field.name.startswith("_")}
    if set(result) != fields:
        _log_ingress_denial("root_ipc_schema", CoreGatewayDenied())
        raise CoreGatewayDenied("root core ingress proof has an unknown schema")
    body = dict(result)
    proof_sha = body.pop("proof_sha256", None)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
    if (proof_sha != hashlib.sha256(b"hermes-jarvis-core-ingress-v1\0" + canonical).hexdigest()
            or result.get("nonce") != nonce or time.monotonic() >= deadline):
        _log_ingress_denial("root_ipc_binding", CoreGatewayDenied())
        raise CoreGatewayDenied("root core ingress proof is mismatched or late")
    try:
        observation = CoreVerifiedIngressObservation(**result, _seal=_PROOF_SEAL)
        _read_config_current(config)
        listener = os.lstat(config.ingress_socket)
        if observation.verify_current(config, peer_pid=peer_pid, peer_uid=peer_uid,
            peer_gid=peer_gid, listener_identity=(listener.st_dev, listener.st_ino)) is not True:
            raise ValueError
        return observation
    except Exception as error:
        _log_ingress_denial("root_ipc_currentness", error)
        raise CoreGatewayDenied("root core ingress proof is invalid or stale") from None


def verify_current_core_overview(config: CoreGatewayConfig, *, peer_pid: int,
                                 peer_uid: int, peer_gid: int,
                                 accepted_ingress: Any) -> CoreVerifiedOverviewObservation:
    from .core_gateway import _log_ingress_denial, _read_config_current
    _read_config_current(config)
    nonce = os.urandom(32).hex()
    deadline = time.monotonic() + MAX_PROOF_SECONDS
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        raise CoreGatewayDenied("root core overview inspector is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(MAX_PROOF_SECONDS)
    try:
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {"op": "observe-core-overview", "nonce": nonce,
                "peer_pid": peer_pid, "peer_uid": peer_uid, "peer_gid": peer_gid}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_REQUEST:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw)) + raw)
        result = _read_frame(conn, deadline, MAX_RESPONSE)
    except Exception as error:
        _log_ingress_denial("root_core_overview_exchange", error)
        raise CoreGatewayDenied("root core overview proof is unavailable") from None
    finally:
        conn.close()
    fields = {"schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
              "config_sha256", "core_generation", "core_source_generation", "projection", "proof_sha256"}
    if set(result) != fields:
        raise CoreGatewayDenied("root core overview proof has an unknown schema")
    claims = dict(result)
    proof = claims.pop("proof_sha256", None)
    try:
        expected_proof = _overview_digest(claims)
    except Exception:
        raise CoreGatewayDenied("root core overview proof is malformed") from None
    if (proof != expected_proof or result.get("nonce") != nonce
            or time.monotonic() >= deadline):
        raise CoreGatewayDenied("root core overview proof is mismatched or late")
    try:
        observation = CoreVerifiedOverviewObservation(**result, _seal=_OVERVIEW_PROOF_SEAL)
        _read_config_current(config)
        if observation.verify_current(config, peer_pid=peer_pid, peer_uid=peer_uid,
                                      peer_gid=peer_gid, accepted_ingress=accepted_ingress) is not True:
            raise ValueError
        return observation
    except Exception as error:
        _log_ingress_denial("root_core_overview_currentness", error)
        raise CoreGatewayDenied("root core overview proof is invalid or stale") from None


def verify_current_skill_learning(config: CoreGatewayConfig, *, access_jwt: str,
                                  accepted_ingress: Any) -> CoreVerifiedSkillLearningObservation:
    from .core_gateway import CoreAcceptedIngressObservation, _log_ingress_denial, _read_config_current
    if (type(accepted_ingress) is not CoreAcceptedIngressObservation
            or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
            or not access_jwt.isascii()
            or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                != accepted_ingress.principal.token_fingerprint):
        raise CoreGatewayDenied("current accepted owner ingress is required")
    _read_config_current(config)
    if accepted_ingress.verify_current(config) is not True:
        raise CoreGatewayDenied("current accepted owner ingress is required")
    root_proof = accepted_ingress.root_observation
    nonce = os.urandom(32).hex()
    deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        raise CoreGatewayDenied("root core learning inspector is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(max(0.05, deadline-time.monotonic()))
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {
            "schema": 1, "op": "observe-skill-learning", "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": root_proof.nonce,
            "ingress_proof_sha256": root_proof.proof_sha256,
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_SKILL_LEARNING_REQUEST_BYTES or time.monotonic() >= deadline:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw)) + raw)
        result = _read_frame(conn, deadline, MAX_SKILL_LEARNING_RESPONSE_BYTES, encoding="utf-8")
    except Exception as error:
        _log_ingress_denial("root_skill_learning_exchange", error)
        raise CoreGatewayDenied("root skill learning proof is unavailable") from None
    finally:
        conn.close()
    fields = {"schema", "nonce", "boot_id", "issued_monotonic", "expires_monotonic",
              "config_sha256", "core_generation", "ingress_nonce", "ingress_proof_sha256",
              "readiness", "pending_reasons", "candidates", "proof_sha256"}
    if set(result) != fields:
        raise CoreGatewayDenied("root skill learning proof has an unknown schema")
    claims = dict(result)
    proof_sha = claims.pop("proof_sha256", None)
    try:
        expected = _learning_digest(claims)
    except Exception:
        raise CoreGatewayDenied("root skill learning proof is malformed") from None
    if (proof_sha != expected or result.get("nonce") != nonce
            or result.get("ingress_nonce") != root_proof.nonce
            or result.get("ingress_proof_sha256") != root_proof.proof_sha256
            or time.monotonic() >= deadline):
        raise CoreGatewayDenied("root skill learning proof is mismatched or late")
    try:
        observation = CoreVerifiedSkillLearningObservation(
            schema=result["schema"], nonce=result["nonce"], boot_id=result["boot_id"],
            issued_monotonic=result["issued_monotonic"],
            expires_monotonic=result["expires_monotonic"],
            config_sha256=result["config_sha256"], core_generation=result["core_generation"],
            ingress_nonce=result["ingress_nonce"],
            ingress_proof_sha256=result["ingress_proof_sha256"],
            readiness=result["readiness"], pending_reasons=tuple(result["pending_reasons"]),
            candidates=tuple(result["candidates"]), proof_sha256=result["proof_sha256"],
            _access_fingerprint=accepted_ingress.principal.token_fingerprint,
            _seal=_SKILL_LEARNING_PROOF_SEAL)
        _read_config_current(config)
        if observation.verify_current(config, peer_pid=accepted_ingress.peer_pid,
                peer_uid=accepted_ingress.peer_uid, peer_gid=accepted_ingress.peer_gid,
                accepted_ingress=accepted_ingress) is not True:
            raise ValueError
        return observation
    except Exception as error:
        _log_ingress_denial("root_skill_learning_currentness", error)
        raise CoreGatewayDenied("root skill learning proof is invalid or stale") from None


def verify_current_owner_turn(config: CoreGatewayConfig, *, access_jwt: str,
                              accepted_ingress: Any, session_id: str,
                              conversation_id: str, gateway_turn_id: str,
                              prompt_sha256: str, mission_binding: Any = None,
                              planning_context: Any = None,
                              require_planning_context: bool = False) -> str:
    """Ask the root inspector to mint one current owner-turn handle; return no proof fields."""
    from .core_gateway import CoreAcceptedIngressObservation, _log_ingress_denial, _read_config_current
    try:
        mission_wire = _mission_binding_wire(mission_binding)
        planning_wire = _planning_context_wire(planning_context)
    except Exception:
        raise CoreGatewayDenied("current accepted owner turn is required") from None
    if (type(require_planning_context) is not bool
            or (require_planning_context and planning_wire is None)
            or (planning_wire is not None and mission_wire is not None)
            or (planning_wire is not None and planning_wire["planner_prompt_sha256"] != prompt_sha256)
            or type(accepted_ingress) is not CoreAcceptedIngressObservation
            or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
            or not access_jwt.isascii()
            or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                != accepted_ingress.principal.token_fingerprint
            or not isinstance(session_id, str) or not 1 <= len(session_id) <= 512
            or not session_id.isascii()
            or any(ord(char) < 0x20 for char in session_id)
            or any(not isinstance(value, str)
                   or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", value) is None
                   for value in (conversation_id, gateway_turn_id))
            or not _is_hash(prompt_sha256)):
        raise CoreGatewayDenied("current accepted owner turn is required")
    _read_config_current(config)
    if accepted_ingress.verify_current(config) is not True:
        raise CoreGatewayDenied("current accepted owner turn is required")
    root_proof = accepted_ingress.root_observation
    nonce = os.urandom(32).hex()
    deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
    info = os.lstat(CORE_INSPECTOR_SOCKET)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_gid != config.gateway_gid
            or stat.S_IMODE(info.st_mode) != 0o660):
        raise CoreGatewayDenied("root owner-turn inspector is unavailable")
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        conn.settimeout(max(0.05, deadline-time.monotonic()))
        conn.connect(str(CORE_INSPECTOR_SOCKET))
        if not hasattr(socket, "SO_PEERCRED"):
            raise ValueError
        inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
            "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if inspector_uid != 0 or inspector_pid <= 1:
            raise ValueError
        body = {
            "schema": 1, "op": "observe-owner-turn", "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": root_proof.nonce,
            "ingress_proof_sha256": root_proof.proof_sha256,
            "session_id": session_id, "conversation_id": conversation_id,
            "gateway_turn_id": gateway_turn_id, "prompt_sha256": prompt_sha256,
            "mission_binding": mission_wire, "planning_context": planning_wire,
        }
        raw = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii")
        if len(raw) > MAX_OWNER_TURN_REQUEST_BYTES or time.monotonic() >= deadline:
            raise ValueError
        conn.sendall(struct.pack("!I", len(raw)) + raw)
        result = _read_frame(conn, deadline, MAX_RESPONSE)
    except Exception as error:
        _log_ingress_denial("root_owner_turn_exchange", error)
        raise CoreGatewayDenied("root owner-turn proof is unavailable") from None
    finally:
        conn.close()
    if (set(result) != {"schema", "nonce", "owner_turn_handle"}
            or type(result.get("schema")) is not int or result["schema"] != 1
            or result.get("nonce") != nonce
            or not isinstance(result.get("owner_turn_handle"), str)
            or re.fullmatch(r"[0-9a-f]{32}", result["owner_turn_handle"]) is None
            or time.monotonic() >= deadline):
        raise CoreGatewayDenied("root owner-turn proof is mismatched or late")
    try:
        _read_config_current(config)
        if accepted_ingress.verify_current(config) is not True:
            raise ValueError
    except Exception as error:
        _log_ingress_denial("root_owner_turn_currentness", error)
        raise CoreGatewayDenied("root owner-turn proof is stale") from None
    return result["owner_turn_handle"]


class CoreGatewayInspector:
    """Fixed BFF-side facade for root-verified mission and final-effect IPC."""

    def __init__(self, config: CoreGatewayConfig):
        if type(config) is not CoreGatewayConfig:
            raise CoreGatewayDenied("fixed current core gateway configuration is required")
        self._config = config

    def prepare_master_planning_context(self, access_jwt: str, accepted_ingress: Any,
                                       mission_id: str, revision: int,
                                       planner_prompt_sha256: str) -> PlanningContext:
        """Fetch a root-derived planning DTO for an already reserved owner mission."""
        from .core_gateway import CoreAcceptedIngressObservation, _read_config_current
        if (type(accepted_ingress) is not CoreAcceptedIngressObservation
                or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
                or not access_jwt.isascii()
                or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                    != accepted_ingress.principal.token_fingerprint
                or not isinstance(mission_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", mission_id) is None
                or type(revision) is not int or revision < 1
                or not _is_hash(planner_prompt_sha256)):
            raise CoreGatewayDenied("current accepted mission planning ingress is required")
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("current accepted mission planning ingress is required")
        proof = accepted_ingress.root_observation
        nonce = os.urandom(32).hex()
        deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != self._config.gateway_gid
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise CoreGatewayDenied("root planning inspector is unavailable")
        body = {"schema": 1, "op": "prepare-master-planning-context", "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": proof.nonce, "ingress_proof_sha256": proof.proof_sha256,
            "mission_id": mission_id, "revision": revision,
            "planner_prompt_sha256": planner_prompt_sha256}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(raw) > MAX_OWNER_TURN_REQUEST_BYTES:
            raise CoreGatewayDenied("root planning request exceeded its bound")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(max(0.05, deadline - time.monotonic()))
            conn.connect(str(CORE_INSPECTOR_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            result = _read_frame(conn, deadline, MAX_RESPONSE)
        except Exception:
            raise CoreGatewayDenied("root planning context is unavailable") from None
        finally:
            conn.close()
        try:
            if (set(result) != {"schema", "nonce", "ok", "planning_context"}
                    or result.get("schema") != 1 or result.get("nonce") != nonce
                    or result.get("ok") is not True or time.monotonic() >= deadline):
                raise ValueError
            context = PlanningContext.from_wire(result["planning_context"])
            if (context.mission_id != mission_id or context.revision != revision
                    or context.planner_prompt_sha256 != planner_prompt_sha256):
                raise ValueError
            _read_config_current(self._config)
            if accepted_ingress.verify_current(self._config) is not True:
                raise ValueError
            return context
        except Exception:
            raise CoreGatewayDenied("root planning context is malformed, stale or mismatched") from None

    def read_master_plan(self, access_jwt: str, accepted_ingress: Any,
                         mission_id: str, revision: int) -> RootVerifiedJarvisMasterPlanData | None:
        """Return only a fresh root-read durable plan for this authenticated owner."""
        from .core_gateway import CoreAcceptedIngressObservation, _read_config_current
        if (type(accepted_ingress) is not CoreAcceptedIngressObservation
                or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
                or not access_jwt.isascii()
                or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                    != accepted_ingress.principal.token_fingerprint
                or not isinstance(mission_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", mission_id) is None
                or type(revision) is not int or revision < 1):
            raise CoreGatewayDenied("current authenticated mission ingress is required")
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("current authenticated mission ingress is required")
        proof = accepted_ingress.root_observation
        nonce = os.urandom(32).hex()
        deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != self._config.gateway_gid
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise CoreGatewayDenied("root master plan inspector is unavailable")
        body = {"schema": 1, "op": "read-master-plan", "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": proof.nonce, "ingress_proof_sha256": proof.proof_sha256,
            "mission_id": mission_id, "revision": revision}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(raw) > MAX_OWNER_TURN_REQUEST_BYTES:
            raise CoreGatewayDenied("root plan read request exceeded its bound")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(max(0.05, deadline - time.monotonic()))
            conn.connect(str(CORE_INSPECTOR_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            result = _read_frame(conn, deadline, MAX_MASTER_PLAN_RESPONSE)
        except Exception:
            raise CoreGatewayDenied("root durable master plan is unavailable") from None
        finally:
            conn.close()
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("mission owner ingress changed during plan read")
        if (set(result) != {"schema", "nonce", "ok", "plan_data"}
                or result.get("schema") != 1 or result.get("nonce") != nonce
                or result.get("ok") is not True or time.monotonic() >= deadline):
            raise CoreGatewayDenied("root plan read response is malformed")
        raw_data = result["plan_data"]
        if raw_data is None:
            return None
        expected = {"schema", "mission_id", "revision", "owner_subject_sha256", "goal_sha256",
            "plan_json", "plan_sha256", "response_sha256", "gateway_turn_id", "owner_turn_handle",
            "core_generation", "core_source_generation", "catalog_sha256", "planner_prompt_sha256",
            "master_source_generation_sha256", "master_source_manifest_sha256", "master_prompt_sha256",
            "source_profile_id", "selected_source_ids", "execution_mode"}
        try:
            if type(raw_data) is not dict or set(raw_data) != expected:
                raise ValueError
            data = RootVerifiedJarvisMasterPlanData(
                **{key: value for key, value in raw_data.items() if key != "selected_source_ids"},
                selected_source_ids=tuple(raw_data["selected_source_ids"]),
                _seal=_MASTER_PLAN_DATA_SEAL)
            if (data.mission_id != mission_id or data.revision != revision
                    or data.owner_subject_sha256 != hashlib.sha256(
                        accepted_ingress.principal.subject.encode("utf-8")).hexdigest()
                    or data.is_root_verified_data() is not True):
                raise ValueError
            return data
        except Exception:
            raise CoreGatewayDenied("root durable master plan data is invalid") from None

    def read_native_activity(self, access_jwt: str, accepted_ingress: Any) -> dict[str, Any]:
        """Read only this accepted principal's bounded current-source worker events."""
        from .core_gateway import CoreAcceptedIngressObservation, _read_config_current
        if (type(accepted_ingress) is not CoreAcceptedIngressObservation
                or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
                or not access_jwt.isascii()
                or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                    != accepted_ingress.principal.token_fingerprint):
            raise CoreGatewayDenied("current authenticated activity ingress is required")
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("current authenticated activity ingress is required")
        proof = accepted_ingress.root_observation
        nonce = os.urandom(32).hex()
        deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != self._config.gateway_gid
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise CoreGatewayDenied("root native activity inspector is unavailable")
        body = {"schema": 1, "op": "read-native-activity", "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": proof.nonce, "ingress_proof_sha256": proof.proof_sha256}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(raw) > MAX_OWNER_TURN_REQUEST_BYTES:
            raise CoreGatewayDenied("root native activity request exceeded its bound")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(max(0.05, deadline - time.monotonic()))
            conn.connect(str(CORE_INSPECTOR_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            result = _read_frame(conn, deadline, MAX_NATIVE_ACTIVITY_RESPONSE)
        except Exception:
            raise CoreGatewayDenied("root native activity is unavailable") from None
        finally:
            conn.close()
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("native activity owner ingress changed during read")
        try:
            if (set(result) != {"schema", "nonce", "ok", "activity"}
                    or result.get("schema") != 1 or result.get("nonce") != nonce
                    or result.get("ok") is not True or time.monotonic() >= deadline):
                raise ValueError
            activity = result["activity"]
            if (type(activity) is not dict or set(activity) != {
                    "schema", "observed_at", "window_seconds", "coverage", "instances", "relations"}
                    or activity["schema"] != 1
                    or activity["window_seconds"] != 7 * 24 * 60 * 60
                    or activity["coverage"] != "observed-callbacks"
                    or type(activity["instances"]) is not list or len(activity["instances"]) > 100
                    or activity["relations"] != []
                    or sum(len(item.get("events", [])) for item in activity["instances"]
                           if isinstance(item, dict)) > 200):
                raise ValueError
            return activity
        except Exception:
            raise CoreGatewayDenied("root native activity response is invalid") from None

    def preflight_native_mission(self, binding: Any, *, owner_subject_sha256: str,
                                 gateway_turn_id: str) -> bool:
        """Ask root to re-read a just-spent owner mission before native submit."""
        from .jarvis_mission_executor import MissionBinding
        from .core_gateway import _read_config_current
        if (type(binding) is not MissionBinding or binding.schema != MISSION_BINDING_SCHEMA
                or binding.source_profile_id != "hermes"
                or not _is_hash(owner_subject_sha256)
                or not isinstance(gateway_turn_id, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{24,64}", gateway_turn_id) is None):
            raise CoreGatewayDenied("typed owner mission and generated turn are required")
        _read_config_current(self._config)
        nonce = os.urandom(32).hex()
        body = {"schema": 1, "op": "preflight-native-mission", "nonce": nonce,
                "gateway_turn_id": gateway_turn_id,
                "owner_subject_sha256": owner_subject_sha256,
                "mission_binding": _mission_binding_wire(binding)}
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        deadline = time.monotonic() + MAX_PROOF_SECONDS
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        if (len(raw) > MAX_OWNER_TURN_REQUEST_BYTES or not stat.S_ISSOCK(info.st_mode)
                or info.st_uid != 0 or info.st_gid != self._config.gateway_gid
                or stat.S_IMODE(info.st_mode) != 0o660):
            raise CoreGatewayDenied("root mission preflight is unavailable")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(MAX_PROOF_SECONDS)
            conn.connect(str(CORE_INSPECTOR_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            pid, uid, _gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != 0 or pid <= 1:
                raise ValueError
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            result = _read_frame(conn, deadline, MAX_RESPONSE)
        except Exception:
            raise CoreGatewayDenied("root mission preflight is unavailable") from None
        finally:
            conn.close()
        _read_config_current(self._config)
        if (set(result) != {"schema", "nonce", "ok"} or result.get("schema") != 1
                or result.get("nonce") != nonce or result.get("ok") is not True
                or time.monotonic() >= deadline):
            raise CoreGatewayDenied("spent mission preflight was denied")
        return True

    def _owner_effect_rpc(self, operation: str, *, access_jwt: str,
                          accepted_ingress: Any, owner_turn_handle: str,
                          fields: dict[str, Any] | None = None) -> dict[str, Any]:
        from .core_gateway import CoreAcceptedIngressObservation, _read_config_current
        if (operation not in {"list-final-effects", "decide-final-effect"}
                or type(accepted_ingress) is not CoreAcceptedIngressObservation
                or not isinstance(access_jwt, str) or not 1 <= len(access_jwt) <= 16_384
                or not access_jwt.isascii()
                or hashlib.sha256(access_jwt.encode("ascii")).hexdigest()
                    != accepted_ingress.principal.token_fingerprint
                or not isinstance(owner_turn_handle, str)
                or re.fullmatch(r"[A-Za-z0-9_-]{32,128}", owner_turn_handle) is None):
            raise CoreGatewayDenied("current authenticated owner request is required")
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("current authenticated owner request is required")
        root_proof = accepted_ingress.root_observation
        nonce = os.urandom(32).hex()
        deadline = min(time.monotonic() + MAX_PROOF_SECONDS, accepted_ingress.expires_monotonic)
        info = os.lstat(CORE_INSPECTOR_SOCKET)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or info.st_gid != self._config.gateway_gid or stat.S_IMODE(info.st_mode) != 0o660):
            raise CoreGatewayDenied("root final-effect inspector is unavailable")
        body = {"schema": 1, "op": operation, "nonce": nonce,
            "peer_pid": accepted_ingress.peer_pid, "peer_uid": accepted_ingress.peer_uid,
            "peer_gid": accepted_ingress.peer_gid, "access_jwt": access_jwt,
            "core_generation": accepted_ingress.core_generation,
            "ingress_nonce": root_proof.nonce,
            "ingress_proof_sha256": root_proof.proof_sha256,
            "owner_turn_handle": owner_turn_handle}
        if fields:
            if set(fields) & set(body):
                raise CoreGatewayDenied("final-effect request contains reserved fields")
            body.update(fields)
        raw = json.dumps(body, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")
        if len(raw) > MAX_OWNER_TURN_REQUEST_BYTES or time.monotonic() >= deadline:
            raise CoreGatewayDenied("final-effect request exceeded its bound")
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            conn.settimeout(max(0.05, deadline - time.monotonic()))
            conn.connect(str(CORE_INSPECTOR_SOCKET))
            if not hasattr(socket, "SO_PEERCRED"):
                raise ValueError
            inspector_pid, inspector_uid, _inspector_gid = struct.unpack(
                "3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if inspector_uid != 0 or inspector_pid <= 1:
                raise ValueError
            conn.sendall(struct.pack("!I", len(raw)) + raw)
            result = _read_frame(conn, deadline, MAX_FINAL_EFFECT_RESPONSE)
        except Exception:
            raise CoreGatewayDenied("root final-effect inspector is unavailable") from None
        finally:
            conn.close()
        if (type(result.get("schema")) is not int or result["schema"] != 1
                or result.get("nonce") != nonce or result.get("ok") is not True
                or time.monotonic() >= deadline):
            raise CoreGatewayDenied("root final-effect response is unavailable")
        _read_config_current(self._config)
        if accepted_ingress.verify_current(self._config) is not True:
            raise CoreGatewayDenied("owner ingress changed during final-effect request")
        return result

    def list_final_effects(self, *, access_jwt: str, accepted_ingress: Any,
                           owner_turn_handle: str) -> tuple[Any, ...]:
        from .jarvis_final_effects import FinalEffectReview
        row = self._owner_effect_rpc("list-final-effects", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, owner_turn_handle=owner_turn_handle)
        reviews = row.get("reviews")
        if not isinstance(reviews, list) or len(reviews) > 32:
            raise CoreGatewayDenied("root final-effect review list is malformed")
        result = []
        fields = {"pending_id", "review_sha256", "tool_name", "preview_json", "status",
                  "expires_monotonic"}
        try:
            for item in reviews:
                if not isinstance(item, dict) or set(item) != fields:
                    raise ValueError
                result.append(FinalEffectReview(**item))
        except Exception:
            raise CoreGatewayDenied("root final-effect review list is malformed") from None
        return tuple(result)

    def decide_final_effect(self, *, access_jwt: str, accepted_ingress: Any,
                            owner_turn_handle: str, pending_id: str,
                            review_sha256: str, decision: str,
                            idempotency_key: str) -> str:
        row = self._owner_effect_rpc("decide-final-effect", access_jwt=access_jwt,
            accepted_ingress=accepted_ingress, owner_turn_handle=owner_turn_handle,
            fields={"pending_id": pending_id, "review_sha256": review_sha256,
                    "decision": decision, "idempotency_key": idempotency_key})
        status = row.get("status")
        if status not in {"approved", "denied"}:
            raise CoreGatewayDenied("root final-effect decision is malformed")
        return status


def main() -> None:
    import argparse
    argparse.ArgumentParser(description="read-only root inspector for the core Jarvis ingress").parse_args()
    if os.geteuid() != 0:
        raise SystemExit("core ingress inspector must run as root")
    serve_inspection_socket(CoreGatewayConfig.load(expected_owner_uid=0))


if __name__ == "__main__":
    main()
